// Arcis MPC circuit for Private Set Intersection (PSI).
// Used by Arcium Messenger for blind contact discovery.
//
// Architecture:
// - Client encrypts contact hashes with RescueCipher
// - Server stores its own encrypted hash database
// - This circuit runs inside Arcium MPC network (Arx nodes)
// - Comparison happens on encrypted shares — no node sees raw data
// - Only the client (owner) can decrypt the match result

use arcis::*;

#[encrypted]
pub mod circuits {
    use arcis::*;

    /// Number of contacts per query batch.
    /// MPC circuits require compile-time array sizes (no Vec support).
    /// Can be increased to 50-100 for production after integration testing.
    pub const BATCH_SIZE: usize = 10;

    /// Client's contact list (encrypted phone hashes).
    /// u64 = truncated SHA256(phone_number) — sufficient uniqueness
    /// at much lower gas cost than full 32-byte hashes.
    ///
    /// `count` is the number of real entries, which occupy `hashes[0..count]`;
    /// the rest is padding and may hold any value. It is a field element, not a
    /// `u8`, so that every out-of-range value reaches the check below instead
    /// of being reduced modulo 2^8 first.
    pub struct ClientContacts {
        pub hashes: [u64; BATCH_SIZE],
        pub count: BaseField25519,
    }

    /// Server's registered users (encrypted phone hashes), same layout.
    pub struct ServerContacts {
        pub hashes: [u64; BATCH_SIZE],
        pub count: BaseField25519,
    }

    /// Per-position match result.
    /// matches[i] = true if client.hashes[i] is a real entry that exists among
    /// the server's real entries. `valid` is false if either count is not in
    /// 0..=BATCH_SIZE; then every match is false and the result must be
    /// rejected as a whole, not read as "no matches".
    pub struct MatchResult {
        pub matches: [bool; BATCH_SIZE],
        pub valid: bool,
    }

    /// Returns whether `count` is in 0..=BATCH_SIZE, and which slots are real
    /// (slot i is real iff i < count). Built from equalities only, so it
    /// holds for every field value of `count`.
    fn real_slots(count: BaseField25519) -> (bool, [bool; BATCH_SIZE]) {
        let mut valid = false;
        let mut real = [false; BATCH_SIZE];
        for k in 0..=BATCH_SIZE {
            let is_k = count == BaseField25519::from_usize(k);
            valid = valid || is_k;
            for slot in real.iter_mut().take(k) {
                *slot = *slot || is_k;
            }
        }
        (valid, real)
    }

    /// Blind PSI: compare client contacts against server set
    /// without revealing either side to MPC nodes.
    #[instruction]
    pub fn psi_intersect(
        client_data: Enc<Shared, ClientContacts>,
        server_data: Enc<Shared, ServerContacts>,
    ) -> Enc<Shared, MatchResult> {
        // 1. Convert to secret shares (no node sees real data)
        let client = client_data.to_arcis();
        let server = server_data.to_arcis();

        let (client_valid, client_real) = real_slots(client.count);
        let (server_valid, server_real) = real_slots(server.count);
        let valid = client_valid && server_valid;

        let mut matches = [false; BATCH_SIZE];

        // 2. Blind comparison inside MPC, of real entries only.
        // The == operator here is the Cerberus MPC protocol,
        // not a regular CPU comparison.
        for i in 0..BATCH_SIZE {
            let mut found = false;
            for j in 0..BATCH_SIZE {
                if server_real[j] && client.hashes[i] == server.hashes[j] {
                    found = true;
                }
            }
            matches[i] = valid && client_real[i] && found;
        }

        // 3. Encrypt result with client's key
        // Only the client can decrypt the matches.
        client_data.owner.from_arcis(MatchResult { matches, valid })
    }
}

/// Runs the compiled circuit (`build/psi_intersect.arcis.ir`, written when this
/// crate is compiled) on chosen inputs, through Arcis's mock MPC evaluation.
/// This is the circuit the MXE runs, not a separate model of it; it is not a
/// run on Arx nodes.
#[cfg(test)]
mod tests {
    use super::circuits::{ClientContacts, MatchResult, ServerContacts, BATCH_SIZE};
    use arcis::{testing::*, *};

    const H1: u64 = 0x1111_2222_3333_4444;
    const H2: u64 = 0x5555_6666_7777_8888;
    const H3: u64 = u64::MAX;
    const PAD: u64 = 0x0bad_0bad_0bad_0bad;

    fn count(n: usize) -> BaseField25519 {
        BaseField25519::from_usize(n)
    }

    /// Real entries first, then `pad` repeated.
    fn slots(real: &[u64], pad: u64) -> [u64; BATCH_SIZE] {
        let mut out = [pad; BATCH_SIZE];
        out[..real.len()].copy_from_slice(real);
        out
    }

    struct Psi(ArcisInstructionWithInfo);

    impl Psi {
        fn new() -> Self {
            Psi(get_instruction("psi_intersect"))
        }

        fn run(
            &self,
            client: [u64; BATCH_SIZE],
            client_count: BaseField25519,
            server: [u64; BATCH_SIZE],
            server_count: BaseField25519,
        ) -> MatchResult {
            let client =
                Shared::new(ArcisX25519Pubkey::from_base58(b"client")).from_arcis(ClientContacts {
                    hashes: client,
                    count: client_count,
                });
            let server =
                Shared::new(ArcisX25519Pubkey::from_base58(b"server")).from_arcis(ServerContacts {
                    hashes: server,
                    count: server_count,
                });
            let out: Enc<Shared, MatchResult> = self.0.eval((client, server));
            out.to_arcis()
        }

        /// A valid result, trimmed to the client's count.
        fn matches(
            &self,
            client: &[u64],
            client_pad: u64,
            server: &[u64],
            server_pad: u64,
        ) -> Vec<bool> {
            let r = self.run(
                slots(client, client_pad),
                count(client.len()),
                slots(server, server_pad),
                count(server.len()),
            );
            assert!(r.valid, "valid counts gave an invalid result");
            assert!(
                r.matches[client.len()..].iter().all(|m| !m),
                "a client padding slot matched: {:?}",
                r.matches
            );
            r.matches[..client.len()].to_vec()
        }
    }

    #[test]
    fn empty_sets_and_count_bounds() {
        let psi = Psi::new();
        assert_eq!(psi.matches(&[], 0, &[], 0), Vec::<bool>::new());
        assert_eq!(psi.matches(&[], H1, &[H1], 0), Vec::<bool>::new());
        assert_eq!(psi.matches(&[H1], 0, &[], H1), vec![false]);
        assert_eq!(psi.matches(&[H1], 0, &[H1], 0), vec![true]);
        let ten: Vec<u64> = (1..=10).collect();
        assert_eq!(psi.matches(&ten, 0, &ten, 0), vec![true; 10]);
        let mut other: Vec<u64> = (11..=20).collect();
        other[9] = 3;
        let mut expected = vec![false; 10];
        expected[2] = true;
        assert_eq!(psi.matches(&ten, 0, &other, 0), expected);
    }

    #[test]
    fn a_real_zero_hash_is_compared_like_any_other() {
        let psi = Psi::new();
        // Against an empty server whose padding is zero.
        assert_eq!(psi.matches(&[0], 0, &[], 0), vec![false]);
        // Against real entries padded with zero.
        assert_eq!(psi.matches(&[0, H1], 0, &[H1, H2], 0), vec![false, true]);
        // A real zero on both sides is a match.
        assert_eq!(psi.matches(&[0], PAD, &[H2, 0], PAD), vec![true]);
    }

    #[test]
    fn padding_never_matches() {
        let psi = Psi::new();
        // Server padding equal to a real client hash.
        assert_eq!(
            psi.matches(&[H1, H2], PAD, &[H2, H3], H1),
            vec![false, true]
        );
        // Client padding equal to a real server hash.
        assert_eq!(psi.matches(&[H1], H3, &[H3], PAD), vec![false]);
        // Client padding equal to server padding.
        assert_eq!(psi.matches(&[H1], PAD, &[H2], PAD), vec![false]);
    }

    #[test]
    fn matches_nonmatches_and_duplicates() {
        let psi = Psi::new();
        assert_eq!(
            psi.matches(&[H1, H2, H3], 0, &[H3, PAD, H1], 0),
            vec![true, false, true]
        );
        // Duplicates on the client side are each answered.
        assert_eq!(
            psi.matches(&[H1, H1, H2], 0, &[H1], 0),
            vec![true, true, false]
        );
        // Duplicates on the server side do not change the answer.
        assert_eq!(
            psi.matches(&[H1, H2], 0, &[H2, H2, H2], 0),
            vec![false, true]
        );
    }

    /// Counts outside 0..=BATCH_SIZE, sent straight to the circuit: the result
    /// is marked invalid and carries no match, so it cannot be read as a
    /// normal "no matches" answer. Equal hashes everywhere make any leaked
    /// match visible.
    #[test]
    fn invalid_counts_fail_closed() {
        let psi = Psi::new();
        let all = [H1; BATCH_SIZE];
        let invalid = [
            count(BATCH_SIZE + 1),
            count(255),
            count(256),
            BaseField25519::from_u64(u64::MAX),
            BaseField25519::from_u128(u128::MAX),
            BaseField25519::from_i8(-1),
        ];
        for bad in invalid {
            for (client_count, server_count) in [(bad, count(5)), (count(5), bad), (bad, bad)] {
                let r = psi.run(all, client_count, all, server_count);
                assert!(!r.valid, "invalid count {bad:?} was accepted");
                assert_eq!(
                    r.matches, [false; BATCH_SIZE],
                    "invalid count {bad:?} leaked matches"
                );
            }
        }
        // The same inputs with valid counts do match, so the checks above test the counts.
        let r = psi.run(all, count(5), all, count(5));
        assert!(r.valid);
        assert_eq!(&r.matches[..5], &[true; 5]);
    }
}

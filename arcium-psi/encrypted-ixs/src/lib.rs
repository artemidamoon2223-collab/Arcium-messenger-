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
    pub struct ClientContacts {
        pub hashes: [u64; BATCH_SIZE],
    }

    /// Server's registered users (encrypted phone hashes).
    pub struct ServerContacts {
        pub hashes: [u64; BATCH_SIZE],
    }

    /// Per-position match result.
    /// matches[i] = true if client.hashes[i] exists in server set.
    pub struct MatchResult {
        pub matches: [bool; BATCH_SIZE],
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

        let mut matches = [false; BATCH_SIZE];

        // 2. Blind comparison inside MPC
        // The == operator here is the Cerberus MPC protocol,
        // not a regular CPU comparison.
        for i in 0..BATCH_SIZE {
            let mut found = false;
            for j in 0..BATCH_SIZE {
                if client.hashes[i] == server.hashes[j] {
                    found = true;
                }
            }
            matches[i] = found;
        }

        // 3. Encrypt result with client's key
        // Only the client can decrypt the matches.
        client_data.owner.from_arcis(MatchResult { matches })
    }
}

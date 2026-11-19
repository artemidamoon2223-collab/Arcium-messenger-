//! Tracker R-6: the signed prekey is rotated. The prekey record
//! (`PERSISTED_PREKEY_RECORD_V3`, V2 still read), the rotation rule
//! (`plan_rotation`), the maintenance and publication note the network
//! layer runs at the start of a round, and which signed prekey answers a
//! handshake (`check_answerable`). The network tests are in
//! `spk_rotation.rs`.

use super::*;
use zeroize::ZeroizeOnDrop;

const P: u64 = SIGNED_PREKEY_PERIOD_SECS;
/// A time well after 1970, so that steps of a period back stay positive.
const T0: u64 = 1_800_000_000;

fn record_of(core: &ArciumCore) -> PrekeyRecord {
    unpack_prekeys(&read_record(core)).unwrap()
}

fn id_of(sk: &StaticSecret) -> [u8; SPK_ID_LEN] {
    spk_id(PublicKey::from(sk).as_bytes())
}

fn current_spk(core: &ArciumCore) -> [u8; SPK_ID_LEN] {
    id_of(&record_of(core).signed_prekey_sk)
}

fn prev_spk(core: &ArciumCore) -> Option<[u8; SPK_ID_LEN]> {
    record_of(core).prev.as_ref().map(id_of)
}

/// What the network layer does across two rounds a period apart: the relay
/// accepts the current signed prekey at `at`, and the round at `at + P`
/// rotates it.
fn rotate_by_time(core: &ArciumCore, at: u64) {
    core.note_prekeys_published(&current_spk(core), at).unwrap();
    core.maintain_prekeys(at + P).unwrap();
}

fn initiator(byte: u8) -> Arc<ArciumCore> {
    let core = fresh_core(byte);
    core.save_identity(Identity::generate()).unwrap();
    core
}

fn handshake_naming(spk: [u8; SPK_ID_LEN], opk_id: Option<u64>) -> InitiatorHandshakeV1 {
    InitiatorHandshakeV1 {
        identity_pk: PublicKey::from([9u8; 32]),
        ephemeral_pk: PublicKey::from(&StaticSecret::random_from_rng(OsRng)),
        spk_id: spk,
        opk_id,
    }
}

fn assert_no_previous_in_raw(core: &ArciumCore, after: &str) {
    let raw = read_record(core);
    assert_eq!(raw.len(), PREKEY_RECORD_V3_LEN, "{after}");
    assert_eq!(raw[97] & FLAG_PREV, 0, "{after}: no previous signed prekey is flagged");
    assert!(
        raw[154..186].iter().all(|b| *b == 0),
        "{after}: the previous signed prekey's bytes are gone from the record"
    );
}

// ── The record ───────────────────────────────────────────────────────────

#[test]
fn prekey_record_v3_layout_is_frozen() {
    assert_eq!(PREKEY_RECORD_V3_LEN, 186);
    assert_eq!(RECORD_VERSION_V3, 0x02);
    assert_eq!(PREKEY_RECORD_V2_LEN, 138, "V2 is still read");
    assert_eq!(RECORD_VERSION, 0x01);
    assert_eq!(PREKEYS_KEY, "prekeys/v2", "the record did not move");
    assert_eq!((FLAG_OTP, FLAG_PREV, FLAG_BORN), (0b001, 0b010, 0b100));
    assert_eq!((PUBLISHED_NOT_YET, PUBLISHED_LONG_AGO), (0, 1));
    assert_eq!(SIGNED_PREKEY_PERIOD_SECS, 604_800, "7 days (Owner, D-062)");

    let identity = Identity::generate();
    let mut record = PrekeyRecord::new(&identity);
    record.opk = Some((0x0102_0304_0506_0708, StaticSecret::from([0x11; 32])));
    record.born_opk = Some(0x0102_0304_0506_0708);
    record.published_at = 0x1112_1314_1516_1718;
    record.prev = Some(StaticSecret::from([0x22; 32]));
    let bytes = pack_prekeys(&record);
    assert_eq!(bytes.len(), 186);
    assert_eq!(bytes[0], 0x02);
    assert_eq!(&bytes[1..33], record.signed_prekey_sk.as_bytes());
    assert_eq!(bytes[33..97], record.signature.to_bytes());
    assert_eq!(bytes[97], FLAG_OTP | FLAG_PREV | FLAG_BORN);
    assert_eq!(bytes[98..106], 0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(bytes[106..138], [0x11; 32]);
    assert_eq!(bytes[138..146], 0x1112_1314_1516_1718u64.to_be_bytes());
    assert_eq!(bytes[146..154], 0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(bytes[154..186], [0x22; 32]);

    let back = unpack_prekeys(&bytes).unwrap();
    assert_eq!(pack_prekeys(&back), bytes, "it reads back to the same record");
}

/// A record a build before R-6 wrote. It reads as published long ago,
/// born with its one-time prekey, with no previous signed prekey; the
/// bundle exported from it is unchanged; it is written back as V3; and the
/// first maintenance rotates it, keeping the never-rotated key as the
/// previous one.
#[test]
fn a_v2_record_reads_as_published_long_ago_and_is_written_back_as_v3() {
    let (bob, bundle) = peer_with_prekeys(1);
    let v3 = read_record(&bob);
    let mut v2 = v3[..PREKEY_RECORD_V2_LEN].to_vec();
    v2[0] = RECORD_VERSION;
    v2[97] &= FLAG_OTP;
    bob.store.lock().unwrap().put(PREKEYS_KEY, &v2).unwrap();

    let original = unpack_prekeys(&v3).unwrap();
    let read = unpack_prekeys(&v2).unwrap();
    assert_eq!(read.published_at, PUBLISHED_LONG_AGO);
    assert_eq!(read.born_opk, original.opk_id());
    assert!(read.born_opk.is_some());
    assert!(read.prev.is_none());
    assert_eq!(read.signed_prekey_sk.to_bytes(), original.signed_prekey_sk.to_bytes());
    assert_eq!(read.opk.as_ref().unwrap().1.to_bytes(), original.opk.as_ref().unwrap().1.to_bytes());
    assert_eq!(bob.export_prekey_bundle().unwrap(), bundle, "the bundle is unchanged");

    let written = pack_prekeys(&read);
    assert_eq!((written.len(), written[0]), (PREKEY_RECORD_V3_LEN, RECORD_VERSION_V3));
    assert_eq!(unpack_prekeys(&written).unwrap().published_at, PUBLISHED_LONG_AGO);

    bob.maintain_prekeys(T0).unwrap();
    let after = record_of(&bob);
    assert_eq!(read_record(&bob).len(), PREKEY_RECORD_V3_LEN);
    assert_ne!(id_of(&after.signed_prekey_sk), id_of(&original.signed_prekey_sk), "rotated");
    assert_eq!(
        after.prev.as_ref().map(id_of),
        Some(id_of(&original.signed_prekey_sk)),
        "the never-rotated key answers for one more period"
    );
    assert_eq!(after.published_at, PUBLISHED_NOT_YET);
    assert_eq!(after.born_opk, after.opk_id());
}

#[test]
fn a_malformed_prekey_record_is_refused() {
    let identity = Identity::generate();
    let mut full = PrekeyRecord::new(&identity);
    full.prev = Some(StaticSecret::random_from_rng(OsRng));
    full.published_at = T0;
    let full = pack_prekeys(&full).to_vec();
    let mut bare = PrekeyRecord::new(&identity);
    bare.opk = None;
    bare.born_opk = None;
    let bare = pack_prekeys(&bare).to_vec();
    assert!(unpack_prekeys(&full).is_ok() && unpack_prekeys(&bare).is_ok(), "controls");

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for bit in 3..8 {
        let mut b = full.clone();
        b[97] |= 1 << bit;
        cases.push((format!("V3 flag bit {bit}"), b));
    }
    for (at, what) in [(100, "one-time prekey"), (150, "birth id"), (170, "previous key")] {
        let mut b = bare.clone();
        b[at] = 1;
        cases.push((format!("{what} absent but not zero"), b));
    }
    let mut b = full.clone();
    b[97] &= !FLAG_OTP;
    b[98..138].fill(0);
    cases.push(("previous without a one-time prekey".into(), b));
    let mut b = full.clone();
    b[97] &= !FLAG_BORN;
    b[146..154].fill(0);
    cases.push(("previous without a birth id".into(), b));
    let mut b = full.clone();
    b[153] ^= 1;
    cases.push(("previous with another birth id".into(), b));
    let mut b = full.clone();
    b[0] = RECORD_VERSION;
    cases.push(("version 0x01 with 186 bytes".into(), b));
    let mut b = full[..PREKEY_RECORD_V2_LEN].to_vec();
    b[97] = FLAG_OTP;
    cases.push(("version 0x02 with 138 bytes".into(), b));
    let mut b = full[..PREKEY_RECORD_V2_LEN].to_vec();
    b[0] = RECORD_VERSION;
    b[97] = FLAG_OTP | FLAG_PREV;
    cases.push(("V2 with a V3 flag".into(), b));
    for version in [0x00, 0x03, 0xff] {
        let mut b = full.clone();
        b[0] = version;
        cases.push((format!("version {version:#04x}"), b));
    }
    for len in [0, 1, 137, 139, 185, 187] {
        let mut b = full.clone();
        b.resize(len, 0);
        cases.push((format!("{len} bytes"), b));
    }
    for (what, bytes) in cases {
        assert!(
            matches!(unpack_prekeys(&bytes), Err(CoreError::Storage { .. })),
            "{what} must be refused"
        );
    }
}

/// The secrets of a record wipe themselves when dropped. x25519-dalek 2.0.1
/// derives `Zeroize` with `zeroize(drop)` for `StaticSecret`, which writes a
/// `Drop` that calls it but does not implement the `ZeroizeOnDrop` marker;
/// so this pins what can be pinned: the type can be wiped and has drop
/// glue, and the packed record is a wiping buffer. That the drop really
/// wipes is read from the dependency's source, not observed.
#[test]
fn the_record_secrets_are_wiping_types() {
    fn is_zeroize<T: zeroize::Zeroize>(_: &T) {}
    fn is_wiping<T: ZeroizeOnDrop>(_: &T) {}
    let mut record = PrekeyRecord::new(&Identity::generate());
    record.prev = Some(StaticSecret::random_from_rng(OsRng));
    is_zeroize(&record.signed_prekey_sk);
    is_zeroize(record.prev.as_ref().unwrap());
    is_zeroize(&record.opk.as_ref().unwrap().1);
    assert!(std::mem::needs_drop::<StaticSecret>(), "a Drop runs for every secret");
    is_wiping(&pack_prekeys(&record));
}

// ── The rotation rule ────────────────────────────────────────────────────

#[test]
fn plan_rotation_table() {
    let identity = Identity::generate();
    let at = |published_at: u64, born: Option<u64>, opk: Option<u64>| {
        let mut r = PrekeyRecord::new(&identity);
        r.published_at = published_at;
        r.born_opk = born;
        r.opk = opk.map(|id| (id, StaticSecret::random_from_rng(OsRng)));
        r
    };
    let keep = Some(Rotation { keep_previous: true });
    let drop = Some(Rotation { keep_previous: false });

    // (E): the one-time prekey changed, whatever the clock says.
    for now in [0, T0, u64::MAX] {
        assert_eq!(plan_rotation(&at(0, Some(1), Some(2)), now), drop, "E, now {now}");
        assert_eq!(plan_rotation(&at(T0, Some(1), None), now), drop, "E, consumed, now {now}");
        assert_eq!(plan_rotation(&at(T0, None, Some(1)), now), drop, "E, new, now {now}");
    }
    // Not yet published: never due by time.
    for now in [0, 1, T0, T0 + 10 * P, u64::MAX] {
        assert_eq!(plan_rotation(&at(0, Some(1), Some(1)), now), None, "unpublished, now {now}");
    }
    // A period in either direction, and not a second less.
    let published = at(T0, Some(1), Some(1));
    assert_eq!(plan_rotation(&published, T0), None);
    assert_eq!(plan_rotation(&published, T0 + P - 1), None);
    assert_eq!(plan_rotation(&published, T0 + P), keep);
    assert_eq!(plan_rotation(&published, T0 - (P - 1)), None);
    assert_eq!(plan_rotation(&published, T0 - P), keep);
    // Without a one-time prekey nothing could be answered under it.
    assert_eq!(plan_rotation(&at(T0, None, None), T0 + P), drop);
    assert_eq!(plan_rotation(&at(T0, None, None), T0), None);
    // Published long ago (a V2 record).
    assert_eq!(plan_rotation(&at(1, Some(1), Some(1)), 0), None);
    assert_eq!(plan_rotation(&at(1, Some(1), Some(1)), P + 1), keep);
    // No overflow at the ends.
    assert_eq!(plan_rotation(&at(u64::MAX, Some(1), Some(1)), 0), keep);
    assert_eq!(plan_rotation(&at(1, Some(1), Some(1)), u64::MAX), keep);
    assert_eq!(plan_rotation(&at(u64::MAX, Some(1), Some(1)), u64::MAX), None);
}

#[test]
fn a_time_rotation_keeps_the_previous_and_the_one_time_prekey() {
    let (bob, old_bundle) = peer_with_prekeys(2);
    let before = record_of(&bob);
    let alice = initiator(3);
    let old_hs = alice.establish_session_initiator(1, old_bundle.clone()).unwrap();

    rotate_by_time(&bob, T0);
    let after = record_of(&bob);
    assert_ne!(id_of(&after.signed_prekey_sk), id_of(&before.signed_prekey_sk));
    assert_eq!(after.prev.as_ref().map(id_of), Some(id_of(&before.signed_prekey_sk)));
    assert_eq!(after.opk_id(), before.opk_id(), "the one-time prekey is kept");
    assert_eq!(after.born_opk, after.opk_id());
    assert_eq!(after.published_at, PUBLISHED_NOT_YET);

    let new_bundle = bob.export_prekey_bundle().unwrap();
    assert_ne!(new_bundle, old_bundle);
    assert_eq!(new_bundle[164..204], old_bundle[164..204], "same one-time prekey");
    let carol = initiator(4);
    carol
        .establish_session_initiator(1, new_bundle)
        .expect("the new signed prekey's signature verifies");
    bob.establish_session_responder(1, old_hs)
        .expect("a handshake from the old bundle is answered under the previous key");
}

#[test]
fn maintenance_is_idempotent_and_an_unpublished_key_does_not_age() {
    let (bob, _) = peer_with_prekeys(5);
    let start = read_record(&bob);
    for now in [T0, T0, T0 + P, T0 + 100 * P, 0] {
        bob.maintain_prekeys(now).unwrap();
        assert_eq!(read_record(&bob), start, "nothing is due at {now}");
    }
    bob.note_prekeys_published(&current_spk(&bob), T0).unwrap();
    let published = read_record(&bob);
    bob.maintain_prekeys(T0 + P - 1).unwrap();
    assert_eq!(read_record(&bob), published);
    bob.maintain_prekeys(T0 + P).unwrap();
    let rotated = read_record(&bob);
    assert_ne!(rotated, published);
    bob.maintain_prekeys(T0 + P).unwrap();
    bob.maintain_prekeys(T0 + 50 * P).unwrap();
    assert_eq!(read_record(&bob), rotated, "the new key is not published yet");
}

#[test]
fn a_backward_clock_jump_of_a_period_rotates_and_a_smaller_step_does_not() {
    let (bob, _) = peer_with_prekeys(6);
    let first = current_spk(&bob);
    bob.note_prekeys_published(&first, T0).unwrap();
    let published = read_record(&bob);
    bob.maintain_prekeys(T0 - (P - 1)).unwrap();
    assert_eq!(read_record(&bob), published, "a step back of less than a period");
    bob.maintain_prekeys(T0 - P).unwrap();
    assert_ne!(current_spk(&bob), first, "a step back of a period rotates");
    assert_eq!(prev_spk(&bob), Some(first), "and keeps the previous key");
}

#[test]
fn note_published_only_for_the_current_key_and_only_once() {
    let (bob, _) = peer_with_prekeys(7);
    let unpublished = read_record(&bob);
    bob.note_prekeys_published(&[0xAB; SPK_ID_LEN], T0).unwrap();
    assert_eq!(read_record(&bob), unpublished, "another key's publication is not recorded");
    bob.note_prekeys_published(&current_spk(&bob), T0).unwrap();
    assert_eq!(record_of(&bob).published_at, T0);
    bob.note_prekeys_published(&current_spk(&bob), T0 + 5).unwrap();
    assert_eq!(record_of(&bob).published_at, T0, "only the first acceptance counts");

    let (carol, _) = peer_with_prekeys(8);
    carol.note_prekeys_published(&current_spk(&carol), 0).unwrap();
    assert_eq!(
        record_of(&carol).published_at,
        PUBLISHED_LONG_AGO,
        "a clock before 1970 still records the publication"
    );
}

// ── One-time-prekey changes ──────────────────────────────────────────────

/// After each writer that changes the one-time prekey, the next maintenance
/// rotates the signed prekey and keeps no previous key ((E)): every bundle
/// that named the old signed prekey named a one-time prekey this device no
/// longer holds.
#[test]
fn a_one_time_prekey_change_rotates_at_the_next_maintenance_without_a_previous() {
    let check = |core: &ArciumCore, before: [u8; SPK_ID_LEN], what: &str| {
        let mid = record_of(core);
        assert_eq!(id_of(&mid.signed_prekey_sk), before, "{what}: not rotated by the writer");
        assert_ne!(mid.opk_id(), mid.born_opk, "{what}: the one-time prekey changed");
        core.note_prekeys_published(&before, T0).unwrap();
        core.maintain_prekeys(T0).unwrap();
        let after = record_of(core);
        assert_ne!(id_of(&after.signed_prekey_sk), before, "{what}: rotated (E)");
        assert!(after.prev.is_none(), "{what}: no previous key kept");
        assert_eq!(after.born_opk, after.opk_id(), "{what}");
        assert_eq!(after.published_at, PUBLISHED_NOT_YET, "{what}");
    };

    // A first contact promoted.
    let (bob, bundle) = peer_with_prekeys(9);
    let alice = initiator(10);
    let hs = alice.establish_session_initiator(1, bundle).unwrap();
    bob.establish_session_responder(1, hs).unwrap();
    let before = current_spk(&bob);
    bob.decrypt_message(1, alice.encrypt_message(1, b"hi".to_vec()).unwrap()).unwrap();
    check(&bob, before, "promotion");

    // This device's own session confirmed (`replace_prekey_on_confirm`).
    let (alice, _) = peer_with_prekeys(11);
    let (bob, bob_bundle) = peer_with_prekeys(12);
    let hs = alice.establish_session_initiator(1, bob_bundle).unwrap();
    bob.establish_session_responder(1, hs).unwrap();
    bob.decrypt_message(1, alice.encrypt_message(1, b"hi".to_vec()).unwrap()).unwrap();
    let before = current_spk(&alice);
    alice.decrypt_message(1, bob.encrypt_message(1, b"answer".to_vec()).unwrap()).unwrap();
    check(&alice, before, "confirmation");

    // The one-time replacement of option B on a store without its mark.
    let (bob, _) = peer_with_prekeys(13);
    let before = current_spk(&bob);
    bob.replace_prekey_once().unwrap();
    check(&bob, before, "option B replacement");
}

/// Every writer that replaces the one-time prekey removes the previous
/// signed prekey from the record it writes, also when the handshake was
/// answered under it.
#[test]
fn every_one_time_prekey_writer_drops_the_previous() {
    // A promotion under the current key, and under the previous one.
    for under_previous in [false, true] {
        let (bob, old_bundle) = peer_with_prekeys(14);
        let alice = initiator(15);
        let bundle = if under_previous {
            old_bundle
        } else {
            rotate_by_time(&bob, T0);
            bob.export_prekey_bundle().unwrap()
        };
        let hs = alice.establish_session_initiator(1, bundle).unwrap();
        if under_previous {
            rotate_by_time(&bob, T0);
        }
        assert!(record_of(&bob).prev.is_some(), "control");
        bob.establish_session_responder(1, hs).unwrap();
        bob.decrypt_message(1, alice.encrypt_message(1, b"hi".to_vec()).unwrap()).unwrap();
        assert_no_previous_in_raw(&bob, &format!("promotion, under previous: {under_previous}"));
    }

    // A confirmation of this device's own session.
    let (bob, _) = peer_with_prekeys(16);
    let (carol, carol_bundle) = peer_with_prekeys(17);
    let hs = bob.establish_session_initiator(1, carol_bundle).unwrap();
    carol.establish_session_responder(1, hs).unwrap();
    carol.decrypt_message(1, bob.encrypt_message(1, b"hi".to_vec()).unwrap()).unwrap();
    rotate_by_time(&bob, T0);
    assert!(record_of(&bob).prev.is_some(), "control");
    bob.decrypt_message(1, carol.encrypt_message(1, b"answer".to_vec()).unwrap()).unwrap();
    assert_no_previous_in_raw(&bob, "confirmation");

    // The one-time replacement of option B.
    let (bob, _) = peer_with_prekeys(18);
    rotate_by_time(&bob, T0);
    assert!(record_of(&bob).prev.is_some(), "control");
    bob.replace_prekey_once().unwrap();
    assert_no_previous_in_raw(&bob, "option B replacement");
}

// ── Which key answers ────────────────────────────────────────────────────

#[test]
fn check_answerable_selects_current_or_previous() {
    let identity = Identity::generate();
    let mut record = PrekeyRecord::new(&identity);
    let held = record.opk_id().unwrap();
    let old = id_of(&record.signed_prekey_sk);
    rotate_signed_prekey(&mut record, &identity, Rotation { keep_previous: true });
    let current = id_of(&record.signed_prekey_sk);
    let other = [0xEE; SPK_ID_LEN];

    let ask = |r: &PrekeyRecord, spk, opk| check_answerable(r, &handshake_naming(spk, opk));
    assert!(matches!(ask(&record, current, Some(held)), Ok(Spk::Current)));
    assert!(matches!(ask(&record, old, Some(held)), Ok(Spk::Previous)));
    assert!(matches!(ask(&record, other, Some(held)), Err(CoreError::StaleSignedPrekey)));
    // X-6 under the previous key, as under the current one.
    assert!(matches!(ask(&record, old, None), Err(CoreError::OneTimePrekeyRequired)));
    assert!(matches!(
        ask(&record, old, Some(held ^ 1)),
        Err(CoreError::OneTimePrekeyUnavailable { opk_id }) if opk_id == held ^ 1
    ));
    // Only with the one-time prekey it was published with (not a state any
    // writer leaves; the check does not rely on that).
    let mut changed = PrekeyRecord::new(&identity);
    changed.prev = Some(record.prev.as_ref().unwrap().clone());
    let new_opk = changed.opk_id().unwrap();
    changed.born_opk = Some(new_opk ^ 1);
    assert!(matches!(ask(&changed, old, Some(new_opk)), Err(CoreError::StaleSignedPrekey)));
    let mut none = PrekeyRecord::new(&identity);
    none.prev = Some(record.prev.as_ref().unwrap().clone());
    none.opk = None;
    none.born_opk = None;
    assert!(matches!(ask(&none, old, None), Err(CoreError::StaleSignedPrekey)));
    // An id collision resolves to the current key.
    let mut same = PrekeyRecord::new(&identity);
    same.prev = Some(same.signed_prekey_sk.clone());
    let both = id_of(&same.signed_prekey_sk);
    assert!(matches!(ask(&same, both, same.opk_id()), Ok(Spk::Current)));
    assert!(matches!(same.signed_prekey(Spk::Previous), Ok(_)));
    assert!(matches!(
        PrekeyRecord::new(&identity).signed_prekey(Spk::Previous),
        Err(CoreError::StaleSignedPrekey)
    ));
}

/// A handshake built from the bundle before a rotation is recorded, and its
/// first message creates the session: the one-time prekey is consumed and
/// the previous key leaves the record in the same write. The session is
/// the initiator's (it answers).
#[test]
fn a_handshake_under_the_previous_is_recorded_and_promoted() {
    let (bob, old_bundle) = peer_with_prekeys(19);
    let alice = initiator(20);
    let hs = alice.establish_session_initiator(1, old_bundle).unwrap();
    rotate_by_time(&bob, T0);
    let rotated = record_of(&bob);
    bob.establish_session_responder(1, hs).unwrap();
    assert_eq!(read_record(&bob), pack_prekeys(&rotated).to_vec(), "recording consumes nothing");

    let first = alice.encrypt_message(1, b"under the previous key".to_vec()).unwrap();
    assert_eq!(bob.decrypt_message(1, first).unwrap(), b"under the previous key");
    let after = record_of(&bob);
    assert_ne!(after.opk_id(), rotated.opk_id(), "the one-time prekey is consumed");
    assert!(after.prev.is_none(), "and the previous key with it");
    assert_eq!(id_of(&after.signed_prekey_sk), id_of(&rotated.signed_prekey_sk));
    assert_eq!(after.born_opk, rotated.born_opk, "due for (E) at the next round");
    let reply = bob.encrypt_message(1, b"reply".to_vec()).unwrap();
    assert_eq!(alice.decrypt_message(1, reply).unwrap(), b"reply");
}

/// Two rotations after the bundle it was built from, a handshake is
/// refused when it is recorded and when its first message arrives, the
/// record is untouched by the refusals, and the old signed prekey is
/// nowhere in the record. The database file holds the record only
/// encrypted, so the check of the raw file shows only that the secret is
/// not stored in the clear; whether SQLite's `secure_delete` overwrites
/// the old cell on an update is not shown here.
#[test]
fn a_signed_prekey_past_its_grace_is_refused_and_absent_from_the_store() {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("db").to_str().unwrap().to_string();
    let bob = ArciumCore::new(path.clone(), key32(21)).unwrap();
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let old_bundle = bob.export_prekey_bundle().unwrap();
    let old_secret = record_of(&bob).signed_prekey_sk.to_bytes();
    let alice = initiator(22);
    let carol = initiator(23);
    let alice_hs = alice.establish_session_initiator(1, old_bundle.clone()).unwrap();
    let carol_hs = carol.establish_session_initiator(2, old_bundle).unwrap();

    // Carol's handshake is recorded while still answerable.
    rotate_by_time(&bob, T0);
    bob.establish_session_responder(2, carol_hs).unwrap();
    rotate_by_time(&bob, T0 + P);
    assert!(record_of(&bob).prev.is_some(), "the next key is the previous one now");

    let before = read_record(&bob);
    assert!(matches!(
        bob.establish_session_responder(1, alice_hs),
        Err(CoreError::StaleSignedPrekey)
    ));
    let carol_first = carol.encrypt_message(2, b"too late".to_vec()).unwrap();
    assert!(matches!(
        bob.receive_message(2, carol_first),
        Err(CoreError::StaleSignedPrekey)
    ));
    assert_eq!(read_record(&bob), before, "a refusal writes nothing");

    let record = read_record(&bob);
    assert!(!record.windows(32).any(|w| w == old_secret), "not in the record");
    drop(bob);
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.windows(32).any(|w| w == old_secret), "not in the clear on disk");
}

/// A first message under the previous key authenticates beside an own
/// unconfirmed session (a simultaneous start) and beside an established
/// session (a restart, option B); two rotations later it does not.
#[test]
fn beside_an_own_session_and_beside_an_established_session_a_first_message_under_the_previous_authenticates(
) {
    // Beside an own unconfirmed session.
    let (alice, alice_bundle) = peer_with_prekeys(24);
    let (bob, bob_bundle) = peer_with_prekeys(25);
    alice.establish_session_initiator(1, bob_bundle.clone()).unwrap();
    let bob_hs = bob.establish_session_initiator(1, alice_bundle).unwrap();
    rotate_by_time(&alice, T0);
    alice.record_handshake_beside(1, &bob_hs).unwrap();
    let bob_first = bob.encrypt_message(1, b"under bob's session".to_vec()).unwrap();
    let bob_pk: [u8; 32] = bob_bundle[4..36].try_into().unwrap();
    assert!(alice.beside_authenticates(1, &bob_pk, &bob_first).unwrap());
    rotate_by_time(&alice, T0 + P);
    assert!(
        !alice.beside_authenticates(1, &bob_pk, &bob_first).unwrap(),
        "past its grace"
    );

    // Beside an established session.
    let (alice, _) = peer_with_prekeys(26);
    let (bob, bob_bundle) = peer_with_prekeys(27);
    let hs = alice.establish_session_initiator(1, bob_bundle.clone()).unwrap();
    bob.establish_session_responder(1, hs).unwrap();
    bob.decrypt_message(1, alice.encrypt_message(1, b"hi".to_vec()).unwrap()).unwrap();
    alice.decrypt_message(1, bob.encrypt_message(1, b"answer".to_vec()).unwrap()).unwrap();
    alice.maintain_prekeys(T0).unwrap(); // (E): the confirmation replaced her one-time prekey.
    // Bob's keys on a second database, as after a reinstall.
    let restarted = fresh_core(28);
    restarted.save_identity(bob.load_identity().unwrap().unwrap()).unwrap();
    let restart = restarted
        .establish_session_initiator(1, alice.export_prekey_bundle().unwrap())
        .unwrap();
    rotate_by_time(&alice, T0);
    alice.record_handshake_beside(1, &restart).unwrap();
    let first = restarted.encrypt_message(1, b"restart".to_vec()).unwrap();
    let bob_pk: [u8; 32] = bob_bundle[4..36].try_into().unwrap();
    assert!(alice.beside_authenticates(1, &bob_pk, &first).unwrap());
}

/// Two instances on one database (an in-process stand-in for two
/// processes): the record is created once and a due rotation happens once.
#[test]
fn two_instances_create_prekeys_once_and_rotate_once() {
    let path = tempfile::tempdir().unwrap().keep().join("db").to_str().unwrap().to_string();
    let a = ArciumCore::new(path.clone(), key32(29)).unwrap();
    a.save_identity(Identity::generate()).unwrap();
    let b = ArciumCore::new(path, key32(29)).unwrap();

    a.maintain_prekeys(T0).unwrap();
    let created = read_record(&a);
    b.maintain_prekeys(T0).unwrap();
    assert_eq!(read_record(&b), created, "created once");

    let first = current_spk(&a);
    a.note_prekeys_published(&first, T0).unwrap();
    b.note_prekeys_published(&first, T0 + 1).unwrap();
    assert_eq!(record_of(&a).published_at, T0);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        for core in [&a, &b] {
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait();
                core.maintain_prekeys(T0 + P).unwrap();
            });
        }
    });
    let after = record_of(&a);
    assert_ne!(id_of(&after.signed_prekey_sk), first);
    assert_eq!(after.prev.as_ref().map(id_of), Some(first), "rotated once, not twice");
    assert_eq!(read_record(&b), read_record(&a));
}

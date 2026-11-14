//! A handshake recorded beside this device's own unconfirmed session
//! (`beside.rs`, R-13 option A): what may record one, that recording it
//! changes nothing else, that it goes when the session is confirmed,
//! removed or forgotten, competing connections, and the authentication
//! check that never writes. Real process deaths are in `crash.rs`; the
//! network layer's use of it is exercised in `mobile-ffi`
//! (`tests::false_conflict`).
//!
//! `memory_peers()` gives Alice an initiator session (`ALICE_HANDLE`) on
//! which nothing has been received, and Bob a responder session.

use super::*;
use crate::durable::Conflict;

fn hs(peer: &[u8; 32], bytes: &[u8]) -> ProvisionalHandshake {
    ProvisionalHandshake {
        peer_identity_pk: *peer,
        handshake: bytes.to_vec(),
    }
}

/// Every record in `store` under the namespaces this module touches.
fn records(store: &EncryptedStore) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for ns in ["session:", "handle:", "hsin:", "hsout:", "outbox:", "inbox:", "seen:", "sendid:"] {
        for key in store.list_keys_with_prefix(ns).unwrap() {
            let value = store.get(&key).unwrap();
            out.push((key, value));
        }
    }
    out
}

impl Peers {
    /// Records the handshake `h` from Bob beside Alice's session.
    fn beside(&mut self, h: &[u8]) -> Result<(), MessagingError> {
        self.am
            .record_handshake_beside(&mut self.a, self.alice_pk, ALICE_HANDLE, &hs(&self.bob_pk, h))
    }

    fn beside_record(&self) -> Option<ProvisionalHandshake> {
        self.am.provisional_handshake(&self.a, ALICE_HANDLE).unwrap()
    }

    /// Bob receives Alice's first message and answers it; returns the answer,
    /// which Alice has not received yet.
    fn bob_answers(&mut self) -> OutgoingMessage {
        let m = self.alice_sends(b"first");
        accepted(self.bob_receives(&m.wire).unwrap());
        self.bob_sends(b"answer")
    }
}

#[test]
fn a_handshake_is_recorded_beside_an_own_unconfirmed_session_and_nothing_else_changes() {
    let mut p = memory_peers();
    let before = records(&p.a);
    p.beside(b"hs1").unwrap();
    assert_eq!(p.beside_record(), Some(hs(&p.bob_pk, b"hs1")));
    let mut want = before.clone();
    want.push((
        provisional_key(ALICE_HANDLE),
        encode_provisional(&hs(&p.bob_pk, b"hs1")).unwrap().to_vec(),
    ));
    want.sort();
    let mut after = records(&p.a);
    after.sort();
    assert_eq!(after, want, "the record and nothing else");

    // A repeat changes nothing; another handshake replaces it.
    p.beside(b"hs1").unwrap();
    assert_eq!(p.beside_record(), Some(hs(&p.bob_pk, b"hs1")));
    p.beside(b"hs2").unwrap();
    assert_eq!(p.beside_record(), Some(hs(&p.bob_pk, b"hs2")));

    // The session is Alice's own, untouched: it still sends and is not
    // confirmed.
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 0);
    assert!(!p.am.has_received(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap());
    let m = p.alice_sends(b"still mine");
    assert_eq!(*accepted(p.bob_receives(&m.wire).unwrap()).plaintext, b"still mine");
}

#[test]
fn recording_beside_is_refused_for_any_other_session_and_writes_nothing() {
    // A responder session.
    let mut p = memory_peers();
    let before = records(&p.b);
    assert!(matches!(
        p.bm.record_handshake_beside(&mut p.b, p.bob_pk, BOB_HANDLE, &hs(&p.alice_pk, b"hs")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(records(&p.b), before);

    // Alice's session once a message from Bob authenticated on it.
    let mut p = memory_peers();
    let answer = p.bob_answers();
    accepted(p.alice_receives(&answer.wire).unwrap());
    let before = records(&p.a);
    assert!(matches!(p.beside(b"hs"), Err(MessagingError::AlreadyExists { .. })));
    assert_eq!(records(&p.a), before);

    // Another peer under Alice's handle, and no session at all.
    let mut p = memory_peers();
    let carol = pair().alice_pk;
    assert!(matches!(
        p.am.record_handshake_beside(&mut p.a, p.alice_pk, ALICE_HANDLE, &hs(&carol, b"hs")),
        Err(MessagingError::HandleCollision { .. })
    ));
    assert!(matches!(
        p.am.record_handshake_beside(&mut p.a, p.alice_pk, 0xE0E0, &hs(&p.bob_pk, b"hs")),
        Err(MessagingError::NoSession { .. })
    ));
    assert_eq!(p.beside_record(), None);

    // A commit on the handle with an unknown outcome.
    let mut p = memory_peers();
    test_hooks::inject(CommitFault::UnknownLost);
    assert!(p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &cid(), b"x").is_err());
    assert!(matches!(p.beside(b"hs"), Err(MessagingError::Unresolved { .. })));
    assert_eq!(p.beside_record(), None);
}

fn file_peers(dir: &Path) -> Peers {
    setup(
        EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
        EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
    )
}

/// Another connection commits the receive that confirms Alice's session
/// after the recording classified it: the recording finds the session
/// record changed and writes nothing.
#[test]
fn a_receive_committed_meanwhile_makes_recording_beside_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_peers(dir.path());
    let answer = p.bob_answers();
    let (path, alice_pk) = (dir.path().join("a.db"), p.alice_pk);
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&path, KEY).unwrap();
        accepted(
            Messenger::new()
                .receive(&mut db, alice_pk, ALICE_HANDLE, &answer.wire)
                .unwrap(),
        );
    });
    assert!(matches!(
        p.beside(b"hs"),
        Err(MessagingError::Conflict(Conflict::RecordChanged))
    ));
    assert_eq!(p.beside_record(), None);
    assert!(p.am.has_received(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap());
}

#[test]
fn the_message_that_confirms_the_session_deletes_the_handshake_beside_it() {
    let mut p = memory_peers();
    p.beside(b"hs1").unwrap();
    let answer = p.bob_answers();
    assert_eq!(p.beside_record(), Some(hs(&p.bob_pk, b"hs1")), "sending changes nothing");
    let got = accepted(p.alice_receives(&answer.wire).unwrap());
    assert_eq!(*got.plaintext, b"answer");
    assert_eq!(p.beside_record(), None, "gone with the confirming commit");
    assert_eq!(
        p.am.pending_incoming(&p.a, ALICE_HANDLE).unwrap(),
        vec![got],
        "the message is committed as usual"
    );

    // A record that names another peer under the handle is not this peer's.
    let mut p = memory_peers();
    let carol = pair().alice_pk;
    let foreign = encode_provisional(&hs(&carol, b"other")).unwrap();
    p.a.put(&provisional_key(ALICE_HANDLE), &foreign).unwrap();
    let answer = p.bob_answers();
    accepted(p.alice_receives(&answer.wire).unwrap());
    assert_eq!(p.a.get(&provisional_key(ALICE_HANDLE)).unwrap(), *foreign);
}

/// Another connection records a handshake beside Alice's session after a
/// receive on it was staged: the receive writes nothing, and repeating it
/// commits the message and deletes the record.
#[test]
fn a_handshake_recorded_while_a_receive_is_staged_is_deleted_when_it_is_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_peers(dir.path());
    let answer = p.bob_answers();
    let (path, alice_pk, bob_pk) = (dir.path().join("a.db"), p.alice_pk, p.bob_pk);
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&path, KEY).unwrap();
        Messenger::new()
            .record_handshake_beside(&mut db, alice_pk, ALICE_HANDLE, &hs(&bob_pk, b"late"))
            .unwrap();
    });
    let before = records(&p.a);
    assert!(matches!(
        p.alice_receives(&answer.wire),
        Err(MessagingError::Conflict(Conflict::RecordExists))
    ));
    let mut want = before;
    want.push((
        provisional_key(ALICE_HANDLE),
        encode_provisional(&hs(&p.bob_pk, b"late")).unwrap().to_vec(),
    ));
    want.sort();
    let mut after = records(&p.a);
    after.sort();
    assert_eq!(after, want, "only the other connection's record");
    assert!(p.am.unresolved_generation(ALICE_HANDLE).is_none());

    accepted(p.alice_receives(&answer.wire).unwrap());
    assert_eq!(p.beside_record(), None);
}

#[test]
fn removing_or_forgetting_the_session_takes_the_handshake_beside_it() {
    let mut p = memory_peers();
    p.beside(b"hs1").unwrap();
    p.am.remove_session(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap();
    assert_eq!(p.beside_record(), None);
    assert!(p.a.list_keys_with_prefix("hsin:").unwrap().is_empty());

    let mut p = memory_peers();
    p.beside(b"hs1").unwrap();
    let bob = p.bob_pk;
    p.am.forget_peer(&mut p.a, ALICE_HANDLE, &bob, &[]).unwrap();
    assert!(p.a.list_keys_with_prefix("hsin:").unwrap().is_empty());

    // Another peer's record under a colliding handle stays.
    let mut p = memory_peers();
    let carol = pair().alice_pk;
    let foreign = encode_provisional(&hs(&carol, b"other")).unwrap();
    p.a.put(&provisional_key(ALICE_HANDLE), &foreign).unwrap();
    p.am.remove_session(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap();
    assert_eq!(p.a.get(&provisional_key(ALICE_HANDLE)).unwrap(), *foreign);
}

/// Alice's initiator session, and a maker of Bob's responder session for the
/// same X3DH result: one fresh copy per check, as `mobile-ffi` derives one
/// per message.
fn first_contact_pair() -> (Session, impl Fn() -> Session, [u8; 32], [u8; 32]) {
    let alice_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let bob_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let ad = [alice_pk, bob_pk].concat();
    let spk = StaticSecret::random_from_rng(OsRng);
    let root = [7u8; 32];
    let alice = Session {
        ratchet: DoubleRatchet::init_alice(&root, PublicKey::from(&spk)),
        ad: ad.clone(),
        peer_identity_pk: bob_pk,
    };
    let bob = move || Session {
        ratchet: DoubleRatchet::init_bob(&root, spk.clone()),
        ad: ad.clone(),
        peer_identity_pk: alice_pk,
    };
    (alice, bob, alice_pk, bob_pk)
}

#[test]
fn only_a_message_of_the_handshakes_session_authenticates_and_nothing_is_stored() {
    let (alice, bob, alice_pk, bob_pk) = first_contact_pair();
    let mut a = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut am = Messenger::new();
    am.create_session(&mut a, alice_pk, new_session(ALICE_HANDLE, alice, SessionRole::Initiator))
        .unwrap();
    let first = new_message(am.send(&mut a, alice_pk, ALICE_HANDLE, &cid(), b"open").unwrap());
    let second = new_message(am.send(&mut a, alice_pk, ALICE_HANDLE, &cid(), b"text").unwrap());

    let m = Messenger::new();
    let check = |wire: &[u8]| m.first_message_authenticates(bob_pk, bob(), wire).unwrap();
    assert!(check(&first.wire));
    assert!(check(&second.wire), "any message of the first sending chain");
    let mut tampered = first.wire.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(!check(&tampered));
    assert!(!check(&first.wire[..HEADER_SIZE]), "a header and no ciphertext");
    assert!(!check(b"short"));

    // A message of another session (another X3DH result) does not.
    let (other, _, other_alice, _) = first_contact_pair();
    let mut o = EncryptedStore::open_in_memory(KEY).unwrap();
    am.create_session(&mut o, other_alice, new_session(7, other, SessionRole::Initiator))
        .unwrap();
    let foreign = new_message(am.send(&mut o, other_alice, 7, &cid(), b"x").unwrap());
    assert!(!check(&foreign.wire));

    // A session whose AD is not the X3DH AD of the two identities is refused.
    let mut wrong = bob();
    wrong.ad.reverse();
    assert!(matches!(
        m.first_message_authenticates(bob_pk, wrong, &first.wire),
        Err(MessagingError::Checkpoint(_))
    ));
}

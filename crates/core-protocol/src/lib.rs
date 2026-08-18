//! Session management for Arcium: maps contacts to their Double Ratchet +
//! associated-data state.

use core_crypto::ratchet::DoubleRatchet;
use std::collections::HashMap;

pub type ContactId = u64;

/// A session: the Double Ratchet state, the X3DH-derived associated data it must
/// be bound to for the lifetime of the session (encrypt/decrypt both need the
/// same `ad` the session was established with), and the peer this session
/// actually belongs to.
///
/// `peer_identity_pk` is the peer's 32-byte X25519 DH identity public key — the
/// key X3DH agreed with, not the Ed25519 signing key. It is stored beside the
/// ratchet rather than in a separate map so that ownership cannot drift from the
/// session it describes: there is exactly one record, and it either exists or it
/// does not.
pub struct Session {
    pub ratchet: DoubleRatchet,
    pub ad: Vec<u8>,
    pub peer_identity_pk: [u8; 32],
}

pub type RatchetState = Session;

/// Why a session could not be created. Both variants mean "an entry already
/// occupies this id"; they differ in whether the occupant is the same peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The id already holds a session with this same peer. Establishing again
    /// would discard a live Double Ratchet — including its message keys and
    /// counters — and silently desynchronise both devices, so it is refused.
    /// Deliberate re-handshaking must remove the old session first.
    AlreadyEstablished { contact_id: ContactId },
    /// The id already holds a session with a *different* peer. Local ids are a
    /// 64-bit truncation, so two distinct peers can land on one; overwriting
    /// would hand one contact's ratchet to another.
    HandleCollision { contact_id: ContactId },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::AlreadyEstablished { contact_id } => write!(
                f,
                "session {contact_id} already exists for this peer; refusing to replace a live ratchet"
            ),
            SessionError::HandleCollision { contact_id } => write!(
                f,
                "session id {contact_id} is already held by a different peer; refusing to rebind it"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

pub struct SessionManager {
    sessions: HashMap<ContactId, RatchetState>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    /// Creates a session at `contact_id`, refusing to disturb anything already
    /// there. This is the only way to add a session, so an occupied id can never
    /// be overwritten as a side effect of establishing a new one.
    ///
    /// On either error the manager is left exactly as it was: the existing
    /// session keeps its ratchet state and stays usable.
    pub fn try_new_session(
        &mut self,
        contact_id: ContactId,
        state: RatchetState,
    ) -> Result<(), SessionError> {
        match self.sessions.get(&contact_id) {
            Some(existing) if existing.peer_identity_pk == state.peer_identity_pk => {
                Err(SessionError::AlreadyEstablished { contact_id })
            }
            Some(_) => Err(SessionError::HandleCollision { contact_id }),
            None => {
                self.sessions.insert(contact_id, state);
                Ok(())
            }
        }
    }

    pub fn get_session(&mut self, contact_id: ContactId) -> Option<&mut RatchetState> {
        self.sessions.get_mut(&contact_id)
    }

    pub fn remove_session(&mut self, contact_id: ContactId) {
        self.sessions.remove(&contact_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// A session belonging to the peer whose identity key is all `peer` bytes.
    fn session_with_peer(peer: u8) -> Session {
        let root_key = [0u8; 32];
        let their_sk = StaticSecret::random_from_rng(OsRng);
        Session {
            ratchet: DoubleRatchet::init_alice(root_key, PublicKey::from(&their_sk)),
            ad: b"test-ad".to_vec(),
            peer_identity_pk: [peer; 32],
        }
    }

    fn make_session() -> Session {
        session_with_peer(1)
    }

    #[test]
    fn new_session_is_retrievable() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(1, make_session()).unwrap();
        assert!(mgr.get_session(1).is_some());
    }

    #[test]
    fn missing_session_returns_none() {
        let mut mgr = SessionManager::new();
        assert!(mgr.get_session(99).is_none());
    }

    #[test]
    fn remove_session_deletes_entry() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(2, make_session()).unwrap();
        mgr.remove_session(2);
        assert!(mgr.get_session(2).is_none());
    }

    #[test]
    fn multiple_sessions_are_independent() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(10, make_session()).unwrap();
        mgr.try_new_session(20, make_session()).unwrap();
        assert!(mgr.get_session(10).is_some());
        assert!(mgr.get_session(20).is_some());
        assert!(mgr.get_session(30).is_none());
    }

    /// Replaces the former `new_session_overwrites_existing`, which asserted the
    /// behaviour this change exists to remove: re-establishing under an occupied
    /// id used to discard the live ratchet without a word.
    #[test]
    fn re_establishing_the_same_peer_is_refused_and_keeps_the_original_session() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(3, session_with_peer(7)).unwrap();
        let original_dh = mgr.get_session(3).unwrap().ratchet.our_dh_public().to_bytes();

        let err = mgr.try_new_session(3, session_with_peer(7)).unwrap_err();
        assert_eq!(err, SessionError::AlreadyEstablished { contact_id: 3 });

        let kept = mgr.get_session(3).unwrap();
        assert_eq!(
            kept.ratchet.our_dh_public().to_bytes(),
            original_dh,
            "the rejected attempt must not have swapped in a different ratchet"
        );
        assert_eq!(kept.peer_identity_pk, [7u8; 32]);
    }

    #[test]
    fn a_different_peer_on_an_occupied_id_is_refused_as_a_collision() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(5, session_with_peer(7)).unwrap();
        let original_dh = mgr.get_session(5).unwrap().ratchet.our_dh_public().to_bytes();

        let err = mgr.try_new_session(5, session_with_peer(8)).unwrap_err();
        assert_eq!(err, SessionError::HandleCollision { contact_id: 5 });

        let kept = mgr.get_session(5).unwrap();
        assert_eq!(kept.peer_identity_pk, [7u8; 32], "the first peer must keep the id");
        assert_eq!(kept.ratchet.our_dh_public().to_bytes(), original_dh);
    }

    /// The two refusals are distinguishable, so a caller can tell "you already
    /// have this session" from "this id belongs to someone else".
    #[test]
    fn duplicate_and_collision_are_distinct_errors() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(6, session_with_peer(1)).unwrap();
        assert_ne!(
            mgr.try_new_session(6, session_with_peer(1)).unwrap_err(),
            mgr.try_new_session(6, session_with_peer(2)).unwrap_err(),
        );
    }

    /// A refused insertion must leave nothing behind for a later attempt to trip
    /// over: after removing the occupant, the id is free again.
    #[test]
    fn a_refused_insertion_does_not_poison_the_id() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(9, session_with_peer(1)).unwrap();
        assert!(mgr.try_new_session(9, session_with_peer(2)).is_err());
        mgr.remove_session(9);
        mgr.try_new_session(9, session_with_peer(2)).expect("id must be reusable once vacated");
        assert_eq!(mgr.get_session(9).unwrap().peer_identity_pk, [2u8; 32]);
    }

    #[test]
    fn session_ad_is_retained() {
        let mut mgr = SessionManager::new();
        mgr.try_new_session(4, make_session()).unwrap();
        let session = mgr.get_session(4).unwrap();
        assert_eq!(session.ad, b"test-ad");
    }
}

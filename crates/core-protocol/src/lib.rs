//! Session management for Arcium: maps contacts to their Double Ratchet states.

use core_crypto::ratchet::DoubleRatchet;
use std::collections::HashMap;

pub type ContactId = u64;
pub type RatchetState = DoubleRatchet;

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

    pub fn new_session(&mut self, contact_id: ContactId, state: RatchetState) {
        self.sessions.insert(contact_id, state);
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

    fn make_ratchet() -> RatchetState {
        let root_key = [0u8; 32];
        let their_sk = StaticSecret::random_from_rng(OsRng);
        DoubleRatchet::init_alice(root_key, PublicKey::from(&their_sk))
    }

    #[test]
    fn new_session_is_retrievable() {
        let mut mgr = SessionManager::new();
        mgr.new_session(1, make_ratchet());
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
        mgr.new_session(2, make_ratchet());
        mgr.remove_session(2);
        assert!(mgr.get_session(2).is_none());
    }

    #[test]
    fn multiple_sessions_are_independent() {
        let mut mgr = SessionManager::new();
        mgr.new_session(10, make_ratchet());
        mgr.new_session(20, make_ratchet());
        assert!(mgr.get_session(10).is_some());
        assert!(mgr.get_session(20).is_some());
        assert!(mgr.get_session(30).is_none());
    }

    #[test]
    fn new_session_overwrites_existing() {
        let mut mgr = SessionManager::new();
        mgr.new_session(3, make_ratchet());
        mgr.new_session(3, make_ratchet()); // overwrite
        // still exactly one session for contact 3
        assert!(mgr.get_session(3).is_some());
        mgr.remove_session(3);
        assert!(mgr.get_session(3).is_none());
    }
}

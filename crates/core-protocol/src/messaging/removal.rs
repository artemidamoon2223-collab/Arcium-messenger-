//! [`Messenger::remove_session`].

use core_storage::{EncryptedStore, StorageError};
use zeroize::Zeroizing;

use super::helpers::keys_under;
use super::records::*;
use super::{MessagingError, Messenger, RemovedSession};
use crate::checkpoint::session_storage_key;
use crate::durable::Conflict;

impl Messenger {
    /// Deletes the session under `handle` — its checkpoint, handle record,
    /// stored handshake and every unacknowledged outgoing message — in one
    /// transaction, so a new session with that peer can be established (for
    /// example after the peer refused this session's handshake).
    ///
    /// Refused with [`MessagingError::UndeliveredIncoming`] while accepted
    /// incoming messages are unacknowledged, and with
    /// [`MessagingError::Conflict`] if the session changed while this ran;
    /// nothing is deleted in either case. Duplicate-detection records are
    /// kept. The discarded outgoing messages are returned: only the removed
    /// session could have been used to read them.
    pub fn remove_session(
        &mut self,
        store: &mut EncryptedStore,
        handle: u64,
    ) -> Result<RemovedSession, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let session_key = session_storage_key(&peer);
        // Read the session record first: any send or receive that commits
        // after this changes it, and the transaction below then refuses.
        let before = match store.get(&session_key) {
            Ok(b) => Some(Zeroizing::new(b)),
            Err(StorageError::NotFound) => None,
            Err(e) => return Err(MessagingError::Store(e)),
        };
        let undelivered = keys_under(store, INBOX_NAMESPACE, &inbox_prefix(&peer))?.len();
        if undelivered > 0 {
            return Err(MessagingError::UndeliveredIncoming { count: undelivered });
        }
        let discarded = self.pending_outgoing(store, handle)?;
        #[cfg(test)]
        super::remove_hook::run();

        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        let now = match tx.get(&session_key) {
            Ok(b) => Some(Zeroizing::new(b)),
            Err(StorageError::NotFound) => None,
            Err(e) => return Err(MessagingError::Store(e)),
        };
        if now != before {
            return Err(MessagingError::Conflict(Conflict::RecordChanged));
        }
        let mut doomed = vec![session_key, handle_key(handle), handshake_key(&peer)];
        for m in &discarded {
            doomed.push(outbox_key(&peer, &m.message_id));
            doomed.push(sendid_key(&peer, &m.client_message_id));
        }
        for key in &doomed {
            tx.delete(key).map_err(MessagingError::NotCommitted)?;
        }
        tx.commit().map_err(MessagingError::Store)?;
        self.unresolved.remove(&handle);
        Ok(RemovedSession {
            discarded_outgoing: discarded,
        })
    }
}

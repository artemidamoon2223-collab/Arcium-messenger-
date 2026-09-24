//! Free helpers of [`super::Messenger`].

use core_storage::{EncryptedStore, StorageError, StoreTransaction};
use zeroize::Zeroizing;

use super::records::*;
use super::{MessageId, MessagingError, Received, SendOutcome};
use crate::durable::StageError;

pub(super) fn stage_error(e: StageError) -> MessagingError {
    match e {
        StageError::Ratchet(e) => MessagingError::Ratchet(e),
        StageError::Checkpoint(e) => MessagingError::Checkpoint(e),
        StageError::GenerationExhausted => MessagingError::GenerationExhausted,
        StageError::Unresolved { .. } | StageError::Conflicted => {
            MessagingError::InconsistentStore("unexpected stage state")
        }
    }
}

/// After a refused creation: the handle belongs to another peer, or this
/// peer already has a session.
pub(super) fn classify_taken(
    store: &EncryptedStore,
    handle: u64,
    peer: &[u8; 32],
) -> Result<MessagingError, MessagingError> {
    match store.get(&handle_key(handle)) {
        Ok(bytes) => {
            if decode_handle(&bytes)? == *peer {
                Ok(MessagingError::AlreadyExists { handle })
            } else {
                Ok(MessagingError::HandleCollision { handle })
            }
        }
        Err(StorageError::NotFound) => Ok(MessagingError::AlreadyExists { handle }),
        Err(e) => Err(MessagingError::Store(e)),
    }
}

pub(super) fn read_duplicate(
    store: &EncryptedStore,
    inbox: &str,
    seen: &str,
    id: MessageId,
) -> Result<Option<Received>, MessagingError> {
    match store.get(inbox) {
        Ok(bytes) => {
            let message = decode_inbox(&Zeroizing::new(bytes))?;
            if message.message_id != id {
                return Err(MessagingError::InvalidRecord("inbox"));
            }
            return Ok(Some(Received::Duplicate {
                message_id: id,
                undelivered: Some(message),
            }));
        }
        Err(StorageError::NotFound) => {}
        Err(e) => return Err(MessagingError::Store(e)),
    }
    match store.get(seen) {
        Ok(bytes) => {
            if decode_id_record(SEEN_MAGIC, &bytes, "seen")? != id {
                return Err(MessagingError::InvalidRecord("seen"));
            }
            Ok(Some(Received::Duplicate {
                message_id: id,
                undelivered: None,
            }))
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(MessagingError::Store(e)),
    }
}

/// What an earlier `send` of the same logical message committed, if any.
pub(super) fn read_prior_send(
    store: &EncryptedStore,
    peer: &[u8; 32],
    index_key: &str,
) -> Result<Option<SendOutcome>, MessagingError> {
    let id = match store.get(index_key) {
        Ok(bytes) if bytes.starts_with(ABANDONED_MAGIC) => {
            let message_id = decode_id_record(ABANDONED_MAGIC, &bytes, "sendid")?;
            return Ok(Some(SendOutcome::Abandoned { message_id }));
        }
        Ok(bytes) => decode_id_record(SENDID_MAGIC, &bytes, "sendid")?,
        Err(StorageError::NotFound) => return Ok(None),
        Err(e) => return Err(MessagingError::Store(e)),
    };
    match store.get(&outbox_key(peer, &id)) {
        Ok(bytes) => Ok(Some(SendOutcome::AlreadyPending(decode_outbox(
            &Zeroizing::new(bytes),
        )?))),
        Err(StorageError::NotFound) => {
            Ok(Some(SendOutcome::AlreadyAcknowledged { message_id: id }))
        }
        Err(e) => Err(MessagingError::Store(e)),
    }
}

/// Commits a transaction that is not a session transition. An error from
/// `COMMIT` leaves the outcome unknown; it is never reported as a rollback.
pub(super) fn commit_repeatable(tx: StoreTransaction<'_>) -> Result<(), MessagingError> {
    #[cfg(test)]
    let result = crate::durable::test_hooks::commit_or_fault(tx);
    #[cfg(not(test))]
    let result = tx.commit().map_err(|e| (true, e));
    result.map_err(|(unknown, e)| match unknown {
        true => MessagingError::RepeatableOutcomeUnknown(e),
        false => MessagingError::NotCommitted(e),
    })
}

/// Keys in `namespace` that start with `prefix`.
pub(super) fn keys_under(
    store: &EncryptedStore,
    namespace: &str,
    prefix: &str,
) -> Result<Vec<String>, MessagingError> {
    Ok(store
        .list_keys_with_prefix(namespace)
        .map_err(MessagingError::Store)?
        .into_iter()
        .filter(|k| k.starts_with(prefix))
        .collect())
}

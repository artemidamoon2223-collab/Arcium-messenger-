//! Far skips (tracker R-14): the stored waits per chain, and the far pass
//! of a round that tries a skip once a chain has waited long enough.

use super::*;

/// One session's far-skip waits (tracker R-14): per chain, the ratchet key
/// a far message named, and when one was first and last seen.
pub(super) type FarWaits = Vec<FarWait>;

/// Times are milliseconds of this device's clock since the Unix epoch
/// ([`NetworkMessenger::this_millis`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FarWait {
    pub(super) chain: [u8; 32],
    pub(super) first: u64,
    pub(super) last: u64,
    /// The `last` the store was last given for this chain; `None` if it
    /// was given none since the chain started (or started again) waiting.
    /// Not stored itself.
    pub(super) stored_last: Option<u64>,
}

/// The store key of the far-skip waits of the session `handle` (tracker
/// R-14): `FAR_WAIT_RECORD_V1`. Written only by the network layer, deleted
/// when the session accepts a message, when it is given up, and with the
/// contact.
pub(crate) fn far_wait_key(handle: u64) -> String {
    format!("farwait:v1/{handle:016x}")
}

/// `FAR_WAIT_RECORD_V1`: version (1) = 1, count (1) at most
/// [`FAR_CHAINS_PER_SESSION`], then per chain its ratchet key (32), first
/// and last seen (8 each, big-endian milliseconds). Local, never sent.
const FAR_WAIT_RECORD_VERSION: u8 = 1;
pub(super) const FAR_WAIT_ENTRY_LEN: usize = 32 + 8 + 8;

/// How much later a sighting must be to be stored as the chain's last one:
/// it only orders the chains for dropping, so a minute is precise enough,
/// and a far message repeated many times a minute writes once.
pub(super) const FAR_WAIT_LAST_STEP_MS: u64 = 60_000;

pub(super) fn pack_far_waits(waits: &[FarWait]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + FAR_WAIT_ENTRY_LEN * waits.len());
    out.push(FAR_WAIT_RECORD_VERSION);
    out.push(u8::try_from(waits.len()).unwrap_or(u8::MAX));
    for w in waits {
        out.extend_from_slice(&w.chain);
        out.extend_from_slice(&w.first.to_be_bytes());
        out.extend_from_slice(&w.last.to_be_bytes());
    }
    out
}

/// `None` for anything but a well-formed record: it is then read as no
/// wait, and replaced at the next write.
pub(super) fn unpack_far_waits(bytes: &[u8]) -> Option<FarWaits> {
    let (&version, rest) = bytes.split_first()?;
    let (&count, rest) = rest.split_first()?;
    if version != FAR_WAIT_RECORD_VERSION
        || usize::from(count) > FAR_CHAINS_PER_SESSION
        || rest.len() != FAR_WAIT_ENTRY_LEN * usize::from(count)
    {
        return None;
    }
    let u64_at = |b: &[u8]| u64::from_be_bytes(b.try_into().expect("8 bytes"));
    let mut waits: FarWaits = Vec::with_capacity(usize::from(count));
    // `rest` holds exactly `count` entries (checked above).
    for e in rest.as_chunks::<FAR_WAIT_ENTRY_LEN>().0 {
        let chain: [u8; 32] = e[..32].try_into().expect("32 bytes");
        if waits.iter().any(|w| w.chain == chain) {
            return None;
        }
        let last = u64_at(&e[40..48]);
        waits.push(FarWait {
            chain,
            first: u64_at(&e[32..40]),
            last,
            stored_last: Some(last),
        });
    }
    Some(waits)
}

/// Records a far message of `chain` seen at `now` in `waits`: since when
/// the chain has waited, and whether `waits` changed so that it must be
/// stored. A new chain starts waiting now, in place of the chain seen least
/// recently once [`FAR_CHAINS_PER_SESSION`] wait. A clock read before the
/// chain's first sighting (set back) starts its wait again. The last
/// sighting is kept exact in memory and stored at most once per
/// [`FAR_WAIT_LAST_STEP_MS`], and at the next sighting while the store
/// was not given it: once `waits` is stored, the caller sets each
/// `stored_last` to its `last`.
pub(super) fn note_far_sighting(waits: &mut FarWaits, chain: [u8; 32], now: u64) -> (u64, bool) {
    if let Some(w) = waits.iter_mut().find(|w| w.chain == chain) {
        if now < w.first {
            w.first = now;
            w.last = now;
            w.stored_last = None;
            return (now, true);
        }
        w.last = w.last.max(now);
        let due = w
            .stored_last
            .is_none_or(|stored| w.last.saturating_sub(stored) >= FAR_WAIT_LAST_STEP_MS);
        return (w.first, due);
    }
    if waits.len() >= FAR_CHAINS_PER_SESSION {
        if let Some(stale) = (0..waits.len()).min_by_key(|&i| waits[i].last) {
            waits.remove(stale);
        }
    }
    waits.push(FarWait {
        chain,
        first: now,
        last: now,
        stored_last: None,
    });
    (now, true)
}

/// One round's far skips (tracker R-14): the messages to try once the
/// message pass is over, one per session and at most
/// [`FAR_TRIES_PER_ROUND`]; the sessions that accepted a message in the
/// pass, which try none; and the sessions whose first far message in the
/// pass was judged without being kept, which keep none (a session is judged
/// once per pass).
#[derive(Default)]
pub(super) struct FarRound {
    candidates: Vec<(u64, Vec<u8>)>,
    progressed: HashSet<u64>,
    judged: HashSet<u64>,
}

impl NetworkMessenger {
    /// Test aid: how many far skips this instance tried (R-14).
    #[cfg(test)]
    pub(crate) fn far_tries(&self) -> u32 {
        self.far_tries.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Test aid: how many times a far-skip wait was stored.
    #[cfg(test)]
    pub(crate) fn far_writes(&self) -> u32 {
        self.far_writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether `wire`, which did not decrypt under the session `handle`, is
    /// kept for a far skip at the end of the message pass (`far_pass`;
    /// tracker R-14). It must need one: lie more than `MAX_SKIP` positions
    /// ahead in its chain, so more than a thousand of the contact's messages
    /// in a row are missing. A far skip drops the keys of all but the last
    /// thousand positions it skips, so their texts can no longer be read; it
    /// is kept for a gap nothing fills. So the session must have seen far
    /// messages for [`FAR_SKIP_WAIT`] without accepting a message: by then
    /// the sender has sent again whatever it still holds. A far skip may
    /// also derive up to `MAX_FAR_SKIP` keys per chain before the message
    /// authenticates, so a session keeps one and a round at most
    /// [`FAR_TRIES_PER_ROUND`]. A message not kept is deleted like any
    /// message that does not decrypt, so whoever writes forged far messages
    /// to the mailbox learns nothing from what stays there (R-9). A text is
    /// sent again, and a receipt or GONE message when the text it answers
    /// is. A failed check is reported.
    pub(super) fn far_candidate(&self, handle: u64, wire: &[u8], report: &mut SyncReport) -> bool {
        match self.core.needs_far_skip(handle, wire) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(e) => {
                report
                    .errors
                    .push(format!("checking how far ahead a message lies: {e}"));
                return false;
            }
        }
        let Some(chain) = wire.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
            return false;
        };
        let mut round = self.far_round.lock().expect("far_round");
        if round.judged.contains(&handle) || round.candidates.iter().any(|(h, _)| *h == handle) {
            return false;
        }
        let now = self.this_millis();
        let since = {
            let mut seen = self.far_seen.lock().expect("far_seen");
            let waits = match seen.entry(handle) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    // A wait that cannot be read tries no far skip this round.
                    let Some(stored) = self.stored_far_waits(handle, report) else {
                        round.judged.insert(handle);
                        return false;
                    };
                    e.insert(stored)
                }
            };
            let (since, changed) = note_far_sighting(waits, chain, now);
            if changed && self.store_far_waits(handle, waits, report) {
                for w in waits.iter_mut() {
                    w.stored_last = Some(w.last);
                }
            }
            since
        };
        let wait = u64::try_from(self.limits().far_skip_wait.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(since) < wait || round.candidates.len() >= FAR_TRIES_PER_ROUND {
            round.judged.insert(handle);
            return false;
        }
        round.candidates.push((handle, wire.to_vec()));
        true
    }

    /// Forgets the far-skip waits of the session `handle` (R-14): it
    /// accepted a message, or it is gone and a new session with the contact
    /// will have the same handle. The stored record is deleted unless this
    /// process knows it holds no wait, so an accepted message costs no
    /// write once that is known. After a failed delete (its cause is
    /// returned) the session is read from the store again, and the next
    /// accepted message tries the delete again; until then a far message of
    /// a chain the record names may be tried without the full wait
    /// (docs/NET-MESSAGING.md section 3).
    pub(crate) fn forget_far_waits(&self, handle: u64) -> Result<(), String> {
        let mut seen = self.far_seen.lock().expect("far_seen");
        if seen.get(&handle).is_some_and(Vec::is_empty) {
            return Ok(());
        }
        let result = match self.core.store.lock() {
            Ok(store) => store.delete(&far_wait_key(handle)).map_err(|e| e.to_string()),
            Err(_) => Err("the store lock is poisoned".to_string()),
        };
        if result.is_ok() {
            seen.insert(handle, Vec::new());
        } else {
            seen.remove(&handle);
        }
        result
    }

    /// The far-skip waits of the session `handle` kept in the store: none if
    /// there is no record or a damaged one (it is replaced at the next
    /// write). `None` if the store could not be read, which is reported:
    /// the record may hold a wait, and a later write would replace it.
    fn stored_far_waits(&self, handle: u64, report: &mut SyncReport) -> Option<FarWaits> {
        let stored = match self.core.store.lock() {
            Ok(store) => store.get(&far_wait_key(handle)),
            Err(_) => {
                report.errors.push("reading the wait before a far skip: the store lock is poisoned".into());
                return None;
            }
        };
        match stored {
            Ok(bytes) => Some(unpack_far_waits(&bytes).unwrap_or_default()),
            Err(StorageError::NotFound | StorageError::Decryption) => Some(Vec::new()),
            Err(e) => {
                report.errors.push(format!("reading the wait before a far skip: {e}"));
                None
            }
        }
    }

    /// The far-skip record of the session `handle` was deleted with its
    /// contact (`delete_contact`), in the same transaction: no chain of it
    /// waits.
    pub(crate) fn far_waits_deleted(&self, handle: u64) {
        self.far_seen.lock().expect("far_seen").insert(handle, Vec::new());
    }

    /// Stores the far-skip waits of the session `handle`; whether it did.
    /// A failure is reported. The store keeps what it held: a chain whose
    /// start it never took waits again after a restart, and the write is
    /// asked for again when a far message of the chain is next judged.
    fn store_far_waits(&self, handle: u64, waits: &[FarWait], report: &mut SyncReport) -> bool {
        let result = match self.core.store.lock() {
            Ok(store) => store.put(&far_wait_key(handle), &pack_far_waits(waits)),
            Err(_) => {
                report.errors.push("storing the wait before a far skip: the store lock is poisoned".into());
                return false;
            }
        };
        match result {
            Ok(()) => {
                #[cfg(test)]
                self.far_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            }
            Err(e) => {
                report.errors.push(format!("storing the wait before a far skip: {e}"));
                false
            }
        }
    }

    /// Test aid: how many chains of the session `handle` wait for a far skip.
    #[cfg(test)]
    pub(crate) fn far_waits(&self, handle: u64) -> usize {
        self.far_seen
            .lock()
            .expect("far_seen")
            .get(&handle)
            .map_or(0, Vec::len)
    }

    /// The session `handle` accepted a message: the wait before a far skip
    /// starts again, and it tries none this round (R-14). A failure to
    /// delete the stored wait is reported.
    pub(super) fn far_progress(&self, handle: u64, report: &mut SyncReport) {
        if let Err(e) = self.forget_far_waits(handle) {
            report.errors.push(format!(
                "deleting the wait before a far skip failed: {e}; tried again at the next accepted message"
            ));
        }
        self.far_round
            .lock()
            .expect("far_round")
            .progressed
            .insert(handle);
    }

    /// Tries the far skips the message pass kept (R-14), each for a session
    /// that accepted no message in the pass: one that did may be filling
    /// its gap, and the message comes again. The messages were deleted from
    /// the relay in the pass, so one not read here (a session that moved
    /// on, a failure) is counted dropped and is read only when it comes
    /// again; so is one lost to a crash or to a round that failed before
    /// this, though uncounted. A failure to settle one that was read is
    /// reported; the next round settles it from the inbox.
    pub(super) fn far_pass(&self, report: &mut SyncReport) {
        let (candidates, progressed) = {
            let mut round = self.far_round.lock().expect("far_round");
            (std::mem::take(&mut round.candidates), round.progressed.clone())
        };
        for (handle, wire) in candidates {
            if progressed.contains(&handle) {
                report.dropped += 1;
                continue;
            }
            #[cfg(test)]
            self.far_tries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            #[cfg(test)]
            far_hook::run(far_hook::Stage::BeforeTry, handle);
            match self.core.receive_committed_far(handle, &wire) {
                Ok(Received::Accepted(message)) => {
                    report.accepted += 1;
                    self.far_progress(handle, report);
                    crash_point("after_accept");
                    #[cfg(test)]
                    far_hook::run(far_hook::Stage::BeforeSettle, handle);
                    if let Err(e) = self.settle(handle, &message.message_id, &message.plaintext, report) {
                        report
                            .errors
                            .push(format!("settling a message read with a far skip: {e}"));
                    }
                    crash_point("after_settle");
                }
                // Not reached: a duplicate is found before any decryption.
                Ok(Received::Duplicate { .. }) => report.duplicates += 1,
                Err(CoreError::Crypto { .. }) => report.dropped += 1,
                Err(e) => {
                    report.dropped += 1;
                    report
                        .errors
                        .push(format!("reading a message far ahead in its chain: {e}"));
                }
            }
        }
    }
}

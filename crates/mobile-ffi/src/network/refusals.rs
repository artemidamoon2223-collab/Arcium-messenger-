//! Handshake refusals this process owes or sent (docs/NET-MESSAGING.md,
//! section 6).

use super::*;

/// Refusals this process owes or sent (docs/NET-MESSAGING.md, section 6).
pub(super) struct Refusals {
    /// Refusals not yet stored by the relay: recipient, envelope
    /// body, refused handshake's hash.
    pub(super) queued: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    /// When a refusal was last sent to each contact. It alone limits a
    /// retransmitted handshake too: refused again once the interval has
    /// passed, so a refusal the relay lost after storing it is replaced.
    pub(super) last_to: HashMap<[u8; 32], Instant>,
    /// Least time between two refusals to one contact.
    interval: Duration,
}

impl Default for Refusals {
    fn default() -> Self {
        Self {
            queued: Vec::new(),
            last_to: HashMap::new(),
            interval: REFUSAL_INTERVAL,
        }
    }
}

impl NetworkMessenger {
    /// Test aid: the least time between two refusals to one contact
    /// ([`REFUSAL_INTERVAL`] otherwise).
    #[cfg(test)]
    pub(crate) fn set_refusal_interval(&self, interval: Duration) {
        self.refusals.lock().expect("refusals").interval = interval;
    }

    /// Makes a refusal of `handshake` for `peer` and queues it, unless one
    /// is queued for this handshake or peer already, or one was sent to this
    /// peer less than [`REFUSAL_INTERVAL`] ago. A retransmitted handshake
    /// refused before is refused again once the interval has passed.
    pub(super) fn queue_refusal(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        reason: RefusalReason,
    ) -> Result<(), CoreError> {
        let hash = handshake_hash(handshake);
        {
            let r = self.refusals.lock().expect("refusals");
            let recent = r
                .last_to
                .get(&peer)
                .is_some_and(|t| t.elapsed() < r.interval);
            if recent || r.queued.iter().any(|(to, _, h)| *to == peer || *h == hash) {
                return Ok(());
            }
        }
        let Some(body) = self.core.make_handshake_refusal(peer, handshake, reason)? else {
            return Ok(());
        };
        self.refusals
            .lock()
            .expect("refusals")
            .queued
            .push((peer, body, hash));
        Ok(())
    }

    /// Sends the queued refusals. A refusal stays queued, for the next round,
    /// when the relay refuses to store it (the initiator's mailbox is full),
    /// while the initiator waits after such a refusal (`held`), and when the
    /// connection fails, and once the round's budget is spent; it leaves the
    /// queue only once the relay stored it. A relay refusal does not end the
    /// round (as in `publish_pending`); a failed connection does, as every
    /// network error does, with nothing lost.
    pub(super) fn send_refusals(
        &self,
        conn: &mut Connection,
        budget: &Budget,
        relay_refusals: &mut RelayRefusals,
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        if self.refusals.lock().expect("refusals").queued.is_empty() {
            return Ok(());
        }
        // Read before the queue is taken: a failure here leaves it in place.
        let our = self.core.our_identity_pk()?;
        let queued = std::mem::take(&mut self.refusals.lock().expect("refusals").queued);
        let mut queued = queued.into_iter();
        let mut keep = Vec::new();
        let mut failed = None;
        for (peer, refusal, hash) in queued.by_ref() {
            if !budget.left() {
                // Out of time: the rest goes out next round.
                keep.push((peer, refusal, hash));
                break;
            }
            if relay_refusals.recipients.contains(&peer) || self.held(&peer) {
                keep.push((peer, refusal, hash));
                continue;
            }
            let env = Envelope::Refusal {
                sender: our,
                refusal: refusal.clone(),
            };
            match self.send_to(conn, peer, env.encode(), relay_refusals) {
                Ok(true) => {
                    let mut r = self.refusals.lock().expect("refusals");
                    r.last_to.insert(peer, Instant::now());
                    report.published += 1;
                }
                Ok(false) => keep.push((peer, refusal, hash)),
                Err(e) => {
                    keep.push((peer, refusal, hash));
                    failed = Some(e);
                    break;
                }
            }
        }
        keep.extend(queued);
        // Ahead of anything queued meanwhile, in their order.
        let mut r = self.refusals.lock().expect("refusals");
        keep.append(&mut r.queued);
        r.queued = keep;
        drop(r);
        failed.map_or(Ok(()), Err)
    }

    /// Acts on a refusal from the pinned contact `peer`. It counts only if
    /// its tag checks for the contact's pinned identity key and ours, it
    /// names those two keys, and it names the handshake of our own session with the
    /// contact, which nothing confirmed yet. Then that session can never
    /// be accepted: it is given up and a new one started. Anything else is
    /// dropped and changes nothing.
    pub(super) fn take_refusal(
        &self,
        peer: &[u8; 32],
        card: &Card,
        refusal: &[u8],
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let handle = handle_of(peer);
        let opened = if card.dh_pk == *peer {
            self.core.open_handshake_refusal(refusal, peer)?
        } else {
            None
        };
        let valid = match opened {
            Some(r) => {
                self.core.has_session(handle)?
                    && !self.confirmed(handle)?
                    && self
                        .core
                        .initiator_handshake(handle)?
                        .is_some_and(|hs| handshake_hash(&hs) == r.handshake_hash)
            }
            _ => false,
        };
        if !valid {
            report.dropped += 1;
            return Ok(());
        }
        chat::restart_after_refusal(self, peer, report)
    }
}

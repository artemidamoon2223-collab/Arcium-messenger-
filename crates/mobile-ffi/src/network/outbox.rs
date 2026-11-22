//! Sending: when a pending message is due again, recipients held after a
//! relay refusal, and publishing what the outbox holds.

use super::*;

impl NetworkMessenger {
    /// Whether the session under `handle` has accepted a message from the
    /// peer, which then holds it too.
    pub(super) fn confirmed(&self, handle: u64) -> Result<bool, CoreError> {
        let our = self.core.our_identity_pk()?;
        let (mut store, messenger) = self.core.lock()?;
        messenger
            .has_received(&mut store, our, handle)
            .map_err(|e| CoreError::messaging(handle, e))
    }

    /// Whether the relay accepted the pending message `id` in this process's
    /// lifetime (entries of messages no longer pending are dropped:
    /// [`Self::prune_sent`]).
    pub(super) fn was_sent(&self, id: &[u8]) -> bool {
        let Ok(id) = <[u8; 32]>::try_from(id) else {
            return false;
        };
        self.last_sent.lock().expect("last_sent").contains_key(&id)
    }

    /// Whether `key` may be sent now: never sent in this process, or the
    /// wait after its last send passed. The wait is `retransmit_after` after
    /// the first send and doubles with each further one, up to the cap.
    fn due(&self, key: &[u8; 32]) -> bool {
        let cap = self.limits().retransmit_cap;
        let sent = self.last_sent.lock().expect("last_sent");
        sent.get(key)
            .is_none_or(|(t, sends)| t.elapsed() >= self.retransmit_wait(*sends, cap))
    }

    /// The wait after the `sends`-th send (`sends` >= 1).
    pub(crate) fn retransmit_wait(&self, sends: u32, cap: Duration) -> Duration {
        let doublings = sends.saturating_sub(1).min(31);
        self.retransmit_after
            .checked_mul(1u32 << doublings)
            .unwrap_or(cap)
            .min(cap)
    }

    /// Drops the `last_sent` entries nothing reads any more (tracker R-22).
    /// Its two readers, [`Self::due`] and [`Self::was_sent`], only ask about
    /// messages still in an outbox and about a session's own handshake: an
    /// acknowledged or abandoned message, a receipt (acknowledged as it is
    /// sent) and anything of a contact without a session are never asked
    /// about again. So an entry stays while its key is the id of a pending
    /// outgoing message or the hash of the initiator handshake of a session
    /// read here, and also when it was written after this pass began, by a
    /// send (possibly on a session created meanwhile) it may not have seen.
    pub(super) fn prune_sent(&self) -> Result<(), CoreError> {
        let since = Instant::now();
        // One listing of the outbox's key names, for every contact: no
        // outbox record is read or decrypted (tracker R-22).
        let mut live: HashSet<[u8; 32]> = self.core.pending_outgoing_ids()?.into_iter().collect();
        for (_, handle) in self.sessions()? {
            if let Some(hs) = self.core.initiator_handshake(handle)? {
                live.insert(<[u8; 32]>::from(Sha256::digest(&hs)));
            }
        }
        self.last_sent
            .lock()
            .expect("last_sent")
            .retain(|key, (sent_at, _)| live.contains(key) || *sent_at >= since);
        Ok(())
    }

    fn mark_sent(&self, key: [u8; 32]) {
        let mut sent = self.last_sent.lock().expect("last_sent");
        let sends = sent.get(&key).map_or(0, |(_, n)| *n);
        sent.insert(key, (Instant::now(), sends.saturating_add(1)));
    }

    /// Whether sends to `peer` wait after a relay refusal.
    pub(super) fn held(&self, peer: &[u8; 32]) -> bool {
        let cap = self.limits().retransmit_cap;
        let refused = self.refused.lock().expect("refused");
        refused
            .get(peer)
            .is_some_and(|(t, times)| t.elapsed() < self.retransmit_wait(*times, cap))
    }

    /// Test aid: how many times in a row the relay refused `peer`.
    #[cfg(test)]
    pub(crate) fn refusals_in_a_row(&self, peer: &[u8; 32]) -> u32 {
        self.refused.lock().expect("refused").get(peer).map_or(0, |(_, n)| *n)
    }

    /// Asks the relay to store `envelope` for `peer`. `Ok(false)`: the relay
    /// refused (a full mailbox; on V2 also an envelope that does not name the
    /// connection's authenticated owner as its sender, which this layer never
    /// sends). It read the request and answered, so the
    /// connection is still in step and the round goes on; the recipient
    /// starts or prolongs its wait. Any other failure ends the round, as the
    /// connection's state is then unknown.
    pub(super) fn send_to(
        &self,
        conn: &mut Connection,
        peer: [u8; 32],
        envelope: Vec<u8>,
        relay_refusals: &mut RelayRefusals,
    ) -> Result<bool, CoreError> {
        match conn.send(peer, envelope) {
            Ok(_) => {
                self.refused.lock().expect("refused").remove(&peer);
                Ok(true)
            }
            Err(ClientError::Refused(code)) => {
                let mut refused = self.refused.lock().expect("refused");
                let times = refused.get(&peer).map_or(0, |(_, n)| *n);
                refused.insert(peer, (Instant::now(), times.saturating_add(1)));
                relay_refusals.note(peer, code);
                Ok(false)
            }
            Err(e) => Err(network(e)),
        }
    }

    /// Sends what is due to every session's peer. A peer the relay refuses
    /// gets nothing more in this round and nothing until its wait is over
    /// ([`Self::held`]), so its envelopes stay in their order; the other
    /// peers are not affected.
    pub(super) fn publish_pending(
        &self,
        conn: &mut Connection,
        sessions: &[([u8; 32], u64)],
        budget: &Budget,
        relay_refusals: &mut RelayRefusals,
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let our = self.core.our_identity_pk()?;
        for (peer, handle) in sessions {
            // Out of time: the rest is sent next round.
            if !budget.left() {
                return Ok(());
            }
            if relay_refusals.recipients.contains(peer) || self.held(peer) {
                continue;
            }
            if !self.confirmed(*handle)? {
                if let Some(hs) = self.core.initiator_handshake(*handle)? {
                    let key: [u8; 32] = Sha256::digest(&hs).into();
                    if self.due(&key) {
                        let env = Envelope::Handshake {
                            sender: our,
                            handshake: hs,
                        };
                        if !self.send_to(conn, *peer, env.encode(), relay_refusals)? {
                            continue;
                        }
                        self.mark_sent(key);
                        report.published += 1;
                    }
                }
            }
            for m in self.core.pending_outgoing(*handle)? {
                // A text the user cancelled is never sent again: abandoned
                // here instead (`chat::cancel_text`; R-15).
                if let Some((&client_id::TEXT, app_id)) = m.client_message_id.split_first() {
                    if self.cancelled_text(peer, app_id)? {
                        self.core.abandon_outgoing(*handle, m.message_id)?;
                        continue;
                    }
                }
                let id: [u8; 32] = m.message_id.as_slice().try_into().expect("32-byte id");
                if !self.due(&id) {
                    continue;
                }
                if !budget.left() {
                    return Ok(());
                }
                let env = Envelope::Message {
                    sender: our,
                    wire: m.wire,
                };
                if !self.send_to(conn, *peer, env.encode(), relay_refusals)? {
                    break;
                }
                self.mark_sent(id);
                report.published += 1;
                // Receipts and GONE messages are not answered: each leaves
                // the outbox once the relay accepted it.
                if matches!(
                    m.client_message_id.first(),
                    Some(&client_id::RECEIPT) | Some(&client_id::GONE)
                ) {
                    crash_point("receipt_published");
                    self.core.acknowledge_outgoing(*handle, m.message_id)?;
                }
            }
        }
        Ok(())
    }

    /// Test aid: the keys `last_sent` holds.
    #[cfg(test)]
    pub(crate) fn sent_keys(&self) -> Vec<[u8; 32]> {
        self.last_sent.lock().expect("last_sent").keys().copied().collect()
    }
}

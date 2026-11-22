//! Receiving: what one envelope does, handshakes recorded beside a session,
//! settling accepted messages, receipts, and naming messages beyond recall.

use super::*;

impl NetworkMessenger {
    /// Decides what happens to one fetched envelope. An error return aborts
    /// the round; everything not yet deleted stays on the relay.
    pub(super) fn process(&self, env: Envelope, report: &mut SyncReport) -> Result<Fate, CoreError> {
        let sender = env.sender();
        let card = {
            let store = self.core.store.lock().map_err(|_| CoreError::Storage {
                msg: "mutex poisoned".into(),
            })?;
            pinned(&store, &sender)?
        };
        if card.is_none() {
            report.dropped += 1;
            return Ok(Fate::Delete);
        }
        let handle = handle_of(&sender);
        match env {
            Envelope::Handshake { handshake, .. } => {
                // The handshake must be the sender's own: its initiator key is
                // what the session is keyed from.
                if handshake.len() != crate::INITIATOR_HANDSHAKE_V1_LEN
                    || handshake[4..36] != sender
                {
                    report.dropped += 1;
                    return Ok(Fate::Delete);
                }
                let has_session = self.core.has_session(handle)?;
                // A responder session an older build stored on receipt of a
                // handshake, untouched since, does not stop the handshake
                // here: `establish_session_responder` alone decides whether
                // it retires that session (docs/S2-B2-DURABLE-MESSAGING.md,
                // section 4b). Nothing is decided or changed here.
                let legacy = has_session && self.core.is_legacy_unconfirmed(handle)?;
                if has_session && !legacy {
                    // No session is replaced by a handshake. If ours is an
                    // unconfirmed start of our own, the handshake is recorded
                    // beside it and raises nothing: its bytes are public, so
                    // a mailbox writer can make one (tracker R-13). Both
                    // sides having started is recorded only once the
                    // contact's first message under it authenticates (the
                    // `Message` branch). (A handshake only recorded here is
                    // not a session and does not reach this branch: it may
                    // be replaced.)
                    if self.own_unconfirmed(handle)? {
                        return self.record_beside(sender, &handshake, handle, report);
                    }
                    // Beside an established session it may be the
                    // contact's restart (option B): recorded the same way,
                    // and only its first message, authenticating there,
                    // replaces the session (`take_message`).
                    if self.confirmed(handle)? {
                        return self.record_restart(sender, &handshake, handle, report);
                    }
                    report.dropped += 1;
                    return Ok(Fate::Delete);
                }
                // Recorded as provisional only: the session is created when
                // the initiator's first message authenticates under it.
                match self.core.establish_session_responder(handle, handshake.clone()) {
                    Ok(()) => Ok(Fate::Delete),
                    Err(e) if transient(&e) => {
                        report.errors.push(e.to_string());
                        Ok(Fate::Keep)
                    }
                    // Refused, so the older session stays (something is
                    // pending on it, it changed meanwhile into a session that
                    // is never replaced, or this handshake cannot be
                    // answered — such as a retransmission of the handshake
                    // that session came from): dropped, as for any other
                    // session.
                    Err(_) if legacy => {
                        report.dropped += 1;
                        Ok(Fate::Delete)
                    }
                    Err(e) => {
                        chat::set_flag(self, &sender, chat::HANDSHAKE_REFUSED)?;
                        // No session holds this handshake and its prekeys are
                        // gone: tell the initiator, so it can start again.
                        if let Some(reason) = RefusalReason::of(&e) {
                            self.queue_refusal(sender, &handshake, reason)?;
                        }
                        report.dropped += 1;
                        report.errors.push(format!("handshake refused: {e}"));
                        Ok(Fate::Delete)
                    }
                }
            }
            Envelope::Refusal { refusal, .. } => {
                let card = card.expect("checked above");
                self.take_refusal(&sender, &card, &refusal, report)?;
                Ok(Fate::Delete)
            }
            Envelope::Message { wire, .. } => self.take_message(sender, handle, &wire, report),
        }
    }

    /// A message envelope from the pinned contact `sender` (`process`).
    fn take_message(
        &self,
        sender: [u8; 32],
        handle: u64,
        wire: &[u8],
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        // Without a session, the message is either the first one of a
        // recorded handshake — which creates the session if it
        // authenticates — or waits for its handshake (`NoSession`).
        let first = !self.core.has_session(handle)?;
        let received = self.core.receive_committed(handle, wire);
        // Not a message of our established session: it may be the contact's
        // first message under a handshake recorded beside it, that is, the
        // contact restarted the session (option B). That it authenticates
        // there needs the contact's identity secret (or this device's
        // signed-prekey secret, while that is still held: NET-MESSAGING
        // section 8), and the handshake must
        // name this device's current one-time prekey, which a replay of a
        // handshake older than our session does not (`ArciumCore::new`
        // replaces it when an own session is confirmed). Checked before a far
        // skip, which would otherwise take the message. A failed check is
        // reported and must not abort the round.
        if !first && matches!(received, Err(CoreError::Crypto { .. })) && self.confirmed(handle)? {
            match self.core.beside_authenticates(handle, &sender, wire) {
                Ok(true) => {
                    self.accept_restart(&sender, handle)?;
                    crash_point("restart_after_retire");
                    // No session now: the message is read as the first one
                    // of the recorded handshake, which creates the new one.
                    return self.take_message(sender, handle, wire, report);
                }
                Ok(false) => {}
                Err(e) => report
                    .errors
                    .push(format!("checking a restart beside our session: {e}")),
            }
        }
        if !first
            && matches!(received, Err(CoreError::Crypto { .. }))
            && self.far_candidate(handle, wire, report)
        {
            // Tried once the message pass is over (`far_pass`).
            return Ok(Fate::Delete);
        }
        match received {
            Ok(Received::Accepted(message)) => {
                self.far_progress(handle, report);
                report.accepted += 1;
                if first {
                    report.sessions_accepted += 1;
                }
                crash_point("after_accept");
                self.settle(handle, &message.message_id, &message.plaintext, report)?;
                crash_point("after_settle");
                Ok(Fate::Delete)
            }
            Ok(Received::Duplicate { message_id, .. }) => {
                report.duplicates += 1;
                self.receipt_again(handle, &sender, &message_id)?;
                Ok(Fate::Delete)
            }
            Err(CoreError::NoSession { .. }) => Ok(Fate::Keep),
            Err(CoreError::Crypto { .. }) => {
                // Not a message of our session. If ours is an
                // unconfirmed start of our own, this may be the
                // contact's first message under a handshake
                // recorded beside it. If it authenticates there —
                // which needs the contact's identity secret (or a
                // signed-prekey secret we still hold, NET-MESSAGING
                // section 8) — both
                // devices started a session with each other: the
                // conflict is recorded so the application can show
                // it (section 10). Nothing else is stored.
                //
                // The message is deleted, like any message that
                // does not decrypt here. That loses nothing: the
                // contact keeps it in its outbox and retransmits it,
                // with its handshake, until our receipt (which no
                // session here can give) or until it gives up that
                // session itself. It can only be accepted after
                // `resolve_session_conflict` removed our session, and
                // until then the contact's session stays unconfirmed,
                // so the retransmission is still running then.
                //
                // A beside record that cannot be read or decoded
                // counts as none, as `record_handshake_beside` and
                // `remove_session` treat it: the check is reported
                // and the message is deleted. It must not abort the
                // round, or anyone who stores a message "from" the
                // contact would stall every round here.
                if !first && self.own_unconfirmed(handle)? {
                    match self.core.beside_authenticates(handle, &sender, wire) {
                        Ok(true) => {
                            chat::set_flag(self, &sender, chat::CONFLICT)?;
                            crash_point("conflict_after_flag");
                        }
                        Ok(false) => {}
                        Err(e) => report
                            .errors
                            .push(format!("checking a first message beside our session: {e}")),
                    }
                }
                // A message of our session whose key is gone (it
                // arrived after the key was evicted) can never be
                // read: name it to the contact, who then stops
                // sending it (R-21). Once our session has received
                // from the contact, that includes a message of a chain
                // it no longer knows (left more than `MAX_PREV_CHAINS`
                // steps ago, or of another session of the contact), on
                // its second arrival (`forgotten_seen`); a forged
                // message looks the same. Only the contact can read the
                // GONE message, and it changes nothing for an id the
                // contact has not pending, so a forged message gains
                // nothing, and draws at most one GONE per session per
                // round. A failed check is reported and must not abort
                // the round.
                if !first {
                    let id = message_id(wire);
                    let named = match self.core.beyond_recall(handle, wire) {
                        Ok(Recall::KeyGone) => true,
                        Ok(Recall::ForgottenChain) => self.seen_again(handle, id),
                        Ok(Recall::Unknown) => false,
                        Err(e) => {
                            report
                                .errors
                                .push(format!("checking whether a message is beyond recall: {e}"));
                            false
                        }
                    };
                    if named {
                        self.gone.lock().expect("gone").entry(handle).or_default().push(id);
                    }
                }
                report.dropped += 1;
                Ok(Fate::Delete)
            }
            // The recorded handshake can no longer be answered: the
            // prekeys it names rotated or were consumed since.
            Err(
                e @ (CoreError::StaleSignedPrekey
                | CoreError::OneTimePrekeyUnavailable { .. }
                | CoreError::OneTimePrekeyRequired),
            ) => {
                chat::set_flag(self, &sender, chat::HANDSHAKE_REFUSED)?;
                report.dropped += 1;
                report.errors.push(format!("handshake refused: {e}"));
                Ok(Fate::Delete)
            }
            Err(CoreError::SessionUnresolved { .. }) => {
                self.core.recover_session(handle)?;
                Ok(Fate::Keep)
            }
            Err(e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
        }
    }

    /// Whether our session under `handle` is an unconfirmed start of our
    /// own: this device initiated it and no message from the peer has
    /// authenticated under it yet.
    fn own_unconfirmed(&self, handle: u64) -> Result<bool, CoreError> {
        Ok(self.core.initiator_handshake(handle)?.is_some() && !self.confirmed(handle)?)
    }

    /// Records `handshake` from the pinned contact `peer` beside our own
    /// unconfirmed session with it (docs/S2-B2-DURABLE-MESSAGING.md,
    /// section 4c). Nothing else changes and no flag is set: the record has
    /// no authority, and a later handshake replaces it.
    ///
    /// A handshake this device can never answer (the prekeys it names were
    /// consumed or rotated) is refused as a responder refuses one (section
    /// 6): the refusal is sent, so a genuine initiator gives that session up
    /// and starts again from the current bundle. Without it, a simultaneous
    /// start in which the contact's handshake cannot be answered here would
    /// never show a conflict on this device, and with this device's key the
    /// greater nobody could resolve it. A refusal changes nothing at a peer
    /// whose current handshake it does not name, so one elicited by a forged
    /// handshake is dropped there. The `HANDSHAKE_REFUSED` flag is not set:
    /// `sync_conversations` clears it whenever a session exists.
    fn record_beside(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        handle: u64,
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        match self.core.record_handshake_beside(handle, handshake) {
            Ok(()) => {
                crash_point("beside_after_record");
                Ok(Fate::Delete)
            }
            Err(e) if transient(&e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
            Err(e) => {
                if let Some(reason) = RefusalReason::of(&e) {
                    self.queue_refusal(peer, handshake, reason)?;
                }
                report.dropped += 1;
                report.errors.push(format!("handshake refused: {e}"));
                Ok(Fate::Delete)
            }
        }
    }

    /// Records `handshake` from the pinned contact `peer` beside our
    /// established session with it, as a possible restart of the session by
    /// the contact (option B; `docs/S2-B2-DURABLE-MESSAGING.md` section 4c).
    /// Nothing else changes: the record has no authority, and a later
    /// handshake replaces it.
    ///
    /// A handshake this device cannot answer is refused as beside our own
    /// session (`record_beside`), so a contact whose restart names a
    /// one-time prekey that changed since (another contact's first message
    /// consumed it, or a confirmation of our own session replaced it) gives
    /// that restart up and makes it again from the current bundle. Without
    /// the refusal it would wait for good. Never refused: a late
    /// retransmission of the handshake our responder session came from
    /// (`ArciumCore::is_accepted_handshake`, which also knows it in another
    /// encoding a relay put in its place), whose one-time prekey we consumed
    /// when we accepted it. The contact retransmits it until our receipt
    /// arrives, and a refusal naming it would end the session the contact
    /// has just made. A responder session stored by an older build has no
    /// such record: then the handshake is refused, which ends the contact's
    /// session only if our receipt has not reached it yet. No error is
    /// reported: nothing here needs this user.
    fn record_restart(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        handle: u64,
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        match self.core.record_handshake_beside(handle, handshake) {
            Ok(()) => {
                crash_point("restart_after_record");
                Ok(Fate::Delete)
            }
            Err(e) if transient(&e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
            Err(e) => {
                if !self.core.is_accepted_handshake(&peer, handshake)? {
                    if let Some(reason) = RefusalReason::of(&e) {
                        self.queue_refusal(peer, handshake, reason)?;
                    }
                }
                report.dropped += 1;
                Ok(Fate::Delete)
            }
        }
    }

    /// Whether the message `id` of a chain the session `handle` no longer
    /// knows was seen before (R-21, `forgotten_seen`): then it is named.
    /// Either way it becomes the session's newest note, the least recently
    /// seen one dropped once [`FORGOTTEN_SEEN_PER_SESSION`] are held.
    fn seen_again(&self, handle: u64, id: [u8; 32]) -> bool {
        let mut seen = self.forgotten_seen.lock().expect("forgotten_seen");
        let ids = seen.entry(handle).or_default();
        let again = match ids.iter().position(|seen| *seen == id) {
            Some(at) => {
                ids.remove(at);
                true
            }
            None => {
                if ids.len() >= FORGOTTEN_SEEN_PER_SESSION {
                    ids.pop_front();
                }
                false
            }
        };
        ids.push_back(id);
        again
    }

    /// Forgets the notes of messages of chains the session `handle` no
    /// longer knows (R-21, `forgotten_seen`): it is gone, and a new session
    /// with the contact has the same handle.
    pub(crate) fn forget_forgotten_notes(&self, handle: u64) {
        self.forgotten_seen.lock().expect("forgotten_seen").remove(&handle);
    }

    /// Test aid: how many messages found beyond recall wait to be named.
    #[cfg(test)]
    pub(crate) fn gone_len(&self) -> usize {
        self.gone.lock().expect("gone").values().map(Vec::len).sum()
    }

    /// Applies every accepted message still in the inbox that the network
    /// layer, not the application, consumes.
    pub(super) fn settle_inbox(&self, handle: u64, report: &mut SyncReport) -> Result<(), CoreError> {
        for m in self.core.pending_committed(handle)? {
            self.settle(handle, &m.message_id, &m.plaintext, report)?;
        }
        Ok(())
    }

    /// Texts from `peer` accepted and not yet marked read, in order, each in
    /// a wiping owner. What [`received_texts`](Self::received_texts) returns
    /// to the application, before the copy that leaves Rust ownership.
    pub(crate) fn pending_texts(&self, peer: &[u8; 32]) -> Result<Vec<PendingText>, CoreError> {
        let mut texts = Vec::new();
        for m in self.core.pending_committed(handle_of(peer))? {
            if let Some(Payload::Text(text)) = Payload::decode(&m.plaintext) {
                texts.push((m.message_id, text));
            }
        }
        Ok(texts)
    }

    /// Acts on one accepted message. Idempotent: it runs again for anything
    /// still in the inbox after a crash.
    pub(super) fn settle(
        &self,
        handle: u64,
        id: &[u8],
        plaintext: &[u8],
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let id32: [u8; 32] = id.try_into().expect("32-byte id");
        match Payload::decode(plaintext) {
            // Stays in the inbox for the application; the receipt is
            // committed now, so it survives a crash before it is sent.
            Some(Payload::Text(_)) => self.receipt(handle, &id32, 0).map(|_| ()),
            Some(Payload::Open) => {
                self.receipt(handle, &id32, 0)?;
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            Some(Payload::Receipt(ids)) => {
                for acked in ids {
                    if self.core.acknowledge_outgoing(handle, acked.to_vec())? {
                        report.delivered += 1;
                    }
                }
                crash_point("receipt_applied");
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            // The contact cannot read these: a text of ours still pending
            // among them is abandoned, so it is not sent again and shows
            // NotDelivered (R-21). Any other id is ignored.
            Some(Payload::Gone(ids)) => {
                let texts: Vec<Vec<u8>> = self
                    .core
                    .pending_outgoing(handle)?
                    .into_iter()
                    .filter(|m| m.client_message_id.first() == Some(&client_id::TEXT))
                    .map(|m| m.message_id)
                    .collect();
                for gone in ids {
                    if texts.iter().any(|t| t[..] == gone[..]) {
                        self.core.abandon_outgoing(handle, gone.to_vec())?;
                    }
                }
                crash_point("gone_applied");
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            None => {
                report.dropped += 1;
                report.errors.push("unknown payload type discarded".into());
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
        }
    }

    /// Commits at most one GONE message per session for the messages this
    /// round found beyond recall (R-21), naming the first
    /// [`wire::MAX_RECEIPT_IDS`] of them in id order. The others are found
    /// again when the contact sends them again; and forged messages that only
    /// look late draw no more than one GONE per session per round. A GONE
    /// leaves the outbox once the relay accepted it, so the contact sending
    /// a named message again may never have got it: as for a receipt
    /// ([`Self::receipt_again`]), a later GONE for the same ids is committed,
    /// at most one per minute. A failure is reported and leaves the round
    /// going: the contact sends those messages again, and they are found
    /// again.
    pub(super) fn commit_gone(&self, report: &mut SyncReport) {
        let found = std::mem::take(&mut *self.gone.lock().expect("gone"));
        for (handle, mut ids) in found {
            ids.sort_unstable();
            ids.dedup();
            ids.truncate(wire::MAX_RECEIPT_IDS);
            if let Err(e) = self.name_gone(handle, &ids) {
                report.errors.push(format!("naming messages beyond recall: {e}"));
            }
        }
    }

    fn name_gone(&self, handle: u64, ids: &[[u8; 32]]) -> Result<(), CoreError> {
        let payload = Payload::Gone(ids.to_vec()).encode();
        if let SendResult::AlreadyAcknowledged { .. } =
            self.core.send_committed(handle, &client_id::gone(ids, 0), &payload)?
        {
            self.core
                .send_committed(handle, &client_id::gone(ids, self.this_minute() + 1), &payload)?;
        }
        Ok(())
    }

    pub(super) fn receipt(&self, handle: u64, id: &[u8; 32], round: u64) -> Result<SendResult, CoreError> {
        self.core.send_committed(
            handle,
            &client_id::receipt(id, round),
            &Payload::Receipt(vec![*id]).encode(),
        )
    }

    /// The peer sent `id` again, so it may not have our receipt. If the
    /// original receipt already left the outbox, commit a new one, at most one
    /// per minute per message.
    ///
    /// Only a message that was answered when it was accepted is answered
    /// again: a text or an OPEN, whose receipt `settle` committed under
    /// `client_id::receipt(id, 0)`. A receipt, or a payload this build does
    /// not know, was never answered, so its duplicate is not either: a
    /// replayed receipt changes nothing (docs/NET-MESSAGING.md, section 5).
    /// Send-id records are never deleted, so the check holds for messages
    /// accepted long ago.
    fn receipt_again(&self, handle: u64, peer: &[u8; 32], id: &[u8]) -> Result<(), CoreError> {
        let id32: [u8; 32] = id.try_into().expect("32-byte id");
        if self.core.prior_send(peer, &client_id::receipt(&id32, 0))?.is_none() {
            return Ok(());
        }
        if let SendResult::AlreadyAcknowledged { .. } = self.receipt(handle, &id32, 0)? {
            self.receipt(handle, &id32, self.this_minute() + 1)?;
        }
        Ok(())
    }
}

//! The responder side of a first contact: whether a handshake can be
//! answered, the session it yields, and accepting its first message.

use super::*;

/// Whether this device can answer `handshake` from its prekey `record` (the
/// table on `establish_session_responder`), and under which signed prekey.
/// Consumes nothing.
///
/// The current signed prekey is preferred when both would match (a
/// collision of the 8-byte ids). The previous one answers only while the
/// one-time prekey held is the one the current signed prekey was made with:
/// the one-time prekey every bundle naming the previous one was published
/// with is then gone (every writer that replaces the one-time prekey drops
/// the previous key too, `PrekeyRecord::renew_one_time_prekey`; this check
/// does not rely on it).
pub(crate) fn check_answerable(
    record: &PrekeyRecord,
    handshake: &InitiatorHandshakeV1,
) -> Result<Spk, CoreError> {
    let names = |sk: &StaticSecret| spk_id(PublicKey::from(sk).as_bytes()) == handshake.spk_id;
    let which = if names(&record.signed_prekey_sk) {
        Spk::Current
    } else if record.prev.as_ref().is_some_and(names)
        && record.opk.is_some()
        && record.opk_id() == record.born_opk
    {
        Spk::Previous
    } else {
        return Err(CoreError::StaleSignedPrekey);
    };
    match (record.opk_id(), handshake.opk_id) {
        (Some(held), Some(named)) if held == named => Ok(which),
        (Some(_), Some(named)) | (None, Some(named)) => {
            Err(CoreError::OneTimePrekeyUnavailable { opk_id: named })
        }
        // Without a one-time prekey nothing stops an exact replay of the
        // handshake and its first message (tracker X-6), so one is required
        // whether or not this device holds one.
        (Some(_), None) | (None, None) => Err(CoreError::OneTimePrekeyRequired),
    }
}

/// The responder's session for `handshake`: X3DH with this device's
/// identity, its signed prekey `signed_prekey_sk` (the current or the
/// previous one, as `check_answerable` chose) and the one-time prekey
/// `opk` the handshake names (if any), and the Double Ratchet initialised
/// from the root key. Shared by the promotion (`accept_first_message`, which
/// has taken `opk` out of the prekey record) and the check beside an own
/// session (`ArciumCore::beside_authenticates`, which only reads it), so
/// both derive exactly the same keys.
pub(crate) fn responder_session(
    identity: &Identity,
    our_identity_pk: PublicKey,
    signed_prekey_sk: &StaticSecret,
    opk: Option<&StaticSecret>,
    handshake: &InitiatorHandshakeV1,
) -> Result<Session, CoreError> {
    let bob_session = x3dh_respond(
        &identity.dh_key,
        our_identity_pk,
        signed_prekey_sk,
        opk,
        handshake.identity_pk,
        handshake.ephemeral_pk,
    )?;
    let ratchet = DoubleRatchet::init_bob(&bob_session.root_key, signed_prekey_sk.clone());
    // This runs for every candidate first message, including ones that will
    // not authenticate. The ratchet holds its own copy and wipes it on drop;
    // this one is wiped now rather than after a store commit.
    drop(bob_session.root_key);
    // Owner is the initiator identity this handshake was answered for, not
    // anything the caller asserted separately.
    Ok(Session {
        ratchet,
        ad: bob_session.ad.clone(),
        peer_identity_pk: handshake.identity_pk.to_bytes(),
    })
}

/// Creates the responder session for `provisional` from the initiator's
/// first message `wire`, if it authenticates (see `establish_session_responder`).
///
/// X3DH runs again from the provisional handshake against the prekeys held
/// now, which are checked again first. The session is stored — together with
/// the prekey record with a new one-time prekey in place of the one it used
/// and without a previous signed prekey, only if that record is still
/// byte-identical to the one read here — only if `wire` decrypts under it;
/// otherwise nothing is written. Under the previous signed prekey, its
/// secret is taken out of the record and wiped when this returns. The
/// signed prekey is not rotated here: the next round does, because the
/// one-time prekey changed ((E), `plan_rotation`).
pub(crate) fn accept_first_message(
    identity: &Identity,
    store: &mut EncryptedStore,
    messenger: &mut Messenger,
    session_id: u64,
    provisional: ProvisionalHandshake,
    wire: &[u8],
) -> Result<Received, CoreError> {
    let handshake = unpack_initiator_handshake(&provisional.handshake)?;
    if handshake.identity_pk.to_bytes() != provisional.peer_identity_pk {
        return Err(CoreError::InvalidSessionState {
            session_id,
            msg: "provisional handshake does not match its peer".into(),
        });
    }
    let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
    let mut record = unpack_prekeys(&record_bytes)?;
    let our_identity_pk = PublicKey::from(&identity.dh_key);
    let which = match check_answerable(&record, &handshake) {
        Ok(which) => which,
        Err(refused) => {
            // Another instance on this database may have created the session
            // from this handshake since it was read here, consuming its prekey.
            // The message then belongs to that session.
            return match messenger.peer_of(store, session_id) {
                Ok(Some(_)) => messenger
                    .receive(store, our_identity_pk.to_bytes(), session_id, wire)
                    .map_err(|e| CoreError::messaging(session_id, e)),
                Ok(None) => Err(refused),
                Err(e) => Err(CoreError::messaging(session_id, e)),
            };
        }
    };
    let taken = record.opk.take().map(|(_, sk)| sk);
    // Out of the record before it is packed: the record written with the
    // session holds no previous signed prekey (`renew_one_time_prekey`).
    let previous = record.prev.take();
    let renewed = taken.is_some().then(|| {
        record.renew_one_time_prekey();
        pack_prekeys(&record)
    });
    let signed_prekey_sk = match which {
        Spk::Current => &record.signed_prekey_sk,
        Spk::Previous => previous.as_ref().ok_or(CoreError::StaleSignedPrekey)?,
    };

    let session = responder_session(
        identity,
        our_identity_pk,
        signed_prekey_sk,
        taken.as_ref(),
        &handshake,
    )?;
    let mut extra = match renewed {
        Some(new_record) => vec![SideWrite::replace(PREKEYS_KEY.into(), record_bytes, new_record)
            .map_err(|_| CoreError::Storage {
                msg: "prekey record key is reserved".into(),
            })?],
        None => Vec::new(),
    };
    extra.push(accepted_handshake_write(store, &provisional.peer_identity_pk, &handshake)?);
    let first = FirstContact {
        handle: session_id,
        session,
        provisional,
        extra,
    };
    match messenger.accept_first_message(store, our_identity_pk.to_bytes(), first, wire) {
        Ok(received) => Ok(received),
        // The prekey record (or the accepted-handshake record) changed since
        // it was read: another first message consumed the one-time prekey
        // first.
        Err(MessagingError::ExtraConflict { .. }) => Err(CoreError::OneTimePrekeyUnavailable {
            opk_id: handshake.opk_id.unwrap_or_default(),
        }),
        Err(e) => Err(CoreError::messaging(session_id, e)),
    }
}

/// The side write replacing this device's one-time prekey when its own
/// initiator session is confirmed: the first message from the peer
/// committed on it (`Messenger::with_confirm_hook`). The previous signed
/// prekey goes with it (`PrekeyRecord::renew_one_time_prekey`). The prekey
/// record held now is compared at commit, as when a first message consumes
/// a prekey.
///
/// Why: a handshake stays answerable for as long as the one-time prekey it
/// names is the published one and the signed prekey it names is held, and a
/// signed prekey is held for up to about two periods of rounds that
/// publish the bundle (tracker R-6, `plan_rotation`). Replacing the one-time prekey here makes every
/// handshake built from a bundle this device published before its session
/// with the peer was established unanswerable at once:
/// - a handshake of the peer recorded beside this session, whose first
///   message may have authenticated here, read with the prekey but never
///   accepted (a simultaneous start this device's session won), so that a
///   later leak of the store does not read those messages;
/// - a handshake of the peer this device never saw (withheld, or given up
///   by the peer), so that it and its first message, replayed later, cannot
///   replace the established session (option B): only a restart the peer
///   makes from a bundle published after this point can.
///
/// The cost: another contact's handshake that names the replaced prekey is
/// refused and that contact starts again, as after a first message consumed
/// it; so is a contact's restart of an established session (the network
/// layer refuses it, `record_restart`). Nothing when no prekey record is
/// held or it cannot be read.
pub(crate) fn replace_prekey_on_confirm(
    store: &EncryptedStore,
    _beside: Option<&ProvisionalHandshake>,
) -> Result<Vec<SideWrite>, MessagingError> {
    let bytes = match store.get(PREKEYS_KEY) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(StorageError::NotFound | StorageError::Decryption) => return Ok(Vec::new()),
        Err(e) => return Err(MessagingError::Store(e)),
    };
    let Ok(mut record) = unpack_prekeys(&bytes) else {
        return Ok(Vec::new());
    };
    if record.opk.is_none() {
        return Ok(Vec::new());
    }
    record.renew_one_time_prekey();
    let write = SideWrite::replace(PREKEYS_KEY.into(), bytes, pack_prekeys(&record))
        .map_err(MessagingError::SideWrite)?;
    Ok(vec![write])
}

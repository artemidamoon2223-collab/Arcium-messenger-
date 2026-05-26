&bob.signed_prekey_signature)
        .map_err(|_| X3dhError::BadSignature)?;

    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let dh1 = our_identity_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh2 = ephemeral_sk.diffie_hellman(&bob.identity_pk);
    let dh3 = ephemeral_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh4 = bob
        .one_time_prekey_pk
        .as_ref()
        .map(|opk| ephemeral_sk.diffie_hellman(opk));

    let root_key = derive_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_ref().map(|d| d.as_bytes()));

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(our_identity_pk.as_bytes());
    ad.extend_from_slice(bob.identity_pk.as_bytes());

    Ok(AliceSession {
        root_key,
        ephemeral_pk,
        their_signed_prekey_pk: bob.signed_prekey_pk,
        ad,
    })
}

pub struct BobSession {
    pub root_key: [u8; 32],
    pub their_ephemeral_pk: PublicKey,
    pub ad: Vec<u8>,
}

pub fn x3dh_respond(
    our_identity_sk: &StaticSecret,
    our_identity_pk: PublicKey,
    our_signed_prekey_sk: &StaticSecret,
    our_one_time_prekey_sk: Option<&StaticSecret>,
    their_identity_pk: PublicKey,
    their_ephemeral_pk: PublicKey,
) -> BobSession {
    let dh1 = our_signed_prekey_sk.diffie_hellman(&their_identity_pk);
    let dh2 = our_identity_sk.diffie_hellman(&their_ephemeral_pk);
    let dh3 = our_signed_prekey_sk.diffie_hellman(&their_ephemeral_pk);
    let dh4 = our_one_time_prekey_sk.map(|opk| opk.diffie_hellman(&their_ephemeral_pk));

    let root_key = derive_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_ref().map(|d| d.as_bytes()));

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(their_identity_pk.as_bytes());
    ad.extend_from_slice(our_identity_pk.as_bytes());

    BobSession {
        root_key,
        their_ephemeral_pk,
        ad,
    }
}

fn derive_root(dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: Option<&[u8]>) -> [u8; 32] {
    // X3DH spec: prepend 32 bytes of 0xFF for X25519, then concatenate DH outputs.
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d) = dh4 {
        ikm.extend_from_slice(d);
    }
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut rk = [0u8; 32];
    hk.expand(b"X3DH/v1", &mut rk).expect("hkdf expand");
    rk
}
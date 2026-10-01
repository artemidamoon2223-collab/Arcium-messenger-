//! What the `hmac` / `hkdf` / `sha2` upgrade relies on, pinned in tests.
//!
//! Two kinds of pin:
//!
//! * **Type-level**: the wiping owners that the enabled upstream `zeroize`
//!   features provide must exist on the exact resolved types. Each is an
//!   `assert` that compiles only if the feature is active, so dropping the
//!   `sha2` `zeroize` feature stops this module compiling. They prove that
//!   those owners exist and wipe when dropped; they do not prove that every
//!   secret-derived temporary inside the crates is wiped (it is not: the keyed
//!   key block, the inner digest, HKDF's `T(n)` blocks and stack or register
//!   copies are ordinary locals, see the tracker's H-9 row).
//! * **Known answers**: the standard vectors for HMAC-SHA256 (RFC 4231),
//!   HKDF-SHA256 (RFC 5869) and SHA-256 (FIPS 180-4) on the crates' own public
//!   API, independent of Arcium's constructions. Arcium's own byte-for-byte
//!   pins are the `golden` modules next to each construction.

use hkdf::Hkdf;
use hmac::Hmac;
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn is_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// `sha2`'s `zeroize` feature: the hasher is wiped on drop. Its `ZeroizeOnDrop`
/// is implemented by `sha2` only with the feature, and `digest`'s macro checks
/// that the core and the block buffer have it too. `hmac`'s own `zeroize`
/// feature only reaches `digest` (the block buffer and `CtOutput`), not the
/// hash state, so this is the assertion that fails without `sha2/zeroize`.
#[test]
fn sha256_hasher_is_wiped_on_drop() {
    is_zeroize_on_drop::<Sha256>();
    is_zeroize_on_drop::<sha2::block_api::Sha256VarCore>();
}

/// What a keyed `Hmac<Sha256>` owns: two hash cores (inner and outer keyed
/// state) and a block buffer. `Hmac` itself has no `ZeroizeOnDrop`; it wipes by
/// drop glue through these, so each part is pinned. `finalize`'s `CtOutput`
/// wipes the tag on drop.
#[test]
fn keyed_hmac_parts_and_its_tag_are_wiped_on_drop() {
    is_zeroize_on_drop::<hmac::digest::block_api::Buffer<hmac::block_api::HmacCore<Sha256>>>();
    is_zeroize_on_drop::<hmac::digest::CtOutput<Hmac<Sha256>>>();
}

/// Source-text guard over the files that call `Hkdf` and `Hmac`. It reads
/// spelled forms only, so a renamed alias or a macro would pass it; it exists
/// for the two easy regressions the upgrade invites:
///
/// * `Hkdf::new` (or an `extract` whose key is discarded) drops the HKDF
///   pseudorandom key unwiped, so each `extract` must be matched by the wipe;
/// * `CtOutput::into_bytes` takes `&self` in `digest` 0.11 and *clones* the
///   tag into an ordinary array, so the tag is only ever borrowed.
#[test]
fn the_hkdf_key_is_always_wiped_and_the_hmac_tag_is_never_copied() {
    let sources = [
        ("x3dh.rs", include_str!("x3dh.rs")),
        ("hybrid.rs", include_str!("hybrid.rs")),
        ("ratchet.rs", include_str!("ratchet.rs")),
    ];
    for (name, src) in sources {
        assert!(
            !src.contains("Hkdf::new(") && !src.contains("Hkdf::<Sha256>::new("),
            "{name}: Hkdf::new drops the pseudorandom key unwiped; use extract and wipe it"
        );
        assert_eq!(
            src.matches("::extract(").count(),
            src.matches("prk.as_mut_slice().zeroize()").count(),
            "{name}: every HKDF extract must have its pseudorandom key wiped"
        );
        assert!(
            !src.contains(".into_bytes()"),
            "{name}: CtOutput::into_bytes makes an ordinary copy of the tag"
        );
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::Mac;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    hex(mac.finalize().as_bytes())
}

/// RFC 4231, test cases 1, 2 and 6 (a key longer than the block size).
#[test]
fn hmac_sha256_rfc_4231() {
    assert_eq!(
        hmac_sha256(&[0x0b; 20], b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

/// One RFC 5869 appendix A case (SHA-256).
struct Rfc5869 {
    ikm: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    len: usize,
    prk: &'static str,
    okm: &'static str,
}

/// RFC 5869 appendix A, cases 1 to 3 (SHA-256): the pseudorandom key from
/// `extract` and the output keying material from `expand`.
#[test]
fn hkdf_sha256_rfc_5869() {
    let cases = [
        Rfc5869 {
            ikm: vec![0x0b; 22],
            salt: Some((0u8..13).collect()),
            info: (0xf0u8..=0xf9).collect(),
            len: 42,
            prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        Rfc5869 {
            ikm: (0u8..0x50).collect(),
            salt: Some((0x60u8..0xb0).collect()),
            info: (0xb0u8..=0xff).collect(),
            len: 82,
            prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            okm: concat!(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"
            ),
        },
        Rfc5869 {
            ikm: vec![0x0b; 22],
            salt: None,
            info: vec![],
            len: 42,
            prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ];
    for (i, c) in cases.iter().enumerate() {
        let (prk, hk) = Hkdf::<Sha256>::extract(c.salt.as_deref(), &c.ikm);
        assert_eq!(hex(prk.as_slice()), c.prk, "case {} PRK", i + 1);
        let mut okm = vec![0u8; c.len];
        hk.expand(&c.info, &mut okm).unwrap();
        assert_eq!(okm, unhex(c.okm), "case {} OKM", i + 1);
    }
}

/// FIPS 180-4 examples: empty, "abc", the 448-bit message and one million "a".
#[test]
fn sha256_fips_180_4() {
    let vectors: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (msg, want) in vectors {
        assert_eq!(hex(&Sha256::digest(msg)), want);
    }
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update([b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

//! Golden outputs of the storage key derivations, captured from the
//! production functions at `31f7915` (before the `hmac`/`hkdf`/`sha2`
//! upgrade). A change here would make every existing encrypted database
//! unreadable, so each byte must stay identical. The master key is a fixed
//! pattern, not a secret.

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KEYS: [&str; 4] = [
    "contact:alice",
    "session:v1/0011223344556677",
    "plain-key-without-a-namespace",
    "",
];

#[test]
fn per_key_subkey_is_unchanged() {
    let store = EncryptedStore::open_in_memory([0x42u8; 32]).unwrap();
    let want = [
        "5acabe83da915f80a8a5c0922eba986281181abea564e556785cf1b745f2170a",
        "5f2409864b511ec397ee5cf0d902d649ad0b92cadc759d9c324373f269d94959",
        "4230ff86dbc5efca246df02b60af5dafe6995a21431ade947211ae4ecd232c99",
        "be6c03dd27c1516b35757bce6214ad08d8dd93555c6dc597af6b6e98808503f7",
    ];
    let got: Vec<String> = KEYS.iter().map(|k| hex(&*store.keys.subkey(k))).collect();
    for (k, g) in KEYS.iter().zip(&got) {
        println!("GOLDEN subkey({k:?})={g}");
    }
    assert_eq!(got, want);
}

#[test]
fn key_name_hash_is_unchanged() {
    let store = EncryptedStore::open_in_memory([0x42u8; 32]).unwrap();
    let want = [
        "370170374676b387d2aae4b1b8ba5bcdeeb2a35488b4bed62875f46753f43f3a",
        "8416a0d249b9053ecdd04a2b08d91d465d73fcbf4c4f5f42f81c846928208166",
        "63d41a8ad757d3a6dfde9740766b58c2cab2253b98addfedc09b8fc10d781625",
        "1fbc3dc1d1e5cbeefeb44d743b93254a9c711069ad88fc7c2931e15e588b3329",
    ];
    let got: Vec<String> = KEYS
        .iter()
        .map(|k| hex(&store.keys.key_name_hash(k)))
        .collect();
    for (k, g) in KEYS.iter().zip(&got) {
        println!("GOLDEN key_name_hash({k:?})={g}");
    }
    assert_eq!(got, want);
}

#[test]
fn key_name_encryption_subkey_is_unchanged() {
    let store = EncryptedStore::open_in_memory([0x42u8; 32]).unwrap();
    let got = hex(&*store.keys.key_name_encryption_subkey());
    println!("GOLDEN key_name_encryption_subkey={got}");
    assert_eq!(
        got,
        "c94155fb5f997ee3a88bb853810e7d4bf36a646700e08e17590e09ca8739b8e4"
    );
}

/// Source-text guard: the storage KDFs take the HKDF pseudorandom key from
/// `extract` and wipe it (`KeyMaterial::hkdf`); `Hkdf::new` would drop it
/// unwiped. It reads spelled forms only, so it is not a proof.
#[test]
fn the_hkdf_key_is_always_wiped() {
    let src = include_str!("lib.rs");
    assert!(
        !src.contains("Hkdf::new(") && !src.contains("Hkdf::<Sha256>::new("),
        "Hkdf::new drops the pseudorandom key unwiped; use KeyMaterial::hkdf"
    );
    assert_eq!(
        src.matches("::extract(").count(),
        src.matches("prk.as_mut_slice().zeroize()").count(),
        "every HKDF extract must have its pseudorandom key wiped"
    );
}

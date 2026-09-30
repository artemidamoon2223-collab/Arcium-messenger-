//! Golden outputs of the X3DH root derivation, captured from the production
//! `derive_root` at `31f7915` (before the `hmac`/`hkdf`/`sha2` upgrade). The
//! function is deterministic; both the with-OPK and the without-OPK form must
//! stay byte-identical. Inputs are fixed patterns, not secrets.

use super::derive_root;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn root_derivation_with_a_one_time_prekey_is_unchanged() {
    let rk = derive_root(
        &[0x31u8; 32],
        &[0x32u8; 32],
        &[0x33u8; 32],
        Some([0x34u8; 32]),
    );
    assert_eq!(
        hex(&*rk),
        "3045bc2271a4baca0278bc29f88be6c23ec87e081bb82ef22341aab6e496a47a"
    );
}

#[test]
fn root_derivation_without_a_one_time_prekey_is_unchanged() {
    let rk = derive_root(
        &[0x31u8; 32],
        &[0x32u8; 32],
        &[0x33u8; 32],
        None::<[u8; 32]>,
    );
    assert_eq!(
        hex(&*rk),
        "0d75439e3da8795ea602c2424e92c3374c2e1dc99ff34b8c1784da218410ae73"
    );
}

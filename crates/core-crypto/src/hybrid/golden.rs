//! Golden output of the hybrid KEM's secret combiner, captured from the
//! production `combine_secrets` at `31f7915` (before the `hmac`/`hkdf`/`sha2`
//! upgrade), with ML-KEM-768-sized inputs. Inputs are fixed patterns, not
//! secrets.

use super::combine_secrets;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn combine_secrets_with_realistic_lengths_is_unchanged() {
    let ml_ct: Vec<u8> = (0..1088usize).map(|i| i as u8).collect();
    let ml_pk: Vec<u8> = (0..1184usize).map(|i| (i * 7) as u8).collect();
    let out = combine_secrets(
        &[0xA1u8; 32],
        &[0xA2u8; 32],
        &[0xA3u8; 32],
        &ml_ct,
        &[0xA5u8; 32],
        &ml_pk,
    );
    assert_eq!(
        hex(&*out),
        concat!(
            "809769644261fa4384958d6868a723ff0527fa3324b18e8ff85bf5d8d57343b1",
            "b1a5030fd755a1f3cac2d7afc92eb051f4b771b4d246fffd19a9f9165a46c9b9"
        )
    );
}

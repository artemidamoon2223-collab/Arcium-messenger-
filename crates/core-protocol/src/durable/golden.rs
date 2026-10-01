//! Golden outputs of the durable layer's record digest, captured from the
//! production `record_digest` at `31f7915` (before the `sha2` upgrade). The
//! digest is compared against stored bytes, so it must stay identical. The
//! lengths straddle SHA-256's block and padding boundaries.

use super::record_digest;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn record_digest_is_unchanged() {
    let cases: [(usize, &str); 8] = [
        (
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            55,
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56,
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            63,
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65,
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        ),
        (
            1000,
            "4e4c294b331f7a2099a379bec34b9f9fc03dc46ab465d998f4d683da53487e6d",
        ),
    ];
    let got: Vec<String> = cases
        .iter()
        .map(|(len, _)| {
            let record: Vec<u8> = if *len == 3 {
                b"abc".to_vec()
            } else {
                (0..*len).map(|i| (i % 251) as u8).collect()
            };
            hex(&record_digest(&record))
        })
        .collect();
    for ((len, want), g) in cases.iter().zip(&got) {
        assert_eq!(g, want, "record_digest len {len}");
    }
}

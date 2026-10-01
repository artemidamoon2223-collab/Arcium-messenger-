//! Golden outputs of the ratchet KDFs, captured from the production
//! functions at `31f7915` (before the `hmac`/`hkdf`/`sha2` upgrade) and pasted
//! here. The functions are deterministic, so every byte must stay identical
//! across a dependency change. Inputs are fixed patterns, not secrets.

use super::{kdf_ck, kdf_rk};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `kdf_ck` applied four times, each output chain key feeding the next call.
#[test]
fn chain_kdf_chain_of_four_is_unchanged() {
    let mut ck = [0xA5u8; 32];
    let mut got = Vec::new();
    for _ in 0..4 {
        let (new_ck, mk) = kdf_ck(&ck);
        got.push((hex(&*new_ck), hex(&*mk)));
        ck.copy_from_slice(&*new_ck);
    }
    let want: [(&str, &str); 4] = [
        (
            "ef36d49446d15744a6b00000fae34499f1ea51b4450a6c66f9baa7a26c528b09",
            "eaaeeb6888837f14da842be3d41842187a4ce020a110e494a2b700fc744e6abc",
        ),
        (
            "de9742c938801ed065363e6658fcb708e126292176cb789a29401b4d98c730ca",
            "ec4fc54d6bffda08707abd128a721878ff42d91599daaaab51fc11f6cab54205",
        ),
        (
            "a919c3341bc22fe978bdd8e8b843494ebc10ad07f40831a448b432923c813f5d",
            "2ad6f7e2971d2430708a87bf8ff74d478aacbc21e4fbcd2bd48a0289180a1b4e",
        ),
        (
            "600ab98c0df207cb4f80e5249bd0b7df004b93255d96954d1c029c12d037afd5",
            "60bab79f7c569f3a06fac06fb2389d31730654505a863af657258932d1e419ac",
        ),
    ];
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!((g.0.as_str(), g.1.as_str()), *w, "kdf_ck step {i}");
    }
}

/// `kdf_rk` with a 64-byte and a 32-byte DH output, then chained twice.
#[test]
fn root_kdf_is_unchanged() {
    let dh64: Vec<u8> = (0u8..64).collect();
    let (rk1, ck1) = kdf_rk(&[0x5Au8; 32], &dh64);
    let (rk2, ck2) = kdf_rk(&[0x3Cu8; 32], &[0xC3u8; 32]);
    let mut chained_rk = [0x77u8; 32];
    let mut chained = Vec::new();
    for i in 0u8..2 {
        let (rk, ck) = kdf_rk(&chained_rk, &[i ^ 0x99; 32]);
        chained.push((hex(&*rk), hex(&*ck)));
        chained_rk.copy_from_slice(&*rk);
    }
    let got = [
        (hex(&*rk1), hex(&*ck1)),
        (hex(&*rk2), hex(&*ck2)),
        chained[0].clone(),
        chained[1].clone(),
    ];
    let want: [(&str, &str); 4] = [
        (
            "ef79e37531e2b0f8045a77989be8d0a5cc2975b1c8faa51f40a2552e69ba691d",
            "fd31b5902a9dec4af7ef83e0b12a0dba7f4aa7d2561198fadb5e87b411ee404e",
        ),
        (
            "01f90b2a16803a903a31c60fe3590537510c7a8efef6cbdf88a7e2eb90424e4a",
            "d251a479cced9ddaad437fa3b7feb3512de588174edbc208f01d8ff52b2aa61b",
        ),
        (
            "80e52bdb2733122369618bd412fc235cf42092112f0e83432011c00064077288",
            "d9fafc1bb169f98236fcc2428a2524244b58a7d7fc89a7a3e562286954e1a020",
        ),
        (
            "4120edf2ae261a155d55f74197a294f30f42d73f51580a57bc37a08ea96be6e4",
            "e058b4a61004d3c7eb180be9413ff01d49125849ded72780ee3228f66b8a8dd5",
        ),
    ];
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!((g.0.as_str(), g.1.as_str()), *w, "kdf_rk case {i}");
    }
}

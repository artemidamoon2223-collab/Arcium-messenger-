//! The resolved dependency graph the H-9 memory hardening relies on.
//!
//! The wiping of `hmac`, `hkdf` and `sha2` internals exists only on the
//! `0.13` / `0.13` / `0.11` lines and only with the upstream `zeroize`
//! features, which Cargo enables through the workspace manifest. A manifest
//! edit that drops a feature, or moves one crate back to an older line, would
//! still compile and still pass every test of the derived bytes, so this reads
//! what Cargo resolved (`cargo tree`, offline: it needs the lockfile and
//! registry cache the build already made) and fails if the expected graph is
//! not there. The type-level pins in `src/hash_contract.rs` cover the same
//! feature from the other side, and they only see the crate this test binary
//! links; this sees the whole workspace.
//!
//! What it does not show: that the libraries wipe everything (they do not),
//! or anything about other versions of these crates that unrelated
//! dependencies (`tor-*`, `ed25519-dalek`, `ssh-key`) bring in.

use std::process::Command;

fn tree(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["tree", "--offline"])
        .args(args)
        .output()
        .expect("run cargo tree");
    assert!(
        out.status.success(),
        "cargo tree {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// `hmac/zeroize` and `sha2/zeroize` are enabled on the audited lines.
#[test]
fn the_zeroize_features_are_enabled_on_the_audited_lines() {
    let hmac = tree(&["-e", "features", "-i", "hmac@0.13"]);
    assert!(hmac.contains("hmac feature \"zeroize\""), "{hmac}");
    let sha2 = tree(&["-e", "features", "-i", "sha2@0.11"]);
    assert!(sha2.contains("sha2 feature \"zeroize\""), "{sha2}");
    // `sha2`'s feature is what makes the hash state wipe; `digest` carries it on.
    let digest = tree(&["-e", "features", "-i", "digest@0.11"]);
    assert!(digest.contains("digest feature \"zeroize\""), "{digest}");
}

/// Every crate that calls `hmac`, `hkdf` or `sha2` is on the audited line, and
/// the `sha2` feature reaches each one that calls `sha2`.
#[test]
fn every_arcium_crate_uses_the_audited_lines() {
    let expect: [(&str, &[&str]); 4] = [
        ("core-crypto", &["hmac v0.13", "hkdf v0.13", "sha2 v0.11"]),
        ("core-storage", &["hkdf v0.13", "sha2 v0.11"]),
        ("core-protocol", &["sha2 v0.11"]),
        ("mobile-ffi", &["sha2 v0.11"]),
    ];
    for (krate, deps) in expect {
        let direct = tree(&["-p", krate, "--depth", "1", "--prefix", "none"]);
        for dep in deps {
            assert!(
                direct.lines().any(|l| l.starts_with(dep)),
                "{krate} does not depend on {dep}:\n{direct}"
            );
        }
        if deps.iter().any(|d| d.starts_with("sha2")) {
            let features = tree(&["-p", krate, "-e", "features", "--depth", "1"]);
            assert!(
                features.contains("sha2 feature \"zeroize\""),
                "{krate} does not enable sha2/zeroize:\n{features}"
            );
        }
    }
}

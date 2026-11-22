//! Where the `fault-injection` feature is enabled.
//!
//! The feature compiles scripted storage failures into `core-storage`
//! (`src/fault.rs`). It is a test aid, and a library built for a device must
//! not contain it. With resolver 2, Cargo counts the features a
//! `[dev-dependencies]` entry asks for only in a build that builds tests, so
//! such an entry is the one place that may enable it; a normal or build
//! dependency that enabled it would put it into every build. This reads what
//! Cargo resolved (`cargo tree`, offline, as `core-crypto`'s
//! `tests/feature_graph.rs` does) and fails if a crate of the workspace
//! enables the feature through a normal or build dependency, for any target.
//!
//! What it does not show: what a build given `--features` or
//! `--all-features` on the command line contains (that includes a feature of
//! another crate that passes this one on, while it is off), or a library
//! built in the same Cargo call as tests (`--all-targets`), where the
//! features of dev-dependencies count too. The `compile_error!` in
//! `src/lib.rs` refuses all of these for Android, and for Android only.

use std::process::Command;

const ENABLED: &str = "core-storage feature \"fault-injection\"";

fn tree(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["tree", "--offline", "--locked"])
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

/// What depends on `core-storage`, and with which of its features, over
/// normal and build dependencies only.
fn dependents(extra: &[&str]) -> String {
    let args = [
        &[
            "--workspace",
            "-e",
            "features,normal,build",
            "-i",
            "core-storage",
        ][..],
        extra,
    ]
    .concat();
    tree(&args)
}

/// The check below is not empty: the feature exists under this name, and
/// `cargo tree` prints the line looked for when something enables it.
#[test]
fn cargo_tree_shows_the_feature_when_it_is_enabled() {
    let on = dependents(&["--features", "core-storage/fault-injection"]);
    assert!(on.contains(ENABLED), "{on}");
}

#[test]
fn no_normal_or_build_dependency_enables_fault_injection() {
    for target in [&[][..], &["--target", "all"][..]] {
        let graph = dependents(target);
        // The graph is the one meant: the crates that use the store are in it.
        for user in ["core-protocol v", "mobile-ffi v"] {
            assert!(graph.contains(user), "{target:?}: no {user}:\n{graph}");
        }
        assert!(
            !graph.contains(ENABLED),
            "{target:?}: a normal or build dependency enables fault-injection:\n{graph}"
        );
    }
}

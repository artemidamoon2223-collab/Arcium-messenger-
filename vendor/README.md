# Vendored crates

## arti-client 0.48.0

Why: when a consensus newer than the software lists as required for clients a
protocol this arti does not implement, upstream `arti-client` 0.48.0 ends the
whole process with `std::process::exit(1)` (`src/client.rs`, the callback
passed to `protostatus::enforce_protocol_recommendations`; upstream TODO
#1932). In an app that would close it, and close it again at every start
until it is updated. The Owner chose a patch instead (decision D-190 in the
`continuity` journal): Tor stops, the app keeps running and says that Tor
needs an app update.

What: `arti-client/` is the published crate, unpacked unchanged from
`arti-client-0.48.0.crate` (sha256
`5bb17a5096e30f2b2bf9f7493ff7577ac66ed7059b8e435658a2884546afe70c`, the
checksum crates.io records, and the one `Cargo.lock` recorded before this
patch), with three changes:

- `src/arcium_patch.rs`, new: a per-process record of the shutdown.
  `on_protocol_shutdown` logs it, sets the record and wakes waiters;
  `protocol_shutdown_happened()` reads it; `protocol_shutdown()` is a future
  that finishes once it is set. Never cleared.
- `src/client.rs`: the callback is `crate::arcium_patch::on_protocol_shutdown`
  instead of the closure that printed to stderr, slept 5 s and called
  `std::process::exit(1)`; the `rtclone` it used and its
  `#[allow(clippy::print_stderr)]` go with it.
- `src/lib.rs`: `pub mod arcium_patch;`.

Nothing else changed: the checks themselves (`src/protostatus.rs`) are
upstream's. The check of the cached consensus at bootstrap never called the
callback: it fails the bootstrap with an error of kind `SoftwareDeprecated`,
as upstream. Stopping Tor is the client's owner's part: `core-transport`'s
`TorConnector` waits for `protocol_shutdown()`, then drops its `TorClient`
(`crates/core-transport/src/connector.rs`); `TransportError::NeedsUpdate` is
the state the app can show. That dropping the client also ends arti's
background tasks is inferred from arti's source, not tested: the background
tasks of `tor-circmgr`, `tor-dirmgr`, `tor-chanmgr` and the onion-service
circuit pool hold weak references to their managers, and the task that holds
strong ones ends when the client's dormant-mode sender is dropped
(`src/client.rs`, field `dormant`). The `core-transport` test checks only
that its own reference to the client is the last one.

Its own test, `arcium_patch::test::a_protocol_shutdown_is_recorded_and_wakes_its_waiters`,
runs the shutdown from the same check a running client uses and needs
the process to survive it. CI does not run this crate's tests (it is not a
workspace member); run them in this directory, with the crate's own
`Cargo.lock` (not committed) and the features `core-transport` uses:

```bash
cargo test --locked --lib --no-default-features \
  --features tokio,rustls,compression,onion-service-client,onion-service-service
```

Result on 2026-11-27: `test result: ok. 48 passed; 0 failed` (upstream's
47 and this one). With `std::process::exit(1)` put back into
`on_protocol_shutdown`, the run fails ("test exited abnormally").

Consequences: as for `tor-dirmgr` below (no checksum in `Cargo.lock`,
`cargo audit` does not see this crate, warnings do not fail `-D warnings`).
An arti upgrade means applying the same patch to the new release, or
dropping it if that release no longer exits.

To verify the copy:

```bash
mkdir /tmp/ac && cd /tmp/ac
curl -sSLo arti-client-0.48.0.crate https://static.crates.io/crates/arti-client/0.48.0/download
echo "5bb17a5096e30f2b2bf9f7493ff7577ac66ed7059b8e435658a2884546afe70c  arti-client-0.48.0.crate" | sha256sum -c -
tar -xzf arti-client-0.48.0.crate
cd - && diff -ru /tmp/ac/arti-client-0.48.0 vendor/arti-client
# prints the src/client.rs and src/lib.rs hunks, "Only in ...: arcium_patch.rs",
# and "Only in ...: Cargo.lock" (not committed)
```

To remove: when an arti release no longer exits on a protocol shutdown
(TODO #1932), upgrade `arti-client` in `crates/core-transport`, replace the
`arcium_patch` calls there with that release's mechanism, delete the
`arti-client` line in `[patch.crates-io]` and its `exclude` entry, delete
`vendor/arti-client`, and regenerate `Cargo.lock` with cargo.

## tor-dirmgr 0.48.0

Why: RUSTSEC-2026-0459. `libsqlite3-sys` before 0.39 bundles an SQLite
(< 3.54.0) that can return uninitialized page-cache memory for a crafted
database and `-wal` pair. The fix is `libsqlite3-sys` 0.39, which comes with
`rusqlite` 0.41. `tor-dirmgr` 0.48 (pulled in by `arti-client` 0.48 through
`core-transport`) requires `rusqlite` `>=0.36.0, <0.41.0`, every version of
which needs a `libsqlite3-sys` before 0.39, and `libsqlite3-sys` declares
`links = "sqlite3"`, so cargo allows only one version in the graph. As of
2026-11-24 no `tor-dirmgr` release accepts `rusqlite` 0.41 (0.48.0 is the
newest), so upgrading arti alone does not help. (Until 2026-11-24 this was
`tor-dirmgr` 0.21.0, with `arti-client` 0.21, patched the same way.)

What: `tor-dirmgr/` is the published crate, unpacked unchanged from
`tor-dirmgr-0.48.0.crate` (sha256
`86f7ac56b491b26a6f2b73f0f16fa7a0c66b507163e0f0ed850334b86169b326`, the
checksum crates.io records), with one line changed in `Cargo.toml`:

```diff
 [dependencies.rusqlite]
-version = ">=0.36.0, <0.41.0"
+version = "0.41.0"
 features = ["time"]
```

No source file changed. Built alone with that line, `tor-dirmgr` resolves
`rusqlite` 0.41.1 and `libsqlite3-sys` 0.39.1, and `cargo test` passes its
own tests (`test result: ok. 45 passed; 0 failed`, default features,
2026-11-24). `Cargo.toml.orig` is the upstream original and still names the
old range; cargo does not read it. The crate's own `Cargo.lock` is not
committed (the root `.gitignore` excludes every `Cargo.lock` but the root
one).

How it is wired: the root `Cargo.toml` has `[patch.crates-io] tor-dirmgr =
{ path = "vendor/tor-dirmgr" }` and excludes this directory from the
workspace.

Consequences:
- `Cargo.lock` records no checksum for a path dependency, and `cargo audit`
  does not check advisories for it. This copy is reviewed by diff only.
- Clippy and rustc warnings in this crate are printed (path crates are not
  capped like registry crates) but do not fail `-D warnings`, which applies to
  workspace members.

To verify the copy:

```bash
# cargo never downloads a crate that [patch] replaces, so fetch it directly
mkdir /tmp/td && cd /tmp/td
curl -sSLo tor-dirmgr-0.48.0.crate https://static.crates.io/crates/tor-dirmgr/0.48.0/download
echo "86f7ac56b491b26a6f2b73f0f16fa7a0c66b507163e0f0ed850334b86169b326  tor-dirmgr-0.48.0.crate" | sha256sum -c -
tar -xzf tor-dirmgr-0.48.0.crate
cd - && diff -ru /tmp/td/tor-dirmgr-0.48.0 vendor/tor-dirmgr
# prints the one line above, and "Only in ...: Cargo.lock" (not committed)
```

To remove: when an arti release accepts `rusqlite` >= 0.41, upgrade
`arti-client`/`tor-rtcompat` in `crates/core-transport`, delete the
`[patch.crates-io]` entry and the `exclude`, delete `vendor/tor-dirmgr`, and
regenerate `Cargo.lock` with cargo. If `vendor/` is then empty, the
`vendor/**` CI path filters and the `vendor/` copy in
`.github/scripts/check_rustsec_2026_0387.py` can go too.

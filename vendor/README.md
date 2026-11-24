# Vendored crates

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

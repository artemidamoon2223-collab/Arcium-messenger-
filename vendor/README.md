# Vendored crates

## tor-dirmgr 0.21.0

Why: RUSTSEC-2026-0459. `libsqlite3-sys` before 0.39 bundles an SQLite
(< 3.54.0) that can return uninitialized page-cache memory for a crafted
database and `-wal` pair. The fix is `libsqlite3-sys` 0.39, which comes with
`rusqlite` 0.41. `tor-dirmgr` 0.21 (pulled in by `arti-client` 0.21 through
`core-transport`) requires `rusqlite` 0.31, and `libsqlite3-sys` declares
`links = "sqlite3"`, so cargo allows only one version in the graph. As of
2026-11-11 no `tor-dirmgr` release accepts `rusqlite` 0.41 (0.47 and 0.48
require `< 0.41`), so upgrading arti alone does not help.

What: `tor-dirmgr/` is the published crate, unpacked unchanged from
`tor-dirmgr-0.21.0.crate` (sha256
`181d24e558f2658edac01d2bff615233c2b1be3e17c43d279cc431c7b0da50db`, the
checksum crates.io and the previous `Cargo.lock` record), with one line
changed in `Cargo.toml`:

```diff
 [dependencies.rusqlite]
-version = "0.31.0"
+version = "0.41.0"
 features = ["time"]
```

No source file changed: `tor-dirmgr` builds and passes its own tests against
`rusqlite` 0.41 as published. `Cargo.toml.orig` is the upstream original and
still names 0.31; cargo does not read it.

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
mkdir /tmp/td && tar -xzf ~/.cargo/registry/cache/*/tor-dirmgr-0.21.0.crate -C /tmp/td
diff -ru /tmp/td/tor-dirmgr-0.21.0 vendor/tor-dirmgr   # the one line above
```

To remove: when an arti release accepts `rusqlite` >= 0.41, upgrade
`arti-client`/`tor-rtcompat` in `crates/core-transport`, delete the
`[patch.crates-io]` entry and the `exclude`, delete `vendor/tor-dirmgr`, and
regenerate `Cargo.lock` with cargo. If `vendor/` is then empty, the
`vendor/**` CI path filters and the `vendor/` copy in
`.github/scripts/check_rustsec_2026_0387.py` can go too.

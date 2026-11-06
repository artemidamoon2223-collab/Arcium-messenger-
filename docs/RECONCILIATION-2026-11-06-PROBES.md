# Reconciliation probes — 2026-11-06 (`main` @ `7455da8`)

This appendix belongs to the section "Reconciliation 2026-11-06" in
[`SECURITY-FINDINGS.md`](./SECURITY-FINDINGS.md). It keeps the exact code,
commands and output of the temporary reproductions behind that section, so
that anyone can re-run them.

**What this file is not.** The probes are not part of the test suite. Nothing
here is compiled or run by `cargo test` or CI. A probe passing here only shows
the behaviour that is current at the commit named. It does not show that the
behaviour is acceptable, and it is not a regression test. A fix PR that needs
one of these as a counterexample must add it as a real test in that PR.

All runs below used a disposable clone of
`7455da8440521a14bbb09baf8d646243a8b5d6c6` on 2026-11-06, with rustc/cargo
1.97.0 on Linux x86_64. Two runs were made. The first was the run the
reconciliation cites. The second was a re-run of the five probes, which gave
the same results; the output below is from the re-run.

## How to re-run

From a clean checkout of the commit above:

```bash
# D-009 probes (core-storage)
cp storage_rollback_probe.rs crates/core-storage/src/zz_rollback_probe.rs
printf '\n#[cfg(test)]\nmod zz_rollback_probe;\n' >> crates/core-storage/src/lib.rs
cargo test --locked -p core-storage zz_rollback_probe -- --nocapture --test-threads=1

# D-007 probes (mobile-ffi): register next to the existing `mod identity;`
cp master_key_probe.rs crates/mobile-ffi/src/tests/zz_master_key_probe.rs
sed -i 's/^    mod identity;$/    mod identity;\n    mod zz_master_key_probe;/' crates/mobile-ffi/src/lib.rs
cargo test --locked -p mobile-ffi zz_master_key_probe -- --nocapture --test-threads=1

# Undo
git checkout -- crates/core-storage/src/lib.rs crates/mobile-ffi/src/lib.rs
rm crates/core-storage/src/zz_rollback_probe.rs crates/mobile-ffi/src/tests/zz_master_key_probe.rs
git status --porcelain   # must print nothing
```

The file contents to copy are the two code blocks below.

## D-009 — storage rollback (`storage_rollback_probe.rs`)

```rust
// Temporary reconciliation probe (D-009). Not part of any PR.
use super::*;
use rusqlite::Connection;

fn raw_rows(path: &std::path::Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let c = Connection::open(path).unwrap();
    let mut s = c.prepare("SELECT k, v FROM kv ORDER BY k").unwrap();
    let rows = s
        .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows
}

#[test]
fn probe_single_record_rollback_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let key = [7u8; 32];
    {
        let s = EncryptedStore::open(&path, key).unwrap();
        s.put("session:bob", b"state-v1").unwrap();
    }
    let old = raw_rows(&path);
    assert_eq!(old.len(), 1);
    {
        let s = EncryptedStore::open(&path, key).unwrap();
        s.put("session:bob", b"state-v2").unwrap();
        assert_eq!(s.get("session:bob").unwrap(), b"state-v2");
    }
    // Attacker with write access puts the old ciphertext back into the same row.
    {
        let c = Connection::open(&path).unwrap();
        let n = c
            .execute("UPDATE kv SET v = ?1 WHERE k = ?2", rusqlite::params![old[0].1, old[0].0])
            .unwrap();
        assert_eq!(n, 1);
    }
    let s = EncryptedStore::open(&path, key).unwrap();
    let got = s.get("session:bob").unwrap();
    println!("PROBE single-record rollback: get -> {:?}", String::from_utf8_lossy(&got));
    assert_eq!(got, b"state-v1", "an older ciphertext of the same record is accepted");
}

#[test]
fn probe_whole_file_rollback_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let snap = dir.path().join("db.snapshot");
    let key = [7u8; 32];
    {
        let s = EncryptedStore::open(&path, key).unwrap();
        s.put("session:bob", b"state-v1").unwrap();
    }
    std::fs::copy(&path, &snap).unwrap();
    {
        let s = EncryptedStore::open(&path, key).unwrap();
        s.put("session:bob", b"state-v2").unwrap();
        s.put("contact:carol", b"new").unwrap();
    }
    std::fs::copy(&snap, &path).unwrap();
    let s = EncryptedStore::open(&path, key).unwrap();
    let got = s.get("session:bob").unwrap();
    let carol = s.get("contact:carol");
    println!(
        "PROBE whole-file rollback: session:bob -> {:?}, contact:carol -> {:?}",
        String::from_utf8_lossy(&got),
        carol.as_ref().map(|_| "present").map_err(|e| format!("{e:?}"))
    );
    assert_eq!(got, b"state-v1");
    assert!(matches!(carol, Err(StorageError::NotFound)));
}

#[test]
fn probe_cross_record_swap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let key = [7u8; 32];
    {
        let s = EncryptedStore::open(&path, key).unwrap();
        s.put("session:bob", b"bob-state").unwrap();
        s.put("session:eve", b"eve-state").unwrap();
    }
    let rows = raw_rows(&path);
    assert_eq!(rows.len(), 2);
    // Move one record's ciphertext into the other record's row.
    {
        let c = Connection::open(&path).unwrap();
        c.execute("UPDATE kv SET v = ?1 WHERE k = ?2", rusqlite::params![rows[0].1, rows[1].0])
            .unwrap();
    }
    let s = EncryptedStore::open(&path, key).unwrap();
    let a = s.get("session:bob");
    let b = s.get("session:eve");
    println!("PROBE cross-record swap: bob -> {:?}, eve -> {:?}", a.as_ref().map(|_| "ok").map_err(|e| format!("{e:?}")), b.as_ref().map(|_| "ok").map_err(|e| format!("{e:?}")));
    assert!(
        matches!(a, Err(StorageError::Decryption)) || matches!(b, Err(StorageError::Decryption)),
        "a ciphertext moved to another record's row must not decrypt"
    );
}
```

Output (exit 0):

```text
test zz_rollback_probe::probe_cross_record_swap_is_refused ... PROBE cross-record swap: bob -> Err("Decryption"), eve -> Ok("ok")
test zz_rollback_probe::probe_single_record_rollback_is_accepted ... PROBE single-record rollback: get -> "state-v1"
test zz_rollback_probe::probe_whole_file_rollback_is_accepted ... PROBE whole-file rollback: session:bob -> "state-v1", contact:carol -> Err("NotFound")
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.03s
exit=0
```

## D-007 — master key replaced on an existing database (`master_key_probe.rs`)

The probe models `MasterKeyProvider`'s missing-blob branch at the Rust level:
an existing database is opened with a different master key. It does not run
the Android code (`MasterKeyProvider`, `ArciumApp`, onboarding). That path is
NOT_VERIFIED.

```rust
// Temporary reconciliation probe (D-007). Not part of any PR.
use crate::*;
use tempfile::tempdir;

fn key32(b: u8) -> Vec<u8> {
    vec![b; 32]
}

/// Models MasterKeyProvider's missing-blob branch: an existing database opened
/// with a freshly generated (different) master key.
#[test]
fn probe_new_master_key_on_existing_db_reads_as_no_identity_and_allows_a_second_identity() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("arcium.db").to_str().unwrap().to_string();

    let original_pk = {
        let core = ArciumCore::new(path.clone(), key32(0xA1)).unwrap();
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        core.save_identity(id).unwrap();
        pk
    };

    // "master_key.blob missing" -> a new random key; the database file is unchanged.
    let core_new = ArciumCore::new(path.clone(), key32(0xB2)).unwrap();
    let loaded = core_new.load_identity().unwrap();
    println!("PROBE new key, load_identity -> {}", if loaded.is_some() { "Some" } else { "None (reads as first run)" });
    assert!(loaded.is_none());

    // Onboarding's createOrLoadExisting would now create; the create-only save succeeds.
    let second = Identity::generate();
    let second_pk = second.public_key_bytes();
    let saved = core_new.save_identity(second);
    println!("PROBE new key, save_identity -> {:?}", saved.as_ref().map(|_| "Ok (new identity created)"));
    assert!(saved.is_ok());
    assert_ne!(second_pk, original_pk);
    drop(core_new);

    // The original identity is orphaned, not destroyed: the old key still reads it.
    let core_old = ArciumCore::new(path, key32(0xA1)).unwrap();
    let back = core_old.load_identity().unwrap().expect("original identity row still on disk");
    println!("PROBE old key, load_identity -> original identity present: {}", back.public_key_bytes() == original_pk);
    assert_eq!(back.public_key_bytes(), original_pk);
}

/// A corrupted identity row under the right key is an error, not "no identity".
#[test]
fn probe_corrupted_identity_row_is_an_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("arcium.db").to_str().unwrap().to_string();
    {
        let core = ArciumCore::new(path.clone(), key32(0xA1)).unwrap();
        core.save_identity(Identity::generate()).unwrap();
    }
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let n = c.execute("UPDATE kv SET v = zeroblob(length(v))", []).unwrap();
        assert!(n >= 1);
    }
    let core = ArciumCore::new(path, key32(0xA1)).unwrap();
    let r = core.load_identity();
    println!("PROBE corrupted row, load_identity -> {:?}", r.as_ref().map(|o| o.is_some()).map_err(|e| format!("{e:?}")));
    assert!(matches!(r, Err(CoreError::IdentityUnreadable { .. })));
}
```

Output (exit 0):

```text
test tests::zz_master_key_probe::probe_corrupted_identity_row_is_an_error ... PROBE corrupted row, load_identity -> Err("IdentityUnreadable { msg: \"the record does not decrypt\" }")
test tests::zz_master_key_probe::probe_new_master_key_on_existing_db_reads_as_no_identity_and_allows_a_second_identity ... PROBE new key, load_identity -> None (reads as first run)
PROBE new key, save_identity -> Ok("Ok (new identity created)")
PROBE old key, load_identity -> original identity present: true
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 150 filtered out; finished in 0.04s
exit=0
```

## D-008 — Tor bootstrap with no timeout

```bash
timeout 120 cargo test --locked -p core-transport new_fails_gracefully_without_tor -- --ignored --nocapture
echo "exit=$?"
```

Output: the build took 21 s, then the test printed the line below and was
killed by `timeout` with `exit=124` (120 s in total, so about 99 s of test
time). It never returned a result.

```text
test tests::new_fails_gracefully_without_tor has been running for over 60 seconds
```

The sandbox restricts outbound connections. That the hang comes from the
missing timeout, and not from this network policy, is INFERRED.

## D-011 — `yes | sdkmanager --licenses` under each shell setting

The fake `sdkmanager` reads 4 bytes from stdin and exits. `ok` exits 0, `fail`
exits 1:

```sh
#!/bin/sh
head -c 4 >/dev/null; exit 0      # fake/ok
```

```sh
#!/bin/sh
head -c 4 >/dev/null; exit 1      # fake/fail
```

Commands, with `F` the directory that holds the two fakes:

```bash
for s in ok fail; do
  bash -e -c "yes | $F/$s";                                   echo "default bash -e, sdkmanager=$s: exit=$?"
  bash -e -c "set -o pipefail; yes | $F/$s";                  echo "pipefail, sdkmanager=$s: exit=$?"
  bash -e -c "yes | $F/$s || true";                           echo "bash -e + || true, sdkmanager=$s: exit=$?"
  bash -e -c "set -o pipefail; yes | $F/$s || true";          echo "pipefail + || true, sdkmanager=$s: exit=$?"
  bash -e -c "set +e; yes | $F/$s; rc=\${PIPESTATUS[1]}; set -e; test \$rc -eq 0"
                                                              echo "baseline PIPESTATUS pattern, sdkmanager=$s: exit=$?"
done
```

Output (GNU bash on Linux):

```text
default bash -e, sdkmanager=ok: exit=0
pipefail, sdkmanager=ok: exit=141
bash -e + || true, sdkmanager=ok: exit=0
pipefail + || true, sdkmanager=ok: exit=0
baseline PIPESTATUS pattern, sdkmanager=ok: exit=0
default bash -e, sdkmanager=fail: exit=1
pipefail, sdkmanager=fail: exit=1
bash -e + || true, sdkmanager=fail: exit=0
pipefail + || true, sdkmanager=fail: exit=0
baseline PIPESTATUS pattern, sdkmanager=fail: exit=1
```

- `android-ci.yml:32` runs in the default `bash -e` shell with `|| true`.
- `android-two-device-e2e.yml:88-90` runs under `pipefail` with `|| true`.
- `native-artifact-baseline.yml:38-42` uses the PIPESTATUS pattern.

This reproduces the shell semantics only, not a GitHub Actions runner.

## D-010 — `hash_contact` input variants

```bash
python3 -I -c '
import hashlib,struct
for p in ["+1234567890"," +1234567890","1234567890","+1 234 567 890","+1-234-567-890","+１２３４５６７８９０"]:
    print(repr(p), struct.unpack("<Q",hashlib.sha256(p.encode()).digest()[:8])[0])'
```

Output:

```text
'+1234567890' 5364562789390625858
' +1234567890' 9875464807152349405
'1234567890' 3523764719467328967
'+1 234 567 890' 6658042672419771929
'+1-234-567-890' 17772907986269828605
'+１２３４５６７８９０' 15031987256122241827
```

The first line equals the canonical vector checked by the Rust test
`contact_hash::tests::matches_canonical_vector`
(`crates/core-crypto/src/contact_hash.rs:62`) and the TS test in
`arcium-psi/tests/src/crypto.test.ts`. The other lines come from this Python
re-computation only; they were not run through the Rust or TS functions.

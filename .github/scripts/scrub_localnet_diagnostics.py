#!/usr/bin/env python3
"""Decide which localnet diagnostics may be published, and check that decision.

Usage:
  scrub_localnet_diagnostics.py publish RAW_DIR DEST_DIR STAGING_ROOT KEY_PATH...
  scrub_localnet_diagnostics.py verify PUBLISH_DIR
  scrub_localnet_diagnostics.py --self-test

The arcium-test job uploads diagnostics as a CI artifact of a public
repository. Raw diagnostics are never uploaded. `publish` is the only writer
of the publication directory:

  - Every KEY_PATH (a file or a glob) is required. It must match at least one
    file, every match must be a readable regular file, and together they must
    yield key material; otherwise nothing is published.
  - Every entry under RAW_DIR must be a readable regular file; a symlink or
    anything else fails the whole set.
  - A file is kept only if it contains none of the keys' secrets in the
    encodings below, and no PEM private-key header. The bytes that were
    checked are the bytes written; names lose characters artifacts reject.
  - The kept files and a MANIFEST.json (SHA-256 of each, the run they belong
    to, the files dropped) are written to a fresh directory under
    STAGING_ROOT, which is renamed to DEST_DIR only when all of that
    succeeded. DEST_DIR must not exist beforehand.

`verify` passes only if PUBLISH_DIR holds at least one such directory and
nothing else: every directory has a manifest for this run (GITHUB_RUN_ID and
GITHUB_RUN_ATTEMPT), every file is listed with its hash, every listed file is
present, and there are no symlinks. The upload step runs only if it passed.

Secrets are recognised only for the keys given and only in these encodings:
the raw text of a key file line or JSON string, hex, base58, base64, and the
JSON byte list (with or without spaces); in a 64-byte Solana keypair, the
secret half on its own as well. In a JSON key file, fields named as public
keys are not secrets. Other keys, other encodings, partial or split copies are
not detected. The keys are throwaway localnet keys.
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MIN_LEN = 32
PEM_PRIVATE = "PRIVATE KEY-----"
MANIFEST = "MANIFEST.json"
BAD_NAME_CHARS = '":<>|*?\r\n'


def b58(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def byte_forms(data):
    forms = {data.hex(), b58(data), base64.b64encode(data).decode()}
    forms.add(",".join(str(b) for b in data))
    forms.add(", ".join(str(b) for b in data))
    return forms


def everything(value):
    if isinstance(value, list) and value and all(isinstance(b, int) and 0 <= b < 256 for b in value):
        data = bytes(value)
        yield from byte_forms(data)
        if len(data) == 64:  # Solana keypair: the first half is the secret.
            yield from byte_forms(data[:32])
    elif isinstance(value, list):
        for v in value:
            yield from everything(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from everything(v)
    elif isinstance(value, str) and len(value) >= MIN_LEN:
        yield value


def json_secrets(value):
    """Secrets in a key file: all of it, except fields named as public."""
    if isinstance(value, dict):
        for key, v in value.items():
            name = key.lower()
            if any(w in name for w in ("secret", "private", "seed", "sk")):
                yield from everything(v)
            elif "pub" not in name:
                yield from json_secrets(v)
    else:
        yield from everything(value)


def secrets_of(raw):
    try:
        text = raw.decode()
    except UnicodeDecodeError:
        return byte_forms(raw) if len(raw) <= 128 else set()
    try:
        return set(json_secrets(json.loads(text)))
    except ValueError:
        pass
    if "PUBLIC KEY-----" in text:
        return set()
    found = set()
    for line in text.splitlines():
        line = line.strip()
        if len(line) >= MIN_LEN and not line.startswith("-----"):
            found.add(line)
    return found


class Refused(Exception):
    """The set cannot be checked, so none of it may be published."""


def read_regular(path):
    if path.is_symlink() or not path.is_file():
        raise Refused(f"not a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as e:
        raise Refused(f"cannot read {path}: {e}") from e


def key_needles(key_args):
    if not key_args:
        raise Refused("no key paths given")
    needles = set()
    for arg in key_args:
        p = Path(arg)
        matches = sorted(Path(p.anchor).glob(str(p.relative_to(p.anchor)))) if p.is_absolute() else sorted(Path().glob(arg))
        if not matches and (p.exists() or p.is_symlink()):
            matches = [p]
        if not matches:
            raise Refused(f"required key path matched nothing: {arg}")
        found = set()
        for path in matches:
            found.update(s for s in secrets_of(read_regular(path)) if len(s) >= MIN_LEN)
        if not found:
            raise Refused(f"no key material read from {arg}")
        needles |= found
    return needles


def run_id():
    return f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.environ.get('GITHUB_RUN_ATTEMPT', '0')}"


def publish_name(rel):
    name = "".join("-" if c in BAD_NAME_CHARS else c for c in rel)
    if name.startswith("/") or ".." in Path(name).parts:
        raise Refused(f"unsafe path: {rel}")
    return name


def publish(raw_dir, dest_dir, staging_root, key_args, write=Path.write_bytes):
    raw_dir, dest_dir, staging_root = Path(raw_dir), Path(dest_dir), Path(staging_root)
    if dest_dir.exists() or dest_dir.is_symlink():
        raise Refused(f"{dest_dir} already exists")
    if raw_dir.is_symlink() or not raw_dir.is_dir():
        raise Refused(f"raw directory missing: {raw_dir}")
    needles = key_needles(key_args)
    needles.add(PEM_PRIVATE)

    entries = []
    for root, dirs, files in os.walk(raw_dir, followlinks=False):
        for d in dirs:
            if (Path(root) / d).is_symlink():
                raise Refused(f"symlink in diagnostics: {Path(root) / d}")
        for f in files:
            path = Path(root) / f
            entries.append((str(path.relative_to(raw_dir)), read_regular(path)))

    kept, dropped, names = {}, [], set()
    for rel, data in sorted(entries):
        text = data.decode(errors="replace")
        if any(n in text for n in needles):
            dropped.append(rel)
            continue
        name = publish_name(rel)
        if name in names or name == MANIFEST:
            raise Refused(f"name collision after sanitising: {rel}")
        names.add(name)
        kept[name] = data

    staging_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=dest_dir.name + ".", dir=staging_root))
    try:
        manifest = {"run": run_id(), "keys_checked": len(needles), "dropped": dropped, "files": {}}
        for name, data in kept.items():
            out = staging / name
            out.parent.mkdir(parents=True, exist_ok=True)
            write(out, data)
            manifest["files"][name] = hashlib.sha256(data).hexdigest()
        (staging / MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True))
        os.rename(staging, dest_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def verify(publish_dir):
    publish_dir = Path(publish_dir)
    if publish_dir.is_symlink() or not publish_dir.is_dir():
        raise Refused(f"nothing to publish: {publish_dir} is missing")
    tops = sorted(publish_dir.iterdir())
    if not tops:
        raise Refused(f"nothing to publish: {publish_dir} is empty")
    checked = []
    for top in tops:
        if top.is_symlink() or not top.is_dir():
            raise Refused(f"not a sanitised directory: {top}")
        manifest = json.loads(read_regular(top / MANIFEST))
        if manifest.get("run") != run_id():
            raise Refused(f"{top}: manifest is for run {manifest.get('run')}, not {run_id()}")
        listed = dict(manifest.get("files", {}))
        present = {}
        for root, dirs, files in os.walk(top, followlinks=False):
            for d in dirs:
                if (Path(root) / d).is_symlink():
                    raise Refused(f"symlink: {Path(root) / d}")
            for f in files:
                path = Path(root) / f
                rel = str(path.relative_to(top))
                if rel != MANIFEST:
                    present[rel] = hashlib.sha256(read_regular(path)).hexdigest()
        if present != listed:
            extra = sorted(set(present) - set(listed))
            missing = sorted(set(listed) - set(present))
            changed = sorted(k for k in set(present) & set(listed) if present[k] != listed[k])
            raise Refused(f"{top}: not the checked set (extra {extra}, missing {missing}, changed {changed})")
        checked.append(f"{top.name} ({len(listed)} files, {len(manifest.get('dropped', []))} dropped)")
    return checked


# ---------------------------------------------------------------- self-test

def self_test():
    failed = []

    def expect(cond, what):
        if not cond:
            failed.append(what)

    def refused(fn, *args, **kw):
        try:
            fn(*args, **kw)
        except Refused:
            return True
        return False

    os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"] = "424242", "1"
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        cwd = os.getcwd()
        os.chdir(t)
        try:
            keys = t / "artifacts/localnet"
            keys.mkdir(parents=True)
            kp = list(os.urandom(64))
            (keys / "node_0.json").write_text(json.dumps(kp))
            sec, pub = os.urandom(32), os.urandom(32)
            (keys / "node_bls_0.json").write_text(json.dumps({"secret_key": list(sec), "public_key": list(pub)}))
            pem_body = base64.b64encode(os.urandom(48)).decode()
            (keys / "identity_0.pem").write_text(f"-----BEGIN PRIVATE KEY-----\n{pem_body}\n-----END PRIVATE KEY-----\n")
            wallet = t / "home/id.json"
            wallet.parent.mkdir()
            wallet_kp = list(os.urandom(64))
            wallet.write_text(json.dumps(wallet_kp))
            key_args = ["artifacts/localnet/*", str(wallet)]

            def raw(name, files):
                d = t / "raw" / name
                for rel, content in files.items():
                    (d / rel).parent.mkdir(parents=True, exist_ok=True)
                    (d / rel).write_text(content)
                return d

            benign = {
                "arcium-test.log": "  6 passing (19s)\n",
                "artifacts/arx_node_logs/arx_log_05:10:2026_1.log": f"node pubkey {pub.hex()} {b58(bytes(kp[32:]))}\n",
                "computation-1.json": '{"outcome": "finalized"}\n',
            }
            leaks = {
                "leak_b58.log": "k=" + b58(bytes(kp[:32])),
                "leak_hex.log": "k=" + sec.hex(),
                "leak_b64.log": "k=" + base64.b64encode(sec).decode(),
                "leak_json.log": json.dumps(kp),
                "leak_json_spaced.log": ", ".join(str(b) for b in kp[:32]),
                "leak_pem_body.log": pem_body,
                "leak_pem_header.log": "-----BEGIN PRIVATE KEY-----",
                "leak_wallet.log": b58(bytes(wallet_kp[:32])),
            }
            pub_dir = t / "publish"
            pub_dir.mkdir()
            staging = t / "staging"

            # T1/T7: benign files survive under artifact-safe names; every
            # supported encoding of a synthetic secret is dropped.
            m = publish(raw("matches", {**benign, **leaks}), pub_dir / "matches", staging, key_args)
            got = set(m["files"])
            expect(got == {"arcium-test.log", "artifacts/arx_node_logs/arx_log_05-10-2026_1.log", "computation-1.json"},
                   f"T7 kept set: {got}")
            expect(sorted(m["dropped"]) == sorted(leaks), f"T7 dropped set: {m['dropped']}")
            expect(verify(pub_dir) == ["matches (3 files, 8 dropped)"], "T1 verify")

            # T2: failure diagnostics are published like any other once checked.
            publish(raw("zero-hash", {"arcium-test.log": "  5 passing\n  1 failing\n"}), pub_dir / "zero-hash", staging, key_args)
            expect(len(verify(pub_dir)) == 2, "T2 failure diagnostics publishable")

            # T3: a required key path that matches nothing, a key that cannot
            # be read, or keys without material refuse the set; nothing appears.
            r = raw("t3", benign)
            expect(refused(publish, r, pub_dir / "t3", staging, ["artifacts/none/*", str(wallet)]), "T3 empty glob")
            (keys / "broken.json").symlink_to(t / "missing")
            expect(refused(publish, r, pub_dir / "t3", staging, key_args), "T3 unreadable key")
            (keys / "broken.json").unlink()
            (t / "pubonly").mkdir()
            (t / "pubonly/k.json").write_text(json.dumps({"public_key": list(pub)}))
            expect(refused(publish, r, pub_dir / "t3", staging, ["pubonly/*"]), "T3 no key material")
            expect(refused(publish, r, pub_dir / "t3", staging, []), "T3 no key paths")
            expect(not (pub_dir / "t3").exists(), "T3 left a directory")

            # T4: an entry that cannot be scanned refuses the whole set.
            r4 = raw("t4", benign)
            (r4 / "dangling.log").symlink_to(t / "missing")
            expect(refused(publish, r4, pub_dir / "t4", staging, key_args), "T4 unreadable diagnostics file")
            (r4 / "dangling.log").unlink()
            (r4 / "linked").symlink_to(t / "home", target_is_directory=True)
            expect(refused(publish, r4, pub_dir / "t4", staging, key_args), "T4 symlinked directory")
            expect(not (pub_dir / "t4").exists(), "T4 left a directory")

            # T5: interrupted while writing: no directory is published and the
            # partial staging copy is removed; a set never sanitised is absent.
            calls = []

            def flaky(path, data):
                calls.append(path)
                if len(calls) > 1:
                    raise KeyboardInterrupt
                path.write_bytes(data)

            try:
                publish(raw("t5", benign), pub_dir / "t5", staging, key_args, write=flaky)
                failed.append("T5 interrupted publish returned")
            except KeyboardInterrupt:
                pass
            expect(not (pub_dir / "t5").exists(), "T5 interrupted publish left a directory")
            expect(not any(staging.iterdir()), "T5 staging not cleaned")

            # Killed outright (no cleanup runs): still nothing is published,
            # and the gate refuses what is there.
            def killed(path, data):
                path.write_bytes(data)
                os._exit(9)

            child = os.fork()
            if child == 0:
                try:
                    publish(raw("t5k", benign), pub_dir / "t5k", staging, key_args, write=killed)
                finally:
                    os._exit(0)
            _, status = os.waitpid(child, 0)
            expect(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 9, "T5 kill injection did not run")
            expect(not (pub_dir / "t5k").exists(), "T5 killed publish left a published directory")
            killed_set = t / "killed-publish"
            killed_set.mkdir()
            for leftover in staging.iterdir():
                shutil.move(str(leftover), killed_set / leftover.name)
            expect(refused(verify, killed_set), "T5 gate accepted a partial set")
            expect(refused(verify, t / "never-ran"), "T5 verify of a missing directory")
            (t / "empty").mkdir()
            expect(refused(verify, t / "empty"), "T5 verify of an empty directory")

            # T6: success for one directory authorises nothing else.
            expect(refused(publish, raw("again", benign), pub_dir / "matches", staging, key_args), "T6 overwrite of a published set")
            shutil.copytree(t / "raw/t3", pub_dir / "unchecked")
            expect(refused(verify, pub_dir), "T6 unchecked directory")
            shutil.rmtree(pub_dir / "unchecked")
            (pub_dir / "stray.log").write_text("x")
            expect(refused(verify, pub_dir), "T6 stray top-level file")
            (pub_dir / "stray.log").unlink()
            (pub_dir / "matches/late.log").write_text("added after the check")
            expect(refused(verify, pub_dir), "T6 file added after the check")
            (pub_dir / "matches/late.log").unlink()
            log = pub_dir / "matches/arcium-test.log"
            original = log.read_bytes()
            log.write_text(b58(bytes(kp[:32])))
            expect(refused(verify, pub_dir), "T6 file changed after the check")
            log.write_bytes(original)
            (pub_dir / "matches/computation-1.json").unlink()
            expect(refused(verify, pub_dir), "T6 listed file missing")
            (pub_dir / "matches/computation-1.json").write_text('{"outcome": "finalized"}\n')
            (pub_dir / "matches/link.log").symlink_to(t / "home/id.json")
            expect(refused(verify, pub_dir), "T6 symlink in a published set")
            (pub_dir / "matches/link.log").unlink()
            expect(len(verify(pub_dir)) == 2, "T6 restored set verifies")
            os.environ["GITHUB_RUN_ATTEMPT"] = "2"
            expect(refused(verify, pub_dir), "T6 manifest from another run")
            os.environ["GITHUB_RUN_ATTEMPT"] = "1"
        finally:
            os.chdir(cwd)

    for f in failed:
        print(f"SELF-TEST FAIL: {f}")
    print(f"self-test: T1-T7, {len(failed)} failed")
    return 1 if failed else 0


def main(argv):
    try:
        if argv[1:] == ["--self-test"]:
            return self_test()
        if len(argv) >= 6 and argv[1] == "publish":
            m = publish(argv[2], argv[3], argv[4], argv[5:])
            print(f"published {argv[3]}: {len(m['files'])} files, {len(m['dropped'])} dropped "
                  f"{m['dropped']}, {m['keys_checked']} key encodings checked")
            return 0
        if len(argv) == 3 and argv[1] == "verify":
            for line in verify(argv[2]):
                print(f"verified {line}")
            return 0
    except Refused as e:
        print(f"::error::diagnostics not publishable: {e}")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

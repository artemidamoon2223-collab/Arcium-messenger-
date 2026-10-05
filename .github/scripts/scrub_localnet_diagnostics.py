#!/usr/bin/env python3
"""Drop any localnet diagnostics file that contains key material.

Usage: scrub_localnet_diagnostics.py DIAG_DIR KEY_PATH...

The arcium-test job uploads container, validator and test logs from DIAG_DIR
as a CI artifact. The repository is public, so before the upload this reads
every key file given (the localnet keypairs `arcium test` generates and the
test wallet) and deletes each diagnostics file that contains any of their
secrets in a common encoding: the raw text, hex, base58, base64, or the JSON
byte list. In a JSON key file, fields named as public keys are not secrets.
A file holding a PEM private-key header is deleted as well.
Deleted files are listed by name (never by content) in DIAG_DIR/SCRUBBED.txt.

The keys are throwaway localnet keys; this keeps them out of the artifact
anyway. It cannot recognise encodings it does not know.
"""

import base64
import json
import sys
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MIN_LEN = 32


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


def secrets_of(path):
    raw = path.read_bytes()
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


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    diag = Path(argv[1])
    needles = set()
    for arg in argv[2:]:
        for path in Path().glob(arg) if not Path(arg).is_absolute() else [Path(arg)]:
            if path.is_file():
                needles.update(s for s in secrets_of(path) if len(s) >= MIN_LEN)
    needles.add("PRIVATE KEY-----")
    dropped = []
    for path in sorted(p for p in diag.rglob("*") if p.is_file() and p.name != "SCRUBBED.txt"):
        text = path.read_bytes().decode(errors="replace")
        if any(n in text for n in needles):
            path.unlink()
            dropped.append(str(path.relative_to(diag)))
    (diag / "SCRUBBED.txt").write_text("".join(f"{d}\n" for d in dropped))
    print(f"{len(needles)} key encodings checked; {len(dropped)} diagnostics file(s) dropped: {dropped}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

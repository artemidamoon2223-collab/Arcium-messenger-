#!/usr/bin/env python3
"""Fail-closed check of the UniFFI-generated Kotlin for message plaintext.

A Kotlin `data class` prints every constructor property in `toString`, a
`ByteArray` as its decimal bytes. So a generated record that holds message
plaintext as `kotlin.String` or `kotlin.ByteArray` prints it whenever it is
formatted. The plaintext fields use the custom types `PlaintextBytes` and
`PlaintextText` instead (crates/mobile-ffi/uniffi.toml), Kotlin value classes
whose `toString` is "<redacted>".

This reads every constructor property of every generated class and requires
that each one whose type mentions `kotlin.String`, `kotlin.ByteArray`,
`PlaintextBytes` or `PlaintextText` is listed, with exactly that type, in the
inventory file. A new such field, a changed type (for instance a plaintext
field back to `kotlin.ByteArray`), a listed field that no longer exists, an
unparseable file, or the custom types rendered as a typealias to the builtin
all exit non-zero. Every inventory line records why the field is not message
plaintext, or that it is and uses a redacting type.

Usage: check_generated_plaintext.py <arcium_core.kt> <inventory>
       check_generated_plaintext.py --self-test <arcium_core.kt> <inventory>
"""

import re
import sys

WATCHED = ("kotlin.String", "kotlin.ByteArray", "PlaintextBytes", "PlaintextText")
REDACTING = ("PlaintextBytes", "PlaintextText")
CLASSES = {"A", "C", "D", "F"}

CLASS_RE = re.compile(r"^(\s*)(?:data )?class (\w+)\s*\($")
SEALED_RE = re.compile(r"^sealed class (\w+)")
TOP_RE = re.compile(r"^\S")
# A property; the last one of a sealed variant ends with ") : Parent() {".
PARAM_RE = re.compile(r"^\s*(?:val|var) `(\w+)`: ([^,)]+?)\s*(,\s*|\).*)?$")
END_RE = re.compile(r"^\s*\)")


def fields(source):
    """{"Owner.field": type} for every constructor property of every class."""
    out = {}
    sealed = None
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = SEALED_RE.match(line)
        if m:
            sealed = m.group(1)
        elif TOP_RE.match(line) and not CLASS_RE.match(line):
            sealed = None
        m = CLASS_RE.match(line)
        if m:
            indent, name = m.groups()
            owner = f"{sealed}.{name}" if indent and sealed else name
            i += 1
            while i < len(lines) and not END_RE.match(lines[i]):
                p = PARAM_RE.match(lines[i])
                if p:
                    out[f"{owner}.{p.group(1)}"] = p.group(2).strip()
                    if (p.group(3) or "").startswith(")"):
                        break
                i += 1
        i += 1
    return out


def inventory(text):
    """{"Owner.field": (type, class)} from the inventory file."""
    out = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 3 or parts[2] not in CLASSES:
            raise SystemExit(f"inventory line {n}: expected 'Owner.field<TAB>type<TAB>A|C|D|F': {raw!r}")
        key, typ, cls = parts
        if key in out:
            raise SystemExit(f"inventory line {n}: {key} listed twice")
        if (cls == "A") != any(t in typ for t in REDACTING):
            raise SystemExit(f"inventory line {n}: {key}: class A exactly when the type is a Plaintext* type")
        out[key] = (typ, cls)
    return out


def problems(source, listed):
    found = fields(source)
    errs = []
    declared = len(re.findall(r"^\s*(?:val|var) `\w+`:", source, re.M))
    if not found or len(found) != declared:
        errs.append(f"parsed {len(found)} of {declared} generated properties: the generated Kotlin changed shape")
    for name in REDACTING:
        if f"import com.arcium.messenger.ffi.{name}" not in source:
            errs.append(f"{name} is not imported from com.arcium.messenger.ffi: uniffi.toml was not applied")
        if re.search(rf"^\s*(public )?typealias {name}\b", source, re.M):
            errs.append(f"{name} is a typealias: its toString would not be redacted")
    watched = {k: t for k, t in found.items() if any(w in t for w in WATCHED)}
    for key, typ in sorted(watched.items()):
        if key not in listed:
            errs.append(f"{key}: {typ} is not in the inventory; classify it (message plaintext needs PlaintextBytes/PlaintextText)")
        elif listed[key][0] != typ:
            errs.append(f"{key}: generated type {typ}, inventory says {listed[key][0]}")
    for key in sorted(set(listed) - set(watched)):
        errs.append(f"{key}: in the inventory but not generated (or no longer a watched type)")
    return errs, watched


def self_test(source, listed):
    """The check must reject each of these changes to the real generated file."""
    mutations = {
        "ChatEntry.text back to kotlin.String":
            lambda s: s.replace("var `text`: PlaintextText", "var `text`: kotlin.String", 1),
        "ReceivedText.text back to kotlin.ByteArray":
            lambda s: re.sub(r"(data class ReceivedText \(\n(?:.*\n)*?\s*var `text`: )PlaintextBytes",
                             r"\1kotlin.ByteArray", s, count=1),
        "custom types rendered as typealiases":
            lambda s: s.replace("import com.arcium.messenger.ffi.PlaintextBytes",
                                "public typealias PlaintextBytes = kotlin.ByteArray"),
        "a new record with a String field":
            lambda s: s + "\ndata class Draft (\n    var `body`: kotlin.String\n) {\n}\n",
        "generator stops emitting `data class X (` headers":
            lambda s: re.sub(r"^((?:data )?class \w+)\s*\($", r"\1 constructor(", s, flags=re.M),
    }
    failed = []
    for label, mutate in mutations.items():
        mutated = mutate(source)
        if mutated == source:
            failed.append(f"{label}: mutation did not apply (fixture drifted)")
        elif not problems(mutated, listed)[0]:
            failed.append(f"{label}: NOT rejected")
        else:
            print(f"SELF_TEST rejected: {label}")
    return failed


def main(argv):
    test = argv[:1] == ["--self-test"]
    args = argv[1:] if test else argv
    if len(args) != 2:
        raise SystemExit(__doc__)
    with open(args[0], encoding="utf-8") as f:
        source = f.read()
    with open(args[1], encoding="utf-8") as f:
        listed = inventory(f.read())
    errs, watched = problems(source, listed)
    for e in errs:
        print(f"GENERATED_PLAINTEXT_CHECK: {e}", file=sys.stderr)
    if errs:
        return 1
    plaintext = sorted(k for k, (_, c) in listed.items() if c == "A")
    print(f"GENERATED_PLAINTEXT_CHECK=PASS watched={len(watched)} plaintext={','.join(plaintext)}")
    if test:
        failed = self_test(source, listed)
        for e in failed:
            print(f"SELF_TEST: {e}", file=sys.stderr)
        if failed:
            return 1
        print("GENERATED_PLAINTEXT_SELF_TEST=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

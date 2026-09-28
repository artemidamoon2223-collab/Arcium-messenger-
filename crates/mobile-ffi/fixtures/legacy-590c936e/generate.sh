#!/usr/bin/env bash
# Regenerates the databases in this directory with the build of commit
# 590c936e (before ARCIUM-SESSION-CONFIRMATION-001), using its own code.
# Usage: crates/mobile-ffi/fixtures/legacy-590c936e/generate.sh
set -euo pipefail
BASE=590c936e4db6e1ac07b3c104708fd42c518e0f5e
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'git -C "$repo" worktree remove --force "$work/base" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

git -C "$repo" worktree add --detach "$work/base" "$BASE" >/dev/null
test "$(git -C "$work/base" rev-parse HEAD)" = "$BASE"
cp "$here/generator.rs" "$work/base/crates/mobile-ffi/src/tests/legacy_fixture_gen.rs"
# Register the generator next to the old build's own test modules.
sed -i 's/^    mod net_peer;$/    mod net_peer;\n    mod legacy_fixture_gen;/' "$work/base/crates/mobile-ffi/src/lib.rs"
grep -q 'mod legacy_fixture_gen;' "$work/base/crates/mobile-ffi/src/lib.rs"

mkdir -p "$work/out"
(cd "$work/base" && ARCIUM_LEGACY_FIXTURE_OUT="$work/out" \
    cargo test -p mobile-ffi --lib legacy_fixture_gen -- --ignored --test-threads=1)
cp "$work/out"/* "$here/"
(cd "$here" && sha256sum t1-alice.db t1-bob.db t1-alice-handshake.bin t2-alice.db t2-bob.db > SHA256SUMS)
echo "fixtures written to $here"

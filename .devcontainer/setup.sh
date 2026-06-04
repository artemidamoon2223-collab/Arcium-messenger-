#!/usr/bin/env bash
# Devcontainer setup — installs Solana CLI, Anchor CLI, arcium CLI, TS deps.
# Idempotent: each block checks if the tool/version is already present.
set -euo pipefail

SOLANA_VERSION="3.1.10"
ANCHOR_VERSION="1.0.2"
ARCIUM_VERSION="0.10.4"
ARCUP_VERSION="0.8.5"

# Rust feature installs cargo system-wide; also cover user-local path
export PATH="/usr/local/cargo/bin:$HOME/.cargo/bin:$PATH"

# ── 1. Solana CLI (agave / Anza) ─────────────────────────────────────────────
if solana --version 2>/dev/null | grep -qF "$SOLANA_VERSION"; then
    echo "==> Solana CLI ${SOLANA_VERSION} already installed"
else
    echo "==> Installing Solana CLI v${SOLANA_VERSION} (agave/Anza)..."
    sh -c "$(curl -sSfL "https://release.anza.xyz/v${SOLANA_VERSION}/install")"
fi
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# ── 2. Anchor CLI via AVM ────────────────────────────────────────────────────
if anchor --version 2>/dev/null | grep -qF "$ANCHOR_VERSION"; then
    echo "==> Anchor CLI ${ANCHOR_VERSION} already installed"
else
    echo "==> Installing AVM and Anchor CLI v${ANCHOR_VERSION}..."
    # avm is published on crates.io by coral-xyz
    cargo install avm --locked 2>/dev/null || cargo install avm
    avm install "$ANCHOR_VERSION"
    avm use "$ANCHOR_VERSION"
fi
export PATH="$HOME/.avm/bin:$PATH"

# ── 3. arcium CLI via arcup ──────────────────────────────────────────────────
if arcium --version 2>/dev/null | grep -qF "$ARCIUM_VERSION"; then
    echo "==> arcium CLI ${ARCIUM_VERSION} already installed"
else
    echo "==> Installing arcup v${ARCUP_VERSION} and arcium CLI v${ARCIUM_VERSION}..."
    curl -sSfL \
        "https://bin.arcium.com/download/arcup_x86_64_linux_${ARCUP_VERSION}" \
        -o "$HOME/.cargo/bin/arcup"
    chmod +x "$HOME/.cargo/bin/arcup"
    arcup install "arcium@${ARCIUM_VERSION}" || arcup install arcium
    arcup use "arcium@${ARCIUM_VERSION}"   || arcup use arcium
fi

# ── 4. TypeScript test dependencies ──────────────────────────────────────────
echo "==> Installing TS test deps (arcium-psi/tests)..."
npm install --prefix arcium-psi/tests

# ── 5. Rust dep prefetch (warms Cargo cache) ─────────────────────────────────
echo "==> Prefetching Rust dependencies..."
cargo fetch 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Arcium Messenger devcontainer ready ==="
printf "  Rust stable : %s\n" "$(rustc --version 2>/dev/null)"
printf "  Node.js     : %s\n" "$(node --version 2>/dev/null)"
printf "  Solana CLI  : %s\n" "$(solana --version 2>/dev/null || echo 'restart terminal to pick up PATH')"
printf "  Anchor CLI  : %s\n" "$(anchor --version 2>/dev/null || echo 'restart terminal to pick up PATH')"
printf "  arcium CLI  : %s\n" "$(arcium --version 2>/dev/null || echo 'restart terminal to pick up PATH')"
echo ""
echo "Quick-start commands:"
echo "  cargo test --workspace          # core Rust unit tests"
echo "  cd arcium-psi/tests && npm test # TS crypto tests"
echo "  cd arcium-psi && arcium build   # Arcium circuit build"

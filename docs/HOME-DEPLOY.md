# Home Deploy Checklist — Arcium PSI

Steps that require Anchor CLI + Solana CLI + open network. Cannot be done in the CI sandbox.

## Prerequisites

```bash
# Verify toolchain
solana --version        # expects agave/Anza 3.1.10
anchor --version        # expects 1.0.2
arcium --version        # expects 0.10.4
node --version          # expects 20.x
```

## Step 1 — Build the Arcis circuit

```bash
cd arcium-psi/encrypted-ixs
arcis build
# Output: build/psi_intersect.arcis.ir
```

Compute and record the circuit hash:

```bash
sha256sum build/psi_intersect.arcis.ir
# Update CIRCUIT_HASH in arcium-psi/tests/src/scenarios.test.ts
# Update CIRCUIT_HASH in arcium-psi/tests/.env
```

> **Note:** `CIRCUIT_HASH ≠ git commit SHA`. It is the SHA-256 of the built `.arcis.ir` file.
> The on-chain program stores only this 32-byte hash, not the full circuit binary.

## Step 2 — Fund deployer wallet

```bash
solana airdrop 4 --url devnet
solana balance --url devnet
# Need at least 3 SOL for program + MXE account rent
```

## Step 3 — Deploy the Anchor program

```bash
cd arcium-psi
anchor build
anchor deploy --provider.cluster devnet
# Record the deployed Program ID — update PROGRAM_ID in tests/.env
```

## Step 4 — Register the PSI circuit on-chain

```bash
cd arcium-psi/tests
cp .env.example .env
# Edit .env: fill PROGRAM_ID, CIRCUIT_HASH from Step 1, RPC_URL
npx ts-node src/deploy.ts init-psi-comp-def
```

## Step 5 — Initialize MXE and get lutOffset

```bash
npx ts-node src/deploy.ts init-mxe
# Record lutOffsetSlot from the on-chain MXE account
# Update lutOffset in arcium-psi/tests/src/program.ts line ~172
```

> Current placeholder: `const lutOffset = new BN(0);`
> Replace with: `const lutOffset = mxeAccount.lutOffsetSlot;`

## Step 6 — Run full test suite

```bash
cd arcium-psi/tests
npx mocha --require ts-node/register 'src/**/*.test.ts'
# All ONLINE tests should pass; OFFLINE tests already pass in sandbox
```

## Step 7 — Wire FFI to Kotlin (Android)

```bash
# Build .so for Android
cargo ndk -t arm64-v8a build -p mobile-ffi --release
# Output: target/aarch64-linux-android/release/libarcium_core.so
# (the crate-type/[lib] name in crates/mobile-ffi/Cargo.toml is "arcium_core",
#  not the package name "mobile-ffi" — System.loadLibrary("arcium_core") expects this)
# Copy to android/app/src/main/jniLibs/arm64-v8a/
```

> **Current native binding status:** this step is not yet wired up.
> `crates/mobile-ffi/build.rs` only declares a `cargo:rerun-if-changed` hook — it does not
> invoke `uniffi-bindgen` to generate Kotlin bindings. The Kotlin-generated file
> `uniffi/arcium_core/arcium_core.kt` does not exist yet; `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt`
> is a hand-written stub that mocks the future generated API and never calls
> `System.loadLibrary`. Until `uniffi-bindgen generate` is added to the build and the
> generated bindings replace the stub, `cargo ndk ... && cp libarcium_core.so jniLibs/`
> alone will not make the FFI callable from Kotlin.

## Post-deploy verification

- [ ] `cargo test --workspace` → 54/54 (0 failed)
- [ ] `cd arcium-psi/tests && npx tsc --noEmit` → 0 errors
- [ ] All ONLINE mocha tests pass
- [ ] CIRCUIT_HASH in `.env` matches `sha256sum build/psi_intersect.arcis.ir`
- [ ] `lutOffset` in `program.ts` updated from on-chain MXE account
- [ ] `PROGRAM_ID` in `.env` matches deployed program address

## Manual cleanup (GitHub)

After gdrive-sync workflow was removed (PR #14), delete orphaned secrets:
- Go to: Settings → Secrets and variables → Actions
- Delete: `GDRIVE_CLIENT_ID`, `GDRIVE_CLIENT_SECRET`, `GDRIVE_TOKEN`

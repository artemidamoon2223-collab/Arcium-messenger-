# Home Deploy Checklist — Arcium PSI

Not yet performed; steps below are unverified until the first deploy.

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
cd arcium-psi
arcium build
# Output: build/psi_intersect.arcis.ir (as in .github/workflows/arcium-ci.yml, job arcium-build)
```

Compute and record the circuit hash:

```bash
sha256sum build/psi_intersect.arcis.ir
# Compare with CIRCUIT_HASH in arcium-psi/tests/src/scenarios.test.ts, currently
# dd3bda7c6101e45f765165bfb01327313300758f0e3ae59ad79beace94b7b919
# The arcium-build CI job fails if they differ, so update it there if the build changed.
# Put the same value in CIRCUIT_HASH in arcium-psi/tests/.env
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

> Nothing in the repository reads `tests/.env` yet. The program ID is also a placeholder
> in `programs/arcium-psi/src/lib.rs` (`declare_id!`), `Anchor.toml` (`[programs.devnet]`)
> and `tests/src/program.ts` (`PROGRAM_ID`); a devnet deploy needs a real, retained
> program keypair (finding F-14).

## Step 4 — Register the PSI circuit on-chain

```bash
cd arcium-psi/tests
cp .env.example .env
# Edit .env: fill PROGRAM_ID, CIRCUIT_HASH from Step 1, RPC_URL
```

> No deploy script exists in the repository yet (there is no `src/deploy.ts`); it must be
> written before a deploy, for this step and Step 5. The nearest existing code is the
> localnet test `tests/src/localnet/psi.localnet.ts`, which registers the computation
> definition against a local validator under `arcium test`.

## Step 5 — Initialize MXE and get lutOffset

```bash
# No script yet (see Step 4)
# Record lutOffsetSlot from the on-chain MXE account
# Update lutOffset in arcium-psi/tests/src/program.ts line 171
```

> Current placeholder: `const lutOffset = new BN(0);`
> Replace with: `const lutOffset = mxeAccount.lutOffsetSlot;`

## Step 6 — Run full test suite

```bash
cd arcium-psi/tests
npx mocha --require ts-node/register 'src/**/*.test.ts'
# The ONLINE tests in src/scenarios.test.ts are placeholders that always skip;
# they must be written before they can pass. CI runs only src/crypto.test.ts of these.
```

## Step 7 — Android native library: not part of the deploy

The Android app does not call the PSI program. Its native library (`libarcium_core.so`)
and UniFFI Kotlin bindings are already built by the composite action
`.github/actions/uniffi-android-bridge` in the Android workflows; see `android/README.md`.

## Post-deploy verification

- [ ] `cargo test --workspace --locked` → 0 failed
- [ ] `cd arcium-psi/tests && npx tsc --noEmit` → 0 errors
- [ ] All ONLINE mocha tests pass
- [ ] CIRCUIT_HASH in `.env` matches `sha256sum build/psi_intersect.arcis.ir`
- [ ] `lutOffset` in `program.ts` updated from on-chain MXE account
- [ ] `PROGRAM_ID` in `.env` matches deployed program address

## Manual cleanup (GitHub)

After gdrive-sync workflow was removed (PR #14), delete orphaned secrets:
- Go to: Settings → Secrets and variables → Actions
- Delete: `GDRIVE_CLIENT_ID`, `GDRIVE_CLIENT_SECRET`, `GDRIVE_TOKEN`

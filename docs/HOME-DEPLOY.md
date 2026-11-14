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
env -u ARCIUM_PSI_LOCALNET_CIRCUIT arcium build
# Output: build/psi_intersect.arcis.ir, build/psi_intersect.arcis and
# build/psi_intersect.hash (as in .github/workflows/arcium-ci.yml, job arcium-build)
```

`ARCIUM_PSI_LOCALNET_CIRCUIT` must not be set for a deploy build: with it, the program
registers the localnet circuit URL (`programs/arcium-psi/src/lib.rs`), which only
`arcium test` serves.

Two different hashes come out of this build:

```bash
sha256sum build/psi_intersect.arcis.ir
# CIRCUIT_HASH in arcium-psi/tests/src/scenarios.test.ts, currently
# dd3bda7c6101e45f765165bfb01327313300758f0e3ae59ad79beace94b7b919
# The arcium-build CI job fails if they differ, so update it there if the build changed.
# Put the same value in CIRCUIT_HASH in arcium-psi/tests/.env

sha256sum build/psi_intersect.arcis
# PSI_INTERSECT_CIRCUIT_HASH in programs/arcium-psi/src/lib.rs, currently
# 24e7f6133043d3035622d7447ea050f0429f717d3b7f6a3bb8da3a21114316ef
# The same value, as a JSON byte array, is in build/psi_intersect.hash.
# The arcium-build CI job fails if the constant, this file and the URL below disagree.
```

> **Note:** neither is a git commit SHA. The hash the program registers on chain is the
> second one: the SHA-256 of the compiled circuit `build/psi_intersect.arcis`, the file
> the Arx nodes download and check (arcis-compiler 0.10.4 `compile_and_write` writes it to
> `build/psi_intersect.hash`; the `circuit_hash!` macro of arcium-macros 0.10.4 reads it
> from there). The on-chain computation definition stores this 32-byte hash and the
> circuit URL, not the circuit.

## Step 1b — Publish the circuit (needs the Owner's approval)

The program registers an off-chain circuit source with a fixed URL,
`PSI_INTERSECT_CIRCUIT_URL` in `programs/arcium-psi/src/lib.rs`:

```
https://github.com/artemidamoon2223-collab/Arcium-messenger-/releases/download/psi-intersect-<first 16 hex digits of the hash>/psi_intersect.arcis
```

Before Step 4 the file `build/psi_intersect.arcis` from Step 1 must be downloadable at that
URL without authentication, as a release asset named `psi_intersect.arcis` under the tag
`psi-intersect-<first 16 hex digits>` (currently `psi-intersect-24e7f6133043d303`):

```bash
gh release create psi-intersect-24e7f6133043d303 build/psi_intersect.arcis \
  --title "psi_intersect circuit 24e7f6133043d303" --notes "sha256 24e7f6133043d3035622d7447ea050f0429f717d3b7f6a3bb8da3a21114316ef"
curl -sSfL "<PSI_INTERSECT_CIRCUIT_URL>" | sha256sum
# must print PSI_INTERSECT_CIRCUIT_HASH
```

> Publishing is a release of this repository: it needs the Owner's approval. Registration
> (Step 4) binds the computation definition to this URL, and the Arcium 0.10.4 program has
> no instruction that changes the source of a registered definition (only deactivate and,
> after a wait, close). A GitHub release download URL answers with a redirect (302 to
> `release-assets.githubusercontent.com`); the localnet test serves its circuit through a
> redirect too, but whether the devnet Arx nodes follow one to that host is not verified.
> If the URL must change, change the constant and rebuild; the arcium-build CI job checks
> the URL against the hash.

## Step 2 — Fund deployer wallet

```bash
solana airdrop 4 --url devnet
solana balance --url devnet
# Need at least 3 SOL for program + MXE account rent
```

## Step 3 — Deploy the Anchor program

```bash
cd arcium-psi
env -u ARCIUM_PSI_LOCALNET_CIRCUIT anchor build
grep -caF "<PSI_INTERSECT_CIRCUIT_URL>" target/deploy/arcium_psi.so
# must print 1 or more: the program holds the release circuit URL
anchor deploy --provider.cluster devnet
# Record the deployed Program ID — update PROGRAM_ID in tests/.env
```

> Nothing in the repository reads `tests/.env` yet. The program ID is also a placeholder
> in `programs/arcium-psi/src/lib.rs` (`declare_id!`), `Anchor.toml` (`[programs.devnet]`)
> and `tests/src/program.ts` (`PROGRAM_ID`); a devnet deploy needs a real, retained
> program keypair (finding F-14).

## Step 4 — Register the PSI computation definition (off-chain circuit source)

```bash
cd arcium-psi/tests
cp .env.example .env
# Edit .env: fill PROGRAM_ID, CIRCUIT_HASH from Step 1, RPC_URL
```

> No deploy script exists in the repository yet (there is no `src/deploy.ts`); it must be
> written before a deploy, for this step and Step 5. The nearest existing code is the
> localnet test `tests/src/localnet/psi.localnet.ts`, which registers the computation
> definition against a local validator under `arcium test`.

`init_psi_intersect_comp_def` uploads no circuit. After it, check the stored source: the
computation definition account's `circuitSource` must be `offChain` with `source` equal to
`PSI_INTERSECT_CIRCUIT_URL` and `hash` equal to `PSI_INTERSECT_CIRCUIT_HASH` (the localnet
test makes the same check against its own URL).

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
- [ ] `curl -sSfL <PSI_INTERSECT_CIRCUIT_URL> | sha256sum` matches `PSI_INTERSECT_CIRCUIT_HASH`
- [ ] The computation definition stores `offChain` with that URL and hash
- [ ] `lutOffset` in `program.ts` updated from on-chain MXE account
- [ ] `PROGRAM_ID` in `.env` matches deployed program address

## Manual cleanup (GitHub)

After gdrive-sync workflow was removed (PR #14), delete orphaned secrets:
- Go to: Settings → Secrets and variables → Actions
- Delete: `GDRIVE_CLIENT_ID`, `GDRIVE_CLIENT_SECRET`, `GDRIVE_TOKEN`

# Architecture and Skills Audit — `main` @ `483a664` (2026-10-31)

> **Snapshot, not authority.** Everything here was read at
> `main` = `483a66438a6d148ec624d3de530c79da0a16662f` and will drift. It records
> evidence and recommendations; it authorizes nothing. Re-derive any line before
> relying on it — paths and line numbers are at that SHA. A tracker change, a
> `CLAUDE.md` change or any code fix proposed below is a separate Owner task.

Evidence labels follow `CLAUDE.md` («Границы доказательств»): `SOURCE_VERIFIED`
(read in source, `path:line`), `RUNTIME_VERIFIED` (observed when run),
`INFERRED` (from what), `NOT_VERIFIED` (why). Paths under `crates/` drop the
`crates/` prefix in tables.

## 0. Method

- Code read in a disposable clone of `main` by the author and by three
  read-only fresh-context survey agents (Rust core; Android, FFI and relay;
  PSI, CI and documents). Claims the author relied on for a conclusion or an
  edit were re-read by the author; the rest are marked as the survey's.
- Runs: `cargo test --workspace` on this Rust tree — 428 passed, 0 failed,
  3 ignored (`RUNTIME_VERIFIED`; tree identical to `main`'s `crates/`);
  `cargo test -p core-crypto -- contact_hash rescue` — 7 passed; in
  `arcium-psi/tests`, `npx tsc --noEmit` — 0 errors and the mocha crypto test —
  17 passing (survey C's run; `INFERRED` here from its report); `cargo tree --offline` for the
  dependency findings in §1.5.
- Android runtime evidence on `main`'s tree comes from earlier CI logs read
  through the GitHub API: two-device run `41185016456` on `483a664` (17 of 17
  steps) and instrumentation run `39445227759` on `88e6957`, whose product tree
  equals `483a664` (23 of 23 tests). Nothing was run on an emulator for this
  audit.
- Skills: structural check of all five skills (frontmatter, every backticked
  repository path), a read of every skill file, and seven fresh-context
  behavioural trials (§2.2).

## 1. Architecture as implemented

### 1.1 Shape

```
Android app (Kotlin/Compose, debug builds only reach a relay)
  ├─ MessengerService: sync loop while the activity is STARTED (no background)
  ├─ MasterKeyProvider: random 32-byte key wrapped by an AndroidKeyStore AES-GCM key
  └─ UniFFI/JNA ──► libarcium_core.so (mobile-ffi)
                      ├─ ArciumCore: identity, prekeys, sessions, contacts
                      ├─ NetworkMessenger: sync rounds, receipts, chat history
                      ├─ core-protocol: durable messaging (outbox, inbox, CAS sessions)
                      ├─ core-crypto: X3DH, Double Ratchet, (unused) hybrid KEM, Rescue stub
                      ├─ core-storage: encrypted SQLite key-value store
                      └─ relay::client ── plain TCP ──► arcium-relay (in memory, no auth, no TLS)
core-transport (Tor/arti): skeleton, linked as a dependency, never called
arcium-psi (separate workspace): Anchor program + Arcis circuit, localnet only, not called by the app
```

### 1.2 Subsystem status

| Subsystem | Status | Evidence | Notes |
|---|---|---|---|
| X3DH | IMPLEMENTED | `core-crypto/src/x3dh.rs:69-101`, `:125-223` | DH1–3 and optional DH4; signed prekey verified strictly over an object binding the identity DH key (F-2). One one-time prekey at a time, consumed with session creation by compare-and-swap (`mobile-ffi/src/lib.rs:938-986`). Survey A. |
| Double Ratchet | IMPLEMENTED, no header encryption | `core-crypto/src/ratchet.rs:41` (`MAX_SKIP`), `:212-229` (snapshot/restore on failed decrypt) | XChaCha20-Poly1305 with a random 24-byte nonce; header (ratchet key, `pn`, `n`) in clear as AAD; skipped keys bounded (1000 per chain, 2000 total), no age expiry. Survey A. |
| Post-quantum hybrid (X25519 + ML-KEM-768) | PARTIAL: primitive only | `core-crypto/src/hybrid.rs:48-188`, no callers | Sessions get no PQ protection. `PROJECT_CONTEXT.md` describes it as needing integration — still true. |
| RescueCipher | STUB, unused | `core-crypto/src/rescue.rs:1-47` | ChaCha20-Poly1305 placeholder; its API takes a 32-byte hash while the circuit takes u64 field elements (survey C). Kept by M-3 (`CLAUDE.md`). |
| Encrypted store | IMPLEMENTED | `core-storage/src/lib.rs:106-115` (`journal_mode = DELETE`, `synchronous = EXTRA`), `:88-465` | Per-record HKDF subkey, random nonce, AAD = key name, hashed key names. No rollback protection (`:18-21`, declared). |
| Durable sessions (CAS) | IMPLEMENTED | `core-protocol/src/durable.rs:179-307`, `:414` (`session:`) | Output released only after the commit reports `Ok`; conflict or unknown outcome freezes the instance. Survey A. |
| Durable outbox / inbox, message ids | IMPLEMENTED | `core-protocol/src/messaging.rs:44-49` (message id = SHA-256 of a domain label and the wire bytes), `:495-500` (duplicate check before decrypt); `messaging/records.rs:35-36`; `messaging/helpers.rs:77-84` (send id) | One client id → at most one ciphertext; each message id accepted once. |
| Receipts, retransmission | IMPLEMENTED | `mobile-ffi/src/network.rs:493-523` (republish stored wire bytes), `:700` (receipt handling), `:731-741` (`receipt_again`) | Retransmission clock is in memory, so a new process resends everything pending once. A replayed receipt makes a new receipt (open question vs `docs/NET-MESSAGING.md:170-171`). |
| Chat history | IMPLEMENTED | `mobile-ffi/src/network/chat.rs:170-196` (keys), `:51` (entry states) | Outgoing keyed by app id, incoming by message id. |
| Identity lifecycle | IMPLEMENTED (create-only); key-loss detection absent | `mobile-ffi/src/lib.rs:638-671` | See risk R3. |
| Contact pinning | IMPLEMENTED on the `NetworkMessenger` path | `mobile-ffi/src/contacts.rs:101-117`, `network.rs:183-201` | The exported `establish_session_initiator` checks no pin (survey A); Kotlin calls it at `android/app/src/main/kotlin/com/arcium/messenger/data/MessageRepository.kt:151`. |
| Rust ↔ Kotlin boundary | IMPLEMENTED | `.github/actions/uniffi-android-bridge/action.yml:27-29` (x86_64, arm64-v8a), `crates/mobile-ffi/uniffi.toml` | All exports blocking; plaintext types redact `toString` for generated record properties (not function arguments). Survey B. |
| Android app | IMPLEMENTED (debug relay only) | `android/app/src/main/kotlin/com/arcium/messenger/messaging/MessengerService.kt:114-142`, `RelaySettings.kt:20-29` | Sync only while visible; release builds have no relay at all (untested). PSI, Tor, BLE mesh, Solana: stubs that throw or return empty. |
| Development relay | IMPLEMENTED, development only | `relay/src/server.rs` (TTL 7 days at `:60`; identical-bytes dedup `:265-291`), `relay/src/client.rs:44` (plain `TcpStream`) | In memory; no authentication: any client can fetch, delete or flood any mailbox and overwrite any bundle. |
| Tor transport | PLANNED (skeleton) | `core-transport/src/lib.rs:30` (`"TODO.onion"`); `mobile-ffi/Cargo.toml:16` declares it, no source uses it | Messages go over plain TCP to the relay. |
| Arcium PSI | PARTIAL, localnet only, not wired | `arcium-psi/programs/arcium-psi/src/lib.rs:42` (`init_computation_def(…, None)`), `arcium-psi/encrypted-ixs/src/lib.rs` | Circuit implemented (10 vs 10 u64). Callback verifies but never stores or emits the result (F-14). Server set supplied by the caller (F-4). No deploy. Not called from Rust core or Android. |
| CI | IMPLEMENTED, deterministic | `.github/workflows/*.yml`; `.github/scripts/check_action_pins.py` | Actions pinned to SHAs, no LLM calls; "tests actually ran" guards; emulator runs for instrumentation and two-device e2e. |

### 1.3 Trust boundaries and what the relay sees

- **Relay and network (untrusted).** Confidentiality and integrity of message
  content do not depend on the relay (end-to-end AEAD, receipts inside the
  ratchet). Availability does: it can drop, delay, reorder and replay, and —
  because the protocol has no mailbox authentication — so can any other client.
- **Metadata exposed** (survey B's reading of `relay/src/server.rs`
  and `mobile-ffi/src/network/wire.rs`): recipient key on every request; the
  sender's X25519 key in clear in the envelope; envelope kind; the ratchet
  header (ratchet public key, `pn`, `n`); sizes (no padding found — `INFERRED`);
  timing, including 1.5–4 s polling while the app is open; client IP; bundle
  lookups; a relay-wide sequence counter visible to every client.
- **FFI.** Kotlin holds handles and public data and decides nothing about
  sessions or delivery; plaintext and the master key cross as plain byte
  copies that Kotlin cannot wipe.
- **Disk.** Per-record confidentiality and integrity; no freshness (rollback).
- **PSI (localnet).** Any signer may submit a query; confidentiality rests on
  Arcium's MPC cluster and output integrity on its BLS signature — external,
  `NOT_VERIFIED` here.

### 1.4 Invariants that hold, and where they are tested

| Invariant | Enforced | Tested |
|---|---|---|
| No output before its state transition commits | `core-protocol/src/durable.rs:834-847` | `mobile-ffi/src/tests/durable.rs`, crash-point tests |
| A failed decrypt changes no ratchet state (F-1) | `core-crypto/src/ratchet.rs:212-229` | ratchet unit tests |
| One client id → at most one ciphertext | `core-protocol/src/messaging.rs:443-466` | `mobile-ffi/src/tests/chat.rs`, `tests/network.rs` |
| A message id is accepted once; a duplicate leaves the ratchet untouched | `core-protocol/src/messaging.rs:495-525` | `mobile-ffi/src/tests/network.rs`, `tests/network_crash.rs`; two-device replay step (PR #126, not on `main`) |
| On the network path a text is marked delivered on an authenticated receipt naming its id. Not enforced for every caller: the exported `acknowledge_outgoing` (called from `MessageRepository.kt:217`) removes it unconditionally, and the chat shows "Delivered" for anything not in the outbox | `mobile-ffi/src/network.rs:700-705`; `messaging_api.rs:329`; `network/chat.rs:840-845` | two-device "Delivered" waits |
| A pinned card is never replaced | `mobile-ffi/src/contacts.rs:101-117` | `tests/network.rs`, two-device `addContact` |
| A failed identity read never becomes "no identity" | `IdentityRepository.kt:31-35` | identity instrumentation tests |
| Plaintext records print `<redacted>` | `Plaintext.kt`, `check_generated_plaintext.py` | stringification tests |

Rows are survey A/B readings with the author's spot checks of the cited lines.

### 1.5 Risks, highest first

| # | Risk | Severity | Evidence |
|---|---|---|---|
| R1 | **The product is described as anonymous and Tor-protected; it is neither.** Messages go over plain TCP to an unauthenticated relay that sees sender and recipient keys, sizes, timing and IP. | High (claims vs reality) | `CLAUDE.md:13`, `PROJECT_CONTEXT.md:7` vs `relay/src/client.rs:44`, `core-transport/src/lib.rs:30`; the app itself says "Not anonymous" (survey B). |
| R2 | **Unauthenticated relay operations.** Any client can delete or flood any mailbox and overwrite any prekey bundle, so delivery can be delayed indefinitely by a third party; retransmission recovers only while the sender's app is open. | High (availability) | `relay/src/server.rs` request handling (survey B); exercised deliberately by the e2e key-mismatch step. |
| R3 | **Master-key loss resets identity or bricks the app.** A missing `master_key.blob` makes a new key; the store then reads as empty and onboarding creates a new identity. A lost Keystore key or a corrupt blob makes startup fail on every launch. The blob is written without fsync. `MasterKeyProvider` has no tests. | Medium-High (data loss) | tracker F-9 (limits); continuity record D-007; `MasterKeyProvider.kt:42-67`; `mobile-ffi/src/lib.rs:661-671` (survey A/B). |
| R4 | **The PSI implementation contradicts the project's own rule.** `CLAUDE.md` requires `OffChainCircuitSource` (hash only on chain); the program passes `None` and the localnet test asserts an on-chain circuit and uploads it. Results are never delivered (F-14); the server set is caller-supplied, so low-entropy phone numbers are enumerable (F-4). | High for the PSI milestone (not user-facing yet) | `arcium-psi/programs/arcium-psi/src/lib.rs:37` (comment) vs `:42`; `arcium-psi/tests/src/localnet/psi.localnet.ts:167-168`, `:198-206`. |
| R5 | **No rollback protection** (accepted residual). An older database, or a single older row, still authenticates: consumed prekeys, skipped keys and acknowledged messages can come back. | Medium | `core-storage/src/lib.rs:18-21`; F-10 remainder. |
| R6 | **The unused Tor stack carries eight of the nine dependency advisories.** `ring 0.16.20` and `rsa 0.9.10` (both ignored in `.cargo/audit.toml`) and `rustls-webpki`, `zstd`, `zstd-safe` (two advisories), `zstd-sys` and `crypto-bigint` (six of the seven failing `cargo audit` today) reach the workspace only through `arti-client` in `core-transport`, which `mobile-ffi` declares and never calls. Only `ctutils` (via `core-crypto`) does not. | Medium (supply chain, red CI) | `cargo tree --offline --locked -i <crate>` for all but `crypto-bigint` (`RUNTIME_VERIFIED`); `crypto-bigint` via `tor-keymgr` → `ssh-key` → `elliptic-curve` from the independent reviewer's `Cargo.lock` walk (`INFERRED`: its features are inactive, so `cargo tree` prints nothing, but `cargo audit` reads the lockfile); `mobile-ffi/Cargo.toml:16`. Removing the dependency from `mobile-ffi` alone would not clear `cargo audit`, which reads the whole workspace lockfile while `core-transport` stays a member. |
| R7 | **No background delivery.** Sync runs only while the activity is started; envelopes expire after 7 days. | Medium (product) | `MainActivity.kt:20`, `relay/src/server.rs:60`. |
| R8 | **Replay amplification and unbounded growth.** A replayed text or receipt makes a new receipt (at most one a minute per message); `seen:` and `sendid:` records are never deleted. | Low-Medium | `mobile-ffi/src/network.rs:623-626`, `:731-741` (survey A). |
| R9 | **Fragile failure surfaces.** A poisoned-mutex `expect` panics across the FFI; Kotlin catches only `CoreException`; link state depends on the `"network:"` error-string prefix. | Low | `mobile-ffi/src/network.rs:477-489`; `MessengerService.kt:182`, `:193` (survey B). |
| R10 | **Supply-chain looseness outside the root workspace.** `arcium-psi` has no `Cargo.lock`; the `ts-crypto` job uses `npm install`; the devcontainer falls back to unpinned installs. | Low-Medium | survey C (`arcium-ci.yml:67`, `.devcontainer/setup.sh`). |

### 1.6 Documentation that disagrees with the code

| Document | Says | Code |
|---|---|---|
| `CLAUDE.md:13` | four layers of protection incl. Tor onion | Tor is a skeleton (R1) |
| `CLAUDE.md:45-48` | only the circuit hash is on chain | the circuit is registered on chain (R4) |
| `CLAUDE.md:52` | the Rescue stub's API is right | it does not match the circuit's input format (survey C) |
| `PROJECT_CONTEXT.md` (last changed 2026-05-28, `e7cb1bb`, per GitHub) | Tor "✅ готово"; `SHA256(phone)`; `find_contacts(Vec<Hash>)`; test tables "42 passed" | see R1, R4; contact hash is `u64::from_le_bytes(sha256[0..8])`; circuit is `psi_intersect`; 428 tests pass |
| `README.md` | empty | — |
| `docs/HOME-DEPLOY.md` | hash-only circuit; `src/deploy.ts`; `libmobile_ffi.so` in `src/main/jniLibs` | on-chain circuit; no such file; `libarcium_core.so` under `build/generated/rustBridge/jniLibs` (survey C) |
| `android/README.md` | Hilt, PSI discovery, Tor, `TorManager.kt` | none exist (survey B) |
| `docs/NET-MESSAGING.md:170-171` | a replayed receipt changes nothing | it makes a new receipt (R8) |
| code comments | `core-storage/src/lib.rs:190-192` "synchronous = FULL"; `ArciumCore.kt:12-16` "routing not wired"; `rescue.rs:3` "API matches production" | `EXTRA`; routing is wired; it does not (surveys A, B) |

### 1.7 Not verified by anything in the repository

Power loss and fsync behaviour; rollback; real I/O commit failures (simulated
only); a receipt acknowledged before the relay accepted it — the `mobile-ffi`
suite passes with that defect (trial T3: its probe, kept in the session
scratchpad, is a ready regression test); external X3DH/Double Ratchet test
vectors; decoder fuzzing; arm64-v8a
execution (built, never run in CI); physical devices; release-build behaviour;
`MasterKeyProvider`; background execution; PSI on devnet; the MPC and BLS trust
model.

## 2. Claude Code guidance

### 2.1 Inventory and intended triggers

| Skill | Should load for | Structure |
|---|---|---|
| `engineering-code-review` | any non-trivial change or review; before reporting done | frontmatter valid; 4 files |
| `arcium-security-review` | crypto, protocol, durable state, identity, relay/network, FFI/Android, PSI, CI, dependencies, secrets | valid; 2 files |
| `mbr-integration` | durable state, crash recovery, outbox/ACK, rollback, replay | valid; 3 files |
| `android-uniffi-bridge` | FFI surface, bindings, packaging, Android workflows, claims about Android evidence | valid; 2 files |
| `repo-change-protocol` | clone, scope, PR, merge mechanics | valid; 1 file |

Structural check (script in the session scratchpad, run before and after the
edits): every `SKILL.md` has `name` equal to its directory and a description;
all 118 backticked repository paths at baseline and all 144 after the edits
exist at `483a664` (`RUNTIME_VERIFIED`). The defects found were therefore not
broken links but **claims that had become false** (§2.3).

`.claude/settings.json` (plan mode by default, a SessionStart hook) and
`.claude/hooks/continuity.sh` showed no defect: the hook loaded the continuity
records on every resume in this session and always marked them untrusted. It
re-injects about 8 KB each time it fires; whether that cost is worth it is the
Owner's call. `.pi/settings.json` configures a different agent tool and is
outside this review. `.claude/MIGRATION-REPORT.md` is correctly marked
historical; its open questions (branch naming, subagent fan-out) are still
open.

### 2.2 Behavioural trials

Seven fresh-context agents were given realistic read-only tasks against
synthetic local commits (never pushed). Six prompts did not mention skills;
which skills loaded was read from each agent's transcript (its `Skill` tool
calls), not from its answer.

| # | Task (trap) | Expected skills | Observed `Skill` calls | Outcome |
|---|---|---|---|---|
| T1 | Kotlin UI string change (the two-device test waits for the old text) | engineering | engineering, security | Rejected the change, citing `TwoDeviceMessengerTest.kt:96`; Karpathy block with `goal_driven: fail` |
| T2 | `MAX_SKIP` 1000 → 20000 | engineering, security | engineering, security | Selection correct; run cut short by a usage limit before a verdict |
| T3 | receipt removed from the outbox before it is sent | engineering, security, mbr | engineering, security, mbr | Rejected: a receipt is lost when its SEND fails (at-least-once becomes at-most-once). The 137 `mobile-ffi` tests pass on the change; a probe that cuts the SEND request passes on `main` and fails on the change. Both review blocks |
| T4 | new exported `dh_secret_bytes()` (secret across FFI) | bridge, security, engineering | engineering, security — not bridge | Rejected: a probe showed a third party holding the exported 32 bytes impersonating the user over a real relay. CI proof levels stated correctly, read from the workflows |
| T5 | docs-only wording change | engineering at most; no security | engineering | Accepted; stated a security review was not needed |
| T6 | factual question about relay dedup (negative control) | none | none | Correct answer with lines |
| T7 | positive control: "use the arcium-security-review skill" | security | security | Confirms subagents can load project skills |

What this shows: automatic selection worked for crypto, durable-state,
docs-only and question tasks (`RUNTIME_VERIFIED`, transcripts). The security
review loaded on an ordinary UI change (over-eager, harmless). Reviewers that
are told "read and follow `.claude/skills/X`" read the files directly instead
of loading the skill (three earlier reviewers, transcripts) — so an explicit
path in a prompt bypasses selection rather than testing it.

What it does not show: the edited skills could not be exercised through
automatic selection, because the session's skill registry is the persistent
checkout's copy (the unedited `main` version). Selection with the edited
descriptions is `NOT_VERIFIED`. Seven trials are a sample, not a measurement.

### 2.3 Findings per skill

| Skill / file | Finding | Evidence | Action |
|---|---|---|---|
| `android-uniffi-bridge` `SKILL.md`, `bridge-topology.md` | Central claim false: "No CI job … has ever executed a Kotlin↔Rust call"; runtime proof described as manual | `android-instrumentation.yml:105-117`, `android-two-device-e2e.yml:125-128` run them on x86_64 API-30 emulators | Fixed: three evidence levels; arm64 never run; physical devices manual |
| same | Only one of five workflows that use the bridge action named; a stale `TODO: System.loadLibrary` claim; "`cargo build -p mobile-ffi` generates the .kt" | `grep -l uniffi-android-bridge .github/workflows/*.yml` (5); `ArciumCore.kt` has no TODO; `crates/mobile-ffi/build.rs` only sets rerun-if-changed | Fixed |
| same, description | Trigger "touching crates/mobile-ffi" over-broad; no trigger for claims about Android test runs | T4 changed an exported item, asked what CI proves, and did not load the skill. Its answer was right because it read the workflows; the unedited skill would have supplied the false "never executed" claim | Description sharpened; effect `NOT_VERIFIED` (§2.2) |
| `mbr-integration` map | Part 1 "verified state" (at `5faadaf`, 161 commits ago) says no outbox, no message ids, no ACK, no durable sessions in the app — all now implemented | §1.2 rows; `core-protocol/src/messaging.rs:44-49`, `mobile-ffi/src/lib.rs:621` | Fixed: a "superseded" table with current evidence; historical rows kept |
| `repo-change-protocol` §8 | Grants a standing permission (an empty-commit retrigger) despite §1 ("authorizes nothing … any such wording is a defect") | the skill's own §1 | Fixed: no empty commits; one re-run only if the task allows |
| `repo-change-protocol` §6 | `cargo clippy --workspace --all-targets` (no `-D warnings`) differs from `CLAUDE.md` and CI | `arcium-ci.yml:44` | Fixed: points to the `CLAUDE.md` commands |
| `repo-change-protocol` §2 | Describes the persistent checkout's branch as a fact; no rule for pushing from the clone, so work was pushed by writing into the persistent checkout | this session: a push from the disposable clone to the GitHub URL works (`git push --dry-run`, exit 0) | Fixed |
| `engineering-code-review` `karpathy-review.md` | goal_driven did not say that a check must be able to fail | PR #126 history: a vacuous `accepted == 0` assertion passed its author's checks and was caught later by an independent review | Fixed (§2.4) |
| `delivery-checklist.md` | No verification guidance for Kotlin changes; CI trigger list missing `Cargo.lock` and the action directory; Rust test location incomplete | `android-ci.yml:50-66`; workflow `on:` blocks; `crates/mobile-ffi/src/tests/` | Fixed |
| `repo-map.md` | Missing `relay` crate and two specifications; `core-transport` called "Tor client"; points to `PROJECT_CONTEXT.md` as current | `ls crates/`, `ls docs/`; §1.6 | Fixed |
| `arcium-security-review` `threat-checklist.md` | PSI circuit-source check trusts comments that the code contradicts; "test masking" omits assertions that cannot fail | R4 | Fixed (two clauses) |
| all skills | Authority: each says it authorizes nothing (except §8 above); no skill widens write scope | read of every file | No change |
| all skills | Cost: SKILL.md files are 84–168 lines, references load on demand | file sizes | No change |

Not changed, and why: `arcium-security-review` `SKILL.md` and the evidence
ledger of `mbr-integration` contained no verified defect; `karpathy-origin.md`
is history by design.

### 2.4 Karpathy methodology

**Integration.** `CLAUDE.md` («Ревью и CI») requires it before Owner acceptance;
`engineering-code-review` maps the four principles onto workflow steps and
`references/karpathy-review.md` defines the procedure and the result block; the
original wording is preserved as non-normative history. Correct and
discoverable: in the trials every review agent loaded the skill and three
produced the result block unprompted (T1, T3, T5; T4 summarised its blocks).

**Case study — PR #126 (two-device suite, not merged).**

| Defect in the PR's history | Principle | Caught by |
|---|---|---|
| Commit message overclaimed what a sender-side count catches (`fdf63fd`) | think_before_coding / unverified claims | independent review |
| "The rounds below are the only ones" after stopping the activity — a round already running was not stopped (`3b18839`) | think_before_coding | independent review (`warning`) |
| Three `accepted == 0` rounds after the mailbox was empty and the peer stopped: true by construction (`e531d5f`) | goal_driven | independent review — by the reviewer's own reasoning, not by any criterion in the method |
| An ordering fix with no assertion that it worked (`b75e7cc`) | goal_driven | independent review |
| An exact receipt count that depended on the wall-clock minute (`e2feffd`) | think_before_coding | independent review |

The method caught every one of them, but only when an independent reviewer
applied it; the author's own pre-push checks did not. The vacuous assertion
also shows the one gap in the criteria: goal_driven asked for "a test that
would catch its failure" and said nothing about a test that cannot fail. The
fix made in this branch adds exactly that: name, for each new assertion, the
defect that makes it fail, and where the passing state cannot show it, see the
check fail once (broken fixture, mutant, or negative control). PR #126's final
form follows this pattern (eleven violated fixtures, four mutants, an in-place
control), which is the evidence that the requirement is practical.

Would the method catch the other defect classes? Code against a nonexistent
API — yes in principle (think_before_coding asks for the real signature; in
PR #126 the author generated the real bindings to check names). Unnecessary
complexity and unrelated changes — yes (simplicity_first, surgical_changes;
both scored `pass`/`fail` with evidence in the trials). Unsupported success
claims — yes, through the `unverified` field and `CLAUDE.md`'s labels.
Incomplete diff review — yes, through `complete: yes/no` and the coverage rule.

### 2.5 Proposed corrections not made here (outside the permitted files)

Each is a separate Owner decision.

- **`CLAUDE.md:13-15`** — keep the project description, but replace the claim
  of four active layers with one standing warning (not a status inventory,
  which `CLAUDE.md`'s own F-17 rule forbids): «Tor и Arcium PSI в приложение не
  подключены; не заявляй анонимность или защиту метаданных, пока код этого не
  подтверждает.»
- **`CLAUDE.md:45-48`** — either bring the code to the rule (a PSI task) or
  record that the rule is not yet met, as a tracker finding rather than a
  status line in `CLAUDE.md`. Proposed tracker text: "Circuit registered on
  chain: `init_psi_intersect_comp_def` passes `None` (`lib.rs:42`) and the
  localnet test uploads the circuit (`psi.localnet.ts:167-168`, `:198-206`),
  contrary to the OffChainCircuitSource rule."
- **`CLAUDE.md:52`** → «Сейчас STUB на chacha20poly1305 как placeholder;
  его API не совпадает с форматом входа circuit, и его никто не вызывает.»
- **`CLAUDE.md` «Команды проверки»** — add: «Kotlin/Android: в песочнице нет
  Android SDK. Компиляция — `android-ci.yml`, запуск — `android-instrumentation.yml`
  и `android-two-device-e2e.yml` (эмулятор x86_64, API 30). До их прогона на
  SHA изменение Kotlin — NOT_VERIFIED.»
- **`PROJECT_CONTEXT.md`** — replace the status table and both test tables
  with a dated note pointing to the code; correct the contact hash to
  `u64::from_le_bytes(sha256(phone)[0..8])`, the circuit to `psi_intersect`, the
  circuit source to the current on-chain registration, and Tor to "skeleton,
  not wired". The test tables repeat the F-17 drift class and should go.
- **`README.md`** (empty) → one paragraph: what the repository contains, what
  is implemented, and that Tor and PSI are not wired into the app.
- **`docs/HOME-DEPLOY.md`, `android/README.md`, `docs/NET-MESSAGING.md:170-171`
  and the stale code comments** in §1.6 — corrections listed there.
- **Hooks and settings** — no correction proposed.

## 3. Roadmap — next three milestones

1. **Key and identity durability.** Detect master-key loss instead of silently
   starting over: a key-check record in the store, an explicit "key lost"
   state in the app instead of onboarding or a crash loop, an fsync'd blob
   write, and tests for `MasterKeyProvider`.
   *Acceptance:* emulator instrumentation tests in CI show that (a) a deleted
   blob with an existing database produces the "key lost" state and never a
   new identity, (b) a corrupt blob does the same and the app still starts,
   (c) the normal path keeps the same identity across restarts; the tracker
   row F-9 and the continuity record D-007 are updated after the fix lands.
2. **Authenticated relay operations and an honest transport baseline.** Make
   FETCH, DELETE and bundle publication require proof of the mailbox key
   (for example a signature by the identity key over a relay challenge), add
   TLS to the relay connection, and decide the Tor question: either wire
   `core-transport` or drop it (which also removes the `ring 0.16` / `rsa 0.9`
   / `zstd` / `rustls-webpki` tree behind eight of the nine advisories, R6).
   *Acceptance:* a relay test and a two-device step show that a client without
   the key cannot fetch, delete or overwrite another user's mailbox or bundle;
   the e2e suite stays green; `cargo tree -i ring@0.16.20` is empty for
   `mobile-ffi` or Tor is in use; `CLAUDE.md` and `PROJECT_CONTEXT.md` state
   the actual transport.
3. **PSI to a deployable, rule-conformant state.** Register the circuit with
   an off-chain source and its hash (or change the rule by Owner decision),
   deliver the result to the querier (F-14), and anchor the server set (F-4)
   so a caller cannot test arbitrary guesses.
   *Acceptance:* the localnet test asserts an off-chain circuit source whose
   hash equals the CI-built `psi_intersect.arcis.ir`; a test reads the
   querier's encrypted result from chain state; a test shows a non-authorized
   caller cannot supply the server set; F-4 and F-14 move in the tracker after
   the code lands.

Smaller items for any of these: a regression test that cuts the SEND of a
receipt (§1.7), background delivery (R7), bounded `seen:` and
`sendid:` growth and receipt amplification (R8), panic-free FFI paths (R9), a
`Cargo.lock` for `arcium-psi` and `npm ci` in CI (R10), the documentation
corrections in §2.5, and an Owner decision on PR #126.

## 4. Limits of this audit

- Snapshot at one SHA; three survey agents read most code, the author re-read
  only what conclusions and edits rest on; survey rows not re-read are marked
  as the survey's.
- No emulator, device, devnet or power-loss run was made for this audit.
- Skill selection was observed in seven trials on the unedited skills; the
  effect of the edited descriptions on selection is `NOT_VERIFIED`.
- Severity ratings are judgement, not measurement; this is not a security
  audit.
- `ARCIUM_KARPATHY_REVIEW.md` from Claude Project knowledge was not accessible
  in this environment (no such file in the repository or the session) and was
  not reviewed.

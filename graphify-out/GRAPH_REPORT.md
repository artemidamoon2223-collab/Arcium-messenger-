# Graph Report - .  (2026-06-07)

## Corpus Check
- Corpus is ~25,828 words - fits in a single context window. You may not need a graph.

## Summary
- 530 nodes · 882 edges · 36 communities (31 shown, 5 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 45 edges (avg confidence: 0.87)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Arcium PSI Anchor Program|Arcium PSI Anchor Program]]
- [[_COMMUNITY_Double Ratchet Engine|Double Ratchet Engine]]
- [[_COMMUNITY_Core Crypto Keys|Core Crypto Keys]]
- [[_COMMUNITY_Encrypted Storage|Encrypted Storage]]
- [[_COMMUNITY_Mobile FFI Bindings|Mobile FFI Bindings]]
- [[_COMMUNITY_Android UI Screens|Android UI Screens]]
- [[_COMMUNITY_Android ViewModels|Android ViewModels]]
- [[_COMMUNITY_Architecture Docs|Architecture Docs]]
- [[_COMMUNITY_PSI Program Instructions|PSI Program Instructions]]
- [[_COMMUNITY_RescueCipher PSI Stub|RescueCipher PSI Stub]]
- [[_COMMUNITY_Tor Transport Layer|Tor Transport Layer]]
- [[_COMMUNITY_TypeScript Test Suite|TypeScript Test Suite]]
- [[_COMMUNITY_Session Protocol Manager|Session Protocol Manager]]
- [[_COMMUNITY_PSI Client Utils|PSI Client Utils]]
- [[_COMMUNITY_Graphify Knowledge Graph|Graphify Knowledge Graph]]
- [[_COMMUNITY_Hybrid PQ KEM|Hybrid PQ KEM]]
- [[_COMMUNITY_Dev Container Config|Dev Container Config]]
- [[_COMMUNITY_Android FFI Kotlin|Android FFI Kotlin]]
- [[_COMMUNITY_Android Message Repository|Android Message Repository]]
- [[_COMMUNITY_Bluetooth Mesh Network|Bluetooth Mesh Network]]
- [[_COMMUNITY_TypeScript Config|TypeScript Config]]
- [[_COMMUNITY_Solana Client Kotlin|Solana Client Kotlin]]
- [[_COMMUNITY_Android Contact Repository|Android Contact Repository]]
- [[_COMMUNITY_PSI Encrypted Instructions|PSI Encrypted Instructions]]
- [[_COMMUNITY_Android Identity Repository|Android Identity Repository]]
- [[_COMMUNITY_Android Application|Android Application]]
- [[_COMMUNITY_Claude Settings Hooks|Claude Settings Hooks]]
- [[_COMMUNITY_Devcontainer Setup|Devcontainer Setup]]
- [[_COMMUNITY_Monthly Backup Workflow|Monthly Backup Workflow]]

## God Nodes (most connected - your core abstractions)
1. `DoubleRatchet` - 19 edges
2. `x3dh_initiate()` - 14 edges
3. `Graphify Skill Definition` - 14 edges
4. `SubmitPsiQuery` - 13 edges
5. `EncryptedStore` - 13 edges
6. `Arcium Messenger Project Architecture (CLAUDE.md)` - 13 edges
7. `make_bob()` - 11 edges
8. `ratchet_pair()` - 11 edges
9. `x3dh_respond()` - 11 edges
10. `random_key()` - 11 edges

## Surprising Connections (you probably didn't know these)
- `Graphify Knowledge Graph Workflow` --conceptually_related_to--> `Graphify Skill Definition`  [INFERRED]
  .github/workflows/graphify.yml → .claude/skills/graphify/SKILL.md
- `Android CI Workflow` --conceptually_related_to--> `Android Kotlin + Jetpack Compose Skeleton (4 Screens)`  [INFERRED]
  .github/workflows/android-ci.yml → android/README.md
- `Android CI Workflow` --conceptually_related_to--> `UniFFI cdylib FFI Bridge Rust to Kotlin`  [INFERRED]
  .github/workflows/android-ci.yml → android/README.md
- `Arcium CI Workflow` --conceptually_related_to--> `Anchor Solana Program for PSI (init_user, submit_query, callbacks)`  [INFERRED]
  .github/workflows/arcium-ci.yml → PROJECT_CONTEXT.md
- `Arcium CI Workflow` --conceptually_related_to--> `Arcis PSI Circuit (psi_intersect, BATCH_SIZE=10)`  [INFERRED]
  .github/workflows/arcium-ci.yml → PROJECT_CONTEXT.md

## Import Cycles
- 1-file cycle: `crates/core-crypto/src/lib.rs -> crates/core-crypto/src/lib.rs`
- 1-file cycle: `crates/core-protocol/src/lib.rs -> crates/core-protocol/src/lib.rs`
- 1-file cycle: `crates/core-crypto/src/ratchet.rs -> crates/core-crypto/src/ratchet.rs`
- 1-file cycle: `crates/core-transport/src/lib.rs -> crates/core-transport/src/lib.rs`
- 1-file cycle: `crates/mobile-ffi/src/lib.rs -> crates/mobile-ffi/src/lib.rs`

## Hyperedges (group relationships)
- **Arcium PSI Core Concepts: RescueCipher, OffChainCircuitSource, Contact Hash, Arcis Circuit** — concept_rescue_cipher, concept_off_chain_circuit_source, concept_contact_hash, concept_arcis_circuit, concept_arcium_psi [INFERRED 0.95]
- **Four Security Layers of Arcium Messenger** — concept_x3dh_ratchet, concept_tor_transport, concept_encrypted_sqlite, concept_arcium_psi, concept_security_layers [EXTRACTED 1.00]
- **Graphify Skill Reference Documents** — skills_graphify_skill, skills_graphify_extraction_spec, skills_graphify_query_ref, skills_graphify_update, skills_graphify_exports, skills_graphify_github_merge, skills_graphify_hooks, skills_graphify_transcribe, skills_graphify_add_watch [EXTRACTED 1.00]

## Communities (36 total, 5 thin omitted)

### Community 0 - "Arcium PSI Anchor Program"
Cohesion: 0.08
Nodes (41): Account, Arcium, Result, String, Vec, ArciumSignerAccount, ClockAccount, Cluster (+33 more)

### Community 1 - "Double Ratchet Engine"
Cohesion: 0.13
Nodes (24): ChainKey, Drop, Option, PublicKey, Result, Self, StaticSecret, Vec (+16 more)

### Community 2 - "Core Crypto Keys"
Cohesion: 0.12
Nodes (33): PublicKey, Signature, SigningKey, StaticSecret, Option, PublicKey, Result, Signature (+25 more)

### Community 3 - "Encrypted Storage"
Cohesion: 0.19
Nodes (20): Connection, Drop, Result, Self, String, Vec, P, data_persists_across_reopen() (+12 more)

### Community 4 - "Mobile FFI Bindings"
Cohesion: 0.16
Nodes (22): Arc, Option, Result, Self, SigningKey, StaticSecret, String, Vec (+14 more)

### Community 5 - "Android UI Screens"
Cohesion: 0.08
Nodes (19): String, String, Boolean, String, Bundle, ChatScreen(), ChatViewModel, ComponentActivity (+11 more)

### Community 6 - "Android ViewModels"
Cohesion: 0.09
Nodes (17): StateFlow, String, List, StateFlow, String, StateFlow, Boolean, StateFlow (+9 more)

### Community 7 - "Architecture Docs"
Cohesion: 0.12
Nodes (28): Android Module README, Arcium Messenger Project Architecture (CLAUDE.md), Arcium PSI Architecture Context, Anchor Solana Program for PSI (init_user, submit_query, callbacks), Android Kotlin + Jetpack Compose Skeleton (4 Screens), Arcis PSI Circuit (psi_intersect, BATCH_SIZE=10), Arcium MPC Private Set Intersection for Contact Discovery, Blocking CI Gate for AI Review Steps (+20 more)

### Community 8 - "PSI Program Instructions"
Cohesion: 0.17
Nodes (17): ARCIUM_PROGRAM_ID, buildInitPsiCompDefIx(), buildInitUserIx(), buildSubmitPsiQueryIx(), buildSubmitQueryIx(), DISC_INIT_PSI_COMP_DEF, DISC_INIT_USER, DISC_SUBMIT_PSI_QUERY (+9 more)

### Community 9 - "RescueCipher PSI Stub"
Cohesion: 0.21
Nodes (15): Display, Error, Formatter, Result, Self, Vec, different_nonces_produce_different_ciphertexts(), encrypt_decrypt_round_trip() (+7 more)

### Community 10 - "Tor Transport Layer"
Cohesion: 0.14
Nodes (15): Arc, Result, Self, String, DataStream, Path, PreferredRuntime, io_error_display() (+7 more)

### Community 11 - "TypeScript Test Suite"
Cohesion: 0.10
Nodes (19): dependencies, @arcium-hq/client, @coral-xyz/anchor, @noble/curves, @solana/web3.js, tweetnacl, devDependencies, chai (+11 more)

### Community 12 - "Session Protocol Manager"
Cohesion: 0.25
Nodes (13): ContactId, Option, Self, Default, HashMap, RatchetState, make_ratchet(), missing_session_returns_none() (+5 more)

### Community 13 - "PSI Client Utils"
Cohesion: 0.21
Nodes (14): computeSharedSecret(), decryptResult(), encryptContacts(), generateX25519Keypair(), confirmSignature(), ensureFunded(), generateKeypair(), getBalance() (+6 more)

### Community 14 - "Graphify Knowledge Graph"
Cohesion: 0.12
Nodes (18): Graphify Skill Trigger, AST Structural Extraction for Code Files, Community Detection and God Nodes in Knowledge Graph, Graphify Incremental Update (--update flag), Graphify Knowledge Graph Build Pipeline, Graphify Query Vocabulary Expansion from Graph Labels, Semantic Extraction via LLM Subagents, Graphify Add URL and Watch Folder Reference (+10 more)

### Community 15 - "Hybrid PQ KEM"
Cohesion: 0.24
Nodes (16): Display, Error, Formatter, Result, Vec, combine_secrets(), different_keys_produce_different_secrets(), encaps_decaps_produce_same_secret() (+8 more)

### Community 16 - "Dev Container Config"
Cohesion: 0.13
Nodes (14): customizations, vscode, features, ghcr.io/devcontainers/features/node:1, ghcr.io/devcontainers/features/rust:1, version, profile, version (+6 more)

### Community 17 - "Android FFI Kotlin"
Cohesion: 0.21
Nodes (6): ByteArray, List, Long, String, BooleanArray, ArciumCoreWrapper

### Community 18 - "Android Message Repository"
Cohesion: 0.29
Nodes (7): ByteArray, List, Result, String, Unit, Message, MessageRepository

### Community 19 - "Bluetooth Mesh Network"
Cohesion: 0.18
Nodes (6): Boolean, ByteArray, Result, String, Unit, BluetoothMeshManager

### Community 20 - "TypeScript Config"
Cohesion: 0.20
Nodes (9): compilerOptions, esModuleInterop, forceConsistentCasingInFileNames, module, outDir, skipLibCheck, strict, target (+1 more)

### Community 21 - "Solana Client Kotlin"
Cohesion: 0.36
Nodes (5): ByteArray, Long, Result, String, SolanaClient

### Community 22 - "Android Contact Repository"
Cohesion: 0.43
Nodes (4): List, String, Contact, ContactRepository

### Community 23 - "PSI Encrypted Instructions"
Cohesion: 0.43
Nodes (6): Enc, Shared, ClientContacts, MatchResult, psi_intersect(), ServerContacts

## Knowledge Gaps
- **129 isolated node(s):** `PreToolUse`, `name`, `image`, `version`, `profile` (+124 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `DoubleRatchet` connect `Core Crypto Keys` to `Session Protocol Manager`?**
  _High betweenness centrality (0.005) - this node is a cross-community bridge._
- **Why does `Path` connect `Tor Transport Layer` to `Encrypted Storage`?**
  _High betweenness centrality (0.004) - this node is a cross-community bridge._
- **Are the 6 inferred relationships involving `x3dh_initiate()` (e.g. with `bad_signature_rejected()` and `basic_alice_to_bob()`) actually correct?**
  _`x3dh_initiate()` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `Graphify Skill Definition` (e.g. with `AST Structural Extraction for Code Files` and `Community Detection and God Nodes in Knowledge Graph`) actually correct?**
  _`Graphify Skill Definition` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `PreToolUse`, `name`, `image` to the rest of the system?**
  _132 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Arcium PSI Anchor Program` be split into smaller, more focused modules?**
  _Cohesion score 0.07575757575757576 - nodes in this community are weakly interconnected._
- **Should `Double Ratchet Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.12955465587044535 - nodes in this community are weakly interconnected._
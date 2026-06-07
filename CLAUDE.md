# CLAUDE.md — Arcium Messenger

Этот файл читается автоматически при каждой сессии. Следуй ему всегда.

---

## Правила работы (Karpathy)
https://github.com/forrestchang/andrej-karpathy-skills

- **Think Before Coding** — сначала найди реальные значения/API в коде и пакетах, потом пиши. Не выдумывай.
- **Simplicity First** — минимум кода решающего задачу. Никаких спекулятивных фич, лишних абстракций, обработки невозможных ошибок.
- **Surgical Changes** — не удаляй и не «улучшай» соседний код. Трогай только то, что просили.
- **Goal-Driven** — у каждой задачи есть шаг проверки (cargo test / cargo check / tsc).
- **Не падай молча** — если что-то не работает, объясни почему фактами.
- **Короткие блоки кода** — разработчик на планшете. Дроби длинный код.
- **Не притворяйся** — если шаг нельзя проверить (нет сети/toolchain), скажи прямо.

Общение с разработчиком — на русском. Код и комментарии — на английском.

---

## Агентский workflow (gist.github.com/hqman/e29cb6386c539d795767e8c3fd2c959b)

### Субагенты для параллельных задач
Если задача распадается на независимые части — запускай их параллельно, по одной задаче на субагент. Не делай всё последовательно когда части не зависят друг от друга.

Пример: нужно проверить `cargo test` + `tsc --noEmit` + grep на висячие ссылки — это три независимых вызова, запускай одновременно.

### Чеклист перед сдачей задачи
Не закрывай задачу без явной проверки. Минимум:
```
☐ cargo test --workspace  →  0 упавших
☐ tsc --noEmit            →  0 ошибок  (если трогал TS)
☐ grep на висячие ссылки  →  нет
☐ diff затрагивает ТОЛЬКО запрошенное  →  да
```

---

## Что за проект

Анонимный E2E мессенджер для Android. 4 слоя безопасности:
1. Tor onion (arti, чистый Rust)
2. X3DH + Double Ratchet (как Signal)
3. Шифрованный SQLite (XChaCha20-Poly1305)
4. Arcium MPC для приватного поиска контактов (PSI)

---

## КРИТИЧЕСКИЕ архитектурные правила

### Криптография — два РАЗНЫХ слоя, не путать:
- **Сообщения:** XChaCha20-Poly1305 + Double Ratchet
- **PSI / контакты:** ТОЛЬКО RescueCipher (arithmetic-friendly, совместим с MPC)
- ❌ НИКОГДА не используй XChaCha20/AES для PSI — математически несовместимо с Arcium MPC
- ❌ НИКОГДА не используй RescueCipher для сообщений

### Хэш контакта (канонический стандарт, обе стороны ОБЯЗАНЫ совпадать):
```
u64::from_le_bytes( sha256(phone.as_bytes())[0..8] )
```
Little-Endian, первые 8 байт. TS-сторона уже следует этому (tests/src/utils.ts).

### OffChainCircuitSource:
- .arcis circuit хостится на IPFS/CDN, НЕ загружается on-chain
- On-chain хранится только 32-байтный SHA256 хэш circuit
- ❌ НИКОГДА не встраивай circuit в смарт-контракт (раздувает gas в 100x)
- CIRCUIT_HASH ≠ git commit SHA. Это SHA256 файла psi_intersect.arcis.ir

### RescueCipher в Rust (crates/core-crypto/src/rescue.rs):
- Сейчас STUB на chacha20poly1305 как placeholder. API правильный.
- НЕ заменяй на настоящий Rescue пока circuit не задеплоен на Arcium testnet
- Причина: arcium-client тянет весь Solana/Anchor стек → раздувает Android .so

---

## Версии (проверены, не менять без причины)
- arcium-client = "0.10.4", arcium-anchor 0.10.4 требует anchor-lang "=1.0.2"
- arcis = "0.10.4" (генерирует .arcis.ir)
- @coral-xyz/anchor ^0.30.1, @arcium-hq/client ^0.10.4 (TS сторона)
- ml-kem = "0.3.2" (hybrid PQ, не 0.2)

---

## Окружение (важно!)
- Песочница агента **блокирует сеть** (403 allowlist на api.devnet.solana.com)
- Anchor CLI / Solana CLI **не установлены**
- ❌ НЕ пытайся deploy / airdrop / devnet-тесты в песочнице — они skip
- ✅ Работает: cargo check, cargo test, tsc --noEmit, локальные unit-тесты
- Deploy на devnet — отдельная задача в окружении с открытой сетью + toolchain

---

## Команды проверки
```bash
# Rust core
cargo test                    # все unit-тесты
cargo check                   # быстрая проверка компиляции

# Anchor программа (cargo check работает, anchor build — нет, нужен CLI)
cd arcium-psi && cargo check

# TypeScript тесты
cd arcium-psi/tests && npx tsc --noEmit
npx mocha --require ts-node/register 'src/crypto.test.ts'
```

---

## Статус модулей
```
v0.1 ✅ core-crypto     X3DH + Ratchet + RescueCipher(stub) + Hybrid KEM
v0.2 ✅ core-storage    SQLite + XChaCha20
v0.3 ✅ core-transport  Tor (arti)
v0.4 ✅ core-protocol   SessionManager
v0.5 ✅ mobile-ffi      Identity + ArciumCore (UniFFI)
v0.6 ✅ android         Kotlin + Compose skeleton (4 screens, UniFFI stub)
v1.0 🚧 arcium-psi      Arcis circuit ✅ | Anchor handlers ✅ | deploy ⏳ (нужен toolchain)
v1.1 🚧 post-quantum    Hybrid X25519+ML-KEM ✅
TS tests 🚧             config ✅ | crypto 4/4 ✅ | setup ✅ | deploy/scenarios ⏳
```

---

## Структура репозитория

```
Arcium-messenger-/
├── Cargo.toml                        # workspace: 5 crates, resolver = "2"
├── CLAUDE.md                         # этот файл
├── PROJECT_CONTEXT.md                # архитектурные детали PSI (не для агента)
├── crates/
│   ├── core-crypto/src/
│   │   ├── lib.rs                    # re-exports + 24 unit tests
│   │   ├── x3dh.rs                   # X3DH key exchange
│   │   ├── ratchet.rs                # Double Ratchet (FIFO skipped keys)
│   │   ├── rescue.rs                 # RescueCipher — STUB только для PSI
│   │   ├── hybrid.rs                 # X25519 + ML-KEM-768 PQ hybrid
│   │   └── contact_hash.rs           # sha256(phone)[0..8] → u64 LE
│   ├── core-storage/src/lib.rs       # EncryptedStore: SQLite + XChaCha20
│   ├── core-protocol/src/lib.rs      # SessionManager
│   ├── core-transport/src/lib.rs     # TorClient (arti)
│   └── mobile-ffi/src/lib.rs         # UniFFI cdylib: Identity + ArciumCore
├── arcium-psi/
│   ├── programs/arcium-psi/src/lib.rs  # Anchor: init_user, submit_query, PSI handlers
│   ├── encrypted-ixs/src/lib.rs        # Arcis circuit (arcis = "0.10.4")
│   └── tests/src/
│       ├── crypto.test.ts            # 4/4 ✅
│       ├── setup.test.ts             # ✅
│       ├── scenarios.test.ts         # ⏳ (нужен devnet)
│       └── utils.ts                  # hash_contact: sha256(phone)[0..8] → bigint LE
├── android/app/src/main/kotlin/com/arcium/messenger/
│   ├── ui/{onboarding,chat,contacts,settings}/  # 4 Compose screens
│   ├── ffi/ArciumCore.kt             # UniFFI bindings stub
│   └── data/{Contact,Identity,Message}Repository.kt
└── .github/workflows/
    ├── arcium-ci.yml                 # core-rust → ts-crypto → arcium-build → arcium-test
    ├── android-ci.yml                # assembleDebug (JDK 17 + Android SDK)
    ├── security-review.yml           # Claude Code review на диффе PR
    └── monthly-backup.yml            # → GitHub Releases
```

---

## Ключевые API

### core-crypto

**X3DH** (`x3dh.rs`):
```rust
pub fn x3dh_initiate(id_sk: &StaticSecret, id_pk: PublicKey, bundle: &PrekeyBundle)
    -> Result<AliceSession, X3dhError>
// AliceSession { root_key: [u8;32], ad: Vec<u8>, ephemeral_pk: PublicKey }

pub fn x3dh_respond(id_sk, id_pk, spk_sk, otpk_sk: Option<&StaticSecret>,
    alice_id_pk, alice_eph_pk) -> BobSession
// BobSession { root_key: [u8;32], ad: Vec<u8> }
```

**DoubleRatchet** (`ratchet.rs`):
```rust
DoubleRatchet::init_alice(root_key: RootKey, their_initial_dh: PublicKey) -> Self
DoubleRatchet::init_bob(root_key: RootKey, our_initial_dh: StaticSecret) -> Self
fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>), RatchetError>
fn decrypt(&mut self, hdr: &Header, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError>
// pub const MAX_SKIP: u32 = 1000
```

**Hybrid KEM** (`hybrid.rs`) — X25519 + ML-KEM-768:
```rust
pub fn hybrid_keygen() -> (HybridPublicKey, HybridSecretKey)
pub fn hybrid_encaps(pk: &HybridPublicKey) -> (Vec<u8>, [u8; 64])  // (ct, shared_secret)
pub fn hybrid_decaps(sk: &HybridSecretKey, ct: &[u8]) -> Result<[u8; 64], HybridError>
```

**Contact hash** (`contact_hash.rs`):
```rust
pub fn hash_contact(phone: &str) -> u64   // sha256(phone)[0..8] as u64 LE — КАНОНИЧЕСКИЙ
```

**RescueCipher STUB** (`rescue.rs`):
```rust
// ⚠️ STUB — chacha20poly1305 placeholder, только для PSI
RescueCipher { key: [u8; 32] }            // конструктор из ключа
pub fn psi_pack_contact(phone_hash: &[u8;32], cipher: &RescueCipher, nonce: &[u8;16]) -> Vec<u8>
```

### core-storage

```rust
EncryptedStore::open(path: P, master_key: [u8; 32]) -> Result<Self, StorageError>
EncryptedStore::open_in_memory(master_key: [u8; 32]) -> Result<Self, StorageError>
fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError>
fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>         // Err(NotFound) если нет
fn delete(&self, key: &str) -> Result<(), StorageError>
fn list_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError>
```

### core-protocol

```rust
type ContactId = u64;  // == hash_contact() output
SessionManager::new() -> Self
fn new_session(&mut self, id: ContactId, state: DoubleRatchet)
fn get_session(&mut self, id: ContactId) -> Option<&mut DoubleRatchet>
fn remove_session(&mut self, id: ContactId)
```

### mobile-ffi (UniFFI cdylib → Kotlin)

```rust
// Identity
Identity::generate() -> Arc<Identity>        // Ed25519 + X25519 keypair
fn public_key_bytes(&self) -> Vec<u8>        // 32-byte Ed25519 verifying key

// ArciumCore
ArciumCore::new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError>
fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError>
fn load_identity(&self) -> Option<Arc<Identity>>

enum CoreError { Storage { msg: String }, InvalidKey { msg: String } }
```

---

## Workflow разработки

### Создать ветку и отправить PR
```bash
git checkout -b claude/<task-slug>
# ... изменения ...
cargo test --workspace          # должно быть 0 упавших
git push -u origin claude/<task-slug>
# → создать PR → squash merge в main
```

### Обновить UniFFI биндинги для Android
```bash
# Шаг 1: генерация .kt из Rust (работает в sandbox)
cargo build -p mobile-ffi

# Шаг 2: компиляция .so (нужен NDK — только локально / android-ci.yml)
cargo ndk -t arm64-v8a build -p mobile-ffi --release
# выход: target/aarch64-linux-android/release/libmobile_ffi.so
```
Kotlin-биндинги уже скомпилированы в `android/app/src/main/kotlin/.../ffi/ArciumCore.kt`.

### Добавить тест
- **Rust**: `#[cfg(test)] mod tests { ... }` в конце файла крейта
- **TS**: `arcium-psi/tests/src/*.test.ts`; запуск: `npx mocha --require ts-node/register 'src/новый.test.ts'`
- После добавления — обновить счётчик в разделе "Тесты" этого файла

---

## GitHub — конфигурация и история PR

### Репозиторий
- `artemidamoon2223-collab/Arcium-messenger-`
- Основная ветка: `main`
- Соглашение по веткам: `claude/<task-slug>`
- Мёрж: squash в main

### Secrets (Settings → Secrets and variables → Actions)
- `ANTHROPIC_API_KEY` — ключ с console.anthropic.com для Claude Security Review
  - ⚠️ Ключ периодически протухает — если `security-review` падает с "API key not set", нужно обновить секрет и перезапустить job

### GitHub Actions (`.github/workflows/`)
| Файл | Триггер | Что делает |
|------|---------|-----------|
| `arcium-ci.yml` | push / PR / manual | 4 jobs: core-rust → ts-crypto → arcium-build → arcium-test |
| `android-ci.yml` | push/PR `android/**` | JDK 17 + Android SDK, `./gradlew assembleDebug` |
| `security-review.yml` | PR opened/sync | Claude Code security review на диффе PR |
| `monthly-backup.yml` | schedule | Бэкап в GitHub Releases |

### Версии CI (НЕ менять без проверки)
Берутся из `arcium-hq/setup-arcium@v0.10.4` defaults (README подтверждён):
- Rust: `stable --profile minimal`
- Node.js: `20` (job ts-crypto) / `24.10.0` (внутри arcium action)
- Solana CLI (agave/Anza): `3.1.10`
- Anchor CLI: `1.0.2`
- arcium CLI: `0.10.4`

### devcontainer (`.devcontainer/`)
Смёржен в PR #10. Покрывает: Rust, Node 20, Solana, Anchor, arcium, TS deps.
**Не покрывает:** Android SDK/NDK (собирается локально через android-ci).
Проверка: открыть Codespace → дождаться setup.sh → `cargo test --workspace`.

### История PR (все смёржены в main)
| PR | Ветка | Что сделано |
|----|-------|------------|
| #1 | snapshot | Восстановлены 11 крипто-тестов, исправлен Cargo.toml |
| #2 | snapshot | v1.0 Arcium PSI: circuit + Anchor handlers + CI pipeline |
| #3 | android-skeleton | v0.6 Android skeleton (Kotlin + Compose) |
| #4 | sec-fixes | M-2 (save_identity ошибки), L-2 (zeroize FFI), L-1 (Drop ratchet) |
| #5 | sec-fixes | clippy + cargo audit в CI ✅ смёржен |
| #6 | snapshot | Claude Security Review workflow + .gitignore |
| #7 | i2-contact-hash | I-2: документация hash_contact (ширина 64 бит, privacy model, M-3 caveat) |
| #8 | i1-solana-url | I-1: Solana RPC URL → BuildConfig (AGP 8+, buildConfig = true) |
| #9 | l3-fifo | L-3: trim_skipped FIFO (IndexMap) + zeroize при eviction |
| #10 | devcontainer | .devcontainer для GitHub Codespaces |

### Открытые задачи (НЕ начаты)
- **M-3** (NO-GO, отложен): RescueCipher stub в Rust остаётся — настоящий Rescue только в TS `@arcium-hq/client`. Нет Rust-крейта от Arcium без Solana стека.
- **devnet deploy**: нужен Anchor CLI + Solana CLI + открытая сеть (не sandbox).
- **drop_bounds warning** в `ratchet.rs:313`: безвредно, убрать при следующем касании файла.

### Тесты (текущее состояние, `cargo test --workspace`)
```
core-crypto    27/27 ✅  (24 base + 3 ratchet FIFO/zeroize)
core-protocol   5/5  ✅
core-storage   10/10 ✅
core-transport  5/5  ✅  (1 ignored — Tor без сети)
mobile-ffi      7/7  ✅
─────────────────────
Итого: 54/54, 0 упавших
```

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

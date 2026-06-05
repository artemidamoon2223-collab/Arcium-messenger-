# CLAUDE.md — Arcium Messenger

Этот файл читается автоматически при каждой сессии. Следуй ему всегда.

---

## Правила работы (Karpathy)
https://github.com/multica-ai/andrej-karpathy-skills

- **Think Before Coding** — сначала найди реальные значения/API в коде и пакетах, потом пиши. Не выдумывай.
- **Surgical Changes** — не удаляй существующий код. Добавляй, не ломай.
- **Goal-Driven** — у каждой задачи есть шаг проверки (cargo test / cargo check / tsc).
- **Не падай молча** — если что-то не работает, объясни почему фактами.
- **Короткие блоки кода** — разработчик на планшете. Дроби длинный код.
- **Не притворяйся** — если шаг нельзя проверить (нет сети/toolchain), скажи прямо.

Общение с разработчиком — на русском. Код и комментарии — на английском.

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
| #5 | sec-fixes | clippy + cargo audit в CI (PR открыт, статус проверить) |
| #6 | snapshot | Claude Security Review workflow + .gitignore |
| #7 | i2-contact-hash | I-2: документация hash_contact (ширина 64 бит, privacy model, M-3 caveat) |
| #8 | i1-solana-url | I-1: Solana RPC URL → BuildConfig (AGP 8+, buildConfig = true) |
| #9 | l3-fifo | L-3: trim_skipped FIFO (IndexMap) + zeroize при eviction |
| #10 | devcontainer | .devcontainer для GitHub Codespaces |

### Открытые задачи (НЕ начаты)
- **M-3** (NO-GO, отложен): RescueCipher stub в Rust остаётся — настоящий Rescue только в TS `@arcium-hq/client`. Нет Rust-крейта от Arcium без Solana стека.
- **PR #5** (clippy + cargo audit): статус не ясен — проверить перед следующей сессией.
- **devnet deploy**: нужен Anchor CLI + Solana CLI + открытая сеть (не sandbox).
- **drop_bounds warning** в `ratchet.rs:313`: безвредно, убрать при следующем касании файла.

### Тесты (текущее состояние, `cargo test --workspace`)
```
core-crypto    24/24 ✅
core-protocol   5/5  ✅
core-storage   10/10 ✅
core-transport  5/5  ✅  (1 ignored — Tor без сети)
mobile-ffi      7/7  ✅
─────────────────────
Итого: 51/51, 0 упавших
```

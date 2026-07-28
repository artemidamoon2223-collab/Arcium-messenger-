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
- **Security analysis** — использовать ТОЛЬКО признанные классы угроз: timing/cache/power/EM side-channel, X3DH/replay/OPK protocol bugs, PSI/MPC correctness, on-chain access control, traffic analysis, FFI boundary, supply chain. ❌ НЕ добавлять псевдонаучные модели (phase/frequency/Fibonacci/Mishin/quasicrystal/PhaseSCA).
- **Не инвентаризируй состояние репозитория** — в этом файле не место сигнатурам, счётчикам, деревьям каталогов, статусным таблицам, спискам веток и истории PR. Такие копии расходятся с репозиторием по построению. Читай исходники и GitHub.

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
- ml-kem = "0.3" (hybrid PQ, не 0.2; Cargo.toml pin = "0.3", exact patch locked by Cargo.lock)

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

## Workflow разработки

### Создать ветку и отправить PR
```bash
git checkout -b claude/<task-slug>
# ... изменения ...
cargo test --workspace          # должно быть 0 упавших
git push -u origin claude/<task-slug>
# → создать PR и остановиться: мёрдж — только по отдельному указанию владельца
```

### Обновить UniFFI биндинги для Android
```bash
# Шаг 1: генерация .kt из Rust (работает в sandbox)
cargo build -p mobile-ffi

# Шаг 2: компиляция .so (нужен NDK — только локально / android-ci.yml)
cargo ndk -t arm64-v8a build -p mobile-ffi --release
# выход: target/aarch64-linux-android/release/libarcium_core.so
```
Kotlin-биндинги уже скомпилированы в `android/app/src/main/kotlin/.../ffi/ArciumCore.kt`.

### Добавить тест
- **Rust**: `#[cfg(test)] mod tests { ... }` в конце файла крейта
- **TS**: `arcium-psi/tests/src/*.test.ts`; запуск: `npx mocha --require ts-node/register 'src/новый.test.ts'`

---

## GitHub — конфигурация

### Репозиторий
- `artemidamoon2223-collab/Arcium-messenger-`
- Основная ветка: `main`
- Соглашение по веткам: `claude/<task-slug>`
- Мёрж: обычный merge commit (НЕ squash), по отдельному указанию владельца

### Secrets (Settings → Secrets and variables → Actions)
- `ANTHROPIC_API_KEY` — ключ с console.anthropic.com для Claude Security Review **и karpathy-review**
  - ⚠️ Ключ периодически протухает — если `karpathy-review` или `security-review` падает, нужно обновить секрет и перезапустить job
  - ❌ НИКОГДА не добавляй `continue-on-error: true` в шаги AI-review — это превращает BLOCKING gate в advisory. Вместо этого обнови ключ.
  - ⚠️ Требует биллинга на **console.anthropic.com** (отдельно от claude.ai подписки). Без карты ключи генерируются, но API их отклоняет.
  - Проверь ключ перед вставкой: `curl -s https://api.anthropic.com/v1/models -H "x-api-key: KEY" -H "anthropic-version: 2023-06-01"` — должен вернуть `{"data":[`

### Версии CI (НЕ менять без проверки)
Берутся из defaults экшена `arcium-hq/setup-arcium@v0.10.4` — не бампай их вслепую, сверяйся с его README.

### devcontainer (`.devcontainer/`)
Смёржен в PR #10.
**Не покрывает:** Android SDK/NDK (собирается локально через android-ci).
Проверка: открыть Codespace → дождаться setup.sh → `cargo test --workspace`.

### Открытые задачи
- **PR #5** (clippy + cargo audit): ✅ смёржен 2026-06-07 владельцем.
- **ANTHROPIC_API_KEY**: нужен валидный ключ с биллингом на console.anthropic.com — оба gate блокируют PR без него. Проверить: `curl -s https://api.anthropic.com/v1/models -H "x-api-key: KEY" -H "anthropic-version: 2023-06-01"`.
- **M-3** (NO-GO, отложен): RescueCipher stub в Rust остаётся — настоящий Rescue только в TS `@arcium-hq/client`. Нет Rust-крейта от Arcium без Solana стека.
- **devnet deploy**: нужен Anchor CLI + Solana CLI + открытая сеть (не sandbox). См. `docs/HOME-DEPLOY.md`.
- **Branch protection** (owner-only): Settings → Branches → main → Require status checks → добавить `karpathy-review` + `security-review`. Без этого мерж возможен даже при красных гейтах.
- **Stale branches**: периодически просматривай GitHub UI → Settings → Branches и удаляй смёрженные/заброшенные ветки.
- **RUSTSEC-2025-0009 (ring 0.16.x)**: REVISIT AT SECURITY AUDIT — отслеживай выход arti-client, использующего ring ≥ 0.17.12. Как только появится — обновить arti-client и убрать ignore из `.cargo/audit.toml`.
- **RUSTSEC-2023-0071 (rsa 0.9.x)**: REVISIT AT SECURITY AUDIT — нет исправленной версии upstream. Следи за crates.io/crates/rsa.

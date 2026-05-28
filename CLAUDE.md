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
- arcis = "0.9.7" (генерирует .arcis.ir)
- @coral-xyz/anchor ^0.30, @arcium-hq/client ^0.10.4 (TS сторона)
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
v1.0 🚧 arcium-psi      Arcis circuit ✅ | Anchor handlers ✅ | deploy ⏳ (нужен toolchain)
v1.1 🚧 post-quantum    Hybrid X25519+ML-KEM ✅
TS tests 🚧             config ✅ | crypto 4/4 ✅ | setup ✅ | deploy/scenarios ⏳
```

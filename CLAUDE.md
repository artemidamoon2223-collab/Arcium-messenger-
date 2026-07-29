# CLAUDE.md — Arcium Messenger

Постоянное ядро: только то, что нужно почти в каждой сессии. Специализированные
процедуры лежат в `.claude/skills/` и подключаются по необходимости.

Общение с разработчиком — на русском. Код, комментарии, сообщения коммитов и
тела PR — на английском.

---

## Что за проект

Анонимный E2E-мессенджер для Android. Четыре слоя защиты: Tor onion (arti),
X3DH + Double Ratchet, шифрованный SQLite (XChaCha20-Poly1305), Arcium MPC для
приватного поиска контактов (PSI).

Ориентация: Rust-ядро в `crates/`, Anchor-программа и Arcis-circuit в
`arcium-psi/`, Android-приложение в `android/`, документация и трекер находок в
`docs/`. Подробная карта намеренно не живёт здесь — см.
`.claude/skills/engineering-code-review/references/repo-map.md`.

❌ Не инвентаризируй состояние репозитория в этом файле: здесь не место
сигнатурам, счётчикам файлов и воркфлоу, деревьям каталогов, статусным
таблицам, спискам веток и истории PR. Такие копии расходятся с репозиторием по
построению, а файл читается каждой сессией как истина (находка F-17 в
`docs/SECURITY-FINDINGS.md`). Читай исходники и GitHub. Одиночное версионное
ограничение, записанное как предупреждение, инвентарём не является.

---

## КРИТИЧЕСКИЕ криптографические правила

### Два РАЗНЫХ слоя, не путать
- **Сообщения:** XChaCha20-Poly1305 + Double Ratchet
- **PSI / контакты:** ТОЛЬКО RescueCipher (arithmetic-friendly, совместим с MPC)
- ❌ НИКОГДА не используй XChaCha20/AES для PSI — математически несовместимо с Arcium MPC
- ❌ НИКОГДА не используй RescueCipher для сообщений

### Хэш контакта — канонический стандарт, обе стороны ОБЯЗАНЫ совпадать
```
u64::from_le_bytes( sha256(phone.as_bytes())[0..8] )
```
Little-endian, первые 8 байт.

### OffChainCircuitSource
- .arcis circuit хостится на IPFS/CDN, НЕ загружается on-chain
- On-chain хранится только 32-байтный SHA256 хэш circuit
- ❌ НИКОГДА не встраивай circuit в смарт-контракт (раздувает gas в 100x)
- CIRCUIT_HASH ≠ git commit SHA. Это SHA256 файла psi_intersect.arcis.ir

### RescueCipher в Rust (`crates/core-crypto/src/rescue.rs`)
- Сейчас STUB на chacha20poly1305 как placeholder; API правильный
- НЕ заменяй на настоящий Rescue пока circuit не задеплоен на Arcium testnet
- Причина: arcium-client тянет весь Solana/Anchor стек → раздувает Android .so

### Обращение с криптокодом
Криптографическую логику, протоколы и параметры не меняй попутно с другой
задачей: отдельная задача, отдельный PR, явное указание владельца. Не выдавай
экспериментальный или заглушечный код за production-ready.

---

## Границы доказательств и формулировок

Действует во всех отчётах, телах PR и сообщениях коммитов.

- Успешная компиляция НЕ доказывает runtime-корректность, безопасность или
  корректность протокола.
- Зелёный CI-чек доказывает только то, что джоба доехала до конца. Если джоба
  маскирует ненулевой код возврата, её цвет не доказывает ничего —
  доказательством является лог.
- Тест-грин ≠ безопасно. Схема-валидно ≠ верно. Хорошо оформлено ≠ верно.
- Всегда указывай, чего результат НЕ устанавливает.
- Если шаг нельзя проверить (нет сети, toolchain или прав) — скажи это прямо;
  не выводи ответ по косвенным признакам и не выдавай догадку за факт.
- Собственный пересказ ранее сделанной работы доказательством не является.
  Claim подкрепляется путём с номером строки, SHA коммита или именем
  прошедшего теста. Перепроверяй номера строк перед цитированием.

---

## Анализ безопасности

Использовать ТОЛЬКО признанные классы угроз: timing/cache/power/EM
side-channel, X3DH/replay/OPK protocol bugs, PSI/MPC correctness, on-chain
access control, traffic analysis, FFI boundary, supply chain.

❌ НЕ добавлять псевдонаучные модели
(phase/frequency/Fibonacci/Mishin/quasicrystal/PhaseSCA).

---

## Окружение

- Песочница агента блокирует сеть (403 allowlist на api.devnet.solana.com)
- Anchor CLI / Solana CLI в песочнице не установлены
- ❌ НЕ пытайся deploy / airdrop / devnet-тесты в песочнице
- Deploy на devnet — отдельная задача с открытой сетью и toolchain,
  см. `docs/HOME-DEPLOY.md`

---

## Команды проверки

Подтверждены `.github/workflows/arcium-ci.yml` и `.devcontainer/setup.sh`:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cd arcium-psi/tests && npx tsc --noEmit
cd arcium-psi/tests && npx mocha --require ts-node/register 'src/crypto.test.ts'
```

Не закрывай задачу без явной проверки. Минимум: тесты — 0 упавших;
`tsc --noEmit` — 0 ошибок, если трогал TS; diff затрагивает ТОЛЬКО
запрошенное. Развёрнутый чеклист — в навыке `engineering-code-review`.

---

## Версии — не менять без причины

- arcium-client 0.10.4; arcium-anchor 0.10.4 требует anchor-lang `=1.0.2`
- arcis 0.10.4 (генерирует .arcis.ir)
- @coral-xyz/anchor ^0.30.1, @arcium-hq/client ^0.10.4 (TS-сторона)
- ml-kem `0.3` (hybrid PQ, не 0.2)
- Версии CI берутся из defaults `arcium-hq/setup-arcium@v0.10.4` — не бампай
  вслепую, сверяйся с его README

---

## Постоянные ограничения

- Мёрдж: обычный merge commit (НЕ squash) и только по отдельному явному
  указанию владельца. Зелёный CI указанием не является.
- ❌ НИКОГДА не добавляй `continue-on-error: true` в шаги AI-review
  (`security-review`, `karpathy-review`): это превращает блокирующий гейт в
  advisory. Вместо этого обнови `ANTHROPIC_API_KEY`.
- `ANTHROPIC_API_KEY` требует биллинга на console.anthropic.com (отдельно от
  подписки claude.ai). Проверка ключа перед вставкой:
  `curl -s https://api.anthropic.com/v1/models -H "x-api-key: KEY" -H "anthropic-version: 2023-06-01"`
  → должен вернуть `{"data":[`
- Branch protection на main — owner-only. Состав required status checks
  доступными инструментами не читается; не выводи его по косвенным признакам.
- M-3 (NO-GO): RescueCipher stub в Rust остаётся — настоящий Rescue есть только
  в TS `@arcium-hq/client`, Rust-крейта без Solana-стека нет.
- RUSTSEC-2025-0009 (ring 0.16.x) и RUSTSEC-2023-0071 (rsa 0.9.x): REVISIT AT
  SECURITY AUDIT. Ignore в `.cargo/audit.toml` снимать только после появления
  исправленной версии upstream.

---

## Навыки (`.claude/skills/`)

- **repo-change-protocol** — как выполняются изменения: одноразовый клон,
  дисциплина объёма, стандарты доказательств, построение PR, механика мёрджа,
  разделение фикса и обновления трекера. Ничего не авторизует.
- **engineering-code-review** — конкретные инженерные требования к правкам и
  ревью, чеклист сдачи, карта репозитория.
- **android-uniffi-bridge** — генерация UniFFI-биндингов, кросс-сборка `.so`,
  упаковка в APK и граница между compile/package и runtime-доказательством.

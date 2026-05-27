# Arcium Messenger — Project Context

## Security Architecture

| Слой | Защищает | Технология | Статус |
|------|----------|------------|--------|
| Tor onion | IP-адреса | arti crate | ✅ готово |
| X3DH+Ratchet | Сообщения | Curve25519 + XChaCha20 | ✅ готово |
| Arcium MPC | PSI контакты | RescueCipher (НЕ XChaCha20!) | 🚧 v1.0 |
| Solana | Метаданные | OffChainCircuitSource + 32-byte hash | 🚧 v1.0 |

⚠️ ВАЖНО: XChaCha20 математически несовместим с MPC-сетью Arcium.
Для PSI ОБЯЗАТЕЛЬНО использовать RescueCipher.

## PSI ARCHITECTURE

### Клиент (телефон) — лёгкие вычисления:
1. Хэши контактов: SHA256(phone_number)
2. Упаковка через RescueCipher + x25519 shared secret с MPC кластером
3. Отправка зашифрованного массива в Arcium

### Arcis circuit (тяжёлые вычисления на серверах Arcium):
```
#[instruction]
pub fn find_contacts(
    client_hashes: Enc<Shared, Vec<Hash>>,
    server_hashes: Enc<Shared, Vec<Hash>>,
) -> Enc<Shared, Vec<bool>> {
    let client = client_hashes.to_arcis();
    let server = server_hashes.to_arcis();
    client.iter().map(|c| server.contains(c)).collect()
}
// == и contains в Arcis = MPC протокол Cerberus, не CPU операция!
```

### Экономия газа (OffChainCircuitSource):
- БЕЗ паттерна: загрузить .arcis в Solana → $25+ газа
- С паттерном: записать 32-byte hash → $0.25 газа ✅
- .arcis файл хранится на IPFS/CDN
- В Anchor: OffChainCircuitSource { url, hash: [u8; 32] }

### Reference implementations (изучить перед v1.0):
- arcium-hq/examples — Blackjack, Voting, Auction (официальные)
- ANAVHEOBA/arcium_poker — ArcisRNG в MPC
- 0xsupremedev/private-orderflow-dex — сравнение вслепую

## Roadmap

| Версия | Крейт | Описание |
|--------|-------|----------|
| v0.1 ✅ | core-crypto | X3DH + Double Ratchet (11 тестов) |
| v0.2 ✅ | core-storage | Encrypted SQLite store (8 тестов) |
| v0.3 ✅ | core-transport | Tor transport skeleton (5 тестов) |
| v0.4 ✅ | core-protocol | SessionManager (5 тестов) |
| v0.5 ✅ | mobile-ffi | Identity + ArciumCore реальная логика (5 тестов) |
| v1.0 🚧 | arcium-psi | RescueCipher + psi_intersect.arcis + OffChainCircuitSource (только дома, нужен Solana CLI + Anchor) |

## ⚠️ ЗАПРЕЩЕНО ДЛЯ АГЕНТА — PSI реализация

При реализации v1.0 arcium-psi СТРОГО ЗАПРЕЩЕНО:
- ❌ SHA256 хэши напрямую как PSI вход (MPC не может обработать)
- ❌ XChaCha20/AES для шифрования PSI данных
- ❌ Встраивать .arcis circuit код in-chain в Anchor программу
- ✅ ВСЕГДА RescueCipher для PSI слоя
- ✅ ВСЕГДА OffChainCircuitSource паттерн

# Running the relay on a server

What this covers: one `arcium-relay` process on one rented Linux server,
reachable by the app over TCP, keeping its mailboxes on disk. What it does
not cover: Tor (F-15), several relays, monitoring beyond the system journal.

## 1. What the relay is trusted with

Nothing secret. Envelopes are end-to-end encrypted by the phones; the relay
stores and forwards them. It does see, and its disk holds: recipient and
sender keys, sizes and times. Treat the server as a metadata store: full-disk
encryption, no other services on it, access only by SSH key.

## 2. Build

On a machine with a current stable Rust toolchain (`rustup`), or on the
server itself:

```bash
git clone https://github.com/artemidamoon2223-collab/Arcium-messenger-.git
cd Arcium-messenger-
cargo build --release --locked -p relay --bin arcium-relay
# binary: target/release/arcium-relay
```

## 3. Install

```bash
sudo useradd --system --home /var/lib/arcium-relay --shell /usr/sbin/nologin arcium-relay
sudo install -d -o arcium-relay -g arcium-relay -m 0700 /var/lib/arcium-relay
sudo install -m 0755 target/release/arcium-relay /usr/local/bin/arcium-relay
```

Keys: `sudo -u arcium-relay arcium-relay keygen --out /var/lib/arcium-relay/keys --address relay.example.org:7700`
(use the server's public name or IP and the port the app connects to)
prints the connection string the app needs:
`arcium-relay-v2:<host>:<port>:<tls pin>:<auth key>`.
Keep the key file only on the server, mode 0600; back it up offline. A new
key file means a new connection string in every app.

## 4. systemd unit

`/etc/systemd/system/arcium-relay.service`:

```ini
[Unit]
Description=Arcium Messenger relay
After=network-online.target
Wants=network-online.target

[Service]
User=arcium-relay
Group=arcium-relay
ExecStart=/usr/local/bin/arcium-relay --listen 0.0.0.0:7700 \
  --db /var/lib/arcium-relay/relay.db --keys /var/lib/arcium-relay/keys
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/arcium-relay
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now arcium-relay
journalctl -u arcium-relay -f
```

## 5. Firewall

Open only SSH and the relay port, for example with `ufw`:

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 7700/tcp
sudo ufw enable
```

## 6. Configure the app

In the app, open Settings and paste the connection string printed by
`keygen` into the relay field. Settings then shows "Encrypted relay". A
release build accepts only such a string (`android/README.md`, "Configuring
a relay"). Everyone who should reach each other enters the same string.

Check from any machine that the port answers (the TLS handshake itself
needs the app or the relay's own client):

```bash
nc -vz relay.example.org 7700
```

## 7. Backups and updates

- The database (`relay.db`, with its `-wal` and `-shm` files) holds only
  undelivered envelopes and bundles; losing it delays delivery (senders
  retransmit) but loses no message. A backup is optional. A database a V2
  relay has served is refused by a relay started without `--keys`.
- Keep the clock correct (NTP, enabled by default on most distributions):
  envelope ages are recomputed from the wall clock after a restart.
- The key file must be backed up: without it the apps cannot verify the
  relay.
- Update: build the new binary, `systemctl stop`, replace, `systemctl start`.
  The database survives restarts; a file of an unknown schema version is
  refused rather than reinterpreted.

## 8. Limits to know

- One thread per connection; at most 1024 connections, 32 per IP address
  (`--max-connections`, `--max-connections-per-address`); 4096 envelopes per
  mailbox and 1 GiB of envelopes in all (`--max-total-bytes`). No rate limit
  on SENDs beyond those caps.
- Anyone can still send to any mailbox (needed for first contact); a full
  mailbox refuses new envelopes.
- The relay operator (whoever controls the server) can withhold, delete or
  reorder envelopes and sees metadata. The phones detect forgery and replay;
  they cannot detect withholding.

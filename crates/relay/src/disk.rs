//! Optional durable storage for the relay: one SQLite file
//! ([`RelayConfig::db`](crate::server::RelayConfig::db)).
//!
//! The relay keeps serving from memory. This file is written through before
//! a request that changes stored state is answered, so an envelope the relay
//! accepted (`SEND` answered OK) survives a restart, and so does a deletion
//! (`DELETE` answered OK) and a bundle (`PUT_BUNDLE` answered OK). If a
//! write fails, the request is not answered and the connection is closed:
//! the client sees a network error and retries, as after any lost answer.
//!
//! Stored as received: envelopes are end-to-end encrypted by the endpoints;
//! their recipient keys, sizes and arrival times are not. Encrypting the disk
//! is left to the host. The file (and SQLite's `-wal` and `-shm` beside it) is
//! readable by its owner only, and `secure_delete` overwrites deleted rows.
//!
//! While the disk refuses writes (full, failing), every SEND and DELETE, and
//! every PUT_BUNDLE that changes a bundle, is refused this way until the disk
//! is fixed; reads keep working, and a PUT_BUNDLE of the bundle already
//! stored is answered without a write.
//!
//! Ages are kept with the monotonic clock while the relay runs, and with the
//! wall clock in the file: a restart computes each envelope's age from the
//! wall clock. If the host's clock jumped forward by more than the TTL
//! between two runs, envelopes the relay had accepted are dropped at load;
//! if it went back, they are kept longer. The host needs a correct clock.
//!
//! Sequence numbers are `u64` and stored bit for bit in SQLite's signed
//! 64-bit `INTEGER`; nothing here orders by them in SQL.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::protocol::Key;

/// The layout this build writes and reads.
const SCHEMA_VERSION: i64 = 1;

/// The relay's durable state.
pub(crate) struct Disk {
    conn: Connection,
}

/// What [`Disk::load`] found: envelopes still within the TTL, with their age.
pub(crate) struct Loaded {
    pub next_seq: u64,
    pub envelopes: Vec<(Key, u64, Duration, Vec<u8>)>,
    pub bundles: Vec<(Key, Vec<u8>)>,
}

fn io_err(e: rusqlite::Error) -> io::Error {
    io::Error::other(format!("relay database: {e}"))
}

fn key_of(bytes: Vec<u8>) -> io::Result<Key> {
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "relay database: bad key length"))
}

/// Makes `path` readable and writable by its owner only, creating it empty
/// if missing, before SQLite opens it (SQLite gives `-wal` and `-shm` the
/// database file's permissions); existing `-wal` and `-shm` files are
/// restricted too.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?
        .set_permissions(Permissions::from_mode(0o600))?;
    for suffix in ["-wal", "-shm"] {
        let mut side = path.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            std::fs::set_permissions(&side, Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Milliseconds since the Unix epoch, now.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Disk {
    /// Opens (or creates) the database at `path`. Refuses a file written by
    /// another schema version.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        restrict(path)?;
        let conn = Connection::open(path).map_err(io_err)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> io::Result<Self> {
        // WAL with FULL sync: a committed transaction survives a crash or a
        // power loss of the host, as far as the disk keeps its promises. In
        // a rollback journal, FULL could lose the last commit on power loss,
        // so a database that does not switch to WAL is refused.
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .map_err(io_err)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(io::Error::other(format!(
                "relay database: journal mode is {mode}, not WAL"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL").map_err(io_err)?;
        conn.pragma_update(None, "secure_delete", "ON").map_err(io_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS envelopes (
                 seq INTEGER PRIMARY KEY,
                 recipient BLOB NOT NULL,
                 stored_at_ms INTEGER NOT NULL,
                 bytes BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS bundles (owner BLOB PRIMARY KEY, bytes BLOB NOT NULL);",
        )
        .map_err(io_err)?;
        let version: Option<i64> = conn
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| r.get(0))
            .optional()
            .map_err(io_err)?;
        match version {
            None => {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema', ?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(io_err)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("relay database has schema {other}, this build reads {SCHEMA_VERSION}"),
                ))
            }
        }
        Ok(Self { conn })
    }

    /// Everything stored, without envelopes older than `ttl` (which are
    /// deleted from the file now). `next_seq` is never below 1 or below any
    /// stored sequence number plus one.
    pub(crate) fn load(&self, ttl: Duration) -> io::Result<Loaded> {
        let now = now_ms();
        let cutoff = now.saturating_sub(ttl.as_millis().min(u64::MAX as u128) as u64);
        self.conn
            .execute("DELETE FROM envelopes WHERE stored_at_ms < ?1", params![cutoff as i64])
            .map_err(io_err)?;
        let mut next_seq: u64 = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'next_seq'", [], |r| r.get::<_, i64>(0))
            .optional()
            .map_err(io_err)?
            .map_or(1, |v| v as u64)
            .max(1);
        let mut stmt = self
            .conn
            .prepare("SELECT recipient, seq, stored_at_ms, bytes FROM envelopes")
            .map_err(io_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(io_err)?;
        let mut envelopes = Vec::new();
        for row in rows {
            let (recipient, seq, stored_at, bytes) = row.map_err(io_err)?;
            if let Some(after) = seq.checked_add(1) {
                next_seq = next_seq.max(after);
            } else {
                // `u64::MAX` is stored: nothing more can be numbered.
                next_seq = u64::MAX;
            }
            // A stored time in the future (the clock moved back) counts as now.
            let age = Duration::from_millis(now.saturating_sub(stored_at));
            envelopes.push((key_of(recipient)?, seq, age, bytes));
        }
        let mut stmt = self.conn.prepare("SELECT owner, bytes FROM bundles").map_err(io_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(io_err)?;
        let mut bundles = Vec::new();
        for row in rows {
            let (owner, bytes) = row.map_err(io_err)?;
            bundles.push((key_of(owner)?, bytes));
        }
        Ok(Loaded {
            next_seq,
            envelopes,
            bundles,
        })
    }

    /// Stores an accepted envelope and the next sequence number, in one
    /// transaction.
    pub(crate) fn store_envelope(
        &mut self,
        seq: u64,
        recipient: &Key,
        stored_at_ms: u64,
        bytes: &[u8],
        next_seq: u64,
    ) -> io::Result<()> {
        let tx = self.conn.transaction().map_err(io_err)?;
        tx.execute(
            "INSERT INTO envelopes (seq, recipient, stored_at_ms, bytes) VALUES (?1, ?2, ?3, ?4)",
            params![seq as i64, &recipient[..], stored_at_ms as i64, bytes],
        )
        .map_err(io_err)?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('next_seq', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![next_seq as i64],
        )
        .map_err(io_err)?;
        tx.commit().map_err(io_err)
    }

    /// Deletes `recipient`'s envelopes numbered `seqs`, in one transaction.
    /// Numbers not stored are ignored, as by `DELETE`.
    pub(crate) fn delete_envelopes(&mut self, recipient: &Key, seqs: &[u64]) -> io::Result<()> {
        if seqs.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction().map_err(io_err)?;
        {
            let mut stmt = tx
                .prepare("DELETE FROM envelopes WHERE seq = ?1 AND recipient = ?2")
                .map_err(io_err)?;
            for seq in seqs {
                stmt.execute(params![*seq as i64, &recipient[..]]).map_err(io_err)?;
            }
        }
        tx.commit().map_err(io_err)
    }

    /// Stores (or replaces) `owner`'s bundle.
    pub(crate) fn put_bundle(&mut self, owner: &Key, bytes: &[u8]) -> io::Result<()> {
        self.conn
            .execute(
                "INSERT INTO bundles (owner, bytes) VALUES (?1, ?2)
                 ON CONFLICT(owner) DO UPDATE SET bytes = excluded.bytes",
                params![&owner[..], bytes],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    /// Test aid: a database that refuses every write, as a full or failing
    /// disk would.
    #[cfg(test)]
    pub(crate) fn read_only(path: &Path) -> io::Result<Self> {
        use rusqlite::OpenFlags;
        Self::open(path)?; // create the schema first
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(io_err)?;
        Ok(Self { conn })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sequence numbers above `i64::MAX` survive the signed column, and the
    /// counter never restarts below a stored number.
    #[test]
    fn sequence_numbers_near_the_top_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let mut disk = Disk::open(&path).unwrap();
        disk.store_envelope(u64::MAX - 1, &[3; 32], now_ms(), b"x", u64::MAX).unwrap();
        disk.store_envelope(5, &[3; 32], now_ms(), b"y", 6).unwrap();
        drop(disk);
        let loaded = Disk::open(&path).unwrap().load(Duration::from_secs(60)).unwrap();
        assert_eq!(loaded.next_seq, u64::MAX, "the larger stored number wins over a lower counter");
        let mut seqs: Vec<u64> = loaded.envelopes.iter().map(|e| e.1).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![5, u64::MAX - 1]);
    }

    /// A file written by another schema version is refused, not reinterpreted.
    #[test]
    fn another_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        drop(Disk::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute("UPDATE meta SET value = 2 WHERE key = 'schema'", [])
            .unwrap();
        let err = Disk::open(&path).err().expect("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The file and SQLite's files beside it are readable by their owner only.
    #[cfg(unix)]
    #[test]
    fn the_database_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let mut disk = Disk::open(&path).unwrap();
        disk.store_envelope(1, &[1; 32], now_ms(), b"a", 2).unwrap();
        for name in ["relay.db", "relay.db-wal", "relay.db-shm"] {
            let mode = std::fs::metadata(dir.path().join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{name}: {mode:o}");
        }
    }

    /// Deleting numbers that are not stored, or another recipient's, changes
    /// nothing.
    #[test]
    fn deletes_touch_only_the_named_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let mut disk = Disk::open(&path).unwrap();
        disk.store_envelope(1, &[1; 32], now_ms(), b"a", 2).unwrap();
        disk.delete_envelopes(&[2; 32], &[1, 99]).unwrap();
        let loaded = disk.load(Duration::from_secs(60)).unwrap();
        assert_eq!(loaded.envelopes.len(), 1);
        assert_eq!(loaded.next_seq, 2);
    }
}

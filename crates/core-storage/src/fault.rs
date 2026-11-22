//! Scripted failures of store operations, for tests.
//!
//! Compiled into this crate's own tests, and into a build that enables the
//! `fault-injection` feature. Only a `[dev-dependencies]` entry may enable
//! it (`tests/feature_graph.rs` checks the workspace), and a build for
//! Android with it on does not compile (`lib.rs`).
//!
//! A test arms one fault for the thread it runs on: the n-th operation of a
//! kind, or of any kind, that this thread then makes through an
//! [`EncryptedStore`](crate::EncryptedStore) or a
//! [`StoreTransaction`](crate::StoreTransaction) returns an I/O error
//! instead of its result, and the fault is spent. Other threads are not
//! affected, so tests that run in parallel do not disturb each other.
//!
//! ```text
//! let fault = fault::arm(fault::Op::Commit, 0, fault::Outcome::Committed);
//! let result = code_under_test(&mut store);
//! assert!(fault.fired());
//! ```
//!
//! # What this is not
//!
//! Nothing here makes SQLite or the file system fail. The store returns an
//! error of the kind a failed operation returns (SQLite's primary
//! `SQLITE_IOERR` code, with a message of its own, not the extended code and
//! text of a real failure), and either does not run the operation or (a
//! commit, [`Outcome::Committed`]) runs it to completion first. It cannot
//! produce a torn write, a lost `fsync` or a power cut, and
//! it says nothing about what SQLite does after a real I/O error beyond the
//! two documented cases it copies: the statement alone is undone
//! ([`Outcome::NotRun`]), or SQLite ends the whole transaction
//! ([`Outcome::TransactionEnded`]).

use crate::StorageError;
use rusqlite::Connection;
use std::cell::RefCell;
use std::marker::PhantomData;

/// A store operation a fault can be armed for. An operation counts once the
/// store's own check of the transaction state has let it through, whatever
/// it then returns: one refused by that check (for example a `put` through
/// a transaction SQLite already ended) is neither counted nor listed by
/// [`trace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `get`, on the store or in a transaction.
    Get,
    /// `put`, on the store or in a transaction.
    Put,
    /// `delete`, on the store or in a transaction.
    Delete,
    /// `EncryptedStore::list_keys_with_prefix`.
    List,
    /// `EncryptedStore::transaction`.
    Begin,
    /// `StoreTransaction::commit`.
    Commit,
}

/// What the store does when an armed fault fires. The operation returns an
/// error in every case ([`is_injected`] recognises it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The operation does not run. Inside a transaction the transaction
    /// stays open, with the writes made before: what SQLite does when it
    /// undoes one failed statement. A commit is not attempted and its
    /// transaction is rolled back.
    NotRun,
    /// Inside a transaction: the operation does not run and the whole
    /// transaction is rolled back at once, as SQLite does on its own after
    /// some errors. Later operations through the same handle are refused
    /// and its commit fails. Anywhere else: as [`Outcome::NotRun`].
    TransactionEnded,
    /// A commit only: the commit runs to completion, then the error is
    /// returned. The caller sees a failed commit whose writes are stored.
    /// If the commit itself fails, its own error is returned instead, and
    /// the fault is spent all the same.
    Committed,
}

struct Pending {
    /// Which [`Armed`] this belongs to.
    id: u64,
    /// `None`: an operation of any kind.
    op: Option<Op>,
    /// How many matching operations run normally first.
    skip: usize,
    outcome: Outcome,
}

struct State {
    pending: Option<Pending>,
    /// The id the next armed fault gets.
    next_id: u64,
    trace: Option<Vec<Op>>,
}

thread_local! {
    static STATE: RefCell<State> = const {
        RefCell::new(State {
            pending: None,
            next_id: 0,
            trace: None,
        })
    };
}

/// An armed fault. Dropping it disarms the fault if it has not fired, so a
/// fault never outlives the test that armed it, also when that test panics.
/// It answers for its own fault only: once that fired, another may be armed
/// while this one is still held, and neither disturbs the other.
#[must_use = "the fault is disarmed when this is dropped"]
pub struct Armed {
    id: u64,
    // Dropped on the thread that armed it.
    _not_send: PhantomData<*const ()>,
}

impl Armed {
    /// Whether the fault fired: the operation it waited for was made and
    /// failed.
    pub fn fired(&self) -> bool {
        !self.waits()
    }

    fn waits(&self) -> bool {
        STATE.with(|s| s.borrow().pending.as_ref().is_some_and(|p| p.id == self.id))
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        if self.waits() {
            STATE.with(|s| s.borrow_mut().pending = None);
        }
    }
}

/// Arms a fault for the `nth` operation of kind `op` (0 is the next one)
/// this thread makes from now on.
///
/// # Panics
///
/// If a fault is already armed on this thread, or if `outcome` is
/// [`Outcome::Committed`] and `op` is not [`Op::Commit`].
pub fn arm(op: Op, nth: usize, outcome: Outcome) -> Armed {
    assert!(
        outcome != Outcome::Committed || op == Op::Commit,
        "Outcome::Committed is for Op::Commit only"
    );
    set(Some(op), nth, outcome)
}

/// Arms a fault for the `nth` operation of any kind (0 is the next one)
/// this thread makes from now on. With the list [`trace`] returns, a test
/// can fail each operation of a piece of code in turn.
///
/// # Panics
///
/// If a fault is already armed on this thread, or if `outcome` is
/// [`Outcome::Committed`], which only a commit can have.
pub fn arm_any(nth: usize, outcome: Outcome) -> Armed {
    assert!(
        outcome != Outcome::Committed,
        "Outcome::Committed is for Op::Commit only"
    );
    set(None, nth, outcome)
}

fn set(op: Option<Op>, skip: usize, outcome: Outcome) -> Armed {
    let id = STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(
            s.pending.is_none(),
            "a fault is already armed on this thread"
        );
        let id = s.next_id;
        s.next_id += 1;
        s.pending = Some(Pending {
            id,
            op,
            skip,
            outcome,
        });
        id
    });
    Armed {
        id,
        _not_send: PhantomData,
    }
}

/// Runs `f` and returns its result with every store operation this thread
/// asked for meanwhile, in order. An operation an armed fault failed is
/// listed too.
///
/// # Panics
///
/// If called inside another `trace` on the same thread.
pub fn trace<R>(f: impl FnOnce() -> R) -> (R, Vec<Op>) {
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            STATE.with(|s| s.borrow_mut().trace = None);
        }
    }
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(s.trace.is_none(), "trace is already running on this thread");
        s.trace = Some(Vec::new());
    });
    let _stop = Stop;
    let result = f();
    let ops = STATE.with(|s| s.borrow_mut().trace.take().unwrap_or_default());
    (result, ops)
}

/// Whether `error` is the one an armed fault returns.
pub fn is_injected(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::Db(rusqlite::Error::SqliteFailure(_, Some(message))) if message == MESSAGE
    )
}

const MESSAGE: &str = "injected storage fault";

/// The error a fault returns: an I/O failure as SQLite reports one.
pub(crate) fn injected() -> StorageError {
    StorageError::Db(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
        Some(MESSAGE.to_string()),
    ))
}

/// Notes `op` for [`trace`], and returns the outcome of the armed fault if
/// this is the operation it waited for. The fault is then spent.
fn hit(op: Op) -> Option<Outcome> {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if let Some(trace) = s.trace.as_mut() {
            trace.push(op);
        }
        let pending = s.pending.as_mut()?;
        if pending.op.is_some_and(|wanted| wanted != op) {
            return None;
        }
        if pending.skip > 0 {
            pending.skip -= 1;
            return None;
        }
        s.pending.take().map(|p| p.outcome)
    })
}

/// Before an operation outside a transaction.
pub(crate) fn before(op: Op) -> Result<(), StorageError> {
    match hit(op) {
        None => Ok(()),
        Some(_) => Err(injected()),
    }
}

/// Before an operation inside the transaction open on `conn`.
pub(crate) fn before_in_transaction(op: Op, conn: &Connection) -> Result<(), StorageError> {
    match hit(op) {
        None => Ok(()),
        Some(Outcome::TransactionEnded) => {
            // What SQLite does on its own after some errors. The handle then
            // finds the connection in autocommit mode and refuses to go on.
            let _ = conn.execute_batch("ROLLBACK");
            Err(injected())
        }
        Some(_) => Err(injected()),
    }
}

/// At a commit: `Some(true)` to commit and then fail, `Some(false)` to fail
/// without committing, `None` to commit normally.
pub(crate) fn at_commit() -> Option<bool> {
    hit(Op::Commit).map(|outcome| outcome == Outcome::Committed)
}

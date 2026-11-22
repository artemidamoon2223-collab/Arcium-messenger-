//! The fault layer does what `fault.rs` says, and only that: the armed
//! operation fails, the others run, and the store ends in the state each
//! [`Outcome`] names.

use super::fault::{self, Op, Outcome};
use super::*;

fn store() -> EncryptedStore {
    EncryptedStore::open_in_memory([9u8; 32]).unwrap()
}

/// `result` is the error an armed fault returns.
#[track_caller]
fn injected<T: std::fmt::Debug>(result: Result<T, StorageError>) {
    let error = result.expect_err("the armed fault fires");
    assert!(fault::is_injected(&error), "{error}");
}

#[track_caller]
fn missing(store: &EncryptedStore, key: &str) {
    assert!(
        matches!(store.get(key), Err(StorageError::NotFound)),
        "{key}"
    );
}

#[test]
fn the_nth_operation_of_the_kind_fails_and_the_others_run() {
    let s = store();
    let fault = fault::arm(Op::Put, 1, Outcome::NotRun);
    s.put("a", b"1").unwrap();
    assert!(!fault.fired());
    injected(s.put("b", b"2"));
    assert!(fault.fired());
    s.put("c", b"3").unwrap();
    assert_eq!(s.get("a").unwrap(), b"1");
    missing(&s, "b");
    assert_eq!(s.get("c").unwrap(), b"3");
}

#[test]
fn an_operation_of_another_kind_does_not_fire_the_fault() {
    let s = store();
    let fault = fault::arm(Op::Delete, 0, Outcome::NotRun);
    s.put("a", b"1").unwrap();
    assert_eq!(s.get("a").unwrap(), b"1");
    assert!(!fault.fired());
    injected(s.delete("a"));
    assert_eq!(s.get("a").unwrap(), b"1", "the delete did not run");
}

/// An operation counts when it is asked for, whatever it returns.
#[test]
fn an_operation_that_fails_by_itself_still_counts() {
    let s = store();
    s.put("a", b"1").unwrap();
    let _fault = fault::arm(Op::Get, 1, Outcome::NotRun);
    missing(&s, "absent");
    injected(s.get("a"));
}

#[test]
fn every_operation_outside_a_transaction_can_fail_and_changes_nothing() {
    let mut s = store();
    s.put("ns:a", b"1").unwrap();
    {
        let _fault = fault::arm(Op::Get, 0, Outcome::NotRun);
        injected(s.get("ns:a"));
    }
    {
        let _fault = fault::arm(Op::Delete, 0, Outcome::NotRun);
        injected(s.delete("ns:a"));
    }
    {
        let _fault = fault::arm(Op::List, 0, Outcome::NotRun);
        injected(s.list_keys_with_prefix("ns:"));
    }
    {
        let _fault = fault::arm(Op::Begin, 0, Outcome::NotRun);
        injected(s.transaction().map(|_| ()));
    }
    {
        // Nothing to end outside a transaction: as `NotRun`.
        let _fault = fault::arm(Op::Put, 0, Outcome::TransactionEnded);
        injected(s.put("ns:b", b"2"));
    }
    assert_eq!(s.get("ns:a").unwrap(), b"1");
    assert_eq!(s.list_keys_with_prefix("ns:").unwrap(), ["ns:a"]);
    s.transaction().unwrap().commit().unwrap();
}

/// `NotRun` inside a transaction: the statement alone is lost. The
/// transaction stays open with what was written before, as its
/// documentation says of a failed operation.
#[test]
fn a_failed_operation_leaves_its_transaction_open() {
    let mut s = store();
    let fault = fault::arm(Op::Put, 1, Outcome::NotRun);
    let tx = s.transaction().unwrap();
    tx.put("a", b"1").unwrap();
    injected(tx.put("b", b"2"));
    assert!(fault.fired());
    assert_eq!(tx.get("a").unwrap(), b"1");
    tx.commit().unwrap();
    assert_eq!(s.get("a").unwrap(), b"1");
    missing(&s, "b");
}

/// `TransactionEnded`: everything written so far is gone, the handle refuses
/// to go on, its commit fails (with SQLite's own error), and the store works
/// afterwards.
#[test]
fn a_fault_that_ends_the_transaction_discards_it() {
    let mut s = store();
    s.put("old", b"0").unwrap();
    let fault = fault::arm(Op::Delete, 0, Outcome::TransactionEnded);
    let tx = s.transaction().unwrap();
    tx.put("a", b"1").unwrap();
    injected(tx.delete("old"));
    assert!(fault.fired());
    assert!(matches!(
        tx.put("b", b"2"),
        Err(StorageError::TransactionStateInvalid(_))
    ));
    assert!(matches!(
        tx.get("a"),
        Err(StorageError::TransactionStateInvalid(_))
    ));
    let error = tx.commit().expect_err("no transaction is left to commit");
    assert!(!fault::is_injected(&error), "{error}");
    missing(&s, "a");
    missing(&s, "b");
    assert_eq!(s.get("old").unwrap(), b"0");
    s.put("c", b"3").unwrap();
    s.transaction().unwrap().commit().unwrap();
}

#[test]
fn a_commit_that_does_not_run_stores_nothing() {
    for outcome in [Outcome::NotRun, Outcome::TransactionEnded] {
        let mut s = store();
        let fault = fault::arm(Op::Commit, 0, outcome);
        let tx = s.transaction().unwrap();
        tx.put("a", b"1").unwrap();
        tx.put("b", b"2").unwrap();
        injected(tx.commit());
        assert!(fault.fired());
        missing(&s, "a");
        missing(&s, "b");
        s.transaction().unwrap().commit().unwrap();
    }
}

/// `Committed`: the caller is told the commit failed, and the store holds
/// every write of it.
#[test]
fn a_commit_that_fails_after_it_ran_stores_everything() {
    let mut s = store();
    let fault = fault::arm(Op::Commit, 0, Outcome::Committed);
    let tx = s.transaction().unwrap();
    tx.put("a", b"1").unwrap();
    tx.put("b", b"2").unwrap();
    injected(tx.commit());
    assert!(fault.fired());
    assert_eq!(s.get("a").unwrap(), b"1");
    assert_eq!(s.get("b").unwrap(), b"2");
}

#[test]
fn dropping_an_armed_fault_disarms_it() {
    let s = store();
    {
        let fault = fault::arm(Op::Put, 0, Outcome::NotRun);
        assert!(!fault.fired());
    }
    s.put("a", b"1").unwrap();
    let _again = fault::arm(Op::Put, 0, Outcome::NotRun);
}

/// Each `Armed` answers for its own fault. Once the first fired, a second
/// can be armed while the first is still held: the first still reads as
/// fired, the second as waiting, and dropping the first does not disarm the
/// second.
#[test]
fn a_spent_fault_does_not_disturb_the_next_one() {
    let s = store();
    let first = fault::arm(Op::Put, 0, Outcome::NotRun);
    injected(s.put("a", b"1"));
    assert!(first.fired());
    let second = fault::arm(Op::Put, 0, Outcome::NotRun);
    assert!(first.fired(), "the first fault fired, whatever waits now");
    assert!(!second.fired());
    drop(first);
    assert!(!second.fired(), "dropping the first left the second armed");
    injected(s.put("a", b"1"));
    assert!(second.fired());
    missing(&s, "a");
}

/// An operation the store's transaction-state check refuses is neither
/// counted nor listed; one an armed fault fails is listed.
#[test]
fn trace_lists_a_faulted_operation_and_not_a_refused_one() {
    let mut s = store();
    let fault = fault::arm(Op::Put, 0, Outcome::TransactionEnded);
    let ((), ops) = fault::trace(|| {
        let tx = s.transaction().unwrap();
        injected(tx.put("a", b"1"));
        assert!(matches!(
            tx.put("b", b"2"),
            Err(StorageError::TransactionStateInvalid(_))
        ));
    });
    assert!(fault.fired());
    assert_eq!(ops, [Op::Begin, Op::Put]);
}

/// A second `trace` inside one panics and leaves the outer list as it was.
#[test]
fn a_nested_trace_is_refused_and_the_outer_one_keeps_its_list() {
    let s = store();
    let ((), ops) = fault::trace(|| {
        s.put("a", b"1").unwrap();
        let nested = std::panic::catch_unwind(|| fault::trace(|| ()));
        assert!(nested.is_err());
    });
    assert_eq!(
        ops,
        [Op::Put],
        "the put noted before the nested call is kept"
    );
}

/// A test that panics while a fault waits, or inside `trace`, leaves neither
/// behind on its thread.
#[test]
fn a_panic_leaves_no_fault_and_no_trace_behind() {
    let s = store();
    let caught = std::panic::catch_unwind(|| {
        let _fault = fault::arm(Op::Put, 0, Outcome::NotRun);
        fault::trace(|| panic!("the test failed"));
    });
    assert!(caught.is_err());
    s.put("a", b"1").unwrap();
    let ((), ops) = fault::trace(|| s.put("b", b"2").unwrap());
    assert_eq!(ops, [Op::Put]);
}

#[test]
#[should_panic(expected = "already armed")]
fn a_second_fault_cannot_be_armed_while_one_waits() {
    let _first = fault::arm(Op::Put, 0, Outcome::NotRun);
    let _second = fault::arm(Op::Get, 0, Outcome::NotRun);
}

#[test]
#[should_panic(expected = "Op::Commit only")]
fn committed_is_refused_for_an_operation_that_is_not_a_commit() {
    let _fault = fault::arm(Op::Put, 0, Outcome::Committed);
}

#[test]
#[should_panic(expected = "Op::Commit only")]
fn committed_is_refused_for_an_operation_of_any_kind() {
    let _fault = fault::arm_any(0, Outcome::Committed);
}

#[test]
fn trace_lists_the_operations_in_order() {
    let mut s = store();
    let ((), ops) = fault::trace(|| {
        s.put("ns:a", b"1").unwrap();
        missing(&s, "ns:absent");
        s.delete("ns:a").unwrap();
        s.list_keys_with_prefix("ns:").unwrap();
        let tx = s.transaction().unwrap();
        tx.put("ns:b", b"2").unwrap();
        tx.get("ns:b").unwrap();
        tx.delete("ns:b").unwrap();
        tx.commit().unwrap();
    });
    assert_eq!(
        ops,
        [
            Op::Put,
            Op::Get,
            Op::Delete,
            Op::List,
            Op::Begin,
            Op::Put,
            Op::Get,
            Op::Delete,
            Op::Commit
        ]
    );
    s.put("ns:c", b"3").unwrap();
    let ((), none) = fault::trace(|| ());
    assert!(none.is_empty(), "nothing is noted outside `trace`");
}

/// A fault armed on one thread does not fire for another thread's store.
#[test]
fn a_fault_belongs_to_the_thread_that_armed_it() {
    let s = store();
    let fault = fault::arm(Op::Put, 0, Outcome::NotRun);
    std::thread::spawn(|| {
        let other = store();
        other.put("a", b"1").unwrap();
        assert_eq!(other.get("a").unwrap(), b"1");
    })
    .join()
    .unwrap();
    assert!(!fault.fired());
    injected(s.put("a", b"1"));
}

#[test]
fn only_the_injected_error_is_recognised() {
    let error = fault::injected();
    assert!(fault::is_injected(&error));
    assert!(
        error.to_string().contains("injected storage fault"),
        "{error}"
    );
    assert!(!fault::is_injected(&StorageError::NotFound));
    assert!(!fault::is_injected(&StorageError::Decryption));
    assert!(!fault::is_injected(&StorageError::TransactionStateInvalid(
        "x"
    )));
    let real = store()
        .conn
        .execute("INSERT INTO no_such_table VALUES (1)", [])
        .expect_err("no such table");
    assert!(!fault::is_injected(&StorageError::Db(real)));
}

/// What the layer is for: fail each operation of a piece of code in turn.
/// A function that replaces two records in one transaction and leaves with
/// `?` on any error ends with both old records or (a commit that failed
/// after it ran) both new ones, never one of each.
#[test]
fn failing_each_operation_in_turn_leaves_both_records_or_neither() {
    fn fresh() -> EncryptedStore {
        let s = store();
        s.put("acct:a", b"old-a").unwrap();
        s.put("acct:b", b"old-b").unwrap();
        s
    }
    fn replace_both(s: &mut EncryptedStore) -> Result<(), StorageError> {
        let tx = s.transaction()?;
        tx.get("acct:a")?;
        tx.put("acct:a", b"new-a")?;
        tx.put("acct:b", b"new-b")?;
        tx.commit()
    }
    fn both(s: &EncryptedStore) -> (Vec<u8>, Vec<u8>) {
        (s.get("acct:a").unwrap(), s.get("acct:b").unwrap())
    }
    let old = (b"old-a".to_vec(), b"old-b".to_vec());
    let new = (b"new-a".to_vec(), b"new-b".to_vec());

    let mut s = fresh();
    let (result, ops) = fault::trace(|| replace_both(&mut s));
    result.unwrap();
    assert_eq!(ops, [Op::Begin, Op::Get, Op::Put, Op::Put, Op::Commit]);
    assert_eq!(both(&s), new);

    for outcome in [Outcome::NotRun, Outcome::TransactionEnded] {
        for n in 0..ops.len() {
            let mut s = fresh();
            let fault = fault::arm_any(n, outcome);
            injected(replace_both(&mut s));
            assert!(fault.fired(), "{outcome:?} at operation {n}");
            drop(fault);
            assert_eq!(both(&s), old, "{outcome:?} at operation {n}");
        }
    }
    let mut s = fresh();
    let fault = fault::arm(Op::Commit, 0, Outcome::Committed);
    injected(replace_both(&mut s));
    drop(fault);
    assert_eq!(both(&s), new);
}

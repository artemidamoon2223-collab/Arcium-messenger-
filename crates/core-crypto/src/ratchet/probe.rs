//! Test-only stand-in for `zeroize::Zeroizing`, used by this crate's unit tests
//! in place of the real type (see the `use` in `ratchet.rs`).
//!
//! It behaves like the real one — wipes its contents when dropped — and also
//! counts how many 32-byte key containers are alive on this thread and, while a
//! log is being kept, records the value of each 32-byte container as it is
//! dropped. That lets a test state, without reading freed memory:
//!
//! - after an operation returns, no key container that the ratchet state does
//!   not hold is still alive (no temporary was leaked, forgotten or kept);
//! - a given key was dropped, and so wiped, at the point the code says it ends;
//! - the 64-byte block a root KDF expands into is dropped when the KDF returns.
//!
//! It shows where the code drops a key container. It does not show that the
//! bytes are gone from memory: that rests on `zeroize` itself.

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::ops::{Deref, DerefMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static LOG: RefCell<Option<Vec<[u8; 32]>>> = const { RefCell::new(None) };
    static BLOCK_LOG: RefCell<Option<Vec<[u8; 64]>>> = const { RefCell::new(None) };
}

fn is_key<Z: 'static>() -> bool {
    TypeId::of::<Z>() == TypeId::of::<[u8; 32]>()
}

/// Number of 32-byte key containers alive on this thread.
pub(crate) fn live_keys() -> isize {
    LIVE.with(Cell::get)
}

/// Starts recording the value of every 32-byte container dropped from now on.
pub(crate) fn start_log() {
    LOG.with(|l| *l.borrow_mut() = Some(Vec::new()));
}

/// Stops recording and returns what was dropped since [`start_log`].
pub(crate) fn take_log() -> Vec<[u8; 32]> {
    LOG.with(|l| l.borrow_mut().take().unwrap_or_default())
}

/// Starts recording the value of every 64-byte container dropped from now on.
pub(crate) fn start_block_log() {
    BLOCK_LOG.with(|l| *l.borrow_mut() = Some(Vec::new()));
}

/// Stops recording and returns what was dropped since [`start_block_log`].
pub(crate) fn take_block_log() -> Vec<[u8; 64]> {
    BLOCK_LOG.with(|l| l.borrow_mut().take().unwrap_or_default())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Zeroizing<Z: Zeroize + 'static>(Z);

impl<Z: Zeroize + 'static> Zeroizing<Z> {
    pub(crate) fn new(value: Z) -> Self {
        if is_key::<Z>() {
            LIVE.with(|c| c.set(c.get() + 1));
        }
        Self(value)
    }
}

impl<Z: Zeroize + Clone + 'static> Clone for Zeroizing<Z> {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl<Z: Zeroize + 'static> Deref for Zeroizing<Z> {
    type Target = Z;
    fn deref(&self) -> &Z {
        &self.0
    }
}

impl<Z: Zeroize + 'static> DerefMut for Zeroizing<Z> {
    fn deref_mut(&mut self) -> &mut Z {
        &mut self.0
    }
}

impl<Z: Zeroize + 'static> Drop for Zeroizing<Z> {
    fn drop(&mut self) {
        if is_key::<Z>() {
            LIVE.with(|c| c.set(c.get() - 1));
            if let Some(key) = (&self.0 as &dyn Any).downcast_ref::<[u8; 32]>() {
                LOG.with(|l| {
                    if let Some(log) = l.borrow_mut().as_mut() {
                        log.push(*key);
                    }
                });
            }
        }
        if let Some(block) = (&self.0 as &dyn Any).downcast_ref::<[u8; 64]>() {
            BLOCK_LOG.with(|l| {
                if let Some(log) = l.borrow_mut().as_mut() {
                    log.push(*block);
                }
            });
        }
        self.0.zeroize();
    }
}

impl<Z: Zeroize + 'static> ZeroizeOnDrop for Zeroizing<Z> {}

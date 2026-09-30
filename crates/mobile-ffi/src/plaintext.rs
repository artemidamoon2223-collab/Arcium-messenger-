//! Application message plaintext as it crosses the FFI boundary into a record.
//!
//! Both types are UniFFI custom types. `uniffi.toml` maps them to the Kotlin
//! value classes of the same name (`android/app/.../ffi/Plaintext.kt`), whose
//! `toString` is `"<redacted>"`; a generated record that holds one therefore
//! does not print the message when it is formatted. Neither type implements
//! `Debug`. This covers accidental formatting only: the text itself is still
//! handed to the application, which owns its copy.

/// Message bytes the application receives.
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextBytes(pub Vec<u8>);

/// Message text the application receives as a string.
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextText(pub String);

uniffi::custom_newtype!(PlaintextBytes, Vec<u8>);
uniffi::custom_newtype!(PlaintextText, String);

//! Deterministic Security Event Engine (v1).
//!
//! Pure mapping `SystemStateSnapshot -> SecurityEvent`. No I/O, no
//! network, no crypto/Tor/PSI subsystem access, no AI. The engine does
//! not detect system state itself; callers construct a snapshot and
//! pass it in. Send-path enforcement and UI wiring are out of scope for
//! v1 and are not implemented here.

/// Closed severity set (full catalog; v1 emits only a subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Closed send-policy set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPolicy {
    Allow,
    Warn,
    Block,
}

/// Closed user-option set. There is no `SendAnyway`/`Bypass`/`Override`
/// variant — those options cannot be represented by this type at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserOption {
    Retry,
    Cancel,
    ContinueAnyway,
    OpenSettings,
    VerifyContact,
}

/// Closed catalog of event names (v1 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventName {
    MessageEncryptionReady,
    MessageEncryptionFailed,
    TorDisconnected,
    ContactNotVerified,
}

/// Closed lookup key into static UI strings. Never free-form text, never
/// interpolated with runtime data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeMessageKey {
    EncryptionReady,
    EncryptionFailed,
    TorDisconnected,
    ContactNotVerified,
}

/// A security event. Exactly the five catalog-approved fields — no
/// additional field exists on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub event: EventName,
    pub severity: Severity,
    pub send_policy: SendPolicy,
    pub user_options: Vec<UserOption>,
    pub safe_message_key: SafeMessageKey,
}

/// Tor connectivity, as a closed enum rather than a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorStatus {
    Connected,
    Disconnected,
}

/// Encryption session readiness, as a closed enum rather than a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionStatus {
    Ready,
    Failed,
}

/// Contact verification status, as a closed enum rather than a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactVerificationStatus {
    Verified,
    NotVerified,
}

/// Read-only input to the engine. Constructed directly by callers
/// (including tests) — the engine does not detect any of these values
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemStateSnapshot {
    pub tor_status: TorStatus,
    pub encryption_status: EncryptionStatus,
    pub contact_verification_status: ContactVerificationStatus,
}

/// Pure, deterministic evaluation: the same snapshot always produces the
/// same event. No randomness, no time-dependence, no external calls.
///
/// Precedence when more than one condition holds in the same snapshot
/// (most severe wins): encryption failure, then Tor disconnection, then
/// missing contact verification, then the all-clear ready state. This
/// order is a deliberate, explicit choice made here because the v1 spec
/// defines each condition individually but does not define combined-state
/// precedence.
pub fn evaluate(snapshot: &SystemStateSnapshot) -> SecurityEvent {
    if snapshot.encryption_status == EncryptionStatus::Failed {
        return SecurityEvent {
            event: EventName::MessageEncryptionFailed,
            severity: Severity::Critical,
            send_policy: SendPolicy::Block,
            user_options: vec![UserOption::Retry, UserOption::Cancel],
            safe_message_key: SafeMessageKey::EncryptionFailed,
        };
    }

    if snapshot.tor_status == TorStatus::Disconnected {
        return SecurityEvent {
            event: EventName::TorDisconnected,
            severity: Severity::High,
            send_policy: SendPolicy::Block,
            user_options: vec![UserOption::Retry, UserOption::Cancel],
            safe_message_key: SafeMessageKey::TorDisconnected,
        };
    }

    if snapshot.contact_verification_status == ContactVerificationStatus::NotVerified {
        return SecurityEvent {
            event: EventName::ContactNotVerified,
            severity: Severity::Medium,
            send_policy: SendPolicy::Warn,
            user_options: vec![
                UserOption::VerifyContact,
                UserOption::ContinueAnyway,
                UserOption::Cancel,
            ],
            safe_message_key: SafeMessageKey::ContactNotVerified,
        };
    }

    SecurityEvent {
        event: EventName::MessageEncryptionReady,
        severity: Severity::Info,
        send_policy: SendPolicy::Allow,
        user_options: vec![],
        safe_message_key: SafeMessageKey::EncryptionReady,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_snapshot() -> SystemStateSnapshot {
        SystemStateSnapshot {
            tor_status: TorStatus::Connected,
            encryption_status: EncryptionStatus::Ready,
            contact_verification_status: ContactVerificationStatus::Verified,
        }
    }

    #[test]
    fn determinism_same_snapshot_same_event() {
        let snapshot = ready_snapshot();
        let first = evaluate(&snapshot);
        let second = evaluate(&snapshot);
        assert_eq!(first, second);
    }

    #[test]
    fn encryption_ready_yields_info_allow() {
        let event = evaluate(&ready_snapshot());
        assert_eq!(event.event, EventName::MessageEncryptionReady);
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.send_policy, SendPolicy::Allow);
        assert_eq!(event.safe_message_key, SafeMessageKey::EncryptionReady);
    }

    #[test]
    fn encryption_failed_yields_critical_block_no_bypass() {
        let snapshot = SystemStateSnapshot {
            encryption_status: EncryptionStatus::Failed,
            ..ready_snapshot()
        };
        let event = evaluate(&snapshot);
        assert_eq!(event.event, EventName::MessageEncryptionFailed);
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.send_policy, SendPolicy::Block);
        assert_eq!(event.safe_message_key, SafeMessageKey::EncryptionFailed);
        assert!(!event.user_options.contains(&UserOption::ContinueAnyway));
    }

    #[test]
    fn tor_disconnected_yields_high_block_no_bypass() {
        let snapshot = SystemStateSnapshot {
            tor_status: TorStatus::Disconnected,
            ..ready_snapshot()
        };
        let event = evaluate(&snapshot);
        assert_eq!(event.event, EventName::TorDisconnected);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.send_policy, SendPolicy::Block);
        assert_eq!(event.safe_message_key, SafeMessageKey::TorDisconnected);
        assert!(!event.user_options.contains(&UserOption::ContinueAnyway));
    }

    #[test]
    fn contact_not_verified_yields_medium_warn() {
        let snapshot = SystemStateSnapshot {
            contact_verification_status: ContactVerificationStatus::NotVerified,
            ..ready_snapshot()
        };
        let event = evaluate(&snapshot);
        assert_eq!(event.event, EventName::ContactNotVerified);
        assert_eq!(event.severity, Severity::Medium);
        assert_eq!(event.send_policy, SendPolicy::Warn);
        assert_eq!(event.safe_message_key, SafeMessageKey::ContactNotVerified);
        assert!(event.user_options.contains(&UserOption::VerifyContact));
    }
}

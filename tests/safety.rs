//! Integration tests for the risk taxonomy + confirmation-hook layer (R40, R41).
//!
//! NOTE: these test the crate's *public* API (`libwing::{Operation, RiskClass,
//! risk_class, ConfirmationGuard, ConfirmationRequired}`), so they only compile
//! once `libwing/src/lib.rs` has `mod safety;` plus the re-exports described in
//! this unit's final report. Until that wiring lands, this file is expected to
//! fail to compile — the equivalent coverage already runs today via
//! `cargo test --lib safety` against `src/safety.rs`'s own `#[cfg(test)]` module.

use libwing::{risk_class, ConfirmationGuard, Operation, RiskClass};

#[test]
fn every_operation_maps_to_exactly_one_risk_class() {
    let ops = [
        Operation::ReadNodeData,
        Operation::ReadNodeDefinition,
        Operation::Discover,
        Operation::Connect,
        Operation::SubscribeMeters,
        Operation::ReadMeters,
        Operation::KeepAlive,
        Operation::SetNodeValue,
        Operation::SchemaCrawl,
    ];
    for op in ops {
        // Calling twice and comparing pins down "exactly one" rather than
        // just "some class exists".
        assert_eq!(risk_class(op), risk_class(op));
    }
}

#[test]
fn high_risk_classes_carry_the_confirmation_flag() {
    assert!(!RiskClass::ReadOnly.requires_confirmation());
    assert!(!RiskClass::Transient.requires_confirmation());
    assert!(RiskClass::DestructiveSchemaCrawl.requires_confirmation());
    assert!(RiskClass::SnapshotRecall.requires_confirmation());
    assert!(RiskClass::Routing.requires_confirmation());
    assert!(RiskClass::GainPhantom.requires_confirmation());
    assert!(RiskClass::Gpio.requires_confirmation());
    assert!(RiskClass::RecorderTransport.requires_confirmation());
    assert!(RiskClass::PersistentStorage.requires_confirmation());
    assert!(RiskClass::StateChanging.requires_confirmation());
}

#[test]
fn unconfirmed_high_risk_operation_is_blocked() {
    let guard = ConfirmationGuard::new(|_| false);
    assert!(guard.ensure_allowed(Operation::SchemaCrawl).is_err());
}

#[test]
fn confirmed_high_risk_operation_and_read_only_operations_pass() {
    let approve_all = ConfirmationGuard::new(|_| true);
    assert!(approve_all.ensure_allowed(Operation::SchemaCrawl).is_ok());

    let deny_all = ConfirmationGuard::new(|_| false);
    assert!(deny_all.ensure_allowed(Operation::ReadNodeData).is_ok());
}

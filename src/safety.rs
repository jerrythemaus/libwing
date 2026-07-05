//! Operation risk classification and confirmation hooks (R40, R41).
//!
//! This module is a library-grade, opt-in safety layer: it classifies what a
//! caller is about to do and gives them a place to require explicit
//! confirmation before doing it. It is deliberately *not* wired into
//! [`crate::WingConsole`]'s existing methods — adding a mandatory
//! confirmation step to `set_string`/`set_float`/`set_int` would break every
//! existing caller. Instead, a consumer (or a tool like `wingschema`) builds
//! an [`Operation`], asks a [`ConfirmationGuard`] whether it's allowed, and
//! only then calls the underlying `WingConsole` method itself.
//!
//! Higher-level risk classes in [`RiskClass`] (routing, gain/phantom, GPIO,
//! recorder transport, snapshot recall, persistent storage) describe risk at
//! the level of *what a node does*, not at the level of libwing's generic
//! wire operations (`set_string`, `set_float`, `set_int` all just write bytes
//! to a node id). Libwing's own [`Operation`] enum only covers the
//! operations the library itself exposes today, so it maps generic node
//! writes to [`RiskClass::StateChanging`]; a consumer that knows *which*
//! node it's writing (e.g. a phantom-power toggle or a snapshot recall
//! node) is expected to classify that operation more specifically using the
//! same [`RiskClass`] taxonomy.

use std::fmt;

/// A risk class from the origin taxonomy (R40). Every [`Operation`] maps to
/// exactly one of these via [`risk_class`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskClass {
    /// Reads that cannot change console state: node data/definition reads,
    /// discovery. Always safe to retry or run unattended.
    ReadOnly,
    /// Writes with no lasting effect on the console's configuration: session
    /// bookkeeping like connecting, keepalives, and meter subscriptions. Safe
    /// to run unattended; reconnecting or resubscribing costs nothing.
    Transient,
    /// A generic node write whose semantic target isn't known to the layer
    /// doing the classifying. Covers libwing's `set_string`/`set_float`/
    /// `set_int` when the caller hasn't (or can't) attribute a more specific
    /// class below.
    StateChanging,
    /// Writes console configuration that persists across power cycles (e.g.
    /// saving to internal storage). Undoing a mistake may require a restore
    /// from a backup rather than just re-setting a value.
    PersistentStorage,
    /// Recalling a snapshot or scene, which can overwrite the current
    /// mix/routing state in one shot with whatever was saved earlier.
    SnapshotRecall,
    /// Changing signal routing (inputs, outputs, sends, patch points).
    /// Wrong routing can send an unexpected signal to a live output.
    Routing,
    /// Changing gain staging or phantom power. Phantom power in particular
    /// can damage connected equipment if toggled on the wrong input.
    GainPhantom,
    /// Toggling general-purpose I/O, which may drive external hardware
    /// (relays, lighting, talkback switches) with real-world side effects.
    Gpio,
    /// Controlling a recorder's transport (record/stop/arm). A mistaken
    /// operation can stop or corrupt an in-progress recording.
    RecorderTransport,
    /// The full live schema crawl (`wingschema`'s default mode): it flips
    /// every model selector on the console to enumerate per-model subtrees,
    /// which is destructive to the console's current configuration and not
    /// automatically undoable if the restore step fails.
    DestructiveSchemaCrawl,
}

impl RiskClass {
    /// High-risk classes require a confirmation hook to grant approval
    /// before the operation proceeds (R41). [`RiskClass::ReadOnly`] and
    /// [`RiskClass::Transient`] are the only classes that can't change
    /// lasting console state or hardware behavior, so they're the only ones
    /// exempted; every other class can either persist, misroute a signal,
    /// or drive real hardware, so it carries the confirmation flag.
    pub fn requires_confirmation(&self) -> bool {
        !matches!(self, RiskClass::ReadOnly | RiskClass::Transient)
    }
}

impl fmt::Display for RiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RiskClass::ReadOnly => "read-only",
            RiskClass::Transient => "transient",
            RiskClass::StateChanging => "state-changing",
            RiskClass::PersistentStorage => "persistent-storage",
            RiskClass::SnapshotRecall => "snapshot-recall",
            RiskClass::Routing => "routing",
            RiskClass::GainPhantom => "gain-phantom",
            RiskClass::Gpio => "gpio",
            RiskClass::RecorderTransport => "recorder-transport",
            RiskClass::DestructiveSchemaCrawl => "destructive-schema-crawl",
        };
        f.write_str(s)
    }
}

/// An operation from libwing's own operation surface — the calls
/// [`crate::WingConsole`] and the `wingschema` tool actually make today.
/// Each variant maps to exactly one [`RiskClass`] via [`risk_class`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// `WingConsole::request_node_data` — read a node's current value.
    ReadNodeData,
    /// `WingConsole::request_node_definition` — read a node's schema.
    ReadNodeDefinition,
    /// `WingConsole::scan` — discover consoles on the network.
    Discover,
    /// `WingConsole::connect` — open a session to a console.
    Connect,
    /// `WingConsole::request_meter` — subscribe to meter levels.
    SubscribeMeters,
    /// `WingConsole::read_meters` — poll for a meter frame.
    ReadMeters,
    /// `WingConsole::keep_alive` / `keep_alive_meters`.
    KeepAlive,
    /// `WingConsole::set_string` / `set_float` / `set_int` — a generic node
    /// write whose target isn't distinguished at this layer.
    SetNodeValue,
    /// The `wingschema` live sweep: crawls the schema by flipping every
    /// model selector node.
    SchemaCrawl,
}

/// Total mapping from an [`Operation`] to its [`RiskClass`] (R40).
pub fn risk_class(op: Operation) -> RiskClass {
    match op {
        Operation::ReadNodeData => RiskClass::ReadOnly,
        Operation::ReadNodeDefinition => RiskClass::ReadOnly,
        Operation::Discover => RiskClass::ReadOnly,
        Operation::Connect => RiskClass::Transient,
        Operation::SubscribeMeters => RiskClass::Transient,
        Operation::ReadMeters => RiskClass::Transient,
        Operation::KeepAlive => RiskClass::Transient,
        Operation::SetNodeValue => RiskClass::StateChanging,
        Operation::SchemaCrawl => RiskClass::DestructiveSchemaCrawl,
    }
}

/// An [`Operation`] was blocked because it requires confirmation and none
/// was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationRequired {
    pub operation: Operation,
    pub class: RiskClass,
}

impl fmt::Display for ConfirmationRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "operation {:?} ({}) requires confirmation, but none was granted",
            self.operation, self.class
        )
    }
}

impl std::error::Error for ConfirmationRequired {}

/// A lightweight opt-in confirmation hook (R41): wraps a caller-supplied
/// predicate and blocks high-risk operations unless it approves them.
///
/// This is metadata-plus-a-hook, not a framework: it doesn't intercept any
/// `WingConsole` call itself. A caller checks `ensure_allowed` before making
/// the underlying call.
pub struct ConfirmationGuard<F>
where
    F: Fn(Operation) -> bool,
{
    confirm: F,
}

impl<F> ConfirmationGuard<F>
where
    F: Fn(Operation) -> bool,
{
    /// Build a guard from a predicate that returns whether `op` is approved
    /// (e.g. by prompting a user or checking an automation flag).
    pub fn new(confirm: F) -> Self {
        Self { confirm }
    }

    /// Blocks `op` with [`ConfirmationRequired`] if its risk class requires
    /// confirmation and the predicate didn't grant it. Read-only and
    /// transient operations always pass without consulting the predicate.
    pub fn ensure_allowed(&self, op: Operation) -> Result<(), ConfirmationRequired> {
        let class = risk_class(op);
        if class.requires_confirmation() && !(self.confirm)(op) {
            return Err(ConfirmationRequired {
                operation: op,
                class,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OPERATIONS: &[Operation] = &[
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

    #[test]
    fn every_operation_maps_to_exactly_one_risk_class() {
        // `risk_class` is a total function (one match arm per variant, no
        // wildcard), so this just exercises every variant compiles and
        // returns a single, deterministic class.
        for &op in ALL_OPERATIONS {
            let a = risk_class(op);
            let b = risk_class(op);
            assert_eq!(a, b, "{op:?} must map to exactly one class");
        }
    }

    #[test]
    fn high_risk_classes_require_confirmation() {
        assert!(!RiskClass::ReadOnly.requires_confirmation());
        assert!(!RiskClass::Transient.requires_confirmation());
        for class in [
            RiskClass::StateChanging,
            RiskClass::PersistentStorage,
            RiskClass::SnapshotRecall,
            RiskClass::Routing,
            RiskClass::GainPhantom,
            RiskClass::Gpio,
            RiskClass::RecorderTransport,
            RiskClass::DestructiveSchemaCrawl,
        ] {
            assert!(
                class.requires_confirmation(),
                "{class} should require confirmation"
            );
        }
    }

    #[test]
    fn guard_blocks_unconfirmed_high_risk_op() {
        let guard = ConfirmationGuard::new(|_| false);
        let err = guard.ensure_allowed(Operation::SchemaCrawl).unwrap_err();
        assert_eq!(err.operation, Operation::SchemaCrawl);
        assert_eq!(err.class, RiskClass::DestructiveSchemaCrawl);
    }

    #[test]
    fn guard_passes_confirmed_high_risk_op() {
        let guard = ConfirmationGuard::new(|_| true);
        assert!(guard.ensure_allowed(Operation::SchemaCrawl).is_ok());
        assert!(guard.ensure_allowed(Operation::SetNodeValue).is_ok());
    }

    #[test]
    fn guard_passes_read_only_and_transient_without_consulting_predicate() {
        // The predicate always denies; read-only/transient ops must still pass
        // because they never require confirmation in the first place.
        let guard = ConfirmationGuard::new(|_| false);
        assert!(guard.ensure_allowed(Operation::ReadNodeData).is_ok());
        assert!(guard.ensure_allowed(Operation::ReadNodeDefinition).is_ok());
        assert!(guard.ensure_allowed(Operation::Discover).is_ok());
        assert!(guard.ensure_allowed(Operation::Connect).is_ok());
        assert!(guard.ensure_allowed(Operation::SubscribeMeters).is_ok());
        assert!(guard.ensure_allowed(Operation::ReadMeters).is_ok());
        assert!(guard.ensure_allowed(Operation::KeepAlive).is_ok());
    }
}

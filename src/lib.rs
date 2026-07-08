//! [![github]](https://github.com/dannydulai/libwing)&ensp;[![crates-io]](https://crates.io/crates/libwing)&ensp;[![docs-rs]](https://docs.rs/libwing)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! # Libwing SDK Documentation
//!
//! Libwing is a Rust library for interfacing with Behringer Wing digital mixing
//! consoles. It provides functionality for discovering Wing consoles on the
//! network, connecting to them, reading/writing console parameters, and receiving
//! any changes made on the mixer itself.
//!
//! There is a C wrapper for this library. It generally follows the Rust API. You
//! can find it in `libwing.h`.
//!
//! ## Basic Concepts
//!
//! The Wing console exposes its functionality through a tree of nodes. Each node has:
//! - A unique numeric ID
//! - A hierarchical path name (like a filesystem path)
//! - A type (string, float, integer, enum, etc.)
//! - Optional min/max values and units
//! - Read/write or read-only access
//!
//! ## Getting Started
//!
//! ### Connecting
//! If you have a Wing's IP address, you can connect to it:
//!
//! ```rust,no_run
//! # use libwing::WingConsole;
//! # fn main() -> Result<(), libwing::Error> {
//! let mut wing = WingConsole::connect(Some("192.168.1.100"))?;
//! # Ok(())
//! # }
//! ```
//!
//! or just run with no IP address to discover the first Wing console on the network:
//!
//! ```rust,no_run
//! # use libwing::WingConsole;
//! # fn main() -> Result<(), libwing::Error> {
//! let mut wing = WingConsole::connect(None)?;
//! # Ok(())
//! # }
//! ```
//!
//! There is also `WingConsole::scan()` which can be used to scan for Wing mixers.
//!
//! ### Communication Model
//!
//! - You can request properties from the Wing device using `WingConsole.request_node_data()`,
//!   which will result in a `WingResponse::NodeData` being sent if your request was for a valid
//!   property. Note that you may get other properties as well, as the Wing device will send
//!   unsolicited property changes, so you may need to filter for your specific property change.
//!   After the NodeData is sent (or not), the Wing device will send a `WingResponse::RequestEnd`
//!   message.
//!
//! - You can request node definitions using `WingConsole::request_node_definition()`, which cause
//!   a `WingResponse::NodeDef` message to be read. **wingschema** uses this request to dump the
//!   schema. Again, unsolicited messages may be sent, so you may need to filter for your specific
//!   NodeDef. After the NodeDef is sent (or not), the Wing device will send a `WingResponse::RequestEnd`
//!
//! - You can set properties using the `WingConsole::set_*()` functions. These do not send any
//!   response back.
//!
//! - `WingConsole::read()` will block and return you messages from the Wing mixer as they come in.
//!   If the device is modified either physically or via another user of the API, the Wing device
//!   sends unsolicited `WingResponse::NodeData(id, data)` messages.
//!
//! - `WingConsole::request_meter()` will ask the Wing to start sending meter level data (the
//!   bouncing green/yellow/red level lights on the mixer). It returns an u16 ID corresponding to
//!   this request. This ID will returned when you read the meters data.
//!
//! - `WingConsole::read_meters()` will block and return you messages from the Wing mixer as they
//!   come in. It includes the ID returned from the `request_meter()` call for you to help correlate.
//!
//! All these calls are thread safe.

mod console;
mod ffi;
mod helpers;
/// WING icon index ↔ name map (decoded from the protocol-spec "WING Icons" appendix).
pub mod icons;
mod meters;
mod node;
/// OSC-over-UDP transport (U10: R3), a sibling to the Native transport above.
/// Namespaced rather than flattened into the root re-exports below: several of its
/// names (`get_param`, `set_float`, ...) are generic enough that they'd collide or
/// read confusingly next to the rest of this crate's API. Use it as `osc::get_param(..)`,
/// `osc::WingOscClient`, etc.
pub mod osc;
#[cfg(not(feature = "propmap"))]
#[path = "empty-propmap.rs"]
mod propmap;
#[cfg(feature = "propmap")]
mod propmap;
mod safety;
mod schema;

pub use console::{
    DiscoveryInfo, DumpEntry, Meter, NodeDump, NodeValue, ReconnectOutcome, ReconnectPolicy,
    SessionGap, Transport, WingConsole,
};
pub use ffi::{ResponseHandle, WingConsoleHandle};
pub use helpers::{
    decode_enum, encode_enum, write_enum, EnumDecode, EnumKey, EnumValue, RawEnumValue,
};
pub use icons::{icon_category, icon_index, icon_name};
pub use meters::{
    decode_frame, fx_band_gr_db, level_db, ChannelMeter, ChannelMeterV2, DcaMeter, FxMeter,
    MeterFrameEntry, MonitorMeter, CHANNEL_V2_WORDS, CHANNEL_WORDS, DCA_WORDS, FX_WORDS,
    MONITOR_WORDS, OUTPUT_WORDS, RTA_WORDS, SOURCE_WORDS,
};
pub use node::{FloatEnumItem, NodeType, NodeUnit, StringEnumItem, WingNodeData, WingNodeDef};
pub use safety::{risk_class, ConfirmationGuard, ConfirmationRequired, Operation, RiskClass};
pub use schema::{
    transport_availability, LiveSchema, MapMetadata, Provenance, Resolution, Schema, Staleness,
    TransportAvailability, FIRMWARE_BASELINE,
};

type Result<T> = std::result::Result<T, Error>;

/// `#[non_exhaustive]` (R21): new failure modes may be added in a minor release
/// without that being a breaking change for callers who already match with a
/// wildcard arm.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid data received")]
    InvalidData,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Connection error")]
    ConnectionError,
    #[error("Failed to discover Wing console")]
    DiscoveryError,
    #[error("Metering has not been initialized")]
    MeterNotInitialized,
    #[error("Operation timed out waiting for a response")]
    Timeout,
    /// A raw meter frame's length didn't match what the request it was decoded against
    /// implies (see [`decode_frame`]) -- either a short/truncated UDP datagram or a
    /// mismatch between the `request` passed to `decode_frame` and the one that actually
    /// produced `raw`.
    #[error("meter frame length mismatch: expected {expected} i16 words, got {actual}")]
    MeterFrameLength { expected: usize, actual: usize },
}

pub enum WingResponse {
    RequestEnd,
    NodeDef(WingNodeDef),
    NodeData(i32, WingNodeData),
}

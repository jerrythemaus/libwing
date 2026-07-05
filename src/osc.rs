//! OSC-over-UDP transport (U10: R3; subscriptions/robustness/availability U11: R4, R6,
//! R75) -- a sibling to the Native (TCP) transport in `console.rs`, not a replacement
//! for it. WING runs both protocols side by side: Native on TCP port 2222 (see
//! [`crate::WingConsole`]), OSC on UDP port 2223. This module only speaks the latter.
//! For which operations each transport can perform, see
//! [`crate::schema::transport_availability`] (R6).
//!
//! Reference: `references/WING_Remote_Protocols_V3.1-03.md`, "WING OSC protocol data
//! interface" chapter (pages 19-30). Byte-exact golden vectors quoted in doc comments
//! and tests below are taken directly from that document.
//!
//! ## Layout
//!
//! - [`OscMessage`] / [`OscArg`] / [`encode`] / [`decode`]: a pure, offline-testable
//!   OSC 1.0 codec (no bundles, per WING's implementation). No I/O.
//! - Request builders ([`get_param`], [`set_float`], [`toggle`], [`node_set_local`],
//!   [`subscribe`], ...): construct an [`OscMessage`] for a specific WING operation.
//! - Reply/event parsers ([`parse_param_reply`], [`parse_node_ack`], [`parse_node_dump`],
//!   [`parse_console_info`]): decode a received [`OscMessage`] into a typed result;
//!   [`OscEvent`] classifies subscription traffic specifically.
//! - [`WingOscClient`]: the UDP transport tying the above together -- get/set
//!   ([`request`](WingOscClient::request)), subscriptions
//!   ([`subscribe`](WingOscClient::subscribe), [`poll_event`](WingOscClient::poll_event)),
//!   and robustness ([`request_with_policy`](WingOscClient::request_with_policy),
//!   [`take_unsolicited`](WingOscClient::take_unsolicited)).
//!
//! ## Value facets (R14)
//!
//! Unlike Native (raw + display, see [`crate::WingNodeData`]'s docs), a single-parameter
//! OSC `,sff`/`,sfi` reply carries three facets in one message: an ASCII **display**
//! string, a **raw** value normalized to `0.0..1.0`, and the parameter's **real**
//! engineering-unit value (float or int, depending on the parameter's wire type).
//! [`ParamReply`] models these explicitly rather than collapsing them, since OSC (unlike
//! Native) actually puts all three on the wire.
//!
//! ## Namespacing
//!
//! Exported as `pub mod osc` rather than flattened into the crate root: several names
//! here (`get_param`, `set_float`, `Error`-shaped types) would collide with existing
//! root-level exports or read confusingly next to them. Call sites use `osc::get_param(..)`,
//! `osc::WingOscClient`, etc.

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::DiscoveryInfo;

/// WING's OSC server always listens here (R3); see the "OSC Remote Protocol" section,
/// page 19.
pub const OSC_PORT: u16 = 2223;

/// OSC over UDP is capped at 32 KB per the OSC spec and WING's own implementation
/// (page 19: "The maximum UDP packet size is 32k bytes.").
pub const MAX_PACKET_BYTES: usize = 32 * 1024;

/// How long the console keeps an OSC subscription alive without a renewal (page 30:
/// "Subscriptions must be kept alive; they automatically die after 10 seconds.").
pub const SUBSCRIPTION_EXPIRY: Duration = Duration::from_secs(10);

/// Default renewal cadence [`WingOscClient::subscribe`] uses: comfortably inside
/// [`SUBSCRIPTION_EXPIRY`] so a caller polling at a normal rate never brushes the real
/// 10-second deadline.
pub const SUBSCRIPTION_RENEW_MARGIN: Duration = Duration::from_secs(5);

/// `#[non_exhaustive]` (R21) for the same reason as [`crate::Error`]: new failure modes
/// may be added without that being a breaking change for callers matching with a
/// wildcard arm.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OscError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// A decode failure, or an encode/request precondition that doesn't hold. Carries a
    /// static description of which invariant broke.
    #[error("malformed OSC message: {0}")]
    Malformed(&'static str),
    /// Encoding would exceed [`MAX_PACKET_BYTES`]; carries the size that would have been
    /// sent.
    #[error("encoded message exceeds the 32 KB OSC/UDP limit ({0} bytes)")]
    TooLarge(usize),
    /// No reply matching the request arrived before the deadline passed.
    #[error("operation timed out waiting for a reply")]
    Timeout,
    /// The console replied to a node-set with one of its documented error strings
    /// (page 23) instead of `OK`.
    #[error("console rejected the node command: {0:?}")]
    Node(OscNodeError),
    /// [`WingOscClient::request_with_policy`] made every attempt [`RequestPolicy`]
    /// allowed and none got a reply (R75). Carries the attempt count so callers/tests
    /// can observe that retries actually happened, not just that it eventually failed.
    #[error("operation timed out waiting for a reply after {attempts} attempt(s)")]
    RetriesExhausted { attempts: u32 },
}

/// Convenience alias for this module's `Result<T, OscError>`.
pub type Result<T> = std::result::Result<T, OscError>;

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// One OSC 1.0 argument value. WING supports all four standard OSC types (page 19):
/// `i`/`f`/`s`/`b` for int32, float32, string, and blob respectively.
#[derive(Clone, Debug, PartialEq)]
pub enum OscArg {
    Int(i32),
    Float(f32),
    Str(String),
    Blob(Vec<u8>),
}

/// A decoded (or to-be-encoded) OSC message: an address pattern plus zero or more
/// arguments. WING never uses OSC bundles (page 19), so a message is the entire
/// contents of a UDP packet.
#[derive(Clone, Debug, PartialEq)]
pub struct OscMessage {
    pub addr: String,
    pub args: Vec<OscArg>,
}

impl OscMessage {
    pub fn new(addr: impl Into<String>, args: Vec<OscArg>) -> Self {
        Self {
            addr: addr.into(),
            args,
        }
    }
}

/// Appends `s` to `buf` as an OSC string: the ASCII bytes, a NUL terminator, and 0-3
/// further NUL bytes so the total (from `s`'s first byte) is a multiple of 4 (page 19).
fn push_osc_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    let padded_total = (s.len() + 1).div_ceil(4) * 4;
    buf.resize(buf.len() + (padded_total - s.len()), 0);
}

/// Appends `data` to `buf` as an OSC blob: a big-endian int32 length, the raw bytes,
/// then 0-3 zero bytes so the data (not the length prefix) is padded to a 4-byte
/// multiple (page 19).
fn push_osc_blob(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
    buf.extend_from_slice(data);
    let pad = (4 - (data.len() % 4)) % 4;
    buf.resize(buf.len() + pad, 0);
}

/// Encodes `msg` to wire bytes.
///
/// A zero-argument message is encoded as a bare, tag-omitted address (e.g. `/?` ->
/// `2f3f0000`, 4 bytes) -- the compact form WING's own documentation uses for every GET
/// request example, and the form [`decode`] round-trips back to `args: vec![]`. WING
/// also accepts the "more compliant" form with an explicit empty tag string (`/?~~,~~~`,
/// 8 bytes, page 20) as *input*; [`decode`] accepts that shape too, but `encode` always
/// produces the shorter, spec-canonical one.
///
/// Errors with [`OscError::TooLarge`] if the encoded message would exceed
/// [`MAX_PACKET_BYTES`].
pub fn encode(msg: &OscMessage) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    push_osc_string(&mut buf, &msg.addr);

    if !msg.args.is_empty() {
        let mut tag = String::with_capacity(msg.args.len() + 1);
        tag.push(',');
        for arg in &msg.args {
            tag.push(match arg {
                OscArg::Int(_) => 'i',
                OscArg::Float(_) => 'f',
                OscArg::Str(_) => 's',
                OscArg::Blob(_) => 'b',
            });
        }
        push_osc_string(&mut buf, &tag);

        for arg in &msg.args {
            match arg {
                OscArg::Int(v) => buf.extend_from_slice(&v.to_be_bytes()),
                OscArg::Float(v) => buf.extend_from_slice(&v.to_be_bytes()),
                OscArg::Str(v) => push_osc_string(&mut buf, v),
                OscArg::Blob(v) => push_osc_blob(&mut buf, v),
            }
        }
    }

    if buf.len() > MAX_PACKET_BYTES {
        return Err(OscError::TooLarge(buf.len()));
    }
    Ok(buf)
}

/// Reads a NUL-terminated, 4-byte-padded OSC string starting at `*i`, advancing `*i`
/// past its padding.
fn read_osc_string(bytes: &[u8], i: &mut usize) -> Result<String> {
    let start = *i;
    let nul = bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(OscError::Malformed("unterminated OSC string"))?;
    let s = std::str::from_utf8(&bytes[start..start + nul])
        .map_err(|_| OscError::Malformed("invalid utf8 in OSC string"))?
        .to_string();
    let padded_total = (nul + 1).div_ceil(4) * 4;
    if start + padded_total > bytes.len() {
        return Err(OscError::Malformed("truncated OSC string padding"));
    }
    *i = start + padded_total;
    Ok(s)
}

fn read_i32(bytes: &[u8], i: &mut usize) -> Result<i32> {
    let end = *i + 4;
    let chunk: [u8; 4] = bytes
        .get(*i..end)
        .ok_or(OscError::Malformed("truncated int32 argument"))?
        .try_into()
        .unwrap();
    *i = end;
    Ok(i32::from_be_bytes(chunk))
}

fn read_f32(bytes: &[u8], i: &mut usize) -> Result<f32> {
    let end = *i + 4;
    let chunk: [u8; 4] = bytes
        .get(*i..end)
        .ok_or(OscError::Malformed("truncated float32 argument"))?
        .try_into()
        .unwrap();
    *i = end;
    Ok(f32::from_be_bytes(chunk))
}

fn read_blob(bytes: &[u8], i: &mut usize) -> Result<Vec<u8>> {
    let size = read_i32(bytes, i)?;
    let size = usize::try_from(size).map_err(|_| OscError::Malformed("negative blob size"))?;
    let data = bytes
        .get(*i..*i + size)
        .ok_or(OscError::Malformed("truncated blob data"))?
        .to_vec();
    *i += size;
    let pad = (4 - (size % 4)) % 4;
    if *i + pad > bytes.len() {
        return Err(OscError::Malformed("truncated blob padding"));
    }
    *i += pad;
    Ok(data)
}

/// Decodes wire bytes into an [`OscMessage`].
///
/// Accepts both message shapes WING documents as valid input (page 19): a bare
/// address with the type tag string omitted entirely (decodes to `args: vec![]`), and
/// an address followed by an explicit (possibly empty, `","`) type tag string.
/// Rejects anything not starting with `/` (which also rejects OSC bundles, `#bundle...`
/// -- WING supports messages only, page 19).
pub fn decode(bytes: &[u8]) -> Result<OscMessage> {
    let mut i = 0;
    let addr = read_osc_string(bytes, &mut i)?;
    if !addr.starts_with('/') {
        return Err(OscError::Malformed(
            "address pattern must start with '/' (bundles are not supported)",
        ));
    }

    if i >= bytes.len() {
        // Type tag string omitted entirely -- a bare-address GET.
        return Ok(OscMessage { addr, args: vec![] });
    }

    let tag = read_osc_string(bytes, &mut i)?;
    let mut chars = tag.chars();
    if chars.next() != Some(',') {
        return Err(OscError::Malformed("type tag string must start with ','"));
    }

    let mut args = Vec::new();
    for tag_char in chars {
        args.push(match tag_char {
            'i' => OscArg::Int(read_i32(bytes, &mut i)?),
            'f' => OscArg::Float(read_f32(bytes, &mut i)?),
            's' => OscArg::Str(read_osc_string(bytes, &mut i)?),
            'b' => OscArg::Blob(read_blob(bytes, &mut i)?),
            _ => return Err(OscError::Malformed("unsupported OSC type tag")),
        });
    }
    Ok(OscMessage { addr, args })
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// Rejects `path` if it contains an OSC-reserved address-pattern character (page 19:
/// "wildcards '?' and '*' in Address Patterns are reserved for special cases") or one of
/// the other OSC 1.0 pattern metacharacters (`[`, `]`, `{`, `}`, `,`, space) that a
/// literal WING node path should never contain. Applied by every builder below that
/// takes a caller-supplied path as the message *address*.
///
/// The two deliberate non-literal address forms WING documents are built without going
/// through this validator, so they're unaffected: [`get_param_by_id`] constructs `/#..`
/// directly from a hash id (never free-form text), and [`with_reply_port`] only prepends
/// `/%<port>` to an address some other builder already validated.
fn validate_address_path(path: &str) -> Result<()> {
    if path.contains(['*', '?', '[', ']', '{', '}', ',', ' ']) {
        return Err(OscError::Malformed(
            "address path contains an OSC-reserved wildcard/pattern character",
        ));
    }
    Ok(())
}

/// GET a single parameter or node by its path (page 20-21), e.g. `/ch/1/fdr`.
pub fn get_param(path: &str) -> Result<OscMessage> {
    validate_address_path(path)?;
    Ok(OscMessage::new(path, vec![]))
}

/// GET a single parameter or node by its native hash id instead of its path (page 21):
/// `/#f50f69f8` for id `0xf50f69f8`. Always valid -- the address is synthesized from the
/// id, never free-form text, so there's nothing for [`validate_address_path`] to reject.
pub fn get_param_by_id(id: i32) -> OscMessage {
    OscMessage::new(format!("/#{:08x}", id as u32), vec![])
}

/// SET a parameter by sending a string value; WING converts it to the parameter's
/// actual wire type (page 22).
pub fn set_string(path: &str, value: &str) -> Result<OscMessage> {
    validate_address_path(path)?;
    Ok(OscMessage::new(path, vec![OscArg::Str(value.to_string())]))
}

/// SET a parameter by sending a float32 value (page 22).
pub fn set_float(path: &str, value: f32) -> Result<OscMessage> {
    validate_address_path(path)?;
    Ok(OscMessage::new(path, vec![OscArg::Float(value)]))
}

/// SET a parameter by sending an int32 value (page 22).
pub fn set_int(path: &str, value: i32) -> Result<OscMessage> {
    validate_address_path(path)?;
    Ok(OscMessage::new(path, vec![OscArg::Int(value)]))
}

/// Toggles a 0/1 int parameter (page 22): sending `-1` to an int-typed 0/1 parameter
/// flips it, saving a read-before-write round-trip.
pub fn toggle(path: &str) -> Result<OscMessage> {
    set_int(path, -1)
}

/// SET a `StringEnum` parameter by its item name (page 22), e.g. `mode` -> `"FX"`.
pub fn set_enum_by_name(path: &str, name: &str) -> Result<OscMessage> {
    set_string(path, name)
}

/// SET an enum parameter by its position in the item list (page 23), e.g. `mode` ->
/// index `6` (== `"FX"` in that def's list).
pub fn set_enum_by_index(path: &str, index: i32) -> Result<OscMessage> {
    set_int(path, index)
}

/// Formats `name=value` pairs into the `,` and `=` node-string grammar shared by
/// [`node_set_local`] and [`node_set_root`] (page 23).
fn format_node_pairs(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// SET multiple parameters under one node in a single request (page 24), e.g.
/// `node_path = "/ch/1"`, `pairs = [("fdr", "4"), ("mute", "1")]` sends
/// `fdr=4,mute=1`. The console acks on `<node_path>*` (see [`parse_node_ack`]).
pub fn node_set_local(node_path: &str, pairs: &[(&str, &str)]) -> Result<OscMessage> {
    validate_address_path(node_path)?;
    Ok(OscMessage::new(
        node_path,
        vec![OscArg::Str(format_node_pairs(pairs))],
    ))
}

/// SET across multiple nodes from the root in a single request (page 23-24). `payload`
/// is WING's own root grammar verbatim -- `/` starts a node group, `.` navigates,
/// `=` assigns, `,` separates -- e.g.
/// `"/ch.1.fdr=-1,mute=0,.2.fdr=0,mute=1"`. The console acks on `/*` (see
/// [`parse_node_ack`]).
///
/// Kept as a thin string passthrough rather than a structured multi-node builder: the
/// grammar mixes per-node and per-parameter separators in a way a generic builder would
/// only reproduce awkwardly, and every documented example is naturally written as this
/// string already.
pub fn node_set_root(payload: &str) -> OscMessage {
    OscMessage::new("/", vec![OscArg::Str(payload.to_string())])
}

/// Node introspection: full data dump (`*` argument, page 24) -- the same content a
/// snap file would save; read-only/temporary data is excluded.
pub fn node_dump(node_path: &str) -> Result<OscMessage> {
    validate_address_path(node_path)?;
    Ok(OscMessage::new(
        node_path,
        vec![OscArg::Str("*".to_string())],
    ))
}

/// Node introspection: parameter description without current values (`?` argument,
/// page 24).
pub fn node_describe(node_path: &str) -> Result<OscMessage> {
    validate_address_path(node_path)?;
    Ok(OscMessage::new(
        node_path,
        vec![OscArg::Str("?".to_string())],
    ))
}

/// Node introspection: parameter description including current values (`#` argument,
/// page 25).
pub fn node_describe_with_values(node_path: &str) -> Result<OscMessage> {
    validate_address_path(node_path)?;
    Ok(OscMessage::new(
        node_path,
        vec![OscArg::Str("#".to_string())],
    ))
}

/// Console identification (page 20): replies `,s` with
/// `"WING,ip,name,model,serial,firmware"` (see [`parse_console_info`]).
pub fn console_info() -> OscMessage {
    OscMessage::new("/?", vec![])
}

/// Wraps `msg` with the `/%<port>` reply-port prefix (page 21): the console's reply
/// goes to `port` on the same IP instead of the requesting socket's own port. Any OSC
/// command can be wrapped this way.
pub fn with_reply_port(port: u16, msg: OscMessage) -> OscMessage {
    OscMessage::new(format!("/%{port}{}", msg.addr), msg.args)
}

// ---------------------------------------------------------------------------
// Subscriptions (R4)
// ---------------------------------------------------------------------------

/// The three OSC event-subscription formats (page 30). **Only one is active
/// console-wide at any time**, granted to whichever client last (re)subscribed -- see
/// [`WingOscClient::subscribe`] for the full takeover story.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// `/*b`: event-driven native-binary messages. Delivered as a `,b` blob on the
    /// constant address `/`; the payload is exactly the native/binary-interface wire
    /// format (see [`crate::console`]) and can be sent back to the console verbatim.
    Binary,
    /// `/*s`: OSC "triplet" events, addressed by the parameter's own path, using the
    /// same `,s` (string/enum) / `,sff` (float) / `,sfi` (int) shapes as a plain
    /// get/set reply (see [`parse_param_reply`]). `$`-prefixed sibling paths (e.g.
    /// `/ch/1/$fdr`, the 0.0..1.0-normalized twin of `/ch/1/fdr`) stream alongside the
    /// plain path.
    OscTriplet,
    /// `/*S`: OSC "single-tag" events, addressed by the parameter's own path, reporting
    /// just its native wire type (`,f` or `,i`) with no display/raw facet -- see
    /// [`ParamFacets::NativeFloat`]/[`ParamFacets::NativeInt`]. Re-sendable to the
    /// console verbatim.
    OscNative,
}

impl SubscriptionFormat {
    fn address(self) -> &'static str {
        match self {
            Self::Binary => "/*b",
            Self::OscTriplet => "/*s",
            Self::OscNative => "/*S",
        }
    }
}

/// Builds the subscribe-or-renew message for `format` (page 30): a bare address with no
/// arguments, e.g. `/*b`. Sending this same message again before it expires (see
/// [`WingOscClient::subscribe`]) is how a subscription is renewed; there's no separate
/// "renew" message on the wire.
pub fn subscribe(format: SubscriptionFormat) -> OscMessage {
    OscMessage::new(format.address(), vec![])
}

// ---------------------------------------------------------------------------
// Reply parsers
// ---------------------------------------------------------------------------

/// The three reply shapes a single-parameter GET can come back as (page 21), carrying
/// the raw/display/real facets the wire actually provides -- see the module docs.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum ParamFacets {
    /// `,s`: a string or enum-typed parameter. Only a display facet exists on the wire.
    StringOrEnum { display: String },
    /// `,sff`: a float-typed parameter. `raw` is normalized `0.0..1.0`; `value` is the
    /// real engineering-unit value (e.g. dB).
    Float {
        display: String,
        raw: f32,
        value: f32,
    },
    /// `,sfi`: an int-typed parameter. `raw` is normalized `0.0..1.0`; `value` is the
    /// real integer value.
    Int {
        display: String,
        raw: f32,
        value: i32,
    },
    /// `,f`: a bare float, with no display/raw facet. Never produced by a get/set
    /// reply -- only by a [`SubscriptionFormat::OscNative`] (`/*S`) event (page 30),
    /// which reports just the parameter's native value.
    NativeFloat(f32),
    /// `,i`: as `NativeFloat`, but for an int-typed parameter.
    NativeInt(i32),
}

/// A parsed single-parameter GET reply.
#[derive(Clone, Debug, PartialEq)]
pub struct ParamReply {
    pub path: String,
    pub facets: ParamFacets,
}

/// Parses a single-parameter GET reply (page 21): `,s` / `,sff` / `,sfi` depending on
/// the parameter's type. Also parses a [`SubscriptionFormat::OscNative`] (`/*S`) event's
/// bare `,f` / `,i` shape into [`ParamFacets::NativeFloat`]/[`ParamFacets::NativeInt`]
/// (page 30) -- a plain get/set reply never takes that shape, so there's no ambiguity
/// reusing this parser for both.
pub fn parse_param_reply(msg: &OscMessage) -> Result<ParamReply> {
    let facets = match msg.args.as_slice() {
        [OscArg::Str(display)] => ParamFacets::StringOrEnum {
            display: display.clone(),
        },
        [OscArg::Str(display), OscArg::Float(raw), OscArg::Float(value)] => ParamFacets::Float {
            display: display.clone(),
            raw: *raw,
            value: *value,
        },
        [OscArg::Str(display), OscArg::Float(raw), OscArg::Int(value)] => ParamFacets::Int {
            display: display.clone(),
            raw: *raw,
            value: *value,
        },
        [OscArg::Float(value)] => ParamFacets::NativeFloat(*value),
        [OscArg::Int(value)] => ParamFacets::NativeInt(*value),
        _ => return Err(OscError::Malformed("unexpected parameter reply shape")),
    };
    Ok(ParamReply {
        path: msg.addr.clone(),
        facets,
    })
}

/// A parsed subscription event (R4): what [`WingOscClient::poll_event`] classifies each
/// received datagram into while a subscription is active.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum OscEvent {
    /// A `/*s` triplet event or `/*S` single-tag event, parsed like a get/set reply
    /// (see [`parse_param_reply`]). `/*S` events land in [`ParamFacets::NativeFloat`]/
    /// [`ParamFacets::NativeInt`], the one shape a plain get/set reply never produces.
    Param(ParamReply),
    /// A `/*b` event: the native-interface blob payload (page 30), re-sendable to the
    /// console verbatim. The event's address is always the constant `/` on the wire,
    /// so only the payload is carried here.
    Binary(Vec<u8>),
    /// Didn't match either recognized event shape. Never dropped silently -- e.g. a
    /// node-set ack can legitimately arrive on the same socket if a caller also issues
    /// [`WingOscClient::request`] calls while a subscription is active (see
    /// [`WingOscClient::poll_event`]'s docs for how to avoid that ambiguity).
    Raw(OscMessage),
}

/// Classifies one received datagram as subscription-event traffic (see [`OscEvent`]).
///
/// A node-ack-shaped address (`/*` or `<node>*`, see [`parse_node_ack`]) is routed to
/// [`OscEvent::Raw`] rather than through [`parse_param_reply`], even though its `,s`
/// payload would otherwise parse as a (bogus) [`ParamFacets::StringOrEnum`]: an ack is
/// never a parameter event, so treating it as one would misreport e.g. `"OK"` as a
/// parameter's display value.
fn classify_event(msg: OscMessage) -> OscEvent {
    if msg.addr == "/" {
        return match msg.args.as_slice() {
            [OscArg::Blob(data)] => OscEvent::Binary(data.clone()),
            _ => OscEvent::Raw(msg),
        };
    }
    if msg.addr.ends_with('*') {
        return OscEvent::Raw(msg);
    }
    match parse_param_reply(&msg) {
        Ok(reply) => OscEvent::Param(reply),
        Err(_) => OscEvent::Raw(msg),
    }
}

/// The node-set error strings WING documents (page 23). `#[non_exhaustive]`: a future
/// firmware could add another.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OscNodeError {
    NodeNotFound,
    ValueError,
    BufferOverflow,
    NodeIsNotPar,
    IncompleteData,
    StackEmpty,
}

impl OscNodeError {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "NODE NOT FOUND" => Self::NodeNotFound,
            "VALUE ERROR" => Self::ValueError,
            "BUFFER OVERFLOW" => Self::BufferOverflow,
            "NODE IS NOT PAR" => Self::NodeIsNotPar,
            "INCOMPLETE DATA" => Self::IncompleteData,
            "STACK EMPTY" => Self::StackEmpty,
            _ => return None,
        })
    }
}

/// Parses a node-set acknowledgement, from either the root form (`/*`) or the
/// node-local form (`<node>*`, page 24). Returns `Ok(())` for `OK`, or
/// `Err(OscError::Node(_))` for one of the six documented error strings.
pub fn parse_node_ack(msg: &OscMessage) -> Result<()> {
    if !msg.addr.ends_with('*') {
        return Err(OscError::Malformed(
            "not a node-ack address (expected '/*' or '<node>*')",
        ));
    }
    let payload = match msg.args.as_slice() {
        [OscArg::Str(s)] => s.as_str(),
        _ => {
            return Err(OscError::Malformed(
                "node ack payload must be a single string",
            ))
        }
    };
    if payload == "OK" {
        return Ok(());
    }
    match OscNodeError::parse(payload) {
        Some(err) => Err(OscError::Node(err)),
        None => Err(OscError::Malformed("unrecognized node ack payload")),
    }
}

/// Parses a node data dump (`*` reply, page 24) into its `name=value` pairs, in wire
/// order. A trailing `,` (every documented dump example ends with one) yields no
/// trailing empty pair.
pub fn parse_node_dump(msg: &OscMessage) -> Result<Vec<(String, String)>> {
    let payload = match msg.args.as_slice() {
        [OscArg::Str(s)] => s.as_str(),
        _ => {
            return Err(OscError::Malformed(
                "node dump payload must be a single string",
            ))
        }
    };
    Ok(payload
        .split(',')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect())
}

/// Parses a console info reply (`/?`, page 20): `"WING,ip,name,model,serial,firmware"`.
/// Reuses [`DiscoveryInfo`] -- same fields, same order as the broadcast-discovery reply
/// [`crate::WingConsole::scan`] parses.
pub fn parse_console_info(msg: &OscMessage) -> Result<DiscoveryInfo> {
    let payload = match msg.args.as_slice() {
        [OscArg::Str(s)] => s.as_str(),
        _ => {
            return Err(OscError::Malformed(
                "console info payload must be a single string",
            ))
        }
    };
    let parts: Vec<&str> = payload.split(',').collect();
    if parts.len() < 6 || parts[0] != "WING" {
        return Err(OscError::Malformed("unexpected console info payload"));
    }
    Ok(DiscoveryInfo {
        ip: parts[1].to_string(),
        name: parts[2].to_string(),
        model: parts[3].to_string(),
        serial: parts[4].to_string(),
        firmware: parts[5].to_string(),
    })
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Default policy for [`WingOscClient::request_with_policy`] (R75): 3 attempts of 500ms
/// each. Chosen to comfortably outlast an occasional dropped UDP datagram on a LAN
/// without turning a genuinely-unreachable console into a multi-second hang.
impl Default for RequestPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            timeout_per_attempt: Duration::from_millis(500),
        }
    }
}

/// Retry policy for [`WingOscClient::request_with_policy`] (R75): UDP has no delivery
/// guarantee, so a request or its reply can simply vanish. Re-sending the same request
/// is safe for every builder in this module -- gets are idempotent, and a set landing
/// twice (because the first send's reply was lost, not the send itself) just reapplies
/// the same value.
#[derive(Clone, Copy, Debug)]
pub struct RequestPolicy {
    pub attempts: u32,
    pub timeout_per_attempt: Duration,
}

/// Tracks an active subscription's format and renewal schedule (R4). Not `pub`: exposed
/// only through [`WingOscClient`]'s methods.
#[derive(Clone, Copy, Debug)]
struct SubscriptionState {
    format: SubscriptionFormat,
    renew_interval: Duration,
    next_renew: Instant,
}

/// A minimal OSC-over-UDP client (R3, R4, R75). UDP is connectionless, so `connect`
/// only binds a local socket and resolves the target -- there's no handshake to
/// perform.
///
/// All methods take `&self` (interior mutability via `RefCell`, not `Mutex`: this type
/// isn't meant to be shared across threads, just to let `request`/`subscribe`/
/// `poll_event` all be called through a shared reference without a separate `&mut`
/// story). It is not designed for concurrent use from multiple threads or for
/// interleaving foreground [`request`](Self::request) calls with background
/// [`poll_event`](Self::poll_event) polling on *the same instance* -- see
/// [`poll_event`](Self::poll_event)'s docs for why, and use
/// [`bind_reply_port`](Self::bind_reply_port) to give a subscription its own socket
/// when a caller needs both.
pub struct WingOscClient {
    socket: UdpSocket,
    target: SocketAddr,
    /// `Some` only after [`bind_reply_port`](Self::bind_reply_port); when set,
    /// [`recv`](Self::recv)/[`request`](Self::request) read from this socket instead
    /// of `socket`, matching a request built with [`with_reply_port`].
    reply_socket: Option<UdpSocket>,
    /// Messages received by [`request`](Self::request) that didn't match what it was
    /// waiting for (R75: out-of-order replies), in arrival order. Drained by
    /// [`take_unsolicited`](Self::take_unsolicited).
    unsolicited: RefCell<Vec<OscMessage>>,
    /// Set by [`subscribe`](Self::subscribe); consulted by
    /// [`poll_event`](Self::poll_event) to auto-renew on cadence.
    subscription: RefCell<Option<SubscriptionState>>,
}

impl WingOscClient {
    /// Binds an ephemeral local UDP socket and targets `ip:2223` (R3).
    pub fn connect(ip: &str) -> Result<Self> {
        let target = (ip, OSC_PORT)
            .to_socket_addrs()?
            .next()
            .ok_or(OscError::Malformed("could not resolve console address"))?;
        Self::connect_addr(target)
    }

    /// Like [`connect`](Self::connect), but targets an arbitrary, already-resolved
    /// address rather than assuming [`OSC_PORT`] -- mirrors
    /// [`crate::WingConsole::connect_addr`]. Mainly useful for tests driving a
    /// loopback stand-in console on an ephemeral port.
    pub fn connect_addr(target: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(target)?;
        Ok(Self {
            socket,
            target,
            reply_socket: None,
            unsolicited: RefCell::new(Vec::new()),
            subscription: RefCell::new(None),
        })
    }

    /// Also binds a second local socket on `reply_port`, for replies the caller
    /// redirects there by wrapping requests with [`with_reply_port`]. Once bound,
    /// [`recv`](Self::recv)/[`request`](Self::request) read from this socket instead
    /// of the one `connect` created (the console's IP doesn't change, page 21 -- only
    /// the destination port of its reply does). This is also the mechanism for giving
    /// a subscription its own socket/port when a caller also needs foreground
    /// `request`/`request_with_policy` calls against the same console -- see
    /// [`poll_event`](Self::poll_event)'s docs -- by wrapping the subscribe message with
    /// [`with_reply_port`] targeting this port before sending it on a second client.
    ///
    /// Local port conflict (R75): if `reply_port` is already bound by another process
    /// (or another socket in this one), this returns `Err(OscError::Io(_))` -- bind
    /// failure is a plain OS error, already a typed variant of this module's error enum.
    pub fn bind_reply_port(mut self, reply_port: u16) -> Result<Self> {
        let sock = UdpSocket::bind(("0.0.0.0", reply_port))?;
        sock.connect(self.target)?;
        self.reply_socket = Some(sock);
        Ok(self)
    }

    fn recv_socket(&self) -> &UdpSocket {
        self.reply_socket.as_ref().unwrap_or(&self.socket)
    }

    /// Encodes and sends `msg`, without waiting for a reply.
    pub fn send(&self, msg: &OscMessage) -> Result<()> {
        let bytes = encode(msg)?;
        self.socket.send(&bytes)?;
        Ok(())
    }

    /// Blocks up to `timeout` for one datagram and decodes it. `Err(OscError::Timeout)`
    /// if nothing arrives in time.
    pub fn recv(&self, timeout: Duration) -> Result<OscMessage> {
        let sock = self.recv_socket();
        sock.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; MAX_PACKET_BYTES];
        let n = sock.recv(&mut buf).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => OscError::Timeout,
            _ => OscError::Io(e),
        })?;
        decode(&buf[..n])
    }

    /// Drains any datagrams already sitting in the socket buffer that are exact
    /// duplicates of `matched` (R75: WING or an intervening network can deliver a UDP
    /// reply twice). Anything that isn't an exact duplicate is buffered via
    /// [`unsolicited`](Self::take_unsolicited) instead of being lost. Uses a very short
    /// timeout rather than a true non-blocking peek: a genuine duplicate of a just-sent
    /// reply arrives essentially immediately on a loopback/LAN, so this adds negligible
    /// latency while still catching it.
    fn drain_duplicate_replies(&self, matched: &OscMessage) {
        loop {
            match self.recv(Duration::from_millis(1)) {
                Ok(msg) if msg == *matched => continue,
                Ok(msg) => {
                    self.unsolicited.borrow_mut().push(msg);
                    break;
                }
                Err(_) => break,
            }
        }
    }

    /// Sends `msg` and waits up to `timeout` for its reply: a message whose address
    /// equals `msg.addr` (the normal get/set-single-parameter case), or the node-ack
    /// address it implies (`<msg.addr>*`, covering [`node_set_local`]; `/*` also
    /// matches, covering [`node_set_root`]).
    ///
    /// Robustness (R75): anything else received while waiting -- an out-of-order
    /// unrelated message -- is buffered (arrival order preserved) rather than dropped,
    /// available via [`take_unsolicited`](Self::take_unsolicited); this mirrors
    /// [`crate::WingConsole`]'s attended-get pattern. Once the real reply arrives, any
    /// exact duplicate of it already queued behind it is drained and discarded rather
    /// than left to confuse a subsequent `request` to the same address.
    pub fn request(&self, msg: &OscMessage, timeout: Duration) -> Result<OscMessage> {
        let deadline = Instant::now() + timeout;
        self.send(msg)?;
        let node_ack_addr = format!("{}*", msg.addr);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(OscError::Timeout);
            }
            let reply = self.recv(remaining)?;
            if reply.addr == msg.addr || reply.addr == node_ack_addr || reply.addr == "/*" {
                self.drain_duplicate_replies(&reply);
                return Ok(reply);
            }
            self.unsolicited.borrow_mut().push(reply);
        }
    }

    /// [`request`](Self::request), retrying up to `policy.attempts` times (R75) if an
    /// attempt times out -- covers a lost request as well as a lost reply, since the
    /// client can't tell which happened. Returns
    /// `Err(OscError::RetriesExhausted { attempts })` if every attempt times out;
    /// any non-timeout error (e.g. [`OscError::Node`]) is returned immediately without
    /// retrying, since re-sending wouldn't change a console-side rejection.
    pub fn request_with_policy(
        &self,
        msg: &OscMessage,
        policy: RequestPolicy,
    ) -> Result<OscMessage> {
        for attempt in 1..=policy.attempts.max(1) {
            match self.request(msg, policy.timeout_per_attempt) {
                Ok(reply) => return Ok(reply),
                Err(OscError::Timeout) if attempt < policy.attempts => continue,
                Err(OscError::Timeout) => {
                    return Err(OscError::RetriesExhausted { attempts: attempt })
                }
                Err(e) => return Err(e),
            }
        }
        Err(OscError::RetriesExhausted {
            attempts: policy.attempts,
        })
    }

    /// Drains and returns every message [`request`](Self::request) has buffered as
    /// unrelated/out-of-order traffic since the last call (R75), in arrival order.
    pub fn take_unsolicited(&self) -> Vec<OscMessage> {
        std::mem::take(&mut self.unsolicited.borrow_mut())
    }

    /// Subscribes to `format`'s event stream (page 30), auto-renewing every
    /// [`SUBSCRIPTION_RENEW_MARGIN`] via [`poll_event`](Self::poll_event) thereafter.
    ///
    /// **Only one OSC subscription is active console-wide at a time (R4), granted to
    /// whichever client last (re)subscribed.** The protocol gives the displaced client
    /// no notification -- it just stops receiving events. Renewal is itself a
    /// re-subscribe, so it's also a takeover: if two clients are both subscribed and
    /// both renewing, whichever renews last each 10-second window "wins" that window,
    /// and the two subscriptions ping-pong for as long as both keep renewing. This is
    /// the protocol's documented behavior, not a bug in this client -- there is no way
    /// to detect or prevent it from the wire alone. Consequently: prolonged silence from
    /// [`poll_event`](Self::poll_event) is *not* reliable evidence of displacement
    /// either (a quiet console produces no events regardless of who holds the
    /// subscription), so don't build a staleness/takeover detector on top of it.
    pub fn subscribe(&self, format: SubscriptionFormat) -> Result<()> {
        self.subscribe_with_renewal(format, SUBSCRIPTION_RENEW_MARGIN)
    }

    /// Like [`subscribe`](Self::subscribe), with an injectable renewal cadence. Exists
    /// so tests can exercise renewal on a short, deterministic interval instead of
    /// waiting out the real 10-second expiry; production callers should use
    /// [`subscribe`](Self::subscribe).
    pub fn subscribe_with_renewal(
        &self,
        format: SubscriptionFormat,
        renew_interval: Duration,
    ) -> Result<()> {
        self.send(&subscribe(format))?;
        *self.subscription.borrow_mut() = Some(SubscriptionState {
            format,
            renew_interval,
            next_renew: Instant::now() + renew_interval,
        });
        Ok(())
    }

    /// Whether the active subscription (if any) is due for its renewal re-send.
    /// [`poll_event`](Self::poll_event) checks this on its own; exposed for callers
    /// pumping their own read loop instead (mirrors
    /// [`crate::WingConsole::keep_alive_meters`]'s caller-owned-pumping story).
    pub fn renew_due(&self) -> bool {
        self.subscription
            .borrow()
            .as_ref()
            .is_some_and(|s| Instant::now() >= s.next_renew)
    }

    /// Re-sends the active subscription's message, re-asserting ownership of it (see
    /// [`subscribe`](Self::subscribe)'s takeover docs), and reschedules the next
    /// renewal. A no-op if there's no active subscription.
    pub fn renew(&self) -> Result<()> {
        let format = match self.subscription.borrow().as_ref() {
            Some(s) => s.format,
            None => return Ok(()),
        };
        self.send(&subscribe(format))?;
        if let Some(s) = self.subscription.borrow_mut().as_mut() {
            s.next_renew = Instant::now() + s.renew_interval;
        }
        Ok(())
    }

    /// Blocks up to `timeout` for the next subscription event, transparently renewing
    /// the active subscription when its cadence comes due while waiting -- mirrors how
    /// [`crate::WingConsole::read_meters`] folds its own keep-alive into a blocking
    /// read: a caller just needs to keep calling `poll_event` at least as often as the
    /// renewal interval, with no separate timer/thread required.
    ///
    /// Requires an active subscription ([`subscribe`](Self::subscribe) first); returns
    /// `Err(OscError::Malformed(_))` otherwise.
    ///
    /// Not safe to interleave with foreground [`request`](Self::request)/
    /// [`request_with_policy`](Self::request_with_policy) calls on the same client: both
    /// read from the same socket, so a get/set reply could be consumed here and
    /// misclassified as an [`OscEvent::Raw`], or an event could be consumed by
    /// `request` and buffered as unsolicited instead of reaching `poll_event`. A caller
    /// needing both should use [`bind_reply_port`](Self::bind_reply_port) to give the
    /// subscription (via [`with_reply_port`]) a dedicated socket/port, polling that from
    /// one client while issuing requests from another.
    pub fn poll_event(&self, timeout: Duration) -> Result<OscEvent> {
        if self.subscription.borrow().is_none() {
            return Err(OscError::Malformed(
                "poll_event called with no active subscription",
            ));
        }
        let deadline = Instant::now() + timeout;
        loop {
            if self.renew_due() {
                self.renew()?;
            }
            let until_deadline = deadline.saturating_duration_since(Instant::now());
            if until_deadline.is_zero() {
                return Err(OscError::Timeout);
            }
            let until_renew = self
                .subscription
                .borrow()
                .as_ref()
                .map(|s| s.next_renew.saturating_duration_since(Instant::now()))
                .unwrap_or(until_deadline);
            let wait = until_deadline
                .min(until_renew)
                .max(Duration::from_millis(1));
            match self.recv(wait) {
                Ok(msg) => return Ok(classify_event(msg)),
                Err(OscError::Timeout) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

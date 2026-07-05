//! OSC-over-UDP transport (U10: R3) -- a sibling to the Native (TCP) transport in
//! `console.rs`, not a replacement for it. WING runs both protocols side by side:
//! Native on TCP port 2222 (see [`crate::WingConsole`]), OSC on UDP port 2223. This
//! module only speaks the latter.
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
//!   ...): construct an [`OscMessage`] for a specific WING operation.
//! - Reply parsers ([`parse_param_reply`], [`parse_node_ack`], [`parse_node_dump`],
//!   [`parse_console_info`]): decode a received [`OscMessage`] into a typed result.
//! - [`WingOscClient`]: the thin UDP transport tying the above together.
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

/// GET a single parameter or node by its path (page 20-21), e.g. `/ch/1/fdr`.
pub fn get_param(path: &str) -> OscMessage {
    OscMessage::new(path, vec![])
}

/// GET a single parameter or node by its native hash id instead of its path (page 21):
/// `/#f50f69f8` for id `0xf50f69f8`.
pub fn get_param_by_id(id: i32) -> OscMessage {
    OscMessage::new(format!("/#{:08x}", id as u32), vec![])
}

/// SET a parameter by sending a string value; WING converts it to the parameter's
/// actual wire type (page 22).
pub fn set_string(path: &str, value: &str) -> OscMessage {
    OscMessage::new(path, vec![OscArg::Str(value.to_string())])
}

/// SET a parameter by sending a float32 value (page 22).
pub fn set_float(path: &str, value: f32) -> OscMessage {
    OscMessage::new(path, vec![OscArg::Float(value)])
}

/// SET a parameter by sending an int32 value (page 22).
pub fn set_int(path: &str, value: i32) -> OscMessage {
    OscMessage::new(path, vec![OscArg::Int(value)])
}

/// Toggles a 0/1 int parameter (page 22): sending `-1` to an int-typed 0/1 parameter
/// flips it, saving a read-before-write round-trip.
pub fn toggle(path: &str) -> OscMessage {
    set_int(path, -1)
}

/// SET a `StringEnum` parameter by its item name (page 22), e.g. `mode` -> `"FX"`.
pub fn set_enum_by_name(path: &str, name: &str) -> OscMessage {
    set_string(path, name)
}

/// SET an enum parameter by its position in the item list (page 23), e.g. `mode` ->
/// index `6` (== `"FX"` in that def's list).
pub fn set_enum_by_index(path: &str, index: i32) -> OscMessage {
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
pub fn node_set_local(node_path: &str, pairs: &[(&str, &str)]) -> OscMessage {
    OscMessage::new(node_path, vec![OscArg::Str(format_node_pairs(pairs))])
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
pub fn node_dump(node_path: &str) -> OscMessage {
    OscMessage::new(node_path, vec![OscArg::Str("*".to_string())])
}

/// Node introspection: parameter description without current values (`?` argument,
/// page 24).
pub fn node_describe(node_path: &str) -> OscMessage {
    OscMessage::new(node_path, vec![OscArg::Str("?".to_string())])
}

/// Node introspection: parameter description including current values (`#` argument,
/// page 25).
pub fn node_describe_with_values(node_path: &str) -> OscMessage {
    OscMessage::new(node_path, vec![OscArg::Str("#".to_string())])
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
}

/// A parsed single-parameter GET reply.
#[derive(Clone, Debug, PartialEq)]
pub struct ParamReply {
    pub path: String,
    pub facets: ParamFacets,
}

/// Parses a single-parameter GET reply (page 21): `,s` / `,sff` / `,sfi` depending on
/// the parameter's type.
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
        _ => return Err(OscError::Malformed("unexpected parameter reply shape")),
    };
    Ok(ParamReply {
        path: msg.addr.clone(),
        facets,
    })
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

/// A minimal OSC-over-UDP client (R3). UDP is connectionless, so `connect` only binds
/// a local socket and resolves the target -- there's no handshake to perform.
///
/// Extension points left for U11 (R4, R75): this struct deliberately has no
/// subscription state, no de-duplication/reordering buffer, and no retry policy.
/// [`request`](Self::request) is a simple send-and-filter loop, not the
/// buffer-unrelated-replies approach [`crate::WingConsole`]'s attended-get uses --
/// good enough for single-shot get/set, but subscriptions need more (a persistent
/// listener, sequence tracking, one-active-subscription takeover) that belongs in U11.
pub struct WingOscClient {
    socket: UdpSocket,
    target: SocketAddr,
    /// `Some` only after [`bind_reply_port`](Self::bind_reply_port); when set,
    /// [`recv`](Self::recv)/[`request`](Self::request) read from this socket instead
    /// of `socket`, matching a request built with [`with_reply_port`].
    reply_socket: Option<UdpSocket>,
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
        })
    }

    /// Also binds a second local socket on `reply_port`, for replies the caller
    /// redirects there by wrapping requests with [`with_reply_port`]. Once bound,
    /// [`recv`](Self::recv)/[`request`](Self::request) read from this socket instead
    /// of the one `connect` created (the console's IP doesn't change, page 21 -- only
    /// the destination port of its reply does).
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

    /// Sends `msg` and waits up to `timeout` for its reply: a message whose address
    /// equals `msg.addr` (the normal get/set-single-parameter case), or the node-ack
    /// address it implies (`<msg.addr>*`, covering [`node_set_local`]; `/*` also
    /// matches, covering [`node_set_root`]). Anything else received in the meantime is
    /// discarded rather than buffered -- see the struct docs for why.
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
                return Ok(reply);
            }
        }
    }
}

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::native::{ChannelDecoder, ChannelEvent, NativeValue};
use crate::node::{NodeType, PropMap, WingNodeData, WingNodeDef};
use crate::propmap::NAME_TO_DEF;
use crate::{Error, Result, WingResponse};

/// Lock a `Mutex`, recovering the guard if a panic in another thread poisoned it (U4 hardening).
///
/// `WingConsole` shares its transports and state across threads (a meter-reading loop alongside
/// command writers) via `Arc<Mutex<_>>`. With `.lock_recover()`, one thread panicking while
/// holding any of these locks would poison it and turn *every* subsequent console operation on
/// every thread into a panic — a single fault cascading into a total, unrecoverable brick.
///
/// libwing's guarded sections are short and leave their data structurally valid across an unwind,
/// so recovering the guard is safe and deliberate: a peer-thread panic no longer bricks the
/// console. For the transport locks this also degrades cleanly — a genuinely broken socket still
/// surfaces as an I/O error on the next read/write, which the caller maps to
/// [`Error::ConnectionError`] and recovers via reconnect, exactly as before. A read cut short
/// by a reconnect on another clone reports [`Error::Reconnecting`] instead, so it is not
/// mistaken for a drop that needs a second reconnect.
trait LockRecover<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A duplex byte stream `WingConsole` can read/write commands over.
///
/// `Read`/`Write` alone aren't enough: [`WingConsole::decode_next`] dynamically
/// re-arms the read timeout (bounded by the keep-alive cadence, and by an attended-get
/// deadline when one is active) between reads, so the transport must expose that knob.
/// `shutdown` defaults to a no-op so non-socket transports (tests, replay) don't need to
/// implement teardown semantics; [`TcpStream`] overrides it to actually close the socket.
pub trait Transport: Read + Write + Send {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()>;

    fn shutdown(&self, _how: Shutdown) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }

    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        TcpStream::shutdown(self, how)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meter {
    Channel(u8),
    Aux(u8),
    Bus(u8),
    Main(u8),
    Matrix(u8),
    Dca(u8),
    Fx(u8),
    Source(u8),
    Output(u8),
    Monitor,
    Rta,
    Channel2(u8),
    Aux2(u8),
    Bus2(u8),
    Main2(u8),
    Matrix2(u8),
}

impl Meter {
    /// `(opcode, index, max)`: the family's wire opcode, the 1-based index (0 for the
    /// index-less `Monitor`/`Rta`), and the family's largest valid index. The single source
    /// for the family table: subscribe encoding, the server-side subscribe decoder, and the C
    /// API's meter ids all go through this and [`from_wire`](Self::from_wire).
    pub(crate) fn wire(self) -> (u8, u8, u8) {
        match self {
            Meter::Channel(n) => (0xa0, n, 40),
            Meter::Aux(n) => (0xa1, n, 8),
            Meter::Bus(n) => (0xa2, n, 16),
            Meter::Main(n) => (0xa3, n, 4),
            Meter::Matrix(n) => (0xa4, n, 8),
            Meter::Dca(n) => (0xa5, n, 16),
            Meter::Fx(n) => (0xa6, n, 16),
            Meter::Source(n) => (0xa7, n, 16),
            Meter::Output(n) => (0xa8, n, 11),
            Meter::Monitor => (0xa9, 0, 0),
            Meter::Rta => (0xaa, 0, 0),
            Meter::Channel2(n) => (0xab, n, 40),
            Meter::Aux2(n) => (0xac, n, 8),
            Meter::Bus2(n) => (0xad, n, 16),
            Meter::Main2(n) => (0xae, n, 4),
            Meter::Matrix2(n) => (0xaf, n, 8),
        }
    }

    /// Inverse of [`wire`](Self::wire) for a family opcode and 1-based index. The index is not
    /// range-checked here (encoding does that); `None` for an unknown opcode or a nonzero index
    /// on `Monitor`/`Rta`.
    pub(crate) fn from_wire(opcode: u8, index: u8) -> Option<Self> {
        Some(match opcode {
            0xa0 => Meter::Channel(index),
            0xa1 => Meter::Aux(index),
            0xa2 => Meter::Bus(index),
            0xa3 => Meter::Main(index),
            0xa4 => Meter::Matrix(index),
            0xa5 => Meter::Dca(index),
            0xa6 => Meter::Fx(index),
            0xa7 => Meter::Source(index),
            0xa8 => Meter::Output(index),
            0xa9 if index == 0 => Meter::Monitor,
            0xaa if index == 0 => Meter::Rta,
            0xab => Meter::Channel2(index),
            0xac => Meter::Aux2(index),
            0xad => Meter::Bus2(index),
            0xae => Meter::Main2(index),
            0xaf => Meter::Matrix2(index),
            _ => return None,
        })
    }
}

lazy_static::lazy_static! {
    static ref ID_TO_NAME: PropMap<i32, Vec<&'static str>> = {
        let mut id2name = PropMap::<i32, Vec<&'static str>>::default();
        for (&fullname, def) in NAME_TO_DEF.iter() {
            id2name.entry(def.id).or_default().push(fullname);
        }
        id2name
    };
}

const RX_BUFFER_SIZE: usize = 2048;
const DATA_KEEP_ALIVE_SECONDS: u64 = 7;
const METERS_KEEP_ALIVE_SECONDS: u64 = 3;
const WRITE_TIMEOUT_SECONDS: u64 = 5;
const MAX_NODE_DEF_BYTES: usize = 1024 * 1024;
/// The Native channel carrying parameter traffic; bytes on any other channel are not
/// Audio Engine tokens and are dropped by the reader.
const AUDIO_ENGINE_CHANNEL: u8 = 1;
/// Most unrelated responses an attended get buffers while it waits for its target. Far
/// above any legitimate interleave; a peer that floods past it fails the call closed
/// ([`Error::InvalidData`]) instead of growing client memory until the deadline.
const MAX_ATTENDED_BUFFERED: usize = 64 * 1024;
/// Receive buffer for one meter datagram: a 4-byte header plus big-endian i16 samples.
const METER_FRAME_BYTES: usize = 8192;
/// Most samples one meter datagram can carry.
pub(crate) const MAX_METER_SAMPLES: usize = (METER_FRAME_BYTES - 4) / 2;

/// Big-endian samples of a meter frame body. `as_chunks` gives LLVM fixed-size pairs, which it
/// vectorizes (about 2x `chunks_exact` on a full frame).
fn meter_samples(bytes: &[u8]) -> impl Iterator<Item = i16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| i16::from_be_bytes(pair))
}
/// UDP port a WING answers `WING?` discovery and firmware probes on.
const DISCOVERY_PORT: u16 = 2222;
/// Upper bound for one de-escaped Native response and for a raw binary-node capture.
///
/// A whole-desk dump is normally well below 1 MiB. Keeping 16 MiB leaves ample room for
/// future firmware growth while preventing a malformed or hostile peer from growing the
/// timeout replay and binary-capture buffers without bound.
const MAX_NATIVE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn ensure_native_response_capacity(len: usize) -> Result<()> {
    if len >= MAX_NATIVE_RESPONSE_BYTES {
        Err(Error::InvalidData)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryInfo {
    /// From [`WingConsole::scan`]: the source address of the reply datagram, not the address
    /// the reply claims for itself, which any host on the LAN can set to anything.
    pub ip: String,
    pub name: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

impl DiscoveryInfo {
    /// Parses a `WING,<ip>,<name>,<model>,<serial>,<firmware>` reply body (the UDP discovery
    /// reply and the OSC `/?` reply share it). `ip` is the reply's self-asserted address.
    pub(crate) fn parse(reply: &str) -> Option<Self> {
        let mut tokens = reply.split(',');
        if tokens.next()? != "WING" {
            return None;
        }
        Some(Self {
            ip: tokens.next()?.to_string(),
            name: tokens.next()?.to_string(),
            model: tokens.next()?.to_string(),
            serial: tokens.next()?.to_string(),
            firmware: tokens.next()?.to_string(),
        })
    }

    /// [`parse`](Self::parse) for a discovery datagram that arrived from `from`. The claimed
    /// ip is replaced by the datagram source, so a responder can only ever point a client at
    /// itself, never at a third host.
    fn from_datagram(payload: &[u8], from: IpAddr) -> Option<Self> {
        let mut info = Self::parse(std::str::from_utf8(payload).ok()?)?;
        info.ip = from.to_string();
        Some(info)
    }
}

pub struct Meters {
    /// Shared so `read_meters` can wait on it without holding the meter-state lock, which
    /// `keep_alive_meters`/`request_meter` on other clones need.
    pub socket: Arc<UdpSocket>,
    pub port: u16,
}

/// Bounded-backoff policy for [`WingConsole::reconnect`] (R2).
///
/// Each failed attempt sleeps `initial_backoff * 2^n` (capped at `max_backoff`) before the
/// next, so an unreachable console produces bounded backoff instead of a busy loop. After
/// `max_attempts` failures, `reconnect` returns the last connection error.
#[derive(Clone, Debug)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for ReconnectPolicy {
    /// 5 attempts, starting at 250ms and doubling up to a 5s cap.
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(5),
        }
    }
}

/// What a caller must assume was lost across a [`WingConsole::reconnect`] (R42).
///
/// The WING wire protocol has no session resumption: a reconnect is a brand-new TCP session,
/// not a continuation of the old one. This struct is the "surface partial state rather than
/// hiding it" contract -- each field documents the action a consumer should take.
#[derive(Clone, Debug)]
pub struct SessionGap {
    /// Always `true`: any unsolicited `NodeData`/`NodeDef` the console sent between the
    /// disconnect and the reconnect is gone -- there's no buffering or replay on the wire.
    /// Consumers that mirror console state should treat their mirror as stale and re-request
    /// (`get_node_data`/`get_node_definition`/`request_node_data`) whatever they still need.
    pub dropped_events: bool,
    /// `true` iff a meter subscription ([`request_meter`](WingConsole::request_meter)) existed
    /// before the reconnect. The UDP meter socket itself is untouched and still usable, but the
    /// *subscription* lived on the console side of the old TCP session and is gone with it --
    /// the server has forgotten it. Consumers must call `request_meter` again to resume
    /// metering.
    pub meters_invalidated: bool,
    /// Always `true`: the console may have changed (another controller, or the hardware
    /// itself) while this session was down. Consumers that track node values should re-sync
    /// via `get_node_data`/`request_node_data` for the nodes they mirror rather than assume
    /// their cached values are still current.
    pub state_may_have_changed: bool,
}

/// Result of a successful [`WingConsole::reconnect`].
#[derive(Clone, Debug)]
pub struct ReconnectOutcome {
    /// Number of connection attempts made, including the one that succeeded (1-based).
    pub attempts: u32,
    /// What the caller lost / must re-sync across the gap (R42).
    pub gap: SessionGap,
}

struct _WingConsoleMain {
    keep_alive_timer: std::time::Instant,
    rx_buf: [u8; RX_BUFFER_SIZE],
    rx_buf_tail: usize,
    rx_buf_size: usize,
    rx_channels: ChannelDecoder,
    rx_events: VecDeque<ChannelEvent>,
    /// Decoded bytes replayed after a bounded read timed out mid-response. `read_timeout` is
    /// cancellation-safe: bytes already removed from the transport are never discarded.
    replay: VecDeque<(i8, u8)>,
    /// Whole responses already read off the wire but not yet delivered: an attended get that
    /// times out hands back what it buffered, and the next `read()` returns these first.
    pending: VecDeque<WingResponse>,
    read_capture: Vec<(i8, u8)>,
    current_node_id: i32,
    /// Overall deadline for an in-flight attended-get operation (R16/R17), consulted by
    /// `decode_next` so a stuck socket read can't run past it. `None` outside of
    /// attended-get, in which case reads are bounded only by the keep-alive cadence, same
    /// as before this field existed.
    op_deadline: Option<Instant>,
    /// When `Some`, every de-escaped logical byte `decode_next` yields is also appended
    /// here, tapping the raw native token stream without disturbing normal parsing. Set by
    /// `get_binary_node` for the span of one attended data request and taken back out when
    /// it completes; `None` (no capture) at all other times.
    capture: Option<Vec<u8>>,
}

struct _WingConsoleMeters {
    meters: Option<Meters>,
    /// The one subscription the meter keepalive renews: the most recent successful
    /// `request_meter` on this session. Earlier subscriptions are left to lapse.
    active_meter_id: Option<u16>,
    /// Report id for the next `request_meter`; wraps, skipping 0.
    next_meter_id: u16,
    keep_alive_meters_timer: std::time::Instant,
}

/// Handle to a connected (or test-constructed) Wing console. Cheap to `Clone`: clones share
/// the same underlying transports and state via `Arc<Mutex<_>>`, so e.g. a meter-reading loop
/// can hold its own clone of the same session independently of the node-data reader.
///
/// ## Keepalive ownership (R44)
///
/// The WING protocol tears down each socket after a short idle period, so *something* has to
/// keep writing to it even when the caller has nothing new to say:
///
/// - **Data keepalive** (7s cadence) is fully automatic: every [`read`](Self::read) call
///   checks the timer and re-arms it internally. A caller driving `read()` in a loop (the
///   normal usage pattern) never needs to think about this.
/// - **Meter keepalive** (3s cadence) is automatic *only while the caller is actively driving
///   the meter path*: [`read_meters`](Self::read_meters) and [`request_meter`](Self::request_meter)
///   both check and re-arm it internally. A caller that calls `request_meter` once and then
///   stops calling `read_meters` (e.g. a paused meter UI) lets the subscription lapse
///   server-side, since nothing is re-arming the timer on its behalf.
/// - Both have a public escape hatch -- [`keep_alive`](Self::keep_alive) and
///   [`keep_alive_meters`](Self::keep_alive_meters) -- for callers who own a loop that isn't
///   `read()`/`read_meters()` itself (e.g. a UI thread idling with no pending requests) and
///   still need to keep the respective socket alive on their own cadence.
#[derive(Clone)]
pub struct WingConsole {
    rsock: Arc<Mutex<Box<dyn Transport>>>,
    wsock: Arc<Mutex<Box<dyn Transport>>>,
    main: Arc<Mutex<_WingConsoleMain>>,
    read_gate: Arc<Mutex<()>>,
    reconnect_gate: Arc<Mutex<()>>,
    reconnecting: Arc<AtomicBool>,
    /// A raw capture timed out after consuming part of an uncorrelated stream. Only a new
    /// TCP session can prove that the unread tail no longer belongs to the failed request.
    stream_tainted: Arc<AtomicBool>,
    /// Clones waiting on `reconnect_gate`; a `dump_subtree` sweep yields to them.
    pending_reconnects: Arc<AtomicUsize>,
    /// Bumped by every successful reconnect, so a clone that queued behind another clone's
    /// reconnect can see the session was already replaced and skip a second handshake.
    session_generation: Arc<AtomicU64>,
    mtrs: Arc<Mutex<_WingConsoleMeters>>,
    has_meter_socket: Arc<AtomicBool>,
    peer_ip: IpAddr,
    /// The peer's TCP port, so [`reconnect`](Self::reconnect) can target the same endpoint
    /// without re-resolving a hostname (`connect` always used 2222; `connect_addr` may not
    /// have). Unused (and meaningless) on a [`from_transports`](Self::from_transports)
    /// console, which never reconnects.
    peer_port: u16,
    /// UDP port `reconnect` re-probes for firmware; the WING discovery port outside tests.
    firmware_probe_port: u16,
    /// `true` for consoles backed by a real TCP connection ([`connect`](Self::connect) /
    /// [`connect_addr`](Self::connect_addr)); `false` for [`from_transports`](Self::from_transports)
    /// consoles (tests/replay), which have no real peer to reconnect to.
    reconnectable: bool,
    firmware: Arc<Mutex<Option<String>>>,
}

impl WingConsole {
    /// Broadcasts `WING?` and collects replies for up to 5 s. Each console is listed once
    /// (by source address and serial), however many rebroadcasts it answers.
    pub fn scan(stop_on_first: bool) -> Result<Vec<DiscoveryInfo>> {
        let dsock = UdpSocket::bind("0.0.0.0:0")?;
        dsock.set_broadcast(true)?;
        Self::scan_on(
            &dsock,
            SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT)),
            stop_on_first,
            Duration::from_secs(5),
        )
    }

    fn scan_on(
        dsock: &UdpSocket,
        target: SocketAddr,
        stop_on_first: bool,
        window: Duration,
    ) -> Result<Vec<DiscoveryInfo>> {
        dsock.set_read_timeout(Some(Duration::from_millis(500)))?;

        let mut results: Vec<DiscoveryInfo> = Vec::new();
        let mut attempts = 0;
        let deadline = std::time::Instant::now() + window;
        let mut packets_seen = 0;

        dsock.send_to(b"WING?", target)?;
        while attempts < 10 && packets_seen < 100 && std::time::Instant::now() < deadline {
            let mut buf = [0u8; 1024];
            match dsock.recv_from(&mut buf) {
                Ok((received, from)) => {
                    packets_seen += 1;
                    let Some(info) = DiscoveryInfo::from_datagram(&buf[..received], from.ip())
                    else {
                        continue;
                    };
                    if !results
                        .iter()
                        .any(|seen| seen.ip == info.ip && seen.serial == info.serial)
                    {
                        results.push(info);
                        if stop_on_first {
                            break;
                        }
                    }
                }
                Err(_) => {
                    attempts += 1;
                    // Re-broadcast the probe on each receive timeout. UDP broadcast is
                    // unreliable; sending "WING?" only once means a single dropped packet
                    // yields an empty scan even though a console is present.
                    let _ = dsock.send_to(b"WING?", target);
                }
            }
        }

        Ok(results)
    }

    pub fn connect(host_or_ip: Option<&str>) -> Result<Self> {
        // Discovery's broadcast scan reply already carries firmware; reuse it
        // instead of re-probing. Connecting to an explicit IP has no such
        // reply, so `firmware_hint` stays `None` there and a targeted probe
        // runs after the connection is up (R37: capability-detect, don't
        // assume).
        let (ip, firmware_hint) = if let Some(i) = host_or_ip {
            (i.to_string(), None)
        } else {
            let devices = WingConsole::scan(true)?;
            if !devices.is_empty() {
                (devices[0].ip.clone(), Some(devices[0].firmware.clone()))
            } else {
                return Err(Error::DiscoveryError);
            }
        };

        let mut last_connect_error = None;
        for addr in (ip.as_str(), 2222).to_socket_addrs()? {
            match Self::handshake(addr) {
                Ok(console) => {
                    let firmware = firmware_hint
                        .clone()
                        .or_else(|| Self::probe_firmware(addr.ip(), DISCOVERY_PORT));
                    *console.firmware.lock_recover() = firmware;
                    return Ok(console);
                }
                Err(err) => last_connect_error = Some(err),
            }
        }

        if let Some(err) = last_connect_error {
            Err(err)
        } else {
            Err(Error::ConnectionError)
        }
    }

    /// Connects directly to `addr` instead of resolving a hostname/discovery IP against the
    /// default WING port (2222). Useful for consoles reached through port forwarding or on a
    /// non-standard port. Performs the same handshake and best-effort firmware probe as
    /// [`connect`](Self::connect) (there's no discovery reply to reuse here, so firmware is
    /// always probed).
    pub fn connect_addr(addr: SocketAddr) -> Result<Self> {
        let console = Self::handshake(addr)?;
        *console.firmware.lock_recover() = Self::probe_firmware(addr.ip(), DISCOVERY_PORT);
        Ok(console)
    }

    /// TCP connect + Wing handshake (nodelay, write timeout, initial `0xdf 0xd1` probe) against
    /// a single resolved address, returning the raw duplex streams. Shared by
    /// [`connect`](Self::connect), [`connect_addr`](Self::connect_addr), and
    /// [`reconnect`](Self::reconnect) so this logic lives in exactly one place.
    fn handshake_streams(addr: SocketAddr) -> Result<(TcpStream, TcpStream)> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        // stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        // Bound writes: without a write timeout, write_all() can block forever if the
        // peer's receive window stays full (dead/stalled console), permanently hanging
        // any thread that sends a command or keep-alive.
        stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS)))?;
        stream.write_all(&[0xdf, 0xd1])?;
        let wsock = stream.try_clone()?;
        Ok((wsock, stream))
    }

    fn handshake(addr: SocketAddr) -> Result<Self> {
        let (wsock, rsock) = Self::handshake_streams(addr)?;
        Ok(Self::from_streams(wsock, rsock, addr.ip(), addr.port()))
    }

    /// Best-effort unicast firmware probe used by `connect()` when connecting
    /// to an explicit IP (no broadcast scan reply to read firmware from).
    /// Sends the same `"WING?"` discovery query [`scan`](Self::scan)
    /// broadcasts, but unicast to the target so it doesn't depend on subnet
    /// broadcast reachability. Non-fatal by design (R37): any failure --
    /// socket error, timeout, malformed reply -- yields `None` rather than
    /// failing `connect()` or guessing a firmware value.
    ///
    /// Only a reply from `ip` itself counts: datagrams from any other host are ignored, so
    /// a LAN host cannot inject the firmware string that drives newer-firmware warnings.
    fn probe_firmware(ip: IpAddr, port: u16) -> Option<String> {
        let dsock = UdpSocket::bind("0.0.0.0:0").ok()?;
        dsock.send_to(b"WING?", (ip, port)).ok()?;

        let deadline = Instant::now() + Duration::from_millis(300);
        let mut buf = [0u8; 1024];
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            dsock
                .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
                .ok()?;
            let (received, from) = dsock.recv_from(&mut buf).ok()?;
            if from.ip() == ip {
                return DiscoveryInfo::from_datagram(&buf[..received], ip)
                    .map(|info| info.firmware);
            }
        }
    }

    /// The connected console's firmware version, if known (R37).
    ///
    /// Populated at [`connect`](Self::connect) time: from the broadcast scan
    /// reply when connecting via discovery, or from a best-effort unicast
    /// probe when connecting to an explicit IP. Refreshed by the same unicast
    /// probe after [`reconnect`](Self::reconnect); a reconnect probe that gets no
    /// reply keeps the previous value. `None` if neither produced a
    /// reply (e.g. probing blocked by network policy) -- never a guessed or
    /// default value. Feeds [`crate::Schema::staleness`].
    pub fn firmware(&self) -> Option<String> {
        self.firmware.lock_recover().clone()
    }

    fn from_streams(wsock: TcpStream, rsock: TcpStream, peer_ip: IpAddr, peer_port: u16) -> Self {
        Self::from_boxed(Box::new(wsock), Box::new(rsock), peer_ip, peer_port, true)
    }

    /// Construct a [`WingConsole`] over arbitrary reader/writer transports instead of a
    /// live TCP connection to a physical console.
    ///
    /// This is the replay/testing entry point (the record-replay fixture harness builds
    /// on it) -- normal use should go through [`connect`](Self::connect). Because there's no
    /// real peer behind these transports, [`reconnect`](Self::reconnect) always fails with
    /// `Error::InvalidInput` on a console built this way; tests exercising reconnect should
    /// use a real (localhost) TCP socket via [`connect_addr`](Self::connect_addr) instead.
    pub fn from_transports(
        reader: impl Transport + 'static,
        writer: impl Transport + 'static,
        peer_ip: IpAddr,
    ) -> Self {
        Self::from_boxed(Box::new(writer), Box::new(reader), peer_ip, 0, false)
    }

    fn from_boxed(
        wsock: Box<dyn Transport>,
        rsock: Box<dyn Transport>,
        peer_ip: IpAddr,
        peer_port: u16,
        reconnectable: bool,
    ) -> Self {
        Self {
            wsock: Arc::new(Mutex::new(wsock)),
            rsock: Arc::new(Mutex::new(rsock)),
            main: Arc::new(Mutex::new(_WingConsoleMain {
                keep_alive_timer: std::time::Instant::now()
                    + std::time::Duration::from_secs(DATA_KEEP_ALIVE_SECONDS),
                rx_buf: [0; RX_BUFFER_SIZE],
                rx_buf_tail: 0,
                rx_buf_size: 0,
                // Captured/test transports historically pass an already-selected
                // Audio Engine payload. Starting on channel 1 preserves that API;
                // a real stream's handshake selection simply selects it again.
                rx_channels: ChannelDecoder::with_channel(AUDIO_ENGINE_CHANNEL)
                    .expect("Audio Engine is a valid Native channel"),
                rx_events: VecDeque::new(),
                replay: VecDeque::new(),
                pending: VecDeque::new(),
                read_capture: Vec::new(),
                current_node_id: 0,
                op_deadline: None,
                capture: None,
            })),
            read_gate: Arc::new(Mutex::new(())),
            reconnect_gate: Arc::new(Mutex::new(())),
            reconnecting: Arc::new(AtomicBool::new(false)),
            stream_tainted: Arc::new(AtomicBool::new(false)),
            pending_reconnects: Arc::new(AtomicUsize::new(0)),
            session_generation: Arc::new(AtomicU64::new(0)),
            mtrs: Arc::new(Mutex::new(_WingConsoleMeters {
                keep_alive_meters_timer: std::time::Instant::now()
                    + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS),
                meters: None,
                active_meter_id: None,
                next_meter_id: 1,
            })),
            has_meter_socket: Arc::new(AtomicBool::new(false)),
            peer_ip,
            peer_port,
            firmware_probe_port: DISCOVERY_PORT,
            reconnectable,
            firmware: Arc::new(Mutex::new(None)),
        }
    }

    /// Re-establishes the TCP session to the same peer this console was originally connected
    /// to ([`connect`](Self::connect) or [`connect_addr`](Self::connect_addr)), with bounded
    /// exponential backoff between attempts (R2).
    ///
    /// The new streams are swapped into this console's transports **in place**, so clones of
    /// this `WingConsole` (e.g. a meter-reading loop on another thread) keep working without
    /// needing to be re-obtained. Buffered receive state (partial frame, escape flag, current
    /// node id) is reset -- a fresh TCP session has no partial frame to resume. An in-flight
    /// read on another clone is interrupted with a connection error before the swap.
    ///
    /// The meter UDP socket, if any, is left untouched: it's a client-side socket and still
    /// usable. But the meter *subscription* lived server-side on the old session and is gone
    /// with it; see [`SessionGap::meters_invalidated`] -- callers must call
    /// [`request_meter`](Self::request_meter) again to resume metering.
    ///
    /// Concurrent calls on several clones are coalesced: a call that had to wait for another
    /// clone's reconnect to finish returns that session instead of replacing it again, with
    /// [`ReconnectOutcome::attempts`] `== 0`.
    ///
    /// Returns `Err(Error::InvalidInput)` immediately for a console built via
    /// [`from_transports`](Self::from_transports) -- there's no real peer to reconnect to.
    pub fn reconnect(&mut self, policy: &ReconnectPolicy) -> Result<ReconnectOutcome> {
        if !self.reconnectable {
            return Err(Error::InvalidInput);
        }
        let generation = self.session_generation.load(Ordering::Acquire);
        let reconnect_gate = self.reconnect_gate.clone();
        self.pending_reconnects.fetch_add(1, Ordering::AcqRel);
        let _reconnect_guard = reconnect_gate.lock_recover();
        self.pending_reconnects.fetch_sub(1, Ordering::AcqRel);
        let gap = |console: &Self| SessionGap {
            dropped_events: true,
            meters_invalidated: console.has_meter_socket.load(Ordering::Acquire),
            state_may_have_changed: true,
        };
        if self.session_generation.load(Ordering::Acquire) != generation {
            return Ok(ReconnectOutcome {
                attempts: 0,
                gap: gap(self),
            });
        }
        let addr = SocketAddr::new(self.peer_ip, self.peer_port);
        let mut backoff = policy.initial_backoff;
        let mut last_err = Error::ConnectionError;
        for attempt in 1..=policy.max_attempts {
            match Self::handshake_streams(addr) {
                Ok((wsock, rsock)) => {
                    let firmware = Self::probe_firmware(addr.ip(), self.firmware_probe_port);
                    // Close the old read half to wake a clone blocked in `read()`.
                    // Release the writer lock before waiting for that reader: it may
                    // itself need the writer lock to finish a keepalive.
                    self.reconnecting.store(true, Ordering::Release);
                    let _ = self.wsock.lock_recover().shutdown(Shutdown::Read);
                    let read_gate = self.read_gate.clone();
                    let _read_guard = read_gate.lock_recover();
                    // No reader is active now. Keep the writer locked until both
                    // streams and their parser state belong to the new session.
                    // Lock `main` before the sockets: `keep_alive` and `read_inner`
                    // hold `main` while taking a socket lock, so the reverse order
                    // would deadlock against a clone keeping the session alive.
                    {
                        let mut main = self.main.lock_recover();
                        let mut old_writer = self.wsock.lock_recover();
                        let mut old_reader = self.rsock.lock_recover();
                        *old_writer = Box::new(wsock);
                        *old_reader = Box::new(rsock);
                        main.rx_buf_tail = 0;
                        main.rx_buf_size = 0;
                        main.rx_channels = ChannelDecoder::with_channel(AUDIO_ENGINE_CHANNEL)
                            .expect("Audio Engine is a valid Native channel");
                        main.rx_events.clear();
                        main.replay.clear();
                        main.pending.clear();
                        main.read_capture.clear();
                        main.capture = None;
                        main.current_node_id = 0;
                        main.op_deadline = None;
                        main.keep_alive_timer =
                            Instant::now() + Duration::from_secs(DATA_KEEP_ALIVE_SECONDS);
                    }
                    // The subscription died with the old session; stop renewing its id on the
                    // new one. Taken on its own, never under a socket lock (the keepalive
                    // takes `mtrs` before `wsock`).
                    self.mtrs.lock_recover().active_meter_id = None;
                    if firmware.is_some() {
                        *self.firmware.lock_recover() = firmware;
                    }
                    self.session_generation.fetch_add(1, Ordering::AcqRel);
                    self.stream_tainted.store(false, Ordering::Release);
                    self.reconnecting.store(false, Ordering::Release);
                    return Ok(ReconnectOutcome {
                        attempts: attempt,
                        gap: gap(self),
                    });
                }
                Err(err) => {
                    last_err = err;
                    if attempt < policy.max_attempts {
                        std::thread::sleep(backoff);
                        backoff = backoff.saturating_mul(2).min(policy.max_backoff);
                    }
                }
            }
        }
        Err(last_err)
    }

    pub fn read(&mut self) -> Result<WingResponse> {
        // Parsing one logical response spans multiple `main` lock acquisitions. Serialize that
        // whole transaction across cheap `WingConsole` clones so timeout rollback from one
        // reader cannot replay bytes already committed by another reader.
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        self.read_locked()
    }

    /// Complete one read while the caller holds `read_gate`.
    fn read_locked(&mut self) -> Result<WingResponse> {
        if self.stream_tainted.load(Ordering::Acquire) {
            return Err(Error::ConnectionError);
        }
        if self.reconnecting.load(Ordering::Acquire) {
            return Err(Error::Reconnecting);
        }
        let previous_node_id = {
            let mut main = self.main.lock_recover();
            if let Some(response) = main.pending.pop_front() {
                return Ok(response);
            }
            main.read_capture.clear();
            main.current_node_id
        };
        let result = self.read_inner();
        let mut main = self.main.lock_recover();
        if matches!(result, Err(Error::Timeout)) {
            let captured = std::mem::take(&mut main.read_capture);
            for decoded in captured.into_iter().rev() {
                main.replay.push_front(decoded);
            }
            main.current_node_id = previous_node_id;
        } else {
            main.read_capture.clear();
        }
        // A reconnect on another clone shuts the old read half down to wake this reader; the
        // resulting EOF or I/O error is that reconnect, not a dropped session.
        match result {
            Err(Error::ConnectionError | Error::Io(_))
                if self.reconnecting.load(Ordering::Acquire) =>
            {
                Err(Error::Reconnecting)
            }
            result => result,
        }
    }

    fn read_inner(&mut self) -> Result<WingResponse> {
        let mainptr = self.main.clone();
        let mut main = mainptr.lock_recover();
        let mut raw = Vec::new();
        loop {
            raw.clear();
            let (ch, cmd) = self.decode_next(&mut main, &mut raw)?;
            //println!("Channel: {}, Command: {:X}", ch, cmd);
            if cmd <= 0x3f {
                let v = cmd as i32;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_i32(v),
                ));
            } else if cmd <= 0x7f {
                //                let v = cmd - 0x40 + 1;
                // println!("REQUEST: NODE INDEX: {}", v);
            } else if cmd <= 0xbf {
                let len = cmd - 0x80 + 1;
                let v = self.read_string(&mut main, ch, len as usize, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_string(v),
                ));
            } else if cmd <= 0xcf {
                // Node-name selector (navigation), not a value: consume its bytes to stay
                // framed, as `parse_binary_values` and the request decoder do.
                let len = cmd - 0xc0 + 1;
                for _ in 0..len {
                    self.decode_next(&mut main, &mut raw)?;
                }
            } else if cmd == 0xd0 {
                let v = String::new();
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_string(v),
                ));
            } else if cmd == 0xd1 {
                // Length is transmitted as (real_len - 1), so real_len can be up to 256.
                // Widen to usize before the +1 so a 0xff length byte (256-byte string) does
                // not overflow u8 (panic in debug, wrap-to-0 stream desync in release).
                let len = self.read_u8(&mut main, ch, &mut raw)? as usize + 1;
                let v = self.read_string(&mut main, ch, len, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_string(v),
                ));
            } else if cmd == 0xd2 {
                // Widen before +1: a 0xffff index would overflow u16 (debug panic on
                // otherwise-valid protocol input).
                let _v = self.read_u16(&mut main, ch, &mut raw)? as u32 + 1;
                // println!("REQUEST: NODE INDEX: {}", v);
            } else if cmd == 0xd3 {
                let v = self.read_i16(&mut main, ch, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_i16(v),
                ));
            } else if cmd == 0xd4 {
                let v = self.read_i32(&mut main, ch, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_i32(v),
                ));
            } else if cmd == 0xd5 || cmd == 0xd6 {
                let v = self.read_f(&mut main, ch, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_float(v),
                ));
            } else if cmd == 0xd7 {
                main.current_node_id = self.read_i32(&mut main, ch, &mut raw)?;
            } else if cmd == 0xd8 {
                // println!("REQUEST: CLICK");
            } else if cmd == 0xd9 {
                let _v = self.read_i8(&mut main, ch, &mut raw)?;
                // println!("REQUEST: STEP: {}", v);
            } else if cmd == 0xda {
                // println!("REQUEST: TREE: GOTO ROOT");
            } else if cmd == 0xdb {
                // println!("REQUEST: TREE: GO UP 1");
            } else if cmd == 0xdc {
                // println!("REQUEST: DATA");
            } else if cmd == 0xdd {
                // println!("REQUEST: CURRENT NODE DEFINITION");
            } else if cmd == 0xde {
                return Ok(WingResponse::RequestEnd);
            } else if cmd == 0xdf {
                // A u16 length of 0 is the sentinel for "length does not fit in 16 bits";
                // the real length then follows as a u32. The value must be *used*, not
                // discarded, otherwise every extended-length node definition is truncated
                // to an empty body and rejected by WingNodeDef::from_bytes.
                let mut def_len = self.read_u16(&mut main, ch, &mut raw)? as u32;
                if def_len == 0 {
                    def_len = self.read_u32(&mut main, ch, &mut raw)?;
                }
                let def_len = usize::try_from(def_len).map_err(|_| Error::InvalidData)?;
                if def_len > MAX_NODE_DEF_BYTES {
                    return Err(Error::InvalidData);
                }
                raw.clear();
                raw.try_reserve_exact(def_len)
                    .map_err(|_| Error::InvalidData)?;
                for _ in 0..def_len {
                    self.decode_next(&mut main, &mut raw)?;
                }
                return Ok(WingResponse::NodeDef(WingNodeDef::try_from_bytes(&raw)?));
            } else {
                return Err(Error::InvalidData);
            }
        }
    }

    /// [`read`](Self::read), bounded by `timeout`: returns `Err(Error::Timeout)` if nothing
    /// arrives in time instead of blocking indefinitely.
    ///
    /// Plain `read()` has no such bound when the socket goes quiet — `decode_next`'s
    /// WouldBlock/TimedOut retry only checks `op_deadline`, which is `None` outside an attended
    /// fetch (`get_node_data`/`get_node_definition`/`fetch_subtree_definitions`), so it just
    /// re-arms the socket timeout and loops forever, sending automatic keepalives but never
    /// returning control to the caller. A reader loop that also needs to service outbound writes
    /// between reads (e.g. `Controller::reader_loop`) would starve indefinitely once the console
    /// stops replying for even one read cycle: it can never get back to draining newly-queued
    /// commands, so nothing queued after that point ever reaches the wire. This wraps `read()`
    /// with the same deadline mechanism the attended-get paths already use, so a caller can poll
    /// with a short timeout and loop back to check its own outbound work on every `Timeout`.
    pub fn read_timeout(&mut self, timeout: Duration) -> Result<WingResponse> {
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.read_locked();
        self.set_op_deadline(None);
        result
    }

    fn read_i8(&mut self, r: &mut _WingConsoleMain, _ch: i8, raw: &mut Vec<u8>) -> Result<i8> {
        Ok(self.decode_next(r, raw)?.1 as i8)
    }
    fn read_u8(&mut self, r: &mut _WingConsoleMain, _ch: i8, raw: &mut Vec<u8>) -> Result<u8> {
        Ok(self.decode_next(r, raw)?.1)
    }
    fn read_u16(&mut self, r: &mut _WingConsoleMain, _ch: i8, raw: &mut Vec<u8>) -> Result<u16> {
        let a = self.decode_next(r, raw)?;
        let b = self.decode_next(r, raw)?;
        Ok(((a.1 as u16) << 8) | b.1 as u16)
    }
    fn read_i16(&mut self, r: &mut _WingConsoleMain, ch: i8, raw: &mut Vec<u8>) -> Result<i16> {
        Ok(self.read_u16(r, ch, raw)? as i16)
    }
    fn read_u32(&mut self, r: &mut _WingConsoleMain, _ch: i8, raw: &mut Vec<u8>) -> Result<u32> {
        let a = self.decode_next(r, raw)?;
        let b = self.decode_next(r, raw)?;
        let c = self.decode_next(r, raw)?;
        let d = self.decode_next(r, raw)?;
        Ok(((a.1 as u32) << 24) | ((b.1 as u32) << 16) | ((c.1 as u32) << 8) | d.1 as u32)
    }
    fn read_i32(&mut self, r: &mut _WingConsoleMain, ch: i8, raw: &mut Vec<u8>) -> Result<i32> {
        Ok(self.read_u32(r, ch, raw)? as i32)
    }

    fn read_string(
        &mut self,
        r: &mut _WingConsoleMain,
        _ch: i8,
        len: usize,
        raw: &mut Vec<u8>,
    ) -> Result<String> {
        // define u8 array of size len and fill it with decode_next
        let buf = (0..len)
            .map(|_| self.decode_next(r, raw).map(|(_, v)| v))
            .collect::<Result<Vec<u8>>>()?;
        // convert u8 array to string
        String::from_utf8(buf).map_err(|_| Error::InvalidData)
    }

    fn read_f(&mut self, r: &mut _WingConsoleMain, _ch: i8, raw: &mut Vec<u8>) -> Result<f32> {
        let a = self.decode_next(r, raw)?;
        let b = self.decode_next(r, raw)?;
        let c = self.decode_next(r, raw)?;
        let d = self.decode_next(r, raw)?;
        let val = ((a.1 as u32) << 24) | ((b.1 as u32) << 16) | ((c.1 as u32) << 8) | d.1 as u32;
        Ok(f32::from_bits(val))
    }

    /// read() will call this as needed, but if you don't call read() then the Wing Console will
    /// hang up the connection after a 10 seconds of no activity. You should call this yourself
    /// periodically if you are not calling read().
    pub fn keep_alive(&mut self) -> Result<()> {
        self.ensure_stream_usable()?;
        self._keep_alive(&mut self.main.clone().lock_recover())
    }

    fn _keep_alive(&mut self, r: &mut _WingConsoleMain) -> Result<()> {
        if r.keep_alive_timer <= std::time::Instant::now() {
            // println!("keep_alive");
            self.wsock.clone().lock_recover().write_all(&[0xdf, 0xd1])?;
            r.keep_alive_timer =
                std::time::Instant::now() + std::time::Duration::from_secs(DATA_KEEP_ALIVE_SECONDS);
        }
        Ok(())
    }

    /// read_meters() will call this as needed, but if you don't call read_meters() then the Wing Console will
    /// hang up the connection after a 5 seconds of no activity. You should call this yourself
    /// periodically if you are not calling read_meters().
    pub fn keep_alive_meters(&mut self) -> Result<()> {
        self.ensure_stream_usable()?;
        self._keep_alive_meters(&mut self.mtrs.clone().lock_recover())
    }

    fn _keep_alive_meters(&mut self, m: &mut _WingConsoleMeters) -> Result<()> {
        if m.keep_alive_meters_timer <= std::time::Instant::now() {
            // println!("keep_alive_meters");
            let meters = m.meters.as_ref().ok_or(Error::MeterNotInitialized)?;
            if let Some(id) = m.active_meter_id {
                let mut keepalive = vec![0xdf, 0xd3, 0xd4];
                Self::extend_escaped(&mut keepalive, &id.to_be_bytes());
                Self::extend_escaped(&mut keepalive, &meters.port.to_be_bytes());
                keepalive.push(0xdf);
                keepalive.push(0xd1);
                self.wsock.lock_recover().write_all(&keepalive)?;
            }
            m.keep_alive_meters_timer = std::time::Instant::now()
                + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        }
        Ok(())
    }

    /// Decodes one logical byte off the wire, teeing it into `r.capture` when a capture is
    /// active (see `get_binary_node`). All decoding lives in `decode_next_inner`; this
    /// wrapper is the single choke point every emitted byte passes through, so the tee here
    /// records the exact de-escaped stream `read()` consumes -- nothing more, nothing less.
    fn decode_next(&mut self, r: &mut _WingConsoleMain, raw: &mut Vec<u8>) -> Result<(i8, u8)> {
        let (ch, byte) = self.decode_next_inner(r, raw)?;
        if let Some(cap) = r.capture.as_mut() {
            ensure_native_response_capacity(cap.len())?;
            cap.push(byte);
        }
        Ok((ch, byte))
    }

    fn decode_next_inner(
        &mut self,
        r: &mut _WingConsoleMain,
        raw: &mut Vec<u8>,
    ) -> Result<(i8, u8)> {
        loop {
            if self.reconnecting.load(Ordering::Acquire) {
                return Err(Error::Reconnecting);
            }
            if let Some((channel, value)) = r.replay.pop_front() {
                ensure_native_response_capacity(r.read_capture.len())?;
                raw.push(value);
                r.read_capture.push((channel, value));
                return Ok((channel, value));
            }
            while let Some(event) = r.rx_events.pop_front() {
                // Only Audio Engine bytes are parameter tokens; anything the console sends
                // on another channel would desync the parser if read as one.
                if let ChannelEvent::Data(AUDIO_ENGINE_CHANNEL, value) = event {
                    ensure_native_response_capacity(r.read_capture.len())?;
                    raw.push(value);
                    let decoded = (AUDIO_ENGINE_CHANNEL as i8, value);
                    r.read_capture.push(decoded);
                    return Ok(decoded);
                }
            }

            if r.rx_buf_size == 0 {
                self._keep_alive(r)?;
                // Check before arming the socket timeout, not just after: this is what
                // caps a stuck read to at most one capped-timeout interval past the
                // deadline rather than one keep-alive interval (up to 7s) past it.
                if let Some(deadline) = r.op_deadline {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout);
                    }
                }
                let keep_alive_timeout = r
                    .keep_alive_timer
                    .saturating_duration_since(std::time::Instant::now());
                let read_timeout = match r.op_deadline {
                    // Floor at 1ms: if the deadline lands in the window between the explicit
                    // check above and here, `remaining` rounds to zero and
                    // `set_read_timeout(Some(ZERO))` is an OS error (it would surface as
                    // Error::Io, not Error::Timeout). One more short read then re-checks the
                    // deadline and returns Timeout cleanly. Mirrors osc.rs poll_event's guard.
                    Some(deadline) => keep_alive_timeout
                        .min(deadline.saturating_duration_since(Instant::now()))
                        .max(Duration::from_millis(1)),
                    None => keep_alive_timeout,
                };
                self.rsock
                    .clone()
                    .lock_recover()
                    .set_read_timeout(Some(read_timeout))?;
                match self.rsock.clone().lock_recover().read(&mut r.rx_buf) {
                    Ok(n) if n > 0 => {
                        r.rx_buf_size = n;
                        r.rx_buf_tail = 0;
                    }
                    // check for blocking error
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        if let Some(deadline) = r.op_deadline {
                            if Instant::now() >= deadline {
                                return Err(Error::Timeout);
                            }
                        }
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Ok(_) => return Err(Error::ConnectionError),
                    Err(e) => return Err(e.into()),
                }
            }

            let byte = r.rx_buf[r.rx_buf_tail];
            // println!("rx_buf_tail: {}, rx_buf_size: {}, byte: {:X} buf: {}",
            //     self.rx_buf_tail,
            //     self.rx_buf_size, byte,
            //     self.rx_buf.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","));
            r.rx_buf_tail += 1;
            r.rx_buf_size -= 1;

            // `rx_events` is empty here: queue only a second event, and hand the first
            // straight to the caller without a round trip through the deque.
            let [first, second] = r.rx_channels.push_byte(byte)?;
            if let Some(second) = second {
                r.rx_events.push_back(second);
            }
            if let Some(ChannelEvent::Data(AUDIO_ENGINE_CHANNEL, value)) = first {
                ensure_native_response_capacity(r.read_capture.len())?;
                raw.push(value);
                let decoded = (AUDIO_ENGINE_CHANNEL as i8, value);
                r.read_capture.push(decoded);
                return Ok(decoded);
            }
        }
    }

    /// Encode one [`Meter`] request entry into `request_meter`'s subscribe buffer: an opcode byte
    /// followed by an escaped 0-based index byte for every indexed variant (no index byte for
    /// `Monitor`/`Rta`).
    ///
    /// Every indexed variant's `n` is documented (and used throughout wing-core, e.g.
    /// `Controller::default_meter_request`) as the 1-based channel/strip number matching the
    /// console's own numbering (`/ch/1/...`-style). The binary meter-subscribe protocol's index
    /// byte is 0-based, confirmed against a real WING rack console 2026-07-06: requesting
    /// `Meter::Channel(1)` (intending physical channel 1) returned physical channel 2's live level
    /// as the first decoded object — a uniform one-channel shift reproduced with live signal on
    /// channels 2 and 4 landing at decoded slots 1 and 3. Subtract 1 here, once, so every caller
    /// can keep using the 1-based convention the rest of this crate and wing-core already assume.
    fn encode_meter(buf: &mut Vec<u8>, meter: &Meter) -> Result<()> {
        let (opcode, n, max) = meter.wire();
        if max == 0 {
            buf.push(opcode);
            return Ok(());
        }
        let index = n
            .checked_sub(1)
            .filter(|_| n <= max)
            .ok_or(Error::InvalidInput)?;
        buf.push(opcode);
        Self::push_escaped(buf, index);
        Ok(())
    }

    fn push_escaped(buf: &mut Vec<u8>, byte: u8) {
        crate::native::append_escaped(buf, &[byte]);
    }

    fn extend_escaped(buf: &mut Vec<u8>, bytes: &[u8]) {
        crate::native::append_escaped(buf, bytes);
    }

    fn format_id(id: i32, buf: &mut Vec<u8>, prefix: u8, suffix: Option<u8>) {
        buf.push(prefix);

        Self::extend_escaped(buf, &id.to_be_bytes());

        if let Some(suffix1) = suffix {
            buf.push(suffix1);
        }
    }

    pub fn request_node_definition(&mut self, id: i32) -> Result<()> {
        self.ensure_stream_usable()?;
        let mut buf = Vec::new();
        if id == 0 {
            buf.push(0xda);
            buf.push(0xdd);
        } else {
            Self::format_id(id, &mut buf, 0xd7, Some(0xdd));
        };
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    pub fn request_node_data(&mut self, id: i32) -> Result<()> {
        self.ensure_stream_usable()?;
        let mut buf = Vec::new();
        if id == 0 {
            buf.push(0xda);
            buf.push(0xdc);
        } else {
            Self::format_id(id, &mut buf, 0xd7, Some(0xdc));
        };
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    fn ensure_stream_usable(&self) -> Result<()> {
        if self.stream_tainted.load(Ordering::Acquire) {
            Err(Error::ConnectionError)
        } else {
            Ok(())
        }
    }

    fn set_op_deadline(&mut self, deadline: Option<Instant>) {
        self.main.clone().lock_recover().op_deadline = deadline;
    }

    /// Reads until `matcher` returns `Ok`, buffering everything else so it isn't lost.
    ///
    /// Every response `read()` produces goes through `matcher`: a match ends the loop and
    /// returns the matched value plus everything buffered along the way; a non-match is
    /// pushed onto the buffer (in arrival order) and the loop continues. Bails out with
    /// `Error::Timeout` once `deadline` passes -- enforced primarily inside `decode_next`
    /// (which bounds the underlying socket read), with a check here too so a run of
    /// already-buffered bytes that never matches can't loop forever without ever touching
    /// the socket again. On that timeout the buffered responses go back to the front of
    /// the pending queue, so the next `read()` still delivers them. More than
    /// [`MAX_ATTENDED_BUFFERED`] unrelated responses fail with [`Error::InvalidData`].
    fn attended_read_until<T>(
        &mut self,
        deadline: Instant,
        matcher: impl Fn(WingResponse) -> std::result::Result<T, Box<WingResponse>>,
    ) -> Result<(T, Vec<WingResponse>)> {
        let mut buffered = Vec::new();
        let result = loop {
            let resp = match self.read_locked() {
                Ok(resp) => resp,
                Err(err) => break Err(err),
            };
            match matcher(resp) {
                Ok(matched) => return Ok((matched, buffered)),
                Err(_) if buffered.len() >= MAX_ATTENDED_BUFFERED => break Err(Error::InvalidData),
                Err(unrelated) => buffered.push(*unrelated),
            }
            if Instant::now() >= deadline {
                break Err(Error::Timeout);
            }
        };
        if matches!(result, Err(Error::Timeout)) {
            self.requeue(buffered);
        }
        result
    }

    /// Puts responses already read off the wire back in front of the pending queue, in
    /// order, so the next `read()` on any clone delivers them before anything newer.
    pub(crate) fn requeue(&self, responses: Vec<WingResponse>) {
        let mut main = self.main.lock_recover();
        for resp in responses.into_iter().rev() {
            main.pending.push_front(resp);
        }
    }

    /// Requests node `id`'s current value and waits for it, with a timeout (R16, R17).
    ///
    /// Unrelated responses that arrive while waiting -- `NodeData` for other ids, node
    /// definitions, `RequestEnd` markers -- are buffered and returned alongside the match
    /// (in arrival order) instead of being dropped, so a caller layering this over its own
    /// `read()` loop can still forward them to normal handling.
    ///
    /// **`RequestEnd` semantics:** the wire protocol has no correlation ID, so a
    /// `RequestEnd` can't be proven to belong to *this* request -- it might mark the end of
    /// an earlier request's response batch, or of unrelated interleaved traffic. Rather
    /// than guess and risk a false "not found" on live traffic that just happens to
    /// interleave a `RequestEnd`, a `RequestEnd` with no matching `NodeData` is treated as
    /// inconclusive: it's buffered like any other unrelated response and waiting continues
    /// until either the target arrives or the deadline does. A request for a genuinely
    /// invalid id therefore always resolves via timeout, not a fast "not found" -- callers
    /// that care about that distinction should pass a short timeout.
    pub fn get_node_data(
        &mut self,
        id: i32,
        timeout: Duration,
    ) -> Result<(WingNodeData, Vec<WingResponse>)> {
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        self.request_node_data(id)?;
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.attended_read_until(deadline, |resp| match resp {
            WingResponse::NodeData(rid, data) if rid == id => Ok(data),
            other => Err(Box::new(other)),
        });
        self.set_op_deadline(None);
        result
    }

    /// [`get_node_data`](Self::get_node_data), addressing the node by its property-map
    /// name instead of numeric id.
    pub fn get_node_data_by_name(
        &mut self,
        fullname: &str,
        timeout: Duration,
    ) -> Result<(WingNodeData, Vec<WingResponse>)> {
        let id = Self::name_to_id(fullname).ok_or(Error::InvalidInput)?;
        self.get_node_data(id, timeout)
    }

    /// Requests node `id`'s definition and waits for it, with a timeout (R16, R17). See
    /// [`get_node_data`](Self::get_node_data) for the buffering and `RequestEnd`
    /// semantics, which are identical here.
    pub fn get_node_definition(
        &mut self,
        id: i32,
        timeout: Duration,
    ) -> Result<(WingNodeDef, Vec<WingResponse>)> {
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        self.request_node_definition(id)?;
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.attended_read_until(deadline, |resp| match resp {
            WingResponse::NodeDef(def) if def.id == id => Ok(def),
            other => Err(Box::new(other)),
        });
        self.set_op_deadline(None);
        result
    }

    /// Requests and drains a complete subtree definition stream while holding the shared
    /// read gate. Responses queued before the request are excluded from the transaction.
    /// An end marker is accepted only after a definition belonging to this request has
    /// started the batch; an empty subtree cannot be distinguished from an unrelated end
    /// marker, so an end-only response remains inconclusive and the operation times out.
    /// Older queued responses and unrelated newly-read traffic are preserved for the next
    /// reader.
    pub(crate) fn get_node_definitions(
        &mut self,
        root_id: i32,
        timeout: Duration,
    ) -> Result<Vec<WingNodeDef>> {
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        let mut earlier = {
            let mut main = self.main.lock_recover();
            std::mem::take(&mut main.pending)
        };
        if let Err(error) = self.request_node_definition(root_id) {
            self.requeue(earlier.into());
            return Err(error);
        }
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let mut definitions = Vec::new();
        let mut ids = HashSet::from([root_id]);
        let mut buffered = Vec::new();
        let result = loop {
            match self.read_locked() {
                Ok(WingResponse::NodeDef(def))
                    if ids.contains(&def.id) || ids.contains(&def.parent_id) =>
                {
                    ids.insert(def.id);
                    definitions.push(def);
                }
                Ok(WingResponse::RequestEnd) if !definitions.is_empty() => break Ok(definitions),
                Ok(other) if buffered.len() < MAX_ATTENDED_BUFFERED => buffered.push(other),
                Ok(_) => break Err(Error::InvalidData),
                Err(err) => break Err(err),
            }
            if Instant::now() >= deadline {
                break Err(Error::Timeout);
            }
        };
        self.set_op_deadline(None);
        earlier.extend(buffered);
        self.requeue(earlier.into());
        result
    }

    /// [`get_node_definition`](Self::get_node_definition), addressing the node by its
    /// property-map name instead of numeric id.
    pub fn get_node_definition_by_name(
        &mut self,
        fullname: &str,
        timeout: Duration,
    ) -> Result<(WingNodeDef, Vec<WingResponse>)> {
        let id = Self::name_to_id(fullname).ok_or(Error::InvalidInput)?;
        self.get_node_definition(id, timeout)
    }

    /// Subscribes to meters from the Wing mixer and returns a meter ID that can be used to
    /// associate the values that come back when you call read_meter()
    pub fn request_meter(&mut self, meters: &[Meter]) -> Result<u16> {
        self.ensure_stream_usable()?;
        let mut encoded_meters = Vec::with_capacity(meters.len() * 2);
        for meter in meters {
            Self::encode_meter(&mut encoded_meters, meter)?;
        }

        let mtrsptr = self.mtrs.clone();
        let mut mtrs = mtrsptr.lock_recover();
        let id = mtrs.next_meter_id.max(1);

        if mtrs.meters.is_none() {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            let port = socket.local_addr()?.port();
            mtrs.meters = Some(Meters {
                socket: Arc::new(socket),
                port,
            });
            self.has_meter_socket.store(true, Ordering::Release);
        }
        let md = mtrs.meters.as_ref().ok_or(Error::MeterNotInitialized)?;

        let mut buf = vec![0xdf, 0xd3, 0xd3];
        Self::extend_escaped(&mut buf, &md.port.to_be_bytes());
        buf.push(0xd4);
        Self::extend_escaped(&mut buf, &id.to_be_bytes());
        Self::extend_escaped(&mut buf, &md.port.to_be_bytes());
        buf.push(0xdc);

        buf.extend_from_slice(&encoded_meters);

        buf.push(0xde); // end of def
        buf.push(0xdf);
        buf.push(0xd1);

        self.wsock.lock_recover().write_all(&buf)?;

        // Only a subscription that reached the wire takes over the keepalive, and only then
        // is its id spent. The new subscription replaces the old one, which now lapses.
        mtrs.active_meter_id = Some(id);
        mtrs.next_meter_id = id.wrapping_add(1);
        mtrs.keep_alive_meters_timer =
            Instant::now() + Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        Ok(id)
    }

    /// Returns the next meter frame for a subscription made with
    /// [`request_meter`](Self::request_meter): its report id and its samples.
    ///
    /// Waits at most one meter-keepalive interval (3 s) and then returns [`Error::Timeout`], so
    /// a meter loop regains control -- to stop, resubscribe after a reconnect, or notice a dead
    /// link -- even when no frames arrive (UDP blocked, cable pulled, or a subscription lost
    /// with its session). Keepalives are sent while waiting.
    ///
    /// Frames are accepted only from the console's IP address. The protocol has no
    /// authentication, so a host able to spoof that source address can still inject levels.
    pub fn read_meters(&mut self) -> Result<(u16, Vec<i16>)> {
        self.read_meters_timeout(Duration::from_secs(METERS_KEEP_ALIVE_SECONDS))
    }

    /// [`read_meters`](Self::read_meters), bounded by `timeout` instead of the keepalive
    /// interval. Keepalives are still sent on their own cadence while waiting.
    pub fn read_meters_timeout(&mut self, timeout: Duration) -> Result<(u16, Vec<i16>)> {
        let mut buf = [0u8; METER_FRAME_BYTES];
        let (id, received) = self.recv_meter_frame(&mut buf, Instant::now() + timeout)?;
        Ok((id, meter_samples(&buf[4..received]).collect()))
    }

    /// [`read_meters`](Self::read_meters) without allocating: decodes the frame's samples
    /// straight into `out` and returns the report id and the frame's sample count. A frame
    /// with more samples than `out.len()` is not written at all; the returned count tells the
    /// caller how much room it needed.
    pub fn read_meters_into(&mut self, out: &mut [i16]) -> Result<(u16, usize)> {
        let mut buf = [0u8; METER_FRAME_BYTES];
        let deadline = Instant::now() + Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        let (id, received) = self.recv_meter_frame(&mut buf, deadline)?;
        let samples = &buf[4..received];
        let len = samples.len() / 2;
        if let Some(out) = out.get_mut(..len) {
            for (slot, sample) in out.iter_mut().zip(meter_samples(samples)) {
                *slot = sample;
            }
        }
        Ok((id, len))
    }

    /// Receives one well-formed meter datagram from the console into `buf`, returning its
    /// report id and length. The meter-state lock is held only to renew the keepalive, never
    /// across the blocking receive.
    fn recv_meter_frame(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(u16, usize)> {
        loop {
            let (socket, keepalive_due) = {
                let mptr = self.mtrs.clone();
                let mut m = mptr.lock_recover();
                self._keep_alive_meters(&mut m)?;
                let md = m.meters.as_ref().ok_or(Error::MeterNotInitialized)?;
                (md.socket.clone(), m.keep_alive_meters_timer)
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            let wait = deadline
                .min(keepalive_due)
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));
            socket.set_read_timeout(Some(wait))?;
            match socket.recv_from(buf) {
                Ok((received, addr)) => {
                    if addr.ip() == self.peer_ip && received >= 4 && (received - 4) % 2 == 0 {
                        return Ok((u16::from_be_bytes([buf[0], buf[1]]), received));
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error::ConnectionError),
            }
        }
    }

    pub fn set_string(&mut self, id: i32, value: &str) -> Result<()> {
        self.ensure_stream_usable()?;
        let buf = Self::set_string_message(id, value)?;
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    pub fn set_float(&mut self, id: i32, value: f32) -> Result<()> {
        self.ensure_stream_usable()?;
        let buf = Self::set_float_message(id, value)?;
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    pub fn set_int(&mut self, id: i32, value: i32) -> Result<()> {
        self.ensure_stream_usable()?;
        let buf = Self::set_int_message(id, value)?;
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    /// Toggles a 0/1 parameter in one write via the native `click` token (`0xd7 <hash>
    /// 0xd8`), the `wToggleTokenInt` primitive. Flips the parameter server-side without a
    /// read-before-write, so it can't race a concurrent change the way get-then-set would.
    pub fn toggle(&mut self, id: i32) -> Result<()> {
        self.ensure_stream_usable()?;
        let mut buf = Vec::new();
        Self::format_id(id, &mut buf, 0xd7, Some(0xd8));
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    /// Captures the raw, hash-addressed native byte stream for the subtree (or single
    /// parameter) rooted at `id` -- the `wGetBinaryNode`/`wGetBinaryData` primitive.
    ///
    /// Issues one data request (`0xd7 <hash> 0xdc`, or `0xda 0xdc` at the root) and streams
    /// the reply, returning the de-escaped token bytes verbatim (`0xd7 <hash> <value>`
    /// pairs, terminated by the `0xde` end token) *without* decoding them to typed values.
    /// Unlike a dump of parsed/string values, this form round-trips losslessly through
    /// [`set_binary_node`](Self::set_binary_node): every parameter is addressed by numeric
    /// hash, so the dynamically-named model parameters (EQ/gate/comp) that a string dump
    /// can't replay are preserved. This is the correct primitive for external scene
    /// save/restore, and it fetches a whole subtree in a single request rather than the
    /// per-leaf round-trips [`dump_subtree`](Self::dump_subtree) makes.
    ///
    /// **Attended operation.** It assumes a quiescent connection and drains until the first
    /// end-of-data token, so it must not run concurrently with another reader on the same
    /// session -- interleaved unrelated traffic would be captured into the buffer. Bounded
    /// by `timeout`, returning [`Error::Timeout`] if the stream doesn't terminate in time.
    /// After a timeout the Native stream is fenced: subsequent reads and writes return
    /// [`Error::ConnectionError`] until a successful reconnect discards the uncertain tail.
    pub fn get_binary_node(&mut self, id: i32, timeout: Duration) -> Result<Vec<u8>> {
        let read_gate = self.read_gate.clone();
        let _read_guard = read_gate.lock_recover();
        self.request_node_data(id)?;
        let deadline = Instant::now() + timeout;
        // Responses queued before this request were read off the wire already, so they are
        // not part of the capture; set them aside so the drain below only sees new traffic.
        let earlier = {
            let mainptr = self.main.clone();
            let mut main = mainptr.lock_recover();
            main.capture = Some(Vec::new());
            main.op_deadline = Some(deadline);
            std::mem::take(&mut main.pending)
        };
        // Drain the reply stream; the tee in `decode_next` fills `capture` underneath. Read
        // responses themselves are discarded -- the raw bytes are the product here.
        let result = loop {
            match self.read_locked() {
                Ok(WingResponse::RequestEnd) => break Ok(()),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
            if Instant::now() >= deadline {
                break Err(Error::Timeout);
            }
        };
        self.requeue(earlier.into());
        let mainptr = self.main.clone();
        let mut main = mainptr.lock_recover();
        main.op_deadline = None;
        let captured = main.capture.take().unwrap_or_default();
        if matches!(result, Err(Error::Timeout)) {
            self.stream_tainted.store(true, Ordering::Release);
        }
        result.map(|()| captured)
    }

    /// Replays a buffer captured by [`get_binary_node`](Self::get_binary_node) -- the
    /// `wSetBinaryNode` primitive. Sends the native command bytes verbatim (re-applying the
    /// `0xdf` wire escaping), setting every `0xd7 <hash> <value>` pair in the buffer in a
    /// single write. That makes it an effective bulk push -- one write for a whole subtree,
    /// versus one write per parameter through [`set_int`](Self::set_int) et al. Returns the
    /// number of bytes written to the wire (`>= data.len()` when escaping expands it).
    pub fn set_binary_node(&mut self, data: &[u8]) -> Result<usize> {
        self.ensure_stream_usable()?;
        let mut buf = Vec::with_capacity(data.len());
        Self::extend_escaped(&mut buf, data);
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(buf.len())
    }

    /// Reads the console's current state back and reports every **writable** parameter in `data`
    /// whose live value no longer matches -- a confidence check to run right after
    /// [`set_binary_node`](Self::set_binary_node), since a blind bulk push has no per-write ack
    /// and the console can silently drop writes under load.
    ///
    /// `data` is a buffer as captured by [`get_binary_node`](Self::get_binary_node). The check
    /// **re-captures the whole desk in a single request** (`get_binary_node(0, ..)`, a superset of
    /// any restored subtree) and compares each of `data`'s `0xd7 <hash> <value>` pairs against it.
    /// This is deliberately *not* one read per leaf: a per-leaf sweep of a full desk is thousands
    /// of sequential requests, which is slow and (observed on a real WING) makes the console reset
    /// the connection mid-sweep. One re-capture is ~0.4 s for the whole desk.
    ///
    /// Read-only entries are skipped (a raw capture carries them, but a restore never sets them,
    /// so they'd only produce false positives from values that drift on their own).
    ///
    /// **Settle / second pass:** some parameters apply *asynchronously* -- observed on a real WING,
    /// head-amp gain (`/io/in/*/g`) and phantom (`vph`) don't reflect a fresh write within the
    /// ~0.4 s of the first capture, so they'd show as false mismatches. When the first pass finds
    /// any mismatch and `settle` is non-zero, this waits `settle`, re-captures once more, and keeps
    /// only the leaves that *still* mismatch -- transient async ones reconcile and are dropped, a
    /// genuinely dropped write persists. A clean first pass pays no settle cost. The re-check is
    /// again a single whole-desk capture, so it stays reset-safe no matter how many suspects there
    /// are. Pass `Duration::ZERO` to report the first pass verbatim (no second capture).
    ///
    /// Returns a [`VerifyReport`] whose `checked`/`skipped` counts distinguish a genuine clean pass
    /// from an empty/malformed buffer. A parameter absent from the re-capture is reported with
    /// `actual: None`. `capture_timeout` bounds each re-capture.
    pub fn verify_binary_node(
        &mut self,
        data: &[u8],
        capture_timeout: Duration,
        settle: Duration,
    ) -> Result<VerifyReport> {
        let expected = parse_binary_values(data)?;
        let current = self.capture_value_map(capture_timeout)?;

        let mut report = VerifyReport::default();
        let mut suspects: Vec<(i32, NodeValue, Option<NodeValue>)> = Vec::new();
        for (id, want) in expected {
            if id_is_read_only(id) {
                report.skipped += 1;
                continue;
            }
            report.checked += 1;
            let actual = current.get(&id).cloned();
            if !actual
                .as_ref()
                .is_some_and(|a| values_match_at(id, a, &want))
            {
                suspects.push((id, want, actual));
            }
        }

        if suspects.is_empty() {
            return Ok(report);
        }

        // Second pass: give async-applying params (head-amp gain/phantom) time to land, then
        // re-check only the suspects against a fresh whole-desk capture. Those that now match were
        // transient; the rest are real.
        if settle.is_zero() {
            report.mismatches = suspects
                .into_iter()
                .map(|(id, expected, actual)| BinaryMismatch {
                    id,
                    expected,
                    actual,
                })
                .collect();
            return Ok(report);
        }
        std::thread::sleep(settle);
        let recheck = self.capture_value_map(capture_timeout)?;
        for (id, want, _first) in suspects {
            let actual = recheck.get(&id).cloned();
            if !actual
                .as_ref()
                .is_some_and(|a| values_match_at(id, a, &want))
            {
                report.mismatches.push(BinaryMismatch {
                    id,
                    expected: want,
                    actual,
                });
            }
        }
        Ok(report)
    }

    /// Whole-desk re-capture (`get_binary_node(0)`) decoded into an id -> value map, for
    /// [`verify_binary_node`](Self::verify_binary_node)'s comparisons.
    fn capture_value_map(&mut self, timeout: Duration) -> Result<HashMap<i32, NodeValue>> {
        let buf = self.get_binary_node(0, timeout)?;
        Ok(parse_binary_values(&buf)?.into_iter().collect())
    }

    fn set_string_message(id: i32, value: &str) -> Result<Vec<u8>> {
        Self::set_value_message(id, &NativeValue::String(value.to_owned()))
    }

    fn set_float_message(id: i32, value: f32) -> Result<Vec<u8>> {
        Self::set_value_message(id, &NativeValue::Float(value))
    }

    fn set_int_message(id: i32, value: i32) -> Result<Vec<u8>> {
        Self::set_value_message(id, &NativeValue::Integer(value))
    }

    /// `0xd7 <id>` followed by `value`'s token, all escaped for the wire -- the length byte of a
    /// `0xd1` string included. Token encoding is shared with the server-side encoder.
    fn set_value_message(id: i32, value: &NativeValue) -> Result<Vec<u8>> {
        let mut token = Vec::new();
        crate::native::encode_value(&mut token, value)?;
        let mut buf = Vec::with_capacity(token.len() + 8);
        Self::format_id(id, &mut buf, 0xd7, None);
        Self::extend_escaped(&mut buf, &token);
        Ok(buf)
    }

    pub fn name_to_id(fullname: &str) -> Option<i32> {
        if let Ok(num) = fullname.parse::<i32>() {
            Some(num)
        } else {
            NAME_TO_DEF.get(fullname).map(|x| x.id)
        }
    }
    pub fn name_to_def(fullname: &str) -> Option<&WingNodeDef> {
        NAME_TO_DEF.get(fullname)
    }

    /// Iterate every `(fullname, def)` in the embedded property map. Used by offline discovery
    /// (`wing-core::tools::search`, U1) which must rank over the whole tree. Empty when the
    /// `propmap` feature is off.
    pub fn propmap_iter() -> impl Iterator<Item = (&'static str, &'static WingNodeDef)> {
        NAME_TO_DEF.iter().map(|(&k, v)| (k, v))
    }

    /// Builds the embedded property map and its reverse id index now instead of on first use.
    /// Together they take about 20 ms, so an application should call this on a background
    /// thread at startup; otherwise the first lookup pays for it, possibly on a UI thread.
    pub fn preload_property_map() {
        lazy_static::initialize(&NAME_TO_DEF);
        lazy_static::initialize(&ID_TO_NAME);
    }

    /// Total number of entries in the embedded property map. Exposed for the
    /// regeneration consistency tests (see `tests/propmap_consistency.rs`),
    /// which have no other way to see the size of the private `NAME_TO_DEF` map.
    pub fn propmap_len() -> usize {
        NAME_TO_DEF.len()
    }

    #[cfg(test)]
    pub(crate) fn test_with_meter_socket(peer_ip: IpAddr, socket: UdpSocket) -> Self {
        Self::test_with_meter_socket_and_server(peer_ip, socket).0
    }

    /// [`test_with_meter_socket`](Self::test_with_meter_socket), keeping the TCP server half
    /// open (and returned) so keepalive writes succeed.
    #[cfg(test)]
    pub(crate) fn test_with_meter_socket_and_server(
        peer_ip: IpAddr,
        socket: UdpSocket,
    ) -> (Self, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let port = socket.local_addr().unwrap().port();
        let console = Self::from_streams(client.try_clone().unwrap(), client, peer_ip, addr.port());

        {
            let mut meters = console.mtrs.lock_recover();
            meters.meters = Some(Meters {
                socket: Arc::new(socket),
                port,
            });
            meters.active_meter_id = Some(1);
            meters.next_meter_id = 2;
            meters.keep_alive_meters_timer = std::time::Instant::now()
                + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        }

        (console, server)
    }

    pub fn id_to_defs(id: i32) -> Option<Vec<(String, WingNodeDef)>> {
        Self::id_to_defs_iter(id).map(|defs| {
            defs.map(|(name, def)| (name.to_owned(), def.clone()))
                .collect()
        })
    }

    /// Borrow every embedded definition that shares `id` without cloning its
    /// path or definition. The owned [`Self::id_to_defs`] API remains useful
    /// when callers need to retain or mutate the returned values.
    pub fn id_to_defs_iter(
        id: i32,
    ) -> Option<impl ExactSizeIterator<Item = (&'static str, &'static WingNodeDef)>> {
        ID_TO_NAME.get(&id).map(|names| {
            names.iter().map(|&name| {
                let def = NAME_TO_DEF
                    .get(name)
                    .expect("reverse property index references embedded definition");
                (name, def)
            })
        })
    }

    /// Attended-gets every id in `ids`, in order (U6).
    ///
    /// Built on [`get_node_data`](Self::get_node_data), so each miss is a normal
    /// request/wait/timeout cycle. The one thing this adds over calling
    /// `get_node_data` in a loop yourself: unrelated `NodeData` that
    /// `get_node_data` buffers while waiting for one id (e.g. unsolicited
    /// traffic, or a response to an id later in `ids`) is stashed and consulted
    /// before issuing a fresh request for that later id, so a value that
    /// happened to arrive early isn't requested twice. Anything buffered for an
    /// id *not* in `ids` is dropped, same as a bare `get_node_data` call would
    /// drop it. What a timed-out `get_node_data` buffered goes back to the
    /// console's pending queue, so the next id's request reads (and stashes) it
    /// first. A timeout on one id never stops the rest of `ids` from being
    /// attempted.
    pub fn get_nodes(
        &mut self,
        ids: &[i32],
        timeout_per_node: Duration,
    ) -> Vec<(i32, Result<WingNodeData>)> {
        let mut pending: HashMap<i32, WingNodeData> = HashMap::new();
        let mut out = Vec::with_capacity(ids.len());
        for &id in ids {
            if let Some(data) = pending.remove(&id) {
                out.push((id, Ok(data)));
                continue;
            }
            match self.get_node_data(id, timeout_per_node) {
                Ok((data, buffered)) => {
                    for resp in buffered {
                        if let WingResponse::NodeData(bid, bdata) = resp {
                            if bid != id && ids.contains(&bid) {
                                pending.entry(bid).or_insert(bdata);
                            }
                        }
                    }
                    out.push((id, Ok(data)));
                }
                Err(err) => out.push((id, Err(err))),
            }
        }
        out
    }

    /// Writes every `(id, value)` pair in `values`, in order, via the matching
    /// `set_string`/`set_float`/`set_int` (U6). One node's failure doesn't stop
    /// the rest -- each gets its own `Result` in the returned, order-preserving
    /// list.
    pub fn set_nodes(&mut self, values: &[(i32, NodeValue)]) -> Vec<(i32, Result<()>)> {
        values
            .iter()
            .map(|(id, value)| (*id, self.write_node_value(*id, value)))
            .collect()
    }

    fn write_node_value(&mut self, id: i32, value: &NodeValue) -> Result<()> {
        match value {
            NodeValue::String(s) => self.set_string(id, s),
            NodeValue::Float(f) => self.set_float(id, *f),
            NodeValue::Int(i) => self.set_int(id, *i),
        }
    }

    /// Snapshots every writable value node under `root_fullname` (itself
    /// included) from the embedded property map (U6, R18).
    ///
    /// The subtree's *shape* comes from the embedded map, not the console --
    /// no definition round-trip is needed to know which ids exist under the
    /// prefix. Each leaf's *value*, though, is only known live, so this issues
    /// attended `get_node_data` calls in a fixed order (sorted by fullname)
    /// after reading model selectors. Only active model branches are captured,
    /// and selectors are checked again afterward to catch model changes that
    /// persist through the sweep. A change away and back between checks cannot
    /// be detected by this serial protocol, so strict snapshots require a
    /// quiescent console. A selector whose value the embedded map does not know
    /// (a model added by newer firmware) is captured as-is, none of its known
    /// branches are, and its fullname is listed in [`NodeDump::unknown_models`]
    /// so the caller can warn -- newer firmware warns, it never blocks.
    ///
    /// Reconnects on other clones are fenced for the sweep: a clone that asks to
    /// reconnect makes the sweep stop with [`Error::Reconnecting`] at its next
    /// request instead of waiting for the whole dump. Plain container
    /// nodes (`NodeType::Node`, which never carry a
    /// value) and read-only leaves are excluded (R18): restoring a read-only
    /// node would fail anyway, and including a valueless container would just
    /// waste a request that could never resolve to a value.
    ///
    /// Fails fast on the first leaf that doesn't respond within `timeout`
    /// rather than collecting partial results.
    pub fn dump_subtree(&mut self, root_fullname: &str, timeout: Duration) -> Result<NodeDump> {
        let reconnect_gate = self.reconnect_gate.clone();
        let _reconnect_guard = reconnect_gate.lock_recover();
        let leaves = dumpable_leaves(Self::propmap_iter(), root_fullname);

        // A model sweep contains mutually exclusive definitions with reused ids.
        // Read selectors first, from outermost to innermost, so only the active
        // branch contributes values to the snapshot.
        let root_prefix = format!("{root_fullname}/");
        let mut selectors: Vec<_> = Self::propmap_iter()
            .filter(|(name, def)| {
                let Some(parent) = name.strip_suffix("/mdl") else {
                    return false;
                };
                def.node_type == NodeType::StringEnum
                    && (*name == root_fullname
                        || parent == root_fullname
                        || parent.starts_with(&root_prefix)
                        || root_fullname.starts_with(&format!("{parent}/")))
            })
            .collect();
        selectors.sort_by(|a, b| {
            a.0.matches('/')
                .count()
                .cmp(&b.0.matches('/').count())
                .then_with(|| a.0.cmp(b.0))
        });

        let mut active_models = Vec::new();
        let mut selector_values = HashMap::new();
        let mut unknown_models = Vec::new();
        for (fullname, def) in selectors {
            if !path_matches_active_models(fullname, &active_models) {
                continue;
            }
            let data = self.dump_get(def.id, timeout)?;
            let value = dump_value(&data, def)?;
            if data.string_enum_item(def).is_none() {
                unknown_models.push(fullname.to_owned());
            }
            active_models.push(ActiveModel {
                parent: fullname.strip_suffix("/mdl").unwrap(),
                definition: def,
                selected: value.clone(),
            });
            selector_values.insert(fullname, value);
        }

        let mut entries = Vec::with_capacity(leaves.len());
        for (fullname, id) in leaves {
            if !path_matches_active_models(&fullname, &active_models) {
                continue;
            }
            let value = if let Some(value) = selector_values.remove(fullname.as_str()) {
                value
            } else {
                let data = self.dump_get(id, timeout)?;
                dump_value(&data, NAME_TO_DEF.get(fullname.as_str()).unwrap())?
            };
            entries.push(DumpEntry {
                fullname,
                id,
                value,
            });
        }
        for model in &active_models {
            let data = self.dump_get(model.definition.id, timeout)?;
            if dump_value(&data, model.definition)? != model.selected {
                return Err(Error::InvalidData);
            }
        }
        Ok(NodeDump {
            entries,
            unknown_models,
        })
    }

    /// One attended read inside a `dump_subtree` sweep, which first yields to any clone
    /// waiting to reconnect.
    fn dump_get(&mut self, id: i32, timeout: Duration) -> Result<WingNodeData> {
        if self.pending_reconnects.load(Ordering::Acquire) > 0 {
            return Err(Error::Reconnecting);
        }
        Ok(self.get_node_data(id, timeout)?.0)
    }

    /// Applies a [`NodeDump`] back to the console (U6, R18).
    ///
    /// Entries are applied in **model-first order**: any entry whose leaf name
    /// is `mdl` (the property map's convention for a model selector, e.g.
    /// `/fx/1/mdl`) is written before every non-selector entry, so a model's
    /// children land after the model itself has been switched to match --
    /// otherwise they'd be writing into whatever model the slot happened to be
    /// in before the restore. Multiple selectors sort by ascending path depth,
    /// so an outer selector is applied before one nested inside its own
    /// model-specific subtree. Within each of those two groups, entries keep
    /// their original relative order (a stable sort).
    ///
    /// Read-only entries shouldn't exist in a dump produced by
    /// [`dump_subtree`](Self::dump_subtree) (which excludes them at dump time),
    /// but a hand-built or edited [`NodeDump`] could still carry one; as
    /// defense in depth, restoring one is skipped (reported as
    /// `Err(Error::InvalidInput)` in the returned list) rather than attempted.
    ///
    /// One `Result` per entry, in the order actually applied. A failed model
    /// selector stops the restore: later values may belong to that selector's
    /// model and must not be written into whichever model remains active.
    pub fn restore(&mut self, dump: &NodeDump) -> Vec<(String, Result<()>)> {
        let mut ordered: Vec<&DumpEntry> = dump.entries.iter().collect();
        ordered.sort_by_key(|entry| restore_order_key(&entry.fullname));

        let mut selector_failed = false;
        ordered
            .into_iter()
            .map(|entry| {
                if selector_failed {
                    return (entry.fullname.clone(), Err(Error::InvalidInput));
                }
                let blocked = NAME_TO_DEF
                    .get(entry.fullname.as_str())
                    .map(|def| def.read_only)
                    .unwrap_or(false);
                let result = if blocked {
                    Err(Error::InvalidInput)
                } else {
                    self.write_node_value(entry.id, &entry.value)
                };
                if entry.fullname.rsplit('/').next() == Some("mdl") && result.is_err() {
                    selector_failed = true;
                }
                (entry.fullname.clone(), result)
            })
            .collect()
    }
}

struct ActiveModel<'a> {
    parent: &'a str,
    definition: &'a WingNodeDef,
    /// The selector's captured value; a `NodeValue::String` naming a known item unless
    /// the model is unknown to the embedded map, in which case no known branch matches.
    selected: NodeValue,
}

fn path_matches_active_models(path: &str, models: &[ActiveModel<'_>]) -> bool {
    models.iter().all(|model| {
        let Some(relative) = path
            .strip_prefix(model.parent)
            .and_then(|suffix| suffix.strip_prefix('/'))
        else {
            return true;
        };
        model
            .definition
            .string_enum
            .as_ref()
            .and_then(|items| {
                items
                    .iter()
                    .filter(|item| {
                        relative == item.item
                            || relative
                                .strip_prefix(&item.item)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    })
                    .max_by_key(|item| item.item.len())
            })
            .is_none_or(
                |item| matches!(&model.selected, NodeValue::String(name) if *name == item.item),
            )
    })
}

fn dump_value(data: &WingNodeData, def: &WingNodeDef) -> Result<NodeValue> {
    if def.node_type != NodeType::StringEnum {
        return Ok(NodeValue::from_data(data));
    }
    if def.string_enum.is_none() {
        return Err(Error::InvalidData);
    }
    Ok(data
        .string_enum_item(def)
        .map(|item| NodeValue::String(item.to_owned()))
        .unwrap_or_else(|| NodeValue::from_data(data)))
}

/// A node value in whichever facet it was carried in on the wire -- the same
/// three shapes [`WingNodeData`] can hold, but owned and settable back via
/// [`WingConsole::set_nodes`] without needing to route through a specific
/// `set_string`/`set_float`/`set_int` call at each call site (U6).
#[derive(Clone, Debug, PartialEq)]
pub enum NodeValue {
    String(String),
    Float(f32),
    Int(i32),
}

impl NodeValue {
    /// Reads back whichever facet `data` actually carries. A `WingNodeData`
    /// read off the wire always has exactly one of its three facets set (see
    /// `WingConsole::read`), so this always matches one of the first two arms
    /// before falling back to the int facet.
    fn from_data(data: &WingNodeData) -> Self {
        if data.has_string() {
            NodeValue::String(data.get_string())
        } else if data.has_float() {
            NodeValue::Float(data.get_float())
        } else {
            NodeValue::Int(data.get_int())
        }
    }
}

/// One parameter whose read-back value didn't match a restored buffer, produced by
/// [`WingConsole::verify_binary_node`]. `actual` is `None` when the read-back timed out.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryMismatch {
    pub id: i32,
    pub expected: NodeValue,
    pub actual: Option<NodeValue>,
}

/// Outcome of [`WingConsole::verify_binary_node`]: how many writable leaves were read back
/// (`checked`), how many read-only leaves were skipped (`skipped`), and every mismatch found.
/// A clean pass is `mismatches.is_empty() && checked > 0`; `checked == 0` means the buffer held
/// no writable leaves (empty or malformed), which a bare "no mismatches" would hide.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VerifyReport {
    pub checked: usize,
    pub skipped: usize,
    pub mismatches: Vec<BinaryMismatch>,
}

/// Whether `id` resolves (through the embedded map) to a definition that is read-only in every
/// candidate. [`WingConsole::verify_binary_node`] skips such ids because a restore never sets
/// them, so their live value can drift and would only produce false positives. An id absent from
/// the map is treated as writable, so it's still checked.
fn id_is_read_only(id: i32) -> bool {
    match ID_TO_NAME.get(&id) {
        Some(names) if !names.is_empty() => names
            .iter()
            .all(|n| NAME_TO_DEF.get(*n).is_some_and(|d| d.read_only)),
        _ => false,
    }
}

/// Compares a read-back value against the expected one, tolerating float requantization: WING
/// rounds some floats on write, so an exact bit-compare would flag benign differences. Ints and
/// strings compare exactly.
fn values_match(a: &NodeValue, b: &NodeValue) -> bool {
    match (a, b) {
        (NodeValue::Float(x), NodeValue::Float(y)) => {
            (x - y).abs() <= 1e-3_f32.max(x.abs().max(y.abs()) * 1e-4)
        }
        _ => a == b,
    }
}

/// [`values_match`], but also treats a `StringEnum` written as its wire index as equal to the same
/// enum read back as its label. The console accepts an enum set as an integer index yet reports it
/// as a string on capture, so a faithful round-trip (e.g. a scene restore) otherwise shows every
/// enum node as a spurious mismatch. Resolves the def by `id` to compare index against label.
fn values_match_at(id: i32, a: &NodeValue, b: &NodeValue) -> bool {
    if values_match(a, b) {
        return true;
    }
    let (idx, label) = match (a, b) {
        (NodeValue::Int(i), NodeValue::String(s)) | (NodeValue::String(s), NodeValue::Int(i)) => {
            (*i, s.as_str())
        }
        _ => return false,
    };
    let Ok(idx) = usize::try_from(idx) else {
        return false;
    };
    ID_TO_NAME.get(&id).is_some_and(|names| {
        names.iter().any(|name| {
            NAME_TO_DEF.get(*name).is_some_and(|def| {
                def.string_enum
                    .as_ref()
                    .and_then(|items| items.get(idx))
                    .is_some_and(|item| item.item == label)
            })
        })
    })
}

/// Lossy UTF-8 decode of a string payload in the binary stream (WING strings are byte strings).
fn str_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Parses a de-escaped binary-node buffer (as produced by [`WingConsole::get_binary_node`]) into
/// `(id, value)` pairs. `0xd7 <hash>` selects the current node; each following value token emits
/// that node's value. Tree-navigation, click/step and request tokens carry no value and are
/// skipped; the `0xde` end token stops parsing. Returns [`Error::InvalidData`] on a truncated
/// buffer, a value token with no preceding node selector, or a definition-response (`0xdf`) token
/// (which means this is a definition stream, not a value buffer).
pub fn parse_binary_values(data: &[u8]) -> Result<Vec<(i32, NodeValue)>> {
    /// Read `n` bytes at the cursor, advancing it; `InvalidData` if the buffer is too short.
    fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8]> {
        let end = i.checked_add(n).ok_or(Error::InvalidData)?;
        let slice = data.get(*i..end).ok_or(Error::InvalidData)?;
        *i = end;
        Ok(slice)
    }

    let mut out = Vec::new();
    let mut i = 0usize;
    let mut cur: Option<i32> = None;
    let id = |cur: Option<i32>| cur.ok_or(Error::InvalidData);

    while i < data.len() {
        let cmd = data[i];
        i += 1;
        match cmd {
            0x00..=0x3f => out.push((id(cur)?, NodeValue::Int(cmd as i32))),
            0x40..=0x7f => {} // node-index selector (navigation) -- unused with hash addressing
            0x80..=0xbf => {
                let len = (cmd - 0x80) as usize + 1;
                let s = str_from(take(data, &mut i, len)?);
                out.push((id(cur)?, NodeValue::String(s)));
            }
            0xc0..=0xcf => {
                // node-name selector (navigation): consume its bytes, emit no value.
                let len = (cmd - 0xc0) as usize + 1;
                take(data, &mut i, len)?;
            }
            0xd0 => out.push((id(cur)?, NodeValue::String(String::new()))),
            0xd1 => {
                let len = take(data, &mut i, 1)?[0] as usize + 1;
                let s = str_from(take(data, &mut i, len)?);
                out.push((id(cur)?, NodeValue::String(s)));
            }
            0xd2 => {
                take(data, &mut i, 2)?; // node index (word) -- navigation
            }
            0xd3 => {
                let b = take(data, &mut i, 2)?;
                out.push((
                    id(cur)?,
                    NodeValue::Int(i16::from_be_bytes([b[0], b[1]]) as i32),
                ));
            }
            0xd4 => {
                let b = take(data, &mut i, 4)?;
                out.push((
                    id(cur)?,
                    NodeValue::Int(i32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                ));
            }
            0xd5 | 0xd6 => {
                let b = take(data, &mut i, 4)?;
                out.push((
                    id(cur)?,
                    NodeValue::Float(f32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                ));
            }
            0xd7 => {
                let b = take(data, &mut i, 4)?;
                cur = Some(i32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            }
            0xd8 => {} // click
            0xd9 => {
                take(data, &mut i, 1)?; // step
            }
            0xda..=0xdd => {} // tree nav / data / def requests -- no payload
            0xde => break,    // end of data
            0xdf..=0xff => return Err(Error::InvalidData),
        }
    }
    Ok(out)
}

/// Encodes `(id, value)` pairs into the raw, de-escaped binary-node token stream accepted by
/// [`WingConsole::set_binary_node`]. Oversized strings are skipped because the WING string token
/// format carried here can represent at most 256 bytes.
pub fn encode_binary_values(pairs: &[(i32, NodeValue)]) -> Vec<u8> {
    let mut out = Vec::new();

    for (id, value) in pairs {
        let value = match value {
            NodeValue::Int(v) => NativeValue::Integer(*v),
            NodeValue::Float(v) => NativeValue::Float(*v),
            NodeValue::String(s) => NativeValue::String(s.clone()),
        };
        let mut encoded_value = Vec::new();
        if crate::native::encode_value(&mut encoded_value, &value).is_err() {
            continue;
        }

        out.push(0xd7);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&encoded_value);
    }

    out.push(0xde);
    out
}

/// One node's fullname, id, and captured value within a [`NodeDump`] (U6).
#[derive(Clone, Debug, PartialEq)]
pub struct DumpEntry {
    pub fullname: String,
    pub id: i32,
    pub value: NodeValue,
}

/// A snapshot of a subtree's writable values, as produced by
/// [`WingConsole::dump_subtree`] and consumed by [`WingConsole::restore`] (U6,
/// R18). Plain data -- safe to serialize/store by whatever means a caller
/// prefers; this crate takes no dependency on a serialization format for it.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct NodeDump {
    pub entries: Vec<DumpEntry>,
    /// Model selectors (e.g. `/fx/1/mdl`) whose value the embedded property map does not
    /// know, typically a model added by newer firmware. The branches under them were not
    /// captured, so a caller should warn that the dump is incomplete there.
    pub unknown_models: Vec<String>,
}

/// The embedded-map walk shared by [`WingConsole::dump_subtree`]: every
/// `(fullname, id)` under `root_fullname` (itself included) whose def is a
/// value-bearing, writable leaf, sorted by fullname for a deterministic
/// request order.
///
/// Factored out from `dump_subtree` so the read-only/container exclusion (R18)
/// is unit-testable against a synthetic fixture without needing a real
/// read-only entry in the embedded map (as of this map's current sweep, it has
/// none -- see `console::tests::dumpable_leaves_excludes_read_only_and_containers`).
fn dumpable_leaves<'a>(
    entries: impl Iterator<Item = (&'a str, &'a WingNodeDef)>,
    root_fullname: &str,
) -> Vec<(String, i32)> {
    let prefix = format!("{root_fullname}/");
    let mut leaves: Vec<(String, i32)> = entries
        .filter(|(name, def)| {
            def.node_type != NodeType::Node
                && !def.read_only
                && (*name == root_fullname || name.starts_with(&prefix))
        })
        .map(|(name, def)| (name.to_owned(), def.id))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    leaves
}

/// Sort key for [`WingConsole::restore`]'s model-first ordering: model
/// selectors (`false`, shallower-first) before everything else (`true`), with
/// original relative order preserved within each group (the caller sorts with
/// a stable sort).
fn restore_order_key(fullname: &str) -> (bool, usize) {
    if fullname.rsplit('/').next() == Some("mdl") {
        (false, fullname.matches('/').count())
    } else {
        (true, 0)
    }
}

impl Drop for WingConsole {
    fn drop(&mut self) {
        if Arc::strong_count(&self.wsock) == 1 {
            let _ = self.wsock.lock_recover().shutdown(Shutdown::Both);
        }
        if Arc::strong_count(&self.rsock) == 1 {
            let _ = self.rsock.lock_recover().shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn dump_subtree_holds_the_reconnect_fence_until_it_finishes() {
        let _ = WingConsole::propmap_len();
        let mut console = console_with_input(&[]);
        let gate = console.reconnect_gate.clone();
        let guard = gate.lock_recover();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(console.dump_subtree("/not-a-propmap-path", Duration::from_millis(50)))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(guard);
        assert!(done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_ok());
        worker.join().unwrap();
    }

    #[test]
    fn a_read_during_another_clones_reconnect_reports_reconnecting_and_keeps_the_bytes() {
        let mut frame = vec![0xd7];
        frame.extend(42i32.to_be_bytes());
        frame.push(0xd4);
        frame.extend(7i32.to_be_bytes());
        let mut console = console_with_input(&frame);

        console.reconnecting.store(true, Ordering::Release);
        assert!(matches!(
            console.read_timeout(Duration::from_millis(200)),
            Err(Error::Reconnecting)
        ));
        console.reconnecting.store(false, Ordering::Release);
        assert!(matches!(
            console.read_timeout(Duration::from_millis(500)),
            Ok(WingResponse::NodeData(42, _))
        ));
    }

    #[test]
    fn decoding_stops_once_a_reconnect_starts() {
        let mut console = console_with_input(&[0xd7]);
        console.reconnecting.store(true, Ordering::Release);
        let main = console.main.clone();
        let mut r = main.lock_recover();

        assert!(matches!(
            console.decode_next(&mut r, &mut Vec::new()),
            Err(Error::Reconnecting)
        ));
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn dump_subtree_yields_to_a_pending_reconnect() {
        let mut console = console_with_input(&[]);
        console.pending_reconnects.store(1, Ordering::Release);

        assert!(matches!(
            console.dump_subtree("/cfg/amix", Duration::from_millis(100)),
            Err(Error::Reconnecting)
        ));
    }

    /// A connected, reconnectable console whose firmware re-probe goes to `probe_port`.
    fn reconnectable_console(probe_port: u16) -> (WingConsole, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut console = WingConsole::connect_addr(listener.local_addr().unwrap()).unwrap();
        let _ = listener.accept().unwrap();
        console.firmware_probe_port = probe_port;
        (console, listener)
    }

    #[test]
    fn reconnect_refreshes_the_firmware_identity() {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (mut console, listener) = reconnectable_console(probe.local_addr().unwrap().port());
        *console.firmware.lock_recover() = Some("1.0.0".to_string());
        let responder = std::thread::spawn(move || {
            let mut buf = [0; 16];
            let (len, peer) = probe.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], b"WING?");
            probe
                .send_to(b"WING,127.0.0.1,Test,WING,serial,2.0.0", peer)
                .unwrap();
        });

        console.reconnect(&ReconnectPolicy::default()).unwrap();
        let _ = listener.accept().unwrap();
        responder.join().unwrap();
        assert_eq!(console.firmware().as_deref(), Some("2.0.0"));
    }

    #[test]
    fn reconnect_keeps_the_known_firmware_when_the_probe_gets_no_reply() {
        // Bound but silent: the probe times out instead of seeing a refused port.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (mut console, listener) = reconnectable_console(silent.local_addr().unwrap().port());
        *console.firmware.lock_recover() = Some("1.0.0".to_string());

        console.reconnect(&ReconnectPolicy::default()).unwrap();
        let _ = listener.accept().unwrap();
        assert_eq!(console.firmware().as_deref(), Some("1.0.0"));
    }

    // `_keep_alive` holds `main` while it takes `wsock`. A reconnect on another clone must not
    // hold `wsock` while it waits for `main`, or the two block each other forever.
    #[test]
    fn reconnect_waits_for_main_before_taking_the_writer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut console = WingConsole::connect_addr(listener.local_addr().unwrap()).unwrap();
        let (_old_server, _) = listener.accept().unwrap();
        let keeper = console.clone();

        let main = keeper.main.lock_recover();
        let reconnect = std::thread::spawn(move || console.reconnect(&ReconnectPolicy::default()));
        let (_new_server, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !keeper.reconnecting.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "reconnect never reached the swap"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // Give reconnect time to reach its lock sequence, then act as `_keep_alive` would.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            keeper.wsock.try_lock().is_ok(),
            "reconnect holds the writer while waiting for main"
        );
        drop(main);
        reconnect.join().unwrap().unwrap();
    }

    // U4: a mutex poisoned by a peer thread's panic is recovered rather than cascading into a
    // panic on every subsequent lock. `lock_recover` returns the guard (and the intact data).
    #[test]
    fn lock_recover_recovers_a_poisoned_mutex_without_panicking() {
        let m = Arc::new(Mutex::new(42u32));
        let m_panic = m.clone();
        let _ = std::thread::spawn(move || {
            let _guard = m_panic.lock().unwrap();
            panic!("poison the mutex while holding the guard");
        })
        .join();
        assert!(m.lock().is_err(), "the mutex must be poisoned by the panic");
        // `.lock().unwrap()` here would panic; `lock_recover` yields the guard and the value.
        assert_eq!(*m.lock_recover(), 42);
    }

    fn console_with_input(input: &[u8]) -> WingConsole {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, peer_addr) = listener.accept().unwrap();
        server.write_all(input).unwrap();
        WingConsole::from_streams(
            client.try_clone().unwrap(),
            client,
            peer_addr.ip(),
            peer_addr.port(),
        )
    }

    fn plain_node_definition_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_i32.to_be_bytes());
        bytes.extend_from_slice(&2_i32.to_be_bytes());
        bytes.extend_from_slice(&3_u16.to_be_bytes());
        bytes.push(1);
        bytes.push(b'n');
        bytes.push(1);
        bytes.push(b'N');
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes
    }

    #[test]
    fn native_response_limit_accepts_the_last_byte_and_rejects_the_next() {
        assert!(ensure_native_response_capacity(MAX_NATIVE_RESPONSE_BYTES - 1).is_ok());
        assert!(matches!(
            ensure_native_response_capacity(MAX_NATIVE_RESPONSE_BYTES),
            Err(Error::InvalidData)
        ));
    }

    // Regression (confirmed against a real WING rack console, 2026-07-06): every indexed Meter
    // variant's wire index byte must be one less than its 1-based `n`, or the console streams a
    // uniform one-channel-shifted set of levels (channel N's live signal lands on decoded slot
    // N-1). See `encode_meter`'s doc comment for the full incident.
    #[test]
    fn encode_meter_channel_index_is_zero_based_on_the_wire() {
        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Channel(1)).unwrap();
        assert_eq!(
            buf,
            vec![0xa0, 0],
            "Meter::Channel(1) must address wire index 0"
        );

        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Channel(4)).unwrap();
        assert_eq!(
            buf,
            vec![0xa0, 3],
            "Meter::Channel(4) must address wire index 3"
        );
    }

    #[test]
    fn encode_meter_every_indexed_variant_subtracts_one() {
        let cases: &[(Meter, u8)] = &[
            (Meter::Channel(2), 0xa0),
            (Meter::Aux(2), 0xa1),
            (Meter::Bus(2), 0xa2),
            (Meter::Main(2), 0xa3),
            (Meter::Matrix(2), 0xa4),
            (Meter::Dca(2), 0xa5),
            (Meter::Fx(2), 0xa6),
            (Meter::Source(2), 0xa7),
            (Meter::Output(2), 0xa8),
            (Meter::Channel2(2), 0xab),
            (Meter::Aux2(2), 0xac),
            (Meter::Bus2(2), 0xad),
            (Meter::Main2(2), 0xae),
            (Meter::Matrix2(2), 0xaf),
        ];
        for (meter, opcode) in cases {
            let mut buf = Vec::new();
            WingConsole::encode_meter(&mut buf, meter).unwrap();
            assert_eq!(
                buf,
                vec![*opcode, 1],
                "{meter:?} must encode n-1 after its opcode"
            );
        }
    }

    #[test]
    fn encode_meter_monitor_and_rta_have_no_index_byte() {
        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Monitor).unwrap();
        assert_eq!(buf, vec![0xa9]);

        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Rta).unwrap();
        assert_eq!(buf, vec![0xaa]);
    }

    #[test]
    fn encode_meter_rejects_indices_outside_each_family() {
        let cases = [
            Meter::Channel(0),
            Meter::Channel(41),
            Meter::Aux(9),
            Meter::Bus(17),
            Meter::Main(5),
            Meter::Matrix(9),
            Meter::Dca(17),
            Meter::Fx(17),
            Meter::Source(17),
            Meter::Output(12),
            Meter::Channel2(41),
            Meter::Aux2(9),
            Meter::Bus2(17),
            Meter::Main2(5),
            Meter::Matrix2(9),
        ];

        for meter in cases {
            let mut buf = Vec::new();
            assert!(matches!(
                WingConsole::encode_meter(&mut buf, &meter),
                Err(Error::InvalidInput)
            ));
            assert!(buf.is_empty(), "{meter:?} must not be partially encoded");
        }
    }

    #[test]
    fn request_meter_rejects_zero_before_initializing_the_subscription() {
        let mut console = console_with_input(&[]);

        assert!(matches!(
            console.request_meter(&[Meter::Channel(0)]),
            Err(Error::InvalidInput)
        ));
        assert!(!console.has_meter_socket.load(Ordering::Acquire));
    }

    #[test]
    fn set_int_uses_correct_i16_bytes() {
        let msg = WingConsole::set_int_message(0x01020304, 1000).unwrap();
        assert_eq!(msg, vec![0xd7, 1, 2, 3, 4, 0xd3, 0x03, 0xe8]);
    }

    #[test]
    fn set_int_escapes_i16_payload() {
        let msg = WingConsole::set_int_message(1, -8448).unwrap();
        assert_eq!(msg, vec![0xd7, 0, 0, 0, 1, 0xd3, 0xdf, 0xde, 0x00]);
    }

    #[test]
    fn set_string_escapes_payload_and_rejects_too_long() {
        let msg = WingConsole::set_string_message(1, "a\u{7ff}").unwrap();
        assert_eq!(msg, vec![0xd7, 0, 0, 0, 1, 0x82, b'a', 0xdf, 0xde, 0xbf]);
        assert!(matches!(
            WingConsole::set_string_message(1, &"x".repeat(257)),
            Err(Error::InvalidInput)
        ));
    }

    #[test]
    fn set_float_escapes_payload() {
        let value = f32::from_bits(0xdf000001);
        let msg = WingConsole::set_float_message(1, value).unwrap();
        assert_eq!(msg, vec![0xd7, 0, 0, 0, 1, 0xd5, 0xdf, 0xde, 0, 0, 1]);
    }

    #[test]
    fn binary_values_encode_parse_round_trips_value_tokens() {
        let pairs = vec![
            (1, NodeValue::Int(5)),
            (2, NodeValue::Int(-1000)),
            (3, NodeValue::Int(100000)),
            (4, NodeValue::Float(60.138_835)),
            (5, NodeValue::String(String::new())),
            (6, NodeValue::String("9000G".to_string())),
            (7, NodeValue::String("x".repeat(64))),
        ];

        let encoded = encode_binary_values(&pairs);

        assert_eq!(encoded.last(), Some(&0xde));
        assert_eq!(parse_binary_values(&encoded).unwrap(), pairs);
    }

    #[test]
    fn binary_values_parse_raw_token_variants_and_navigation() {
        let mut data = vec![
            0xc0, b'x', // node-name selector, ignored
            0xd2, 0, 7, // word node-index selector, ignored
            0xd7, 0, 0, 0, 9, // id selector
            0xd6,
        ];
        data.extend_from_slice(&1.5f32.to_be_bytes());
        data.push(0x05);
        data.push(0xd1);
        data.push(64);
        data.extend_from_slice(&[b'a'; 65]);
        data.push(0xde);

        assert_eq!(
            parse_binary_values(&data).unwrap(),
            vec![
                (9, NodeValue::Float(1.5)),
                (9, NodeValue::Int(5)),
                (9, NodeValue::String("a".repeat(65)))
            ]
        );
    }

    #[test]
    fn binary_values_parse_rejects_malformed_buffers() {
        assert!(matches!(
            parse_binary_values(&[0x05]),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            parse_binary_values(&[0xd7, 0]),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            parse_binary_values(&[0xd7, 0, 0, 0, 1, 0xd5, 0, 0]),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            parse_binary_values(&[0xdf]),
            Err(Error::InvalidData)
        ));
    }

    #[test]
    fn binary_values_encode_skips_oversized_strings_without_selector() {
        let encoded = encode_binary_values(&[(1, NodeValue::String("x".repeat(257)))]);

        assert_eq!(encoded, vec![0xde]);
        assert_eq!(parse_binary_values(&encoded).unwrap(), Vec::new());
    }

    #[test]
    fn binary_values_encode_extended_string_boundaries() {
        let pairs = vec![
            (1, NodeValue::String("a".repeat(65))),
            (2, NodeValue::String("b".repeat(256))),
        ];
        let encoded = encode_binary_values(&pairs);

        assert!(encoded.windows(2).any(|window| window == [0xd1, 64]));
        assert!(encoded.windows(2).any(|window| window == [0xd1, 255]));
        assert_eq!(parse_binary_values(&encoded).unwrap(), pairs);
    }

    #[test]
    fn oversized_extended_node_definition_length_errors() {
        let mut wing = console_with_input(&[0xdf, 0xdf, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(wing.read(), Err(Error::InvalidData)));
    }

    #[test]
    fn extended_node_definition_uses_u32_length() {
        let def = plain_node_definition_bytes();
        let mut input = vec![0xdf, 0xdf, 0, 0];
        input.extend_from_slice(&(def.len() as u32).to_be_bytes());
        input.extend_from_slice(&def);

        let mut wing = console_with_input(&input);
        let response = wing.read().unwrap();
        let WingResponse::NodeDef(def) = response else {
            panic!("expected node definition");
        };
        assert_eq!(def.parent_id, 1);
        assert_eq!(def.id, 2);
        assert_eq!(def.index, 3);
        assert_eq!(def.name, "n");
        assert_eq!(def.long_name, "N");
    }

    #[test]
    fn nul_string_payload_is_valid_rust_string() {
        let mut wing = console_with_input(&[0x82, b'A', 0, b'B']);
        let response = wing.read().unwrap();
        let WingResponse::NodeData(_, data) = response else {
            panic!("expected node data");
        };
        assert_eq!(data.get_string(), "A\0B");
    }

    #[test]
    fn read_timeout_replays_a_response_fragment_instead_of_corrupting_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, peer_addr) = listener.accept().unwrap();
        let writer = std::thread::spawn(move || {
            server.write_all(&[0xd7, 0, 0, 0, 7, 0xd5, 0x41]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            server.write_all(&[0x20, 0, 0]).unwrap();
        });
        let mut console = WingConsole::from_streams(
            client.try_clone().unwrap(),
            client,
            peer_addr.ip(),
            peer_addr.port(),
        );

        assert!(matches!(
            console.read_timeout(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        let WingResponse::NodeData(id, value) = console
            .read_timeout(Duration::from_millis(200))
            .expect("the replayed prefix and remaining suffix form one response")
        else {
            panic!("expected node data");
        };
        assert_eq!(id, 7);
        assert_eq!(value.get_float(), 10.0);
        writer.join().unwrap();
    }

    #[test]
    fn cloned_readers_serialize_timeout_replay_transactions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, peer_addr) = listener.accept().unwrap();
        let writer = std::thread::spawn(move || {
            server.write_all(&[0xd7, 0, 0, 0, 7, 0xd5, 0x41]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            server
                .write_all(&[0x20, 0, 0, 0xd7, 0, 0, 0, 8, 0xd4, 0, 0, 0, 9])
                .unwrap();
        });
        let mut console = WingConsole::from_streams(
            client.try_clone().unwrap(),
            client,
            peer_addr.ip(),
            peer_addr.port(),
        );
        let mut first = console.clone();
        let timed_out = std::thread::spawn(move || first.read_timeout(Duration::from_millis(20)));
        std::thread::sleep(Duration::from_millis(5));
        let mut second = console.clone();
        let replayed =
            std::thread::spawn(move || second.read_timeout(Duration::from_millis(200)).unwrap());

        assert!(matches!(timed_out.join().unwrap(), Err(Error::Timeout)));
        let WingResponse::NodeData(id, value) = replayed.join().unwrap() else {
            panic!("expected replayed node data");
        };
        assert_eq!(id, 7);
        assert_eq!(value.get_float(), 10.0);
        let WingResponse::NodeData(id, value) = console
            .read_timeout(Duration::from_millis(200))
            .expect("the second response remains exactly once")
        else {
            panic!("expected second node data");
        };
        assert_eq!(id, 8);
        assert_eq!(value.get_int(), 9);
        writer.join().unwrap();
    }

    #[test]
    fn unknown_top_level_command_errors() {
        let mut wing = console_with_input(&[0xe0]);
        assert!(matches!(wing.read(), Err(Error::InvalidData)));
    }

    #[test]
    fn read_meters_before_request_reports_meter_not_initialized() {
        let mut wing = console_with_input(&[]);
        assert!(matches!(
            wing.read_meters(),
            Err(Error::MeterNotInitialized)
        ));
    }

    /// R43: a meter (UDP) socket failure must not tear down parameter (TCP) control, and vice
    /// versa. `test_with_meter_socket` already tears down the TCP server half before handing
    /// back the console, so the console's `read()` fails immediately -- proving the meter path
    /// (a real, independent UDP socket pair) keeps delivering frames regardless.
    #[test]
    fn read_meters_keeps_working_after_tcp_transport_errors() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_ip = sender.local_addr().unwrap().ip();

        let mut console = WingConsole::test_with_meter_socket(peer_ip, receiver);

        // TCP side is already gone (server half dropped inside test_with_meter_socket).
        assert!(console.read().is_err());

        // token (u16) + 2 reserved bytes + one i16 sample, matching read_meters' framing.
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&(-6i16).to_be_bytes());
        sender.send_to(&frame, receiver_addr).unwrap();

        let (token, values) = console.read_meters().unwrap();
        assert_eq!(token, 1);
        assert_eq!(values, vec![-6]);
    }

    fn synthetic_def(id: i32, name: &str, node_type: NodeType, read_only: bool) -> WingNodeDef {
        WingNodeDef {
            id,
            parent_id: 0,
            index: 0,
            name: name.to_string(),
            long_name: String::new(),
            node_type,
            unit: crate::node::NodeUnit::None,
            read_only,
            min_float: None,
            max_float: None,
            steps: None,
            min_int: None,
            max_int: None,
            max_string_len: None,
            string_enum: None,
            float_enum: None,
            raw: Vec::new(),
        }
    }

    /// R18: a dump must exclude read-only nodes and plain (valueless)
    /// container nodes. The real embedded map's current sweep happens to have
    /// zero read-only definitions (verified while implementing this), so this
    /// exercises `dumpable_leaves` directly against a synthetic fixture rather
    /// than the embedded map -- the logic under test is identical either way.
    #[test]
    fn dumpable_leaves_excludes_read_only_and_containers() {
        let fixture: Vec<(String, WingNodeDef)> = vec![
            (
                "/root".to_string(),
                synthetic_def(1, "root", NodeType::Node, false),
            ),
            (
                "/root/writable".to_string(),
                synthetic_def(2, "writable", NodeType::Integer, false),
            ),
            (
                "/root/locked".to_string(),
                synthetic_def(3, "locked", NodeType::Integer, true),
            ),
            (
                "/root/container".to_string(),
                synthetic_def(4, "container", NodeType::Node, false),
            ),
            (
                "/root/container/child".to_string(),
                synthetic_def(5, "child", NodeType::LinearFloat, false),
            ),
            (
                "/unrelated".to_string(),
                synthetic_def(6, "unrelated", NodeType::Integer, false),
            ),
        ];

        let leaves = dumpable_leaves(fixture.iter().map(|(n, d)| (n.as_str(), d)), "/root");

        assert_eq!(
            leaves,
            vec![
                ("/root/container/child".to_string(), 5),
                ("/root/writable".to_string(), 2),
            ]
        );
    }

    #[test]
    fn restore_order_key_puts_model_selectors_first_shallowest_first() {
        let mut names = vec!["/fx/1/HALL/pdel", "/fx/2/mdl", "/fx/1/mdl", "/ch/1/eq/mdl"];
        names.sort_by_key(|n| restore_order_key(n));
        assert_eq!(
            names,
            vec!["/fx/2/mdl", "/fx/1/mdl", "/ch/1/eq/mdl", "/fx/1/HALL/pdel"]
        );
    }

    /// A meter console on loopback: the UDP pair it reads frames from, and the live TCP server.
    fn live_meter_console() -> (WingConsole, UdpSocket, SocketAddr, TcpStream) {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_ip = sender.local_addr().unwrap().ip();
        let (console, server) = WingConsole::test_with_meter_socket_and_server(peer_ip, receiver);
        (console, sender, receiver_addr, server)
    }

    fn meter_frame(id: u16, samples: &[i16]) -> Vec<u8> {
        let mut frame = id.to_be_bytes().to_vec();
        frame.extend_from_slice(&0u16.to_be_bytes());
        for sample in samples {
            frame.extend_from_slice(&sample.to_be_bytes());
        }
        frame
    }

    #[test]
    fn read_meters_returns_timeout_when_no_frames_arrive() {
        let (mut console, _sender, _addr, _server) = live_meter_console();

        let start = Instant::now();
        assert!(matches!(console.read_meters(), Err(Error::Timeout)));
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(2500), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

        let start = Instant::now();
        assert!(matches!(
            console.read_meters_timeout(Duration::from_millis(100)),
            Err(Error::Timeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn read_meters_skips_malformed_datagrams_and_returns_the_real_frame() {
        let (mut console, sender, addr, _server) = live_meter_console();
        for _ in 0..200 {
            sender.send_to(&[1, 2, 3], addr).unwrap(); // too short
            sender.send_to(&[0, 1, 0, 0, 9], addr).unwrap(); // odd sample bytes
        }
        sender.send_to(&meter_frame(1, &[-6, 12]), addr).unwrap();

        let start = Instant::now();
        let (id, samples) = console.read_meters_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!((id, samples), (1, vec![-6, 12]));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn read_meters_into_decodes_without_allocating_and_reports_short_buffers() {
        let (mut console, sender, addr, _server) = live_meter_console();
        sender.send_to(&meter_frame(1, &[-6, 12, 3]), addr).unwrap();
        let mut out = [0i16; 4];
        assert_eq!(console.read_meters_into(&mut out).unwrap(), (1, 3));
        assert_eq!(out, [-6, 12, 3, 0]);

        sender.send_to(&meter_frame(1, &[1, 2, 3]), addr).unwrap();
        let mut short = [7i16; 2];
        assert_eq!(console.read_meters_into(&mut short).unwrap(), (1, 3));
        assert_eq!(short, [7, 7], "a frame that does not fit is not written");
    }

    /// Reads the renewals a meter keepalive wrote to the server, as report ids.
    fn renewed_ids(server: &mut TcpStream) -> Vec<u16> {
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = server.read(&mut buf) {
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        let mut decoder = ChannelDecoder::default();
        let data: Vec<u8> = decoder
            .push(&bytes)
            .unwrap()
            .into_iter()
            .filter_map(|event| match event {
                ChannelEvent::Data(3, byte) => Some(byte),
                _ => None,
            })
            .collect();
        data.chunks_exact(5)
            .filter(|renew| renew[0] == 0xd4)
            .map(|renew| u16::from_be_bytes([renew[1], renew[2]]))
            .collect()
    }

    #[test]
    fn meter_keepalive_renews_only_the_active_subscription() {
        let (mut console, _sender, _addr, mut server) = live_meter_console();
        console.mtrs.lock_recover().active_meter_id = None;
        let first = console.request_meter(&[Meter::Channel(1)]).unwrap();
        let second = console.request_meter(&[Meter::Channel(2)]).unwrap();
        assert_ne!(first, second);
        let _ = renewed_ids(&mut server); // drain the subscribe requests

        console.mtrs.lock_recover().keep_alive_meters_timer = Instant::now();
        console.keep_alive_meters().unwrap();
        assert_eq!(renewed_ids(&mut server), vec![second]);
    }

    struct FailingWriter;

    impl Read for FailingWriter {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Transport for FailingWriter {
        fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_subscribe_spends_no_id_and_ids_wrap_past_zero() {
        let mut console = WingConsole::from_transports(
            FailingWriter,
            FailingWriter,
            IpAddr::from([127, 0, 0, 1]),
        );
        assert!(console.request_meter(&[Meter::Channel(1)]).is_err());
        {
            let m = console.mtrs.lock_recover();
            assert_eq!((m.active_meter_id, m.next_meter_id), (None, 1));
        }

        let (mut console, _sender, _addr, _server) = live_meter_console();
        console.mtrs.lock_recover().next_meter_id = u16::MAX;
        assert_eq!(
            console.request_meter(&[Meter::Channel(1)]).unwrap(),
            u16::MAX
        );
        assert_eq!(console.request_meter(&[Meter::Channel(1)]).unwrap(), 1);
    }

    #[test]
    fn meter_wire_table_round_trips_every_family() {
        for meter in [
            Meter::Channel(40),
            Meter::Aux(8),
            Meter::Bus(16),
            Meter::Main(4),
            Meter::Matrix(8),
            Meter::Dca(16),
            Meter::Fx(16),
            Meter::Source(16),
            Meter::Output(11),
            Meter::Monitor,
            Meter::Rta,
            Meter::Channel2(40),
            Meter::Aux2(8),
            Meter::Bus2(16),
            Meter::Main2(4),
            Meter::Matrix2(8),
        ] {
            let (opcode, index, _) = meter.wire();
            assert_eq!(Meter::from_wire(opcode, index), Some(meter));
        }
        assert_eq!(Meter::from_wire(0xa9, 1), None);
        assert_eq!(Meter::from_wire(0xb0, 1), None);
    }

    #[test]
    fn a_224_byte_string_escapes_its_length_byte() {
        // 112 two-byte Cyrillic letters: 224 bytes, so the length byte is 223 (0xdf), and the
        // body starts with 0xd0, which would read as a channel select after a raw 0xdf.
        let value = "\u{0430}".repeat(112);
        let msg = WingConsole::set_string_message(1, &value).unwrap();

        let mut decoder = ChannelDecoder::with_channel(AUDIO_ENGINE_CHANNEL).unwrap();
        let decoded: Vec<u8> = decoder
            .push(&msg)
            .unwrap()
            .into_iter()
            .map(|event| match event {
                ChannelEvent::Data(AUDIO_ENGINE_CHANNEL, byte) => byte,
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        let mut expected = vec![0xd7, 0, 0, 0, 1, 0xd1, 223];
        expected.extend_from_slice(value.as_bytes());
        assert_eq!(decoded, expected);

        let mut console = console_with_input(&msg);
        match console.read_timeout(Duration::from_millis(500)).unwrap() {
            WingResponse::NodeData(1, data) => assert_eq!(data.get_string(), value),
            _ => panic!("expected the string value"),
        }
    }

    #[test]
    fn node_name_selectors_are_navigation_not_values() {
        let mut input = vec![0xd7];
        input.extend(42i32.to_be_bytes());
        input.extend([0xc2, b'a', b'b', b'c']);
        input.push(0xd4);
        input.extend(7i32.to_be_bytes());
        let mut console = console_with_input(&input);

        match console.read_timeout(Duration::from_millis(500)).unwrap() {
            WingResponse::NodeData(42, data) => assert_eq!(data.get_int(), 7),
            _ => panic!("expected NodeData(42, 7)"),
        }
    }

    #[test]
    fn bytes_on_other_native_channels_are_not_parsed_as_values() {
        let mut input = vec![0xdf, 0xd2, 0x05, 0xdf, 0xd1, 0xd7];
        input.extend(42i32.to_be_bytes());
        input.push(0x03);
        let mut console = console_with_input(&input);

        match console.read_timeout(Duration::from_millis(500)).unwrap() {
            WingResponse::NodeData(42, data) => assert_eq!(data.get_int(), 3),
            _ => panic!("expected NodeData(42, 3)"),
        }
    }

    #[test]
    fn scan_lists_each_console_once_at_its_source_address() {
        let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = responder.local_addr().unwrap();
        let replier = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let (_, client) = responder.recv_from(&mut buf).unwrap();
            for _ in 0..3 {
                responder
                    .send_to(b"WING,10.9.9.9,Desk,WING,SER1,3.1.0", client)
                    .unwrap();
            }
            responder.send_to(b"not a wing reply", client).unwrap();
        });

        let dsock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let found =
            WingConsole::scan_on(&dsock, target, false, Duration::from_millis(800)).unwrap();
        replier.join().unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].ip, "127.0.0.1", "the claimed 10.9.9.9 is ignored");
        assert_eq!(
            (found[0].serial.as_str(), found[0].firmware.as_str()),
            ("SER1", "3.1.0")
        );
    }

    #[test]
    fn a_reconnect_that_waited_for_another_clones_reuses_its_session() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (console, listener) = reconnectable_console(silent.local_addr().unwrap().port());
        listener.set_nonblocking(true).unwrap();
        let gate = console.reconnect_gate.clone();
        let guard = gate.lock_recover();

        let mut waiter = console.clone();
        let worker = std::thread::spawn(move || waiter.reconnect(&ReconnectPolicy::default()));
        while console.pending_reconnects.load(Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }
        // Another clone's reconnect completes while this one waits on the gate.
        console.session_generation.fetch_add(1, Ordering::AcqRel);
        drop(guard);

        let outcome = worker.join().unwrap().unwrap();
        assert_eq!(outcome.attempts, 0);
        assert!(listener.accept().is_err(), "no second handshake was made");
    }

    #[test]
    fn reconnect_and_keepalives_on_other_clones_never_deadlock() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (console, listener) = reconnectable_console(silent.local_addr().unwrap().port());
        let acceptor = std::thread::spawn(move || {
            (0..3)
                .map(|_| listener.accept().unwrap().0)
                .collect::<Vec<_>>()
        });
        let stop = Arc::new(AtomicBool::new(false));

        let mut keeper = console.clone();
        let keeper_stop = stop.clone();
        let keepalives = std::thread::spawn(move || {
            while !keeper_stop.load(Ordering::Acquire) {
                keeper.main.lock_recover().keep_alive_timer = Instant::now();
                keeper.mtrs.lock_recover().keep_alive_meters_timer = Instant::now();
                let _ = keeper.keep_alive();
                let _ = keeper.keep_alive_meters();
            }
        });

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut reconnector = console.clone();
        std::thread::spawn(move || {
            for _ in 0..3 {
                reconnector.reconnect(&ReconnectPolicy::default()).unwrap();
            }
            done_tx.send(()).unwrap();
        });

        let finished = done_rx.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::Release);
        assert!(finished.is_ok(), "reconnect deadlocked against keepalives");
        keepalives.join().unwrap();
        acceptor.join().unwrap();
    }

    #[test]
    fn a_binary_capture_ignores_responses_queued_before_its_request() {
        let mut input = vec![0xd7];
        input.extend(9i32.to_be_bytes());
        input.push(0x05);
        input.push(0xde);
        let mut console = console_with_input(&input);
        console.requeue(vec![WingResponse::RequestEnd]);

        let captured = console
            .get_binary_node(9, Duration::from_millis(500))
            .unwrap();
        assert_eq!(
            captured, input,
            "the queued RequestEnd did not end the capture"
        );
        assert!(matches!(
            console.read_timeout(Duration::from_millis(100)),
            Ok(WingResponse::RequestEnd)
        ));
    }
}

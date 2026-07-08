use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::node::{NodeType, WingNodeData, WingNodeDef};
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
/// [`Error::ConnectionError`] and recovers via reconnect, exactly as before.
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

lazy_static::lazy_static! {
    static ref ID_TO_NAME: HashMap<i32, Vec<String>> = {
        let mut id2name = HashMap::<i32, Vec<String>>::new();
        if id2name.is_empty() {
            for (fullname, def) in NAME_TO_DEF.iter() {
                id2name.get_mut(&def.id).map(|x| x.push(fullname.to_string())).unwrap_or_else(|| {
                    id2name.insert(def.id, vec![fullname.to_string()]);
                });
            }
        }
        id2name
    };
}

const RX_BUFFER_SIZE: usize = 2048;
const DATA_KEEP_ALIVE_SECONDS: u64 = 7;
const METERS_KEEP_ALIVE_SECONDS: u64 = 3;
const WRITE_TIMEOUT_SECONDS: u64 = 5;
const MAX_NODE_DEF_BYTES: usize = 1024 * 1024;

pub struct DiscoveryInfo {
    pub ip: String,
    pub name: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

pub struct Meters {
    pub socket: UdpSocket,
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
    rx_esc: bool,
    rx_current_channel: i8,
    rx_has_in_pipe: Option<u8>,
    current_node_id: i32,
    /// Overall deadline for an in-flight attended-get operation (R16/R17), consulted by
    /// `decode_next` so a stuck socket read can't run past it. `None` outside of
    /// attended-get, in which case reads are bounded only by the keep-alive cadence, same
    /// as before this field existed.
    op_deadline: Option<Instant>,
}

struct _WingConsoleMeters {
    meters: Option<Meters>,
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
    mtrs: Arc<Mutex<_WingConsoleMeters>>,
    peer_ip: IpAddr,
    /// The peer's TCP port, so [`reconnect`](Self::reconnect) can target the same endpoint
    /// without re-resolving a hostname (`connect` always used 2222; `connect_addr` may not
    /// have). Unused (and meaningless) on a [`from_transports`](Self::from_transports)
    /// console, which never reconnects.
    peer_port: u16,
    /// `true` for consoles backed by a real TCP connection ([`connect`](Self::connect) /
    /// [`connect_addr`](Self::connect_addr)); `false` for [`from_transports`](Self::from_transports)
    /// consoles (tests/replay), which have no real peer to reconnect to.
    reconnectable: bool,
    firmware: Arc<Mutex<Option<String>>>,
}

impl WingConsole {
    pub fn scan(stop_on_first: bool) -> Result<Vec<DiscoveryInfo>> {
        let dsock = UdpSocket::bind("0.0.0.0:0")?;
        dsock.set_broadcast(true)?;
        dsock.set_read_timeout(Some(Duration::from_millis(500)))?;

        let mut results = Vec::new();
        let mut attempts = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut packets_seen = 0;

        dsock.send_to(b"WING?", "255.255.255.255:2222")?;
        while attempts < 10 && packets_seen < 100 && std::time::Instant::now() < deadline {
            let mut buf = [0u8; 1024];
            match dsock.recv_from(&mut buf) {
                Ok((received, _)) => {
                    packets_seen += 1;
                    if let Ok(response) = String::from_utf8(buf[..received].to_vec()) {
                        let tokens: Vec<&str> = response.split(',').collect();
                        if tokens.len() >= 6 && tokens[0] == "WING" {
                            results.push(DiscoveryInfo {
                                ip: tokens[1].to_string(),
                                name: tokens[2].to_string(),
                                model: tokens[3].to_string(),
                                serial: tokens[4].to_string(),
                                firmware: tokens[5].to_string(),
                            });
                            if stop_on_first {
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    attempts += 1;
                    // Re-broadcast the probe on each receive timeout. UDP broadcast is
                    // unreliable; sending "WING?" only once means a single dropped packet
                    // yields an empty scan even though a console is present.
                    let _ = dsock.send_to(b"WING?", "255.255.255.255:2222");
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
                        .or_else(|| Self::probe_firmware(addr.ip()));
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
        *console.firmware.lock_recover() = Self::probe_firmware(addr.ip());
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
    fn probe_firmware(ip: IpAddr) -> Option<String> {
        let dsock = UdpSocket::bind("0.0.0.0:0").ok()?;
        dsock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .ok()?;
        dsock.send_to(b"WING?", (ip, 2222)).ok()?;

        let mut buf = [0u8; 1024];
        let (received, _) = dsock.recv_from(&mut buf).ok()?;
        let response = String::from_utf8(buf[..received].to_vec()).ok()?;
        let tokens: Vec<&str> = response.split(',').collect();
        if tokens.len() >= 6 && tokens[0] == "WING" {
            Some(tokens[5].to_string())
        } else {
            None
        }
    }

    /// The connected console's firmware version, if known (R37).
    ///
    /// Populated at [`connect`](Self::connect) time: from the broadcast scan
    /// reply when connecting via discovery, or from a best-effort unicast
    /// probe when connecting to an explicit IP. `None` if neither produced a
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
                rx_esc: false,
                rx_current_channel: -1,
                rx_has_in_pipe: None,
                current_node_id: 0,
                op_deadline: None,
            })),
            mtrs: Arc::new(Mutex::new(_WingConsoleMeters {
                keep_alive_meters_timer: std::time::Instant::now()
                    + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS),
                meters: None,
                next_meter_id: 0,
            })),
            peer_ip,
            peer_port,
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
    /// node id) is reset -- a fresh TCP session has no partial frame to resume.
    ///
    /// The meter UDP socket, if any, is left untouched: it's a client-side socket and still
    /// usable. But the meter *subscription* lived server-side on the old session and is gone
    /// with it; see [`SessionGap::meters_invalidated`] -- callers must call
    /// [`request_meter`](Self::request_meter) again to resume metering.
    ///
    /// Returns `Err(Error::InvalidInput)` immediately for a console built via
    /// [`from_transports`](Self::from_transports) -- there's no real peer to reconnect to.
    pub fn reconnect(&mut self, policy: &ReconnectPolicy) -> Result<ReconnectOutcome> {
        if !self.reconnectable {
            return Err(Error::InvalidInput);
        }
        let addr = SocketAddr::new(self.peer_ip, self.peer_port);
        let mut backoff = policy.initial_backoff;
        let mut last_err = Error::ConnectionError;
        for attempt in 1..=policy.max_attempts {
            match Self::handshake_streams(addr) {
                Ok((wsock, rsock)) => {
                    *self.wsock.lock_recover() = Box::new(wsock);
                    *self.rsock.lock_recover() = Box::new(rsock);
                    {
                        let mut main = self.main.lock_recover();
                        main.rx_buf_tail = 0;
                        main.rx_buf_size = 0;
                        main.rx_esc = false;
                        main.rx_current_channel = -1;
                        main.rx_has_in_pipe = None;
                        main.current_node_id = 0;
                        main.op_deadline = None;
                        main.keep_alive_timer =
                            Instant::now() + Duration::from_secs(DATA_KEEP_ALIVE_SECONDS);
                    }
                    let meters_invalidated = self.mtrs.lock_recover().meters.is_some();
                    return Ok(ReconnectOutcome {
                        attempts: attempt,
                        gap: SessionGap {
                            dropped_events: true,
                            meters_invalidated,
                            state_may_have_changed: true,
                        },
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
        loop {
            let mainptr = self.main.clone();
            let mut main = mainptr.lock_recover();
            let mut raw = Vec::new();
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
                let len = cmd - 0xc0 + 1;
                let v = self.read_string(&mut main, ch, len as usize, &mut raw)?;
                return Ok(WingResponse::NodeData(
                    main.current_node_id,
                    WingNodeData::with_string(v),
                ));
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
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.read();
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
        self._keep_alive(&mut self.main.clone().lock_recover())
    }

    fn _keep_alive(&mut self, r: &mut _WingConsoleMain) -> Result<()> {
        if r.keep_alive_timer <= std::time::Instant::now() {
            // println!("keep_alive");
            self.wsock
                .clone()
                .lock_recover()
                .write_all(&[0xdf, 0xd1])?;
            r.keep_alive_timer =
                std::time::Instant::now() + std::time::Duration::from_secs(DATA_KEEP_ALIVE_SECONDS);
        }
        Ok(())
    }

    /// read_meters() will call this as needed, but if you don't call read_meters() then the Wing Console will
    /// hang up the connection after a 5 seconds of no activity. You should call this yourself
    /// periodically if you are not calling read_meters().
    pub fn keep_alive_meters(&mut self) -> Result<()> {
        self._keep_alive_meters(&mut self.mtrs.clone().lock_recover())
    }

    fn _keep_alive_meters(&mut self, m: &mut _WingConsoleMeters) -> Result<()> {
        if m.keep_alive_meters_timer <= std::time::Instant::now() {
            // println!("keep_alive_meters");
            let meters = m.meters.as_ref().ok_or(Error::MeterNotInitialized)?;
            let mut i = m.next_meter_id as i32;
            while i > 0 {
                let mut keepalive = vec![0xdf, 0xd3, 0xd4];
                Self::extend_escaped(&mut keepalive, &(i as u16).to_be_bytes());
                Self::extend_escaped(&mut keepalive, &meters.port.to_be_bytes());
                keepalive.push(0xdf);
                keepalive.push(0xd1);
                self.wsock.clone().lock_recover().write_all(&keepalive)?;
                i -= 1;
            }
            m.keep_alive_meters_timer = std::time::Instant::now()
                + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        }
        Ok(())
    }

    fn decode_next(&mut self, r: &mut _WingConsoleMain, raw: &mut Vec<u8>) -> Result<(i8, u8)> {
        if let Some(value) = r.rx_has_in_pipe {
            // println!("has in pipe");
            r.rx_has_in_pipe = None;
            raw.push(value);
            return Ok((r.rx_current_channel, value));
        }

        loop {
            self._keep_alive(r)?;
            if r.rx_buf_size == 0 {
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

            if !r.rx_esc {
                if byte == 0xdf {
                    r.rx_esc = true;
                } else {
                    raw.push(byte);
                    break Ok((r.rx_current_channel, byte));
                }
            } else if byte == 0xdf {
                break Ok((r.rx_current_channel, byte));
            } else {
                r.rx_esc = false;
                if byte == 0xde {
                    raw.push(0xdf);
                    break Ok((r.rx_current_channel, 0xdf));
                } else if (0xd0..0xde).contains(&byte) {
                    r.rx_current_channel = (byte - 0xd0) as i8;
                    continue;
                } else if r.rx_current_channel >= 0 {
                    r.rx_has_in_pipe = Some(byte);
                    raw.push(0xdf);
                    break Ok((r.rx_current_channel, 0xdf));
                } else {
                    raw.push(byte);
                    break Ok((r.rx_current_channel, byte));
                }
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
    fn encode_meter(buf: &mut Vec<u8>, meter: &Meter) {
        match meter {
            Meter::Channel(n) => {
                buf.push(0xa0);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Aux(n) => {
                buf.push(0xa1);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Bus(n) => {
                buf.push(0xa2);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Main(n) => {
                buf.push(0xa3);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Matrix(n) => {
                buf.push(0xa4);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Dca(n) => {
                buf.push(0xa5);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Fx(n) => {
                buf.push(0xa6);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Source(n) => {
                buf.push(0xa7);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Output(n) => {
                buf.push(0xa8);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Monitor => {
                buf.push(0xa9);
            }
            Meter::Rta => {
                buf.push(0xaa);
            }
            Meter::Channel2(n) => {
                buf.push(0xab);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Aux2(n) => {
                buf.push(0xac);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Bus2(n) => {
                buf.push(0xad);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Main2(n) => {
                buf.push(0xae);
                Self::push_escaped(buf, *n - 1);
            }
            Meter::Matrix2(n) => {
                buf.push(0xaf);
                Self::push_escaped(buf, *n - 1);
            }
        }
    }

    fn push_escaped(buf: &mut Vec<u8>, byte: u8) {
        buf.push(byte);
        if byte == 0xdf {
            buf.push(0xde);
        }
    }

    fn extend_escaped(buf: &mut Vec<u8>, bytes: &[u8]) {
        for byte in bytes {
            Self::push_escaped(buf, *byte);
        }
    }

    fn format_id(id: i32, buf: &mut Vec<u8>, prefix: u8, suffix: Option<u8>) {
        buf.push(prefix);

        Self::extend_escaped(buf, &id.to_be_bytes());

        if let Some(suffix1) = suffix {
            buf.push(suffix1);
        }
    }

    pub fn request_node_definition(&mut self, id: i32) -> Result<()> {
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
    /// the socket again.
    fn attended_read_until<T>(
        &mut self,
        deadline: Instant,
        matcher: impl Fn(WingResponse) -> std::result::Result<T, WingResponse>,
    ) -> Result<(T, Vec<WingResponse>)> {
        let mut buffered = Vec::new();
        loop {
            let resp = self.read()?;
            match matcher(resp) {
                Ok(matched) => return Ok((matched, buffered)),
                Err(unrelated) => buffered.push(unrelated),
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
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
        self.request_node_data(id)?;
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.attended_read_until(deadline, |resp| match resp {
            WingResponse::NodeData(rid, data) if rid == id => Ok(data),
            other => Err(other),
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
        self.request_node_definition(id)?;
        let deadline = Instant::now() + timeout;
        self.set_op_deadline(Some(deadline));
        let result = self.attended_read_until(deadline, |resp| match resp {
            WingResponse::NodeDef(def) if def.id == id => Ok(def),
            other => Err(other),
        });
        self.set_op_deadline(None);
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
        let mtrsptr = self.mtrs.clone();
        let mut mtrs = mtrsptr.lock_recover();
        mtrs.next_meter_id = mtrs
            .next_meter_id
            .checked_add(1)
            .ok_or(Error::InvalidInput)?;
        if mtrs.next_meter_id == 0 {
            return Err(Error::InvalidInput);
        }

        if mtrs.meters.is_none() {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            let port = socket.local_addr()?.port();
            socket.set_read_timeout(Some(Duration::from_millis(1000)))?;
            mtrs.meters = Some(Meters { socket, port });
        } else {
            self._keep_alive_meters(&mut mtrs)?;
        }
        let md = mtrs.meters.as_ref().ok_or(Error::MeterNotInitialized)?;

        let mut buf = vec![0xdf, 0xd3, 0xd3];
        Self::extend_escaped(&mut buf, &md.port.to_be_bytes());
        buf.push(0xd4);
        Self::extend_escaped(&mut buf, &mtrs.next_meter_id.to_be_bytes());
        Self::extend_escaped(&mut buf, &md.port.to_be_bytes());
        buf.push(0xdc);

        for meter in meters {
            Self::encode_meter(&mut buf, meter);
        }

        buf.push(0xde); // end of def
        buf.push(0xdf);
        buf.push(0xd1);

        self.wsock.clone().lock_recover().write_all(&buf)?;

        Ok(mtrs.next_meter_id)
    }

    /// reads any meter values that have been requested with request_meter() and returns the meter
    /// ID along with the meters values
    pub fn read_meters(&mut self) -> Result<(u16, Vec<i16>)> {
        loop {
            let mptr = self.mtrs.clone();
            let mut m = mptr.lock_recover();

            self._keep_alive_meters(&mut m)?;
            let md = m.meters.as_ref().ok_or(Error::MeterNotInitialized)?;
            let mut buf = [0u8; 8192];
            md.socket.set_read_timeout(Some(
                m.keep_alive_meters_timer
                    .saturating_duration_since(std::time::Instant::now()),
            ))?;
            match md.socket.recv_from(&mut buf) {
                Ok((received, addr)) => {
                    if addr.ip() != self.peer_ip || received < 4 || (received - 4) % 2 != 0 {
                        continue;
                    }
                    return Ok((
                        u16::from_be_bytes([buf[0], buf[1]]),
                        buf[4..received]
                            .chunks_exact(2) // Take 2 bytes at a time
                            .map(|chunk| i16::from_be_bytes([chunk[0], chunk[1]]))
                            .collect(),
                    ));
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => {
                    return Err(Error::ConnectionError);
                }
            }
        }
    }

    pub fn set_string(&mut self, id: i32, value: &str) -> Result<()> {
        let buf = Self::set_string_message(id, value)?;
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    pub fn set_float(&mut self, id: i32, value: f32) -> Result<()> {
        let buf = Self::set_float_message(id, value);
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    pub fn set_int(&mut self, id: i32, value: i32) -> Result<()> {
        let buf = Self::set_int_message(id, value);
        self.wsock.clone().lock_recover().write_all(&buf)?;
        Ok(())
    }

    fn set_string_message(id: i32, value: &str) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        Self::format_id(id, &mut buf, 0xd7, None);

        if value.is_empty() {
            buf.push(0xd0);
        } else if value.len() <= 64 {
            buf.push(0x7f + value.len() as u8);
        } else if value.len() <= 256 {
            buf.push(0xd1);
            buf.push((value.len() - 1) as u8);
        } else {
            return Err(Error::InvalidInput);
        }

        Self::extend_escaped(&mut buf, value.as_bytes());
        Ok(buf)
    }

    fn set_float_message(id: i32, value: f32) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::format_id(id, &mut buf, 0xd7, Some(0xd5));
        Self::extend_escaped(&mut buf, &value.to_be_bytes());
        buf
    }

    fn set_int_message(id: i32, value: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::format_id(id, &mut buf, 0xd7, None);
        let bytes = value.to_be_bytes();

        if (0..=0x3f).contains(&value) {
            buf.push(value as u8);
        } else if (-32768..=32767).contains(&value) {
            buf.push(0xd3);
            Self::extend_escaped(&mut buf, &(value as i16).to_be_bytes());
        } else {
            buf.push(0xd4);
            Self::extend_escaped(&mut buf, &bytes);
        }
        buf
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
        NAME_TO_DEF.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Total number of entries in the embedded property map. Exposed for the
    /// regeneration consistency tests (see `tests/propmap_consistency.rs`),
    /// which have no other way to see the size of the private `NAME_TO_DEF` map.
    pub fn propmap_len() -> usize {
        NAME_TO_DEF.len()
    }

    #[cfg(test)]
    pub(crate) fn test_with_meter_socket(peer_ip: IpAddr, socket: UdpSocket) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let port = socket.local_addr().unwrap().port();
        let console = Self::from_streams(client.try_clone().unwrap(), client, peer_ip, addr.port());

        {
            let mut meters = console.mtrs.lock_recover();
            meters.meters = Some(Meters { socket, port });
            meters.next_meter_id = 1;
            meters.keep_alive_meters_timer = std::time::Instant::now()
                + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS);
        }

        drop(server);
        console
    }

    pub fn id_to_defs(id: i32) -> Option<Vec<(String, WingNodeDef)>> {
        ID_TO_NAME.get(&id).cloned().map(|names| {
            names
                .iter()
                .map(|n| (n, NAME_TO_DEF.get(n)))
                .filter(|x| x.1.is_some())
                .map(|x| (x.0, x.1.unwrap()))
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect()
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
    /// drop it. A timed-out id contributes nothing to this stash either way --
    /// `get_node_data`'s `Err` path carries no partial buffer with it -- but a
    /// timeout on one id never stops the rest of `ids` from being attempted.
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
    /// one attended `get_node_data` per leaf, in a fixed order (sorted by
    /// fullname) so a dump taken twice in a row requests things in the same
    /// order. Plain container nodes (`NodeType::Node`, which never carry a
    /// value) and read-only leaves are excluded (R18): restoring a read-only
    /// node would fail anyway, and including a valueless container would just
    /// waste a request that could never resolve to a value.
    ///
    /// Fails fast on the first leaf that doesn't respond within `timeout`
    /// rather than collecting partial results -- a dump is meant to represent
    /// one consistent snapshot, and a partial one masquerading as complete
    /// would be worse than an explicit error.
    pub fn dump_subtree(&mut self, root_fullname: &str, timeout: Duration) -> Result<NodeDump> {
        let leaves = dumpable_leaves(NAME_TO_DEF.iter(), root_fullname);

        let mut entries = Vec::with_capacity(leaves.len());
        for (fullname, id) in leaves {
            let (data, _buffered) = self.get_node_data(id, timeout)?;
            entries.push(DumpEntry {
                fullname,
                id,
                value: NodeValue::from_data(&data),
            });
        }
        Ok(NodeDump { entries })
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
    /// One `Result` per entry, in the order actually applied -- a failure on
    /// one entry doesn't stop the rest from being attempted.
    pub fn restore(&mut self, dump: &NodeDump) -> Vec<(String, Result<()>)> {
        let mut ordered: Vec<&DumpEntry> = dump.entries.iter().collect();
        ordered.sort_by_key(|entry| restore_order_key(&entry.fullname));

        ordered
            .into_iter()
            .map(|entry| {
                let blocked = NAME_TO_DEF
                    .get(&entry.fullname)
                    .map(|def| def.read_only)
                    .unwrap_or(false);
                let result = if blocked {
                    Err(Error::InvalidInput)
                } else {
                    self.write_node_value(entry.id, &entry.value)
                };
                (entry.fullname.clone(), result)
            })
            .collect()
    }
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
    entries: impl Iterator<Item = (&'a String, &'a WingNodeDef)>,
    root_fullname: &str,
) -> Vec<(String, i32)> {
    let prefix = format!("{root_fullname}/");
    let mut leaves: Vec<(String, i32)> = entries
        .filter(|(name, def)| {
            def.node_type != NodeType::Node
                && !def.read_only
                && (name.as_str() == root_fullname || name.starts_with(&prefix))
        })
        .map(|(name, def)| (name.clone(), def.id))
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
            if let Ok(sock) = self.wsock.lock() {
                let _ = sock.shutdown(std::net::Shutdown::Both);
            }
        }
        if Arc::strong_count(&self.rsock) == 1 {
            if let Ok(sock) = self.rsock.lock() {
                let _ = sock.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

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

    // Regression (confirmed against a real WING rack console, 2026-07-06): every indexed Meter
    // variant's wire index byte must be one less than its 1-based `n`, or the console streams a
    // uniform one-channel-shifted set of levels (channel N's live signal lands on decoded slot
    // N-1). See `encode_meter`'s doc comment for the full incident.
    #[test]
    fn encode_meter_channel_index_is_zero_based_on_the_wire() {
        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Channel(1));
        assert_eq!(
            buf,
            vec![0xa0, 0],
            "Meter::Channel(1) must address wire index 0"
        );

        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Channel(4));
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
            WingConsole::encode_meter(&mut buf, meter);
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
        WingConsole::encode_meter(&mut buf, &Meter::Monitor);
        assert_eq!(buf, vec![0xa9]);

        let mut buf = Vec::new();
        WingConsole::encode_meter(&mut buf, &Meter::Rta);
        assert_eq!(buf, vec![0xaa]);
    }

    #[test]
    fn set_int_uses_correct_i16_bytes() {
        let msg = WingConsole::set_int_message(0x01020304, 1000);
        assert_eq!(msg, vec![0xd7, 1, 2, 3, 4, 0xd3, 0x03, 0xe8]);
    }

    #[test]
    fn set_int_escapes_i16_payload() {
        let msg = WingConsole::set_int_message(1, -8448);
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
        let msg = WingConsole::set_float_message(1, value);
        assert_eq!(msg, vec![0xd7, 0, 0, 0, 1, 0xd5, 0xdf, 0xde, 0, 0, 1]);
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

        let leaves = dumpable_leaves(fixture.iter().map(|(n, d)| (n, d)), "/root");

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
}

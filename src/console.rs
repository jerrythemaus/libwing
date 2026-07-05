use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::node::{WingNodeData, WingNodeDef};
use crate::propmap::NAME_TO_DEF;
use crate::{Error, Result, WingResponse};

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

struct _WingConsoleMain {
    keep_alive_timer: std::time::Instant,
    rx_buf: [u8; RX_BUFFER_SIZE],
    rx_buf_tail: usize,
    rx_buf_size: usize,
    rx_esc: bool,
    rx_current_channel: i8,
    rx_has_in_pipe: Option<u8>,
    current_node_id: i32,
}

struct _WingConsoleMeters {
    meters: Option<Meters>,
    next_meter_id: u16,
    keep_alive_meters_timer: std::time::Instant,
}

#[derive(Clone)]
pub struct WingConsole {
    rsock: Arc<Mutex<TcpStream>>,
    wsock: Arc<Mutex<TcpStream>>,
    main: Arc<Mutex<_WingConsoleMain>>,
    mtrs: Arc<Mutex<_WingConsoleMeters>>,
    peer_ip: IpAddr,
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
        let ip = if let Some(i) = host_or_ip {
            i.to_string()
        } else {
            let devices = WingConsole::scan(true)?;
            if !devices.is_empty() {
                devices[0].ip.clone()
            } else {
                return Err(Error::DiscoveryError);
            }
        };

        let mut last_connect_error = None;
        for addr in (ip.as_str(), 2222).to_socket_addrs()? {
            let attempt =
                TcpStream::connect_timeout(&addr, Duration::from_secs(5)).and_then(|mut stream| {
                    // stream.set_nonblocking(true)?;
                    stream.set_nodelay(true)?;
                    // Bound writes: without a write timeout, write_all() can block forever if the
                    // peer's receive window stays full (dead/stalled console), permanently hanging
                    // any thread that sends a command or keep-alive.
                    stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS)))?;
                    stream.write_all(&[0xdf, 0xd1])?;
                    let wsock = stream.try_clone()?;
                    Ok(Self::from_streams(wsock, stream, addr.ip()))
                });
            match attempt {
                Ok(console) => return Ok(console),
                Err(err) => last_connect_error = Some(err),
            }
        }

        if let Some(err) = last_connect_error {
            Err(err.into())
        } else {
            Err(Error::ConnectionError)
        }
    }

    fn from_streams(wsock: TcpStream, rsock: TcpStream, peer_ip: IpAddr) -> Self {
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
            })),
            mtrs: Arc::new(Mutex::new(_WingConsoleMeters {
                keep_alive_meters_timer: std::time::Instant::now()
                    + std::time::Duration::from_secs(METERS_KEEP_ALIVE_SECONDS),
                meters: None,
                next_meter_id: 0,
            })),
            peer_ip,
        }
    }

    pub fn read(&mut self) -> Result<WingResponse> {
        loop {
            let mainptr = self.main.clone();
            let mut main = mainptr.lock().unwrap();
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
        self._keep_alive(&mut self.main.clone().lock().unwrap())
    }

    fn _keep_alive(&mut self, r: &mut _WingConsoleMain) -> Result<()> {
        if r.keep_alive_timer <= std::time::Instant::now() {
            // println!("keep_alive");
            self.wsock
                .clone()
                .lock()
                .unwrap()
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
        self._keep_alive_meters(&mut self.mtrs.clone().lock().unwrap())
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
                self.wsock.clone().lock().unwrap().write_all(&keepalive)?;
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
                self.rsock.clone().lock().unwrap().set_read_timeout(Some(
                    r.keep_alive_timer
                        .saturating_duration_since(std::time::Instant::now()),
                ))?;
                match self.rsock.clone().lock().unwrap().read(&mut r.rx_buf) {
                    Ok(n) if n > 0 => {
                        // println!("got n {}...", n);
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
        self.wsock.clone().lock().unwrap().write_all(&buf)?;
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
        self.wsock.clone().lock().unwrap().write_all(&buf)?;
        Ok(())
    }

    /// Subscribes to meters from the Wing mixer and returns a meter ID that can be used to
    /// associate the values that come back when you call read_meter()
    pub fn request_meter(&mut self, meters: &[Meter]) -> Result<u16> {
        let mtrsptr = self.mtrs.clone();
        let mut mtrs = mtrsptr.lock().unwrap();
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
            match meter {
                Meter::Channel(n) => {
                    buf.push(0xa0);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Aux(n) => {
                    buf.push(0xa1);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Bus(n) => {
                    buf.push(0xa2);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Main(n) => {
                    buf.push(0xa3);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Matrix(n) => {
                    buf.push(0xa4);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Dca(n) => {
                    buf.push(0xa5);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Fx(n) => {
                    buf.push(0xa6);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Source(n) => {
                    buf.push(0xa7);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Output(n) => {
                    buf.push(0xa8);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Monitor => {
                    buf.push(0xa9);
                }
                Meter::Rta => {
                    buf.push(0xaa);
                }
                Meter::Channel2(n) => {
                    buf.push(0xab);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Aux2(n) => {
                    buf.push(0xac);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Bus2(n) => {
                    buf.push(0xad);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Main2(n) => {
                    buf.push(0xae);
                    Self::push_escaped(&mut buf, *n);
                }
                Meter::Matrix2(n) => {
                    buf.push(0xaf);
                    Self::push_escaped(&mut buf, *n);
                }
            }
        }

        buf.push(0xde); // end of def
        buf.push(0xdf);
        buf.push(0xd1);

        self.wsock.clone().lock().unwrap().write_all(&buf)?;

        Ok(mtrs.next_meter_id)
    }

    /// reads any meter values that have been requested with request_meter() and returns the meter
    /// ID along with the meters values
    pub fn read_meters(&mut self) -> Result<(u16, Vec<i16>)> {
        loop {
            let mptr = self.mtrs.clone();
            let mut m = mptr.lock().unwrap();

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
        self.wsock.clone().lock().unwrap().write_all(&buf)?;
        Ok(())
    }

    pub fn set_float(&mut self, id: i32, value: f32) -> Result<()> {
        let buf = Self::set_float_message(id, value);
        self.wsock.clone().lock().unwrap().write_all(&buf)?;
        Ok(())
    }

    pub fn set_int(&mut self, id: i32, value: i32) -> Result<()> {
        let buf = Self::set_int_message(id, value);
        self.wsock.clone().lock().unwrap().write_all(&buf)?;
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
        let console = Self::from_streams(client.try_clone().unwrap(), client, peer_ip);

        {
            let mut meters = console.mtrs.lock().unwrap();
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

    fn console_with_input(input: &[u8]) -> WingConsole {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, peer_addr) = listener.accept().unwrap();
        server.write_all(input).unwrap();
        WingConsole::from_streams(client.try_clone().unwrap(), client, peer_addr.ip())
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
}

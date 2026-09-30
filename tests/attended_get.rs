//! Offline coverage for the attended-get helpers (U4, R16/R17): request + correlate +
//! await a node value or definition with a timeout, buffering unrelated unsolicited
//! responses instead of dropping them.
//!
//! Exercised entirely over `WingConsole::from_transports` with scripted transports --
//! no real socket or console involved.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use libwing::{Error, LiveSchema, Resolution, Transport, WingConsole, WingResponse};

/// Feeds pre-scripted wire bytes to the console's reader. An empty script reports
/// `TimedOut` (matching what a real timed-out socket read looks like to `decode_next`)
/// rather than `WouldBlock`, since `decode_next` retries `WouldBlock`/`TimedOut`
/// identically -- what matters for these tests is that the read *returns* instead of
/// blocking, so the deadline check between attempts actually runs.
struct ScriptReader {
    bytes: VecDeque<u8>,
    chunk_size: usize,
}

impl ScriptReader {
    fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            bytes: bytes.into(),
            chunk_size,
        }
    }
}

impl Read for ScriptReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no more script data",
            ));
        }
        let n = buf.len().min(self.chunk_size).min(self.bytes.len()).max(1);
        for slot in buf.iter_mut().take(n) {
            *slot = self.bytes.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for ScriptReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for ScriptReader {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

/// Write-capturing transport used for the writer half; nothing in these tests reads
/// from it, but `WingConsole` needs a `Transport` for both directions.
#[derive(Clone, Default)]
struct RecordingWriter {
    written: Arc<Mutex<Vec<u8>>>,
}

impl Read for RecordingWriter {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "writer is not readable",
        ))
    }
}

impl Write for RecordingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for RecordingWriter {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

fn console_with_script(bytes: Vec<u8>, chunk_size: usize) -> WingConsole {
    let reader = ScriptReader::new(bytes, chunk_size);
    let writer = RecordingWriter::default();
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    WingConsole::from_transports(reader, writer, peer_ip)
}

struct AppendableReader {
    bytes: Arc<Mutex<VecDeque<u8>>>,
}

impl Read for AppendableReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes = self.bytes.lock().unwrap();
        if bytes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no response available",
            ));
        }
        let n = buf.len().min(bytes.len());
        for slot in buf.iter_mut().take(n) {
            *slot = bytes.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for AppendableReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for AppendableReader {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CoordinatedState {
    requests: Vec<i32>,
    responses: VecDeque<u8>,
    request_order_decided: bool,
    serialized_requests: bool,
}

struct CoordinatedReader {
    state: Arc<(Mutex<CoordinatedState>, Condvar)>,
    first_read_started: mpsc::Sender<()>,
}

impl Read for CoordinatedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.first_read_started.send(());
        let (state, requests_changed) = &*self.state;
        let mut state = state.lock().unwrap();
        if !state.request_order_decided {
            let (next, _) = requests_changed
                .wait_timeout_while(state, Duration::from_millis(100), |state| {
                    state.requests.len() < 2
                })
                .unwrap();
            state = next;
            state.request_order_decided = true;
            state.serialized_requests = state.requests.len() == 1;
            if state.serialized_requests {
                state.responses.extend(node_data_i32(50, 500));
            } else {
                state.responses.extend(node_data_i32(51, 510));
                state.responses.extend(node_data_i32(50, 500));
            }
        }
        if state.responses.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no more coordinated responses",
            ));
        }
        let n = buf.len().min(state.responses.len());
        for slot in buf.iter_mut().take(n) {
            *slot = state.responses.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for CoordinatedReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for CoordinatedReader {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

struct CoordinatedWriter {
    state: Arc<(Mutex<CoordinatedState>, Condvar)>,
}

impl Read for CoordinatedWriter {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unreachable!("writer transport is never read")
    }
}

impl Write for CoordinatedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let id = i32::from_be_bytes(buf[1..5].try_into().unwrap());
        let (state, requests_changed) = &*self.state;
        let mut state = state.lock().unwrap();
        state.requests.push(id);
        if state.request_order_decided && state.serialized_requests && id == 51 {
            state.responses.extend(node_data_i32(51, 510));
        }
        requests_changed.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for CoordinatedWriter {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `NodeData` response frame carrying an i32: select-node (0xd7) + id, then the i32
/// opcode (0xd4) + value. Mirrors the wire encoding `console.rs`'s own unit tests use;
/// ids/values below are all chosen clear of 0xdf so no escaping is needed.
fn node_data_i32(id: i32, value: i32) -> Vec<u8> {
    let mut buf = vec![0xd7];
    buf.extend_from_slice(&id.to_be_bytes());
    buf.push(0xd4);
    buf.extend_from_slice(&value.to_be_bytes());
    buf
}

/// A minimal plain (`NodeType::Node`) `NodeDef` frame for `id`, using the extended-def
/// wire form (`0xdf 0xdf` marker + u16 length sentinel + u32 length + body), same shape
/// as `console.rs`'s `extended_node_definition_uses_u32_length` test.
fn node_def(id: i32, parent_id: i32) -> Vec<u8> {
    node_def_named(id, parent_id, "n")
}

fn node_def_named(id: i32, parent_id: i32, name: &str) -> Vec<u8> {
    let mut def = Vec::new();
    def.extend_from_slice(&parent_id.to_be_bytes());
    def.extend_from_slice(&id.to_be_bytes());
    def.extend_from_slice(&3_u16.to_be_bytes()); // index
    def.push(name.len() as u8);
    def.extend_from_slice(name.as_bytes());
    def.push(name.len() as u8);
    def.extend(name.bytes().map(|byte| byte.to_ascii_uppercase()));
    def.extend_from_slice(&0_u16.to_be_bytes()); // flags: Node type, no unit, r/w

    let mut frame = vec![0xdf, 0xdf, 0, 0];
    frame.extend_from_slice(&(def.len() as u32).to_be_bytes());
    frame.extend_from_slice(&def);
    frame
}

fn request_end() -> Vec<u8> {
    vec![0xde]
}

#[test]
fn happy_path_returns_matching_value_with_no_buffered_responses() {
    let mut console = console_with_script(node_data_i32(50, 1234), 4096);
    let (data, buffered) = console
        .get_node_data(50, Duration::from_millis(500))
        .expect("target id should resolve");
    assert_eq!(data.get_int(), 1234);
    assert!(buffered.is_empty());
}

#[test]
fn unrelated_responses_are_buffered_in_arrival_order_not_dropped() {
    let mut script = Vec::new();
    script.extend(node_data_i32(51, 99)); // unrelated NodeData
    script.extend(node_def(52, 1)); // unrelated NodeDef
    script.extend(node_data_i32(50, 1234)); // target

    let mut console = console_with_script(script, 4096);
    let (data, buffered) = console
        .get_node_data(50, Duration::from_millis(500))
        .expect("target id should resolve despite interleaved traffic");

    assert_eq!(data.get_int(), 1234);
    assert_eq!(buffered.len(), 2);
    match &buffered[0] {
        WingResponse::NodeData(id, data) => {
            assert_eq!(*id, 51);
            assert_eq!(data.get_int(), 99);
        }
        other => panic!(
            "expected buffered NodeData(51, _), got {}",
            variant_name(other)
        ),
    }
    match &buffered[1] {
        WingResponse::NodeDef(def) => assert_eq!(def.id, 52),
        other => panic!("expected buffered NodeDef(52), got {}", variant_name(other)),
    }
}

#[test]
fn no_matching_response_times_out_instead_of_hanging() {
    // Only unrelated traffic, followed by a RequestEnd -- per the documented semantics,
    // a RequestEnd with no matching NodeData can't be trusted as "not found" (no
    // correlation id on the wire), so this must run out the clock rather than resolve
    // early.
    let mut script = Vec::new();
    script.extend(node_data_i32(51, 99));
    script.extend(request_end());

    let timeout = Duration::from_millis(150);
    let mut console = console_with_script(script, 4096);

    let start = Instant::now();
    let result = console.get_node_data(50, timeout);
    let elapsed = start.elapsed();

    match result {
        Err(Error::Timeout) => {}
        Err(other) => panic!("expected Err(Timeout), got Err({other:?})"),
        Ok(_) => panic!("expected Err(Timeout), got Ok(_)"),
    }
    assert!(
        elapsed >= timeout,
        "returned before the deadline: {elapsed:?} < {timeout:?}"
    );
    assert!(
        elapsed < timeout + Duration::from_millis(500),
        "took far longer than the deadline: {elapsed:?}"
    );
}

#[test]
fn split_response_across_reads_is_still_correlated() {
    // chunk_size = 1 forces every Read::read() call to return a single byte, so the
    // target frame arrives fragmented across many reads.
    let mut console = console_with_script(node_data_i32(50, 777), 1);
    let (data, buffered) = console
        .get_node_data(50, Duration::from_millis(500))
        .expect("byte-at-a-time reads should still decode correctly");
    assert_eq!(data.get_int(), 777);
    assert!(buffered.is_empty());
}

#[test]
fn get_node_definition_correlates_by_def_id() {
    let mut script = Vec::new();
    script.extend(node_def(52, 1)); // unrelated def
    script.extend(node_def(99, 1)); // target def

    let mut console = console_with_script(script, 4096);
    let (def, buffered) = console
        .get_node_definition(99, Duration::from_millis(500))
        .expect("target definition should resolve");

    assert_eq!(def.id, 99);
    assert_eq!(buffered.len(), 1);
    assert!(matches!(&buffered[0], WingResponse::NodeDef(d) if d.id == 52));
}

#[test]
#[cfg(feature = "propmap")]
fn by_name_variants_resolve_through_the_propmap() {
    let name = "/ch/1/fdr";
    let id = WingConsole::name_to_id(name).expect("propmap should know this path");

    let mut console = console_with_script(node_data_i32(id, 42), 4096);
    let (data, buffered) = console
        .get_node_data_by_name(name, Duration::from_millis(500))
        .expect("by-name get should resolve via name_to_id");
    assert_eq!(data.get_int(), 42);
    assert!(buffered.is_empty());

    let mut console = console_with_script(node_def(id, 1), 4096);
    let (def, buffered) = console
        .get_node_definition_by_name(name, Duration::from_millis(500))
        .expect("by-name definition get should resolve via name_to_id");
    assert_eq!(def.id, id);
    assert!(buffered.is_empty());
}

#[test]
fn by_name_variants_reject_unknown_names() {
    let mut console = console_with_script(Vec::new(), 4096);
    assert!(matches!(
        console.get_node_data_by_name("/not/a/real/path", Duration::from_millis(50)),
        Err(Error::InvalidInput)
    ));

    let mut console = console_with_script(Vec::new(), 4096);
    assert!(matches!(
        console.get_node_definition_by_name("/not/a/real/path", Duration::from_millis(50)),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn concurrent_attended_gets_do_not_consume_each_others_responses() {
    let state = Arc::new((
        Mutex::new(CoordinatedState {
            requests: Vec::new(),
            responses: VecDeque::new(),
            request_order_decided: false,
            serialized_requests: false,
        }),
        Condvar::new(),
    ));
    let (first_read_started_tx, first_read_started_rx) = mpsc::channel();
    let reader = CoordinatedReader {
        state: state.clone(),
        first_read_started: first_read_started_tx,
    };
    let writer = CoordinatedWriter {
        state: state.clone(),
    };
    let mut first = WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut second = first.clone();

    let first_get = thread::spawn(move || first.get_node_data(50, Duration::from_millis(500)));
    first_read_started_rx
        .recv_timeout(Duration::from_millis(500))
        .expect("first get should be waiting in the shared reader");
    let second_get = thread::spawn(move || second.get_node_data(51, Duration::from_millis(500)));

    let (first_data, _) = first_get.join().unwrap().expect("id 50 should resolve");
    let (second_data, _) = second_get.join().unwrap().expect("id 51 should resolve");
    assert_eq!(first_data.get_int(), 500);
    assert_eq!(second_data.get_int(), 510);
    assert_eq!(state.0.lock().unwrap().requests, vec![50, 51]);
}

#[test]
fn a_timed_out_get_hands_its_buffered_responses_to_the_next_read() {
    let mut script = node_data_i32(51, 99);
    script.extend(request_end());
    let mut console = console_with_script(script, 4096);

    assert!(matches!(
        console.get_node_data(50, Duration::from_millis(100)),
        Err(Error::Timeout)
    ));
    match console.read_timeout(Duration::from_millis(100)) {
        Ok(WingResponse::NodeData(51, data)) => assert_eq!(data.get_int(), 99),
        other => panic!(
            "expected the buffered NodeData(51), got {:?}",
            other.is_ok()
        ),
    }
    assert!(matches!(
        console.read_timeout(Duration::from_millis(100)),
        Ok(WingResponse::RequestEnd)
    ));
}

#[test]
fn a_flood_of_unrelated_responses_fails_the_get_instead_of_growing_memory() {
    // One node selector, then 70k one-byte values for it: each is an unrelated NodeData.
    let mut script = vec![0xd7];
    script.extend_from_slice(&51_i32.to_be_bytes());
    script.extend(std::iter::repeat_n(0x00, 70_000));
    let mut console = console_with_script(script, 4096);

    let start = Instant::now();
    assert!(matches!(
        console.get_node_data(50, Duration::from_secs(30)),
        Err(Error::InvalidData)
    ));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn refresh_subtree_times_out_on_a_silent_console_and_keeps_interleaved_data() {
    let mut console = console_with_script(node_data_i32(51, 99), 4096);
    let mut schema = LiveSchema::new();

    let start = Instant::now();
    assert!(matches!(
        schema.refresh_subtree(&mut console, 7, Duration::from_millis(150)),
        Err(Error::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    match console.read_timeout(Duration::from_millis(100)) {
        Ok(WingResponse::NodeData(51, data)) => assert_eq!(data.get_int(), 99),
        other => panic!(
            "expected the interleaved NodeData(51), got {:?}",
            other.is_ok()
        ),
    }
}

#[test]
fn refresh_ignores_an_uncorrelated_end_marker() {
    let mut script = request_end();
    script.extend(node_def(7, 0));
    script.extend(request_end());
    let mut console = console_with_script(script, 4096);
    let mut schema = LiveSchema::new();

    assert_eq!(
        schema
            .refresh_subtree(&mut console, 7, Duration::from_millis(500))
            .unwrap(),
        1
    );
    assert!(matches!(
        console.read_timeout(Duration::from_millis(100)),
        Ok(WingResponse::RequestEnd)
    ));
}

#[test]
fn refresh_excludes_a_stale_definition_batch_queued_by_a_timed_out_get() {
    let mut stale = node_def_named(7, 0, "old");
    stale.extend(request_end());
    let shared = Arc::new(Mutex::new(VecDeque::from(stale)));
    let reader = AppendableReader {
        bytes: shared.clone(),
    };
    let writer = RecordingWriter::default();
    let mut console = WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));

    assert!(matches!(
        console.get_node_data(999, Duration::from_millis(50)),
        Err(Error::Timeout)
    ));
    let mut fresh = node_def_named(7, 0, "fresh");
    fresh.extend(request_end());
    shared.lock().unwrap().extend(fresh);

    let mut schema = LiveSchema::new();
    assert_eq!(
        schema
            .refresh_subtree(&mut console, 7, Duration::from_millis(500))
            .unwrap(),
        1
    );
    match schema.resolve_id(7, None).unwrap() {
        Resolution::Confirmed { def, .. } => assert_eq!(def.name, "fresh"),
        Resolution::Unknown { .. } => panic!("fresh definition should resolve"),
        _ => panic!("unexpected resolution variant"),
    }
    match console.read_timeout(Duration::from_millis(100)) {
        Ok(WingResponse::NodeDef(def)) => assert_eq!(def.name, "old"),
        _ => panic!("stale queued definition was not restored"),
    }
    assert!(matches!(
        console.read_timeout(Duration::from_millis(100)),
        Ok(WingResponse::RequestEnd)
    ));
}

fn variant_name(resp: &WingResponse) -> &'static str {
    match resp {
        WingResponse::RequestEnd => "RequestEnd",
        WingResponse::NodeDef(_) => "NodeDef",
        WingResponse::NodeData(_, _) => "NodeData",
    }
}

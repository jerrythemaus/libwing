//! Hardware-free performance baseline for libwing's hot and bulk paths.
//!
//! Run with `cargo bench --bench perf` (release profile; the workspace dev profile is
//! `opt-level = 1` and would skew everything). Everything runs over in-memory transports
//! (`WingConsole::from_transports`) or loopback UDP, so no console is involved and the
//! numbers are only meaningful as before/after comparisons on the same machine.
//!
//! Allocation counting needs a `GlobalAlloc` wrapper, which is `unsafe` by language rule;
//! it is confined to this bench file and delegates straight to `System`.
//!
//! Filter scenarios with a substring: `cargo bench --bench perf -- bulk`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use libwing::native::{encode_responses, NativeResponse, NativeValue};
use libwing::osc::{self, OscArg, OscMessage, WingOscClient};
use libwing::{
    decode_frame, meter_word_count, DumpEntry, Meter, NodeDump, NodeValue, Transport, WingConsole,
    WingResponse,
};

// --- counting allocator ------------------------------------------------------------------

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size(), Relaxed);
        LIVE.fetch_add(l.size(), Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(new, Relaxed);
        LIVE.fetch_add(new, Relaxed);
        LIVE.fetch_sub(l.size(), Relaxed);
        System.realloc(p, l, new)
    }
}

#[global_allocator]
static A: Counting = Counting;

#[derive(Clone, Copy)]
struct Snap {
    t: Instant,
    allocs: usize,
    bytes: usize,
    live: usize,
}

fn snap() -> Snap {
    Snap {
        t: Instant::now(),
        allocs: ALLOCS.load(Relaxed),
        bytes: BYTES.load(Relaxed),
        live: LIVE.load(Relaxed),
    }
}

// --- scenario runner ----------------------------------------------------------------------

/// Runs `body(setup())` `runs` times; `setup` is excluded from the measurement. `body`
/// returns how many units of work it did plus any scenario-specific counters to print.
fn run<S>(
    name: &str,
    runs: usize,
    unit: &str,
    mut setup: impl FnMut() -> S,
    mut body: impl FnMut(S) -> (usize, String),
) {
    let mut samples = Vec::new();
    for _ in 0..runs {
        let s = setup();
        let a = snap();
        let (units, extra) = body(s);
        let b = snap();
        samples.push((
            b.t - a.t,
            b.allocs - a.allocs,
            b.bytes - a.bytes,
            units,
            extra,
        ));
    }
    samples.sort_by_key(|s| s.0);
    let (t, allocs, bytes, units, extra) = &samples[samples.len() / 2];
    let u = (*units).max(1) as f64;
    println!(
        "{name:<34} {:>9.3} ms  {:>9.1} ns/{unit:<6} {:>8.2} allocs/{unit:<6} {:>9.1} B/{unit:<6} {extra}",
        t.as_secs_f64() * 1e3,
        t.as_nanos() as f64 / u,
        *allocs as f64 / u,
        *bytes as f64 / u,
    );
}

fn wanted(filter: &Option<String>, name: &str) -> bool {
    filter.as_ref().is_none_or(|f| name.contains(f.as_str()))
}

// --- in-memory transports -----------------------------------------------------------------

#[derive(Default)]
struct Counters {
    reads: AtomicUsize,
    timeouts: AtomicUsize,
    writes: AtomicUsize,
    written: AtomicUsize,
}

struct SliceReader {
    data: Arc<Vec<u8>>,
    pos: usize,
    c: Arc<Counters>,
}

impl Read for SliceReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.data.len() - self.pos);
        if n == 0 {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.c.reads.fetch_add(1, Relaxed);
        Ok(n)
    }
}
impl Write for SliceReader {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Transport for SliceReader {
    fn set_read_timeout(&mut self, _: Option<Duration>) -> std::io::Result<()> {
        self.c.timeouts.fetch_add(1, Relaxed);
        Ok(())
    }
}

struct CountingWriter(Arc<Counters>);

impl Read for CountingWriter {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::TimedOut.into())
    }
}
impl Write for CountingWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.writes.fetch_add(1, Relaxed);
        self.0.written.fetch_add(b.len(), Relaxed);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Transport for CountingWriter {
    fn set_read_timeout(&mut self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

fn console(data: Vec<u8>) -> (WingConsole, Arc<Counters>) {
    let c = Arc::new(Counters::default());
    let reader = SliceReader {
        data: Arc::new(data),
        pos: 0,
        c: c.clone(),
    };
    let con = WingConsole::from_transports(
        reader,
        CountingWriter(c.clone()),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );
    (con, c)
}

fn io_counters(c: &Counters) -> String {
    format!(
        "reads={} set_timeout={} writes={}",
        c.reads.load(Relaxed),
        c.timeouts.load(Relaxed),
        c.writes.load(Relaxed)
    )
}

// --- scenarios ----------------------------------------------------------------------------

fn propmap_startup() {
    // Must be the first thing that touches the map: it is initialised once per process.
    let mb = |n: usize| n as f64 / 1e6;
    let a = snap();
    let n = WingConsole::propmap_len();
    let b = snap();
    let found = WingConsole::name_to_def("/ch/1/fdr").is_some();
    let c = snap();
    let ids = WingConsole::id_to_defs_iter(0x1234).map(|d| d.len());
    let d = snap();
    let parsed = WingConsole::propmap_iter().count();
    let e = snap();
    std::hint::black_box((found, ids));
    let line = |label: &str, from: Snap, to: Snap, extra: String| {
        println!(
            "propmap {label:<26} {:>9.3} ms  {:>7} allocs  {:>6.2} MB allocated  {:>6.2} MB retained  {extra}",
            (to.t - from.t).as_secs_f64() * 1e3,
            to.allocs - from.allocs,
            mb(to.bytes - from.bytes),
            mb(to.live.saturating_sub(from.live)),
        )
    };
    line("startup (open index)", a, b, format!("{n} defs"));
    line("first lookup (parse 1 def)", b, c, String::new());
    line("first by-id lookup", c, d, String::new());
    line("parse every def (iter)", d, e, format!("{parsed} defs"));

    let names: Vec<&str> = WingConsole::propmap_iter()
        .map(|(n, _)| n)
        .step_by(7)
        .collect();
    run(
        "propmap lookup (warm)",
        5,
        "lookup",
        || (),
        |()| {
            let reps = 20;
            for _ in 0..reps {
                for n in &names {
                    std::hint::black_box(WingConsole::name_to_def(n));
                }
            }
            (
                reps * names.len(),
                format!("{} distinct names", names.len()),
            )
        },
    );
}

fn meter_decode() {
    // The controller's request: 40 channels plus RTA.
    let mut request: Vec<Meter> = (1..=40).map(Meter::Channel).collect();
    request.push(Meter::Rta);
    let words: usize = request.iter().map(meter_word_count).sum();
    let raw: Vec<i16> = (0..words).map(|i| (i as i16).wrapping_mul(37)).collect();
    run(
        "meter decode_frame (40ch+RTA)",
        5,
        "frame",
        || (),
        |()| {
            let n = 100_000;
            for _ in 0..n {
                let f = decode_frame(&request, &raw).unwrap();
                std::hint::black_box(&f);
            }
            (n, format!("{words} words/frame"))
        },
    );
}

fn encode_defs() -> (Vec<NativeResponse>, usize) {
    let defs: Vec<NativeResponse> = WingConsole::propmap_iter()
        .take(20_000)
        .map(|(_, d)| NativeResponse::NodeDef(d.clone()))
        .collect();
    let n = defs.len();
    (defs, n)
}

fn emulator_encode() {
    let (defs, n) = encode_defs();
    run(
        "native encode_responses (defs)",
        5,
        "def",
        || (),
        |()| {
            let wire = encode_responses(&defs).unwrap();
            std::hint::black_box(&wire);
            (n, format!("{} KB wire", wire.len() / 1024))
        },
    );
}

fn bulk_read() {
    let (defs, n) = encode_defs();
    let wire = encode_responses(&defs).unwrap();
    run(
        "bulk read: node defs",
        5,
        "def",
        || console(wire.clone()),
        |(mut con, c)| {
            for _ in 0..n {
                match con.read().unwrap() {
                    WingResponse::NodeDef(d) => {
                        std::hint::black_box(&d);
                    }
                    _ => panic!("expected node def"),
                }
            }
            (n, format!("{} KB {}", wire.len() / 1024, io_counters(&c)))
        },
    );

    let m = 100_000usize;
    let data: Vec<NativeResponse> = (0..m)
        .map(|i| NativeResponse::NodeData {
            id: 0x1000 + (i as i32 % 5000),
            value: if i % 4 == 0 {
                NativeValue::String(format!("ch name {}", i % 40))
            } else {
                NativeValue::Float(i as f32 * 0.01)
            },
        })
        .collect();
    let wire = encode_responses(&data).unwrap();
    run(
        "bulk read: node values",
        5,
        "value",
        || console(wire.clone()),
        |(mut con, c)| {
            for _ in 0..m {
                std::hint::black_box(con.read().unwrap());
            }
            (m, format!("{} KB {}", wire.len() / 1024, io_counters(&c)))
        },
    );
}

fn bulk_write() {
    // Real float leaves from the map, so ids/paths are production-shaped.
    let leaves: Vec<(&str, i32)> = WingConsole::propmap_iter()
        .filter(|(n, _)| !n.contains("$"))
        .filter_map(|(n, d)| {
            WingConsole::name_to_id(n)
                .map(|id| (n, id))
                .filter(|_| d.max_float.is_some())
        })
        .take(5_000)
        .collect();
    let n = leaves.len();

    let values: Vec<(i32, NodeValue)> = leaves
        .iter()
        .map(|&(_, id)| (id, NodeValue::Float(0.5)))
        .collect();
    run(
        "bulk write: set_nodes (float)",
        5,
        "node",
        || console(Vec::new()),
        |(mut con, c)| {
            let r = con.set_nodes(&values);
            assert!(r.iter().all(|(_, r)| r.is_ok()));
            (n, io_counters(&c))
        },
    );

    let dump = NodeDump {
        entries: leaves
            .iter()
            .map(|&(name, id)| DumpEntry {
                fullname: name.to_owned(),
                id,
                value: NodeValue::Float(0.5),
            })
            .collect(),
        unknown_models: Vec::new(),
    };
    run(
        "bulk write: restore (float)",
        5,
        "node",
        || console(Vec::new()),
        |(mut con, c)| {
            let r = con.restore(&dump);
            std::hint::black_box(&r);
            (n, io_counters(&c))
        },
    );
}

fn osc_codec() {
    let msg = OscMessage::new("/ch/1/fdr", vec![OscArg::Float(-3.5)]);
    run(
        "osc encode (/ch/1/fdr ,f)",
        5,
        "msg",
        || (),
        |()| {
            let n = 200_000;
            for _ in 0..n {
                std::hint::black_box(osc::encode(&msg).unwrap());
            }
            (n, String::new())
        },
    );
    let wire = osc::encode(&OscMessage::new(
        "/ch/1/name",
        vec![
            OscArg::Str("Kick In".into()),
            OscArg::Float(1.0),
            OscArg::Int(3),
        ],
    ))
    .unwrap();
    run(
        "osc decode (,sfi)",
        5,
        "msg",
        || (),
        |()| {
            let n = 200_000;
            for _ in 0..n {
                std::hint::black_box(osc::decode(&wire).unwrap());
            }
            (n, String::new())
        },
    );
}

fn osc_request_latency() {
    let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = responder.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = responder.recv_from(&mut buf) {
            if let Ok(req) = osc::decode(&buf[..n]) {
                let reply = OscMessage::new(req.addr, vec![OscArg::Float(0.5)]);
                let _ = responder.send_to(&osc::encode(&reply).unwrap(), from);
            }
        }
    });
    let client = WingOscClient::connect_addr(target).unwrap();
    let req = osc::get_param("/ch/1/fdr").unwrap();
    // Warm up: first request pays socket/thread start.
    client.request(&req, Duration::from_secs(1)).unwrap();
    run(
        "osc request round trip (loopback)",
        5,
        "req",
        || (),
        |()| {
            let n = 200;
            for _ in 0..n {
                client.request(&req, Duration::from_secs(1)).unwrap();
            }
            // Allocation counts include the responder thread; read the time column.
            (n, "(allocs include responder thread)".into())
        },
    );
}

fn main() {
    let filter = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with('-') && a != "bench");
    println!("libwing perf baseline (release). filter={filter:?}\n");
    // Order matters: propmap_startup must run before anything touches the map.
    if wanted(&filter, "propmap") {
        propmap_startup();
    }
    if wanted(&filter, "meter") {
        meter_decode();
    }
    if wanted(&filter, "encode") {
        emulator_encode();
    }
    if wanted(&filter, "bulk") {
        bulk_read();
        bulk_write();
    }
    if wanted(&filter, "osc") {
        osc_codec();
        osc_request_latency();
    }
}

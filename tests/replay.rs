//! Record-replay fixture harness (U14: R71, R72, R73, R78, R81).
//!
//! No WING Rack is reachable from here, so every fixture under `tests/fixtures/` is
//! `# source: synthetic` -- hand-built from the same spec-derived wire encodings the
//! rest of the offline suite uses (see `tests/attended_get.rs`, `tests/osc_encode.rs`).
//! This proves the record-replay *machinery* end-to-end (fixture format, loader,
//! decode/encode assertions, the redaction guard) so it's ready to accept real
//! sanitized hardware captures the moment one exists -- see
//! `tests/fixtures/README.md` for that workflow.
//!
//! Format reference: `tests/fixtures/README.md`. Loader: `tests/fixtures_common/mod.rs`
//! (included below via `#[path]` -- test binaries are separate crates, so this is the
//! plain way to share a small parser between the tests in this one file without
//! promoting it to a public `src/` module). Redaction rules: `tools/redact.rs`
//! (likewise `#[path]`-included, shared with `tools/wingcapture.rs`).

#[path = "fixtures_common/mod.rs"]
mod fixtures_common;
#[path = "../tools/redact.rs"]
mod redact;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libwing::native::{ChannelDecoder, NativeRequest, NativeRequestDecoder};
use libwing::{decode_frame, osc, Meter, MeterFrameEntry, Transport, WingConsole, WingResponse};

use fixtures_common::{Fixture, Line};

#[test]
fn legacy_v1_fixtures_remain_implicit_and_unchanged() {
    for name in [
        "discovery.wingcap",
        "meters_channel_rta.wingcap",
        "native_connect_get_set.wingcap",
        "osc_subscription.wingcap",
    ] {
        let fx = load_fixture(name);
        assert_eq!(fx.header("wingcap_version"), None, "{name}");
        assert!(fx.events.is_empty(), "{name}");
    }
}

#[test]
fn complete_v2_session_preserves_order_directions_and_raw_meter_header() {
    let fx = load_fixture("complete_session_v2.wingcap");
    assert_eq!(fx.header("wingcap_version"), Some("2"));
    for key in [
        "scenario",
        "source",
        "console_model",
        "firmware",
        "capture_date",
        "sanitizer",
        "manual_redaction_attested",
        "expected_behavior",
    ] {
        assert!(fx.header(key).is_some(), "missing {key}");
    }
    assert_eq!(fx.events.len(), 16);
    for (index, event) in fx.events.iter().enumerate() {
        assert_eq!(event.ordinal, index as u64 + 1);
        if index > 0 {
            assert!(event.offset_us >= fx.events[index - 1].offset_us);
        }
    }
    assert!(fx
        .events
        .iter()
        .any(|event| matches!(event.line, Line::DiscoveryOut(_))));
    assert!(fx
        .events
        .iter()
        .any(|event| matches!(event.line, Line::DiscoveryIn(_))));
    assert!(fx
        .events
        .iter()
        .any(|event| matches!(event.line, Line::NativeOut(_))));
    assert!(fx
        .events
        .iter()
        .any(|event| matches!(event.line, Line::NativeIn(_))));
    assert!(fx
        .events
        .iter()
        .any(|event| matches!(event.line, Line::MeterOut(_))));
    let meter = fx
        .events
        .iter()
        .find_map(|event| match &event.line {
            Line::MeterRawIn(bytes) => Some(bytes),
            _ => None,
        })
        .expect("raw meter datagram");
    assert_eq!(&meter[..4], &[0, 1, 0, 0]);

    let discovery = fx.events.iter().find_map(|event| match &event.line {
        Line::DiscoveryIn(bytes) => Some(bytes),
        _ => None,
    });
    let discovery =
        std::str::from_utf8(discovery.expect("discovery reply")).expect("UTF-8 discovery reply");
    let fields = discovery.split(',').collect::<Vec<_>>();
    assert_eq!(fields.first(), Some(&"WING"));
    assert_eq!(fields.get(3), Some(&"RACK"));
    assert_eq!(fields.get(5), Some(&"3.1"));

    let mut requests = NativeRequestDecoder::default();
    let mut decoded = Vec::new();
    for event in &fx.events {
        if let Line::NativeOut(bytes) | Line::MeterOut(bytes) = &event.line {
            decoded.extend(requests.push(bytes).expect("semantic Native request"));
        }
    }
    requests.finish().expect("complete Native request stream");
    assert!(decoded
        .iter()
        .any(|request| matches!(request, NativeRequest::Get { id: 1234 })));
    assert!(decoded
        .iter()
        .any(|request| matches!(request, NativeRequest::Definition { id: 1234 })));
    assert!(decoded
        .iter()
        .any(|request| matches!(request, NativeRequest::Set { id: 1234, .. })));
    assert!(decoded.iter().any(|request| matches!(
        request,
        NativeRequest::MeterSubscribe {
            report_id: 0x0001_1234,
            ..
        }
    )));
    assert!(decoded.iter().any(|request| matches!(
        request,
        NativeRequest::MeterRenew {
            report_id: 0x0001_1234
        }
    )));

    let mut responses = ChannelDecoder::default();
    for event in &fx.events {
        if let Line::NativeIn(bytes) = &event.line {
            responses.push(bytes).expect("framed Native response");
        }
    }
    responses.finish().expect("complete Native response stream");

    assert_eq!(&meter[..4], &[0x00, 0x01, 0x00, 0x00]);
    let words = meter[4..]
        .chunks_exact(2)
        .map(|bytes| i16::from_be_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    assert_eq!(words.len() * 2, meter.len() - 4, "odd meter payload");
    let entries = decode_frame(&[Meter::Channel(1)], &words).expect("semantic meter frame");
    assert!(matches!(entries.as_slice(), [MeterFrameEntry::Channel(_)]));
}

// ---------------------------------------------------------------------------
// Scripted transports (same shapes as tests/attended_get.rs; duplicated rather than
// shared -- each `tests/*.rs` file is its own crate, and this is the smaller amount
// of code compared to any sharing mechanism for something this size).
// ---------------------------------------------------------------------------

struct ScriptReader {
    bytes: VecDeque<u8>,
}

impl ScriptReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
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
        let n = buf.len().min(self.bytes.len()).max(1);
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

fn console_with_script(bytes: Vec<u8>) -> (WingConsole, Arc<Mutex<Vec<u8>>>) {
    let reader = ScriptReader::new(bytes);
    let writer = RecordingWriter::default();
    let written = writer.written.clone();
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    (
        WingConsole::from_transports(reader, writer, peer_ip),
        written,
    )
}

fn parse_fields(s: &str) -> HashMap<String, String> {
    s.split_whitespace()
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn describe(resp: &WingResponse) -> &'static str {
    match resp {
        WingResponse::RequestEnd => "RequestEnd",
        WingResponse::NodeDef(_) => "NodeDef",
        WingResponse::NodeData(_, _) => "NodeData",
    }
}

// ---------------------------------------------------------------------------
// Native scenario (R73)
// ---------------------------------------------------------------------------

#[test]
fn replay_native_connect_get_set() {
    let fx = load_fixture("native_connect_get_set.wingcap");
    assert_eq!(fx.header("source"), Some("synthetic"));

    let (mut console, written) = console_with_script(fx.native_in());

    for request in fx.headers_all("request") {
        run_native_request(&mut console, request);
    }

    let expected_writes: Vec<u8> = fx.native_out().into_iter().flatten().collect();
    assert_eq!(
        *written.lock().unwrap(),
        expected_writes,
        "{:?}: client->console bytes did not match the fixture's N> lines",
        fx.path
    );

    for expect in fx.expects() {
        let resp = console
            .read()
            .unwrap_or_else(|e| panic!("{:?}: expected a decoded response, got {e:?}", fx.path));
        assert_native_expect(&fx, expect, &resp);
    }
}

fn run_native_request(console: &mut WingConsole, request: &str) {
    let fields = parse_fields(request);
    let call = request
        .split_whitespace()
        .next()
        .expect("empty `request:` annotation");
    let id: i32 = fields
        .get("id")
        .expect("`request:` annotation missing id=")
        .parse()
        .expect("id= must be an i32");
    match call {
        "get_node_data" => console.request_node_data(id).unwrap(),
        "get_node_definition" => console.request_node_definition(id).unwrap(),
        "set_int" => {
            let value: i32 = fields["value"].parse().unwrap();
            console.set_int(id, value).unwrap()
        }
        "set_float" => {
            let value: f32 = fields["value"].parse().unwrap();
            console.set_float(id, value).unwrap()
        }
        "set_string" => console.set_string(id, &fields["value"]).unwrap(),
        other => panic!("unrecognized `request:` kind {other:?}"),
    }
}

fn assert_native_expect(fx: &Fixture, expect: &str, resp: &WingResponse) {
    let (kind, rest) = expect.split_once(' ').unwrap_or((expect, ""));
    let fields = parse_fields(rest);
    match (kind, resp) {
        ("RequestEnd", WingResponse::RequestEnd) => {}
        ("NodeData", WingResponse::NodeData(id, data)) => {
            if let Some(v) = fields.get("id") {
                assert_eq!(*id, v.parse::<i32>().unwrap(), "{:?}: id mismatch", fx.path);
            }
            if let Some(v) = fields.get("int") {
                assert_eq!(data.get_int(), v.parse::<i32>().unwrap());
            }
            if let Some(v) = fields.get("float") {
                assert_eq!(data.get_float(), v.parse::<f32>().unwrap());
            }
            if let Some(v) = fields.get("string") {
                assert_eq!(&data.get_string(), v);
            }
        }
        ("NodeDef", WingResponse::NodeDef(def)) => {
            if let Some(v) = fields.get("id") {
                assert_eq!(def.id, v.parse::<i32>().unwrap());
            }
            if let Some(v) = fields.get("name") {
                assert_eq!(&def.name, v);
            }
        }
        (kind, resp) => panic!(
            "{:?}: expect {kind:?} does not match decoded {}",
            fx.path,
            describe(resp)
        ),
    }
}

// ---------------------------------------------------------------------------
// Meter scenario (R73, feeds U8/U9)
// ---------------------------------------------------------------------------

#[test]
fn replay_meters_channel_rta() {
    let fx = load_fixture("meters_channel_rta.wingcap");
    let request = parse_meter_request(fx.header("meters").expect("`meters:` header required"));

    let raw_bytes: Vec<u8> = fx
        .lines
        .iter()
        .filter_map(|l| match l {
            Line::MeterIn(b) => Some(b.clone()),
            _ => None,
        })
        .next()
        .expect("meter scenario needs one `M<` line");
    let words: Vec<i16> = raw_bytes
        .chunks_exact(2)
        .map(|c| i16::from_be_bytes([c[0], c[1]]))
        .collect();

    let entries = decode_frame(&request, &words)
        .unwrap_or_else(|e| panic!("{:?}: decode_frame failed: {e}", fx.path));
    let expects = fx.expects();
    assert_eq!(entries.len(), expects.len());
    for (entry, expect) in entries.iter().zip(expects) {
        assert_meter_expect(&fx, expect, entry);
    }
}

fn parse_meter_request(spec: &str) -> Vec<Meter> {
    spec.split(',')
        .map(|tok| {
            let tok = tok.trim();
            let (name, idx) = match tok.split_once(':') {
                Some((n, i)) => (n, Some(i.parse::<u8>().expect("meter index must be a u8"))),
                None => (tok, None),
            };
            match name {
                "channel" => Meter::Channel(idx.unwrap()),
                "aux" => Meter::Aux(idx.unwrap()),
                "bus" => Meter::Bus(idx.unwrap()),
                "main" => Meter::Main(idx.unwrap()),
                "matrix" => Meter::Matrix(idx.unwrap()),
                "dca" => Meter::Dca(idx.unwrap()),
                "fx" => Meter::Fx(idx.unwrap()),
                "source" => Meter::Source(idx.unwrap()),
                "output" => Meter::Output(idx.unwrap()),
                "monitor" => Meter::Monitor,
                "rta" => Meter::Rta,
                "channel2" => Meter::Channel2(idx.unwrap()),
                "aux2" => Meter::Aux2(idx.unwrap()),
                "bus2" => Meter::Bus2(idx.unwrap()),
                "main2" => Meter::Main2(idx.unwrap()),
                "matrix2" => Meter::Matrix2(idx.unwrap()),
                other => panic!("unrecognized meter kind {other:?}"),
            }
        })
        .collect()
}

fn assert_meter_expect(fx: &Fixture, expect: &str, entry: &MeterFrameEntry) {
    let (kind, rest) = expect.split_once(' ').unwrap_or((expect, ""));
    let fields = parse_fields(rest);
    let channel_like = |m: &libwing::ChannelMeter| {
        let get = |k: &str| fields[k].parse::<i16>().unwrap();
        assert_eq!(m.input_l, get("input_l"));
        assert_eq!(m.input_r, get("input_r"));
        assert_eq!(m.output_l, get("output_l"));
        assert_eq!(m.output_r, get("output_r"));
        assert_eq!(m.gate_key, get("gate_key"));
        assert_eq!(m.gate_gain, get("gate_gain"));
        assert_eq!(m.dyn_key, get("dyn_key"));
        assert_eq!(m.dyn_gain, get("dyn_gain"));
    };
    match (kind, entry) {
        ("Channel", MeterFrameEntry::Channel(m))
        | ("Aux", MeterFrameEntry::Aux(m))
        | ("Bus", MeterFrameEntry::Bus(m))
        | ("Main", MeterFrameEntry::Main(m))
        | ("Matrix", MeterFrameEntry::Matrix(m)) => channel_like(m),
        ("Rta", MeterFrameEntry::Rta(words)) => {
            let len: usize = fields["len"].parse().unwrap();
            assert_eq!(words.len(), len);
            if let Some(v) = fields.get("first") {
                assert_eq!(words[0], v.parse::<i16>().unwrap());
            }
            if let Some(v) = fields.get("last") {
                assert_eq!(*words.last().unwrap(), v.parse::<i16>().unwrap());
            }
        }
        (kind, entry) => panic!(
            "{:?}: expect {kind:?} does not match decoded entry {entry:?}",
            fx.path
        ),
    }
}

// ---------------------------------------------------------------------------
// OSC scenario (R73, feeds U11)
// ---------------------------------------------------------------------------

#[test]
fn replay_osc_subscription() {
    let fx = load_fixture("osc_subscription.wingcap");

    let osc_in: Vec<Vec<u8>> = fx
        .lines
        .iter()
        .filter_map(|l| match l {
            Line::OscIn(b) => Some(b.clone()),
            _ => None,
        })
        .collect();
    let expects = fx.expects();
    assert_eq!(
        osc_in.len(),
        expects.len(),
        "expected one `# expect: Osc ...` per `O<` line"
    );
    for (bytes, expect) in osc_in.iter().zip(&expects) {
        let msg = osc::decode(bytes)
            .unwrap_or_else(|e| panic!("{:?}: O< payload failed to decode: {e}", fx.path));
        let fields = parse_fields(
            expect
                .strip_prefix("Osc ")
                .expect("expect must be `Osc ...`"),
        );
        if let Some(addr) = fields.get("addr") {
            assert_eq!(&msg.addr, addr);
        }
        if let Some(n) = fields.get("args") {
            assert_eq!(msg.args.len(), n.parse::<usize>().unwrap());
        }
    }

    for bytes in fx.lines.iter().filter_map(|l| match l {
        Line::OscOut(b) => Some(b),
        _ => None,
    }) {
        let msg = osc::decode(bytes)
            .unwrap_or_else(|e| panic!("{:?}: O> payload failed to decode: {e}", fx.path));
        let re_encoded = osc::encode(&msg)
            .unwrap_or_else(|e| panic!("{:?}: O> payload failed to re-encode: {e}", fx.path));
        assert_eq!(
            &re_encoded, bytes,
            "{:?}: O> line did not round-trip decode->encode byte-exact",
            fx.path
        );
    }
}

// ---------------------------------------------------------------------------
// Discovery scenario -- demonstrates the redaction conventions (R81)
// ---------------------------------------------------------------------------

#[test]
fn replay_discovery() {
    let fx = load_fixture("discovery.wingcap");
    let payload_bytes = fx
        .lines
        .iter()
        .find_map(|l| match l {
            Line::DiscoveryIn(b) => Some(b.clone()),
            _ => None,
        })
        .expect("discovery scenario needs one `D<` line");
    let payload = String::from_utf8(payload_bytes)
        .expect("discovery reply payload should be a plain ASCII string");

    // The broadcast discovery reply and the OSC `/?` console-info reply share the
    // exact "WING,ip,name,model,serial,firmware" body (see `osc::parse_console_info`'s
    // docs) -- reuse that parser instead of re-implementing the same tokenizer here.
    let msg = osc::OscMessage::new("/?", vec![osc::OscArg::Str(payload)]);
    let info = osc::parse_console_info(&msg)
        .unwrap_or_else(|e| panic!("{:?}: discovery payload failed to parse: {e}", fx.path));

    let expect = fx
        .expects()
        .into_iter()
        .next()
        .expect("discovery fixture needs one `# expect: Discovery ...` line");
    let fields = parse_fields(
        expect
            .strip_prefix("Discovery ")
            .expect("expect must be `Discovery ...`"),
    );
    if let Some(v) = fields.get("ip") {
        assert_eq!(&info.ip, v);
    }
    if let Some(v) = fields.get("name") {
        assert_eq!(&info.name, v);
    }
    if let Some(v) = fields.get("model") {
        assert_eq!(&info.model, v);
    }
    if let Some(v) = fields.get("serial") {
        assert_eq!(&info.serial, v);
    }
    if let Some(v) = fields.get("firmware") {
        assert_eq!(&info.firmware, v);
    }
}

// ---------------------------------------------------------------------------
// Redaction check-in guard (R81)
// ---------------------------------------------------------------------------

/// Every fixture checked into `tests/fixtures/` must pass the same scan
/// `tools/wingcapture.rs` runs before it will emit a sanitized file -- this test is
/// the enforcement point a CI run actually exercises. Scans both the header/comment
/// text and the decoded payload bytes of every data line (REDACTION.md rule 3):
/// serials/IPs can travel inside wire strings -- e.g. a discovery reply or a
/// node-set string value -- not just in a fixture's own metadata.
#[test]
fn every_checked_in_fixture_passes_redaction() {
    for path in fixtures_common::all_fixture_paths() {
        let fx = fixtures_common::load(&path);

        for raw_line in &fx.raw_lines {
            if raw_line.starts_with('#') {
                let findings = redact::scan_str(raw_line);
                assert!(
                    findings.is_empty(),
                    "{path:?}: un-redacted content in header/comment {raw_line:?}: {findings:?}"
                );
            }
        }

        for line in &fx.lines {
            let bytes = match line {
                Line::NativeOut(b)
                | Line::NativeIn(b)
                | Line::MeterIn(b)
                | Line::MeterRawIn(b)
                | Line::MeterOut(b)
                | Line::OscIn(b)
                | Line::OscOut(b)
                | Line::DiscoveryIn(b)
                | Line::DiscoveryOut(b) => Some(b),
                Line::Expect(_) => None,
            };
            if let Some(bytes) = bytes {
                let findings = redact::scan(bytes);
                assert!(
                    findings.is_empty(),
                    "{path:?}: un-redacted content in payload bytes: {findings:?}"
                );
            }
        }
    }
}

/// Negative test for the guard itself (R81): an in-memory, deliberately unsanitized
/// sample must be flagged. Never check in the fixture file this models -- the whole
/// point of this test is that the guard above would reject it.
#[test]
fn redaction_scanner_flags_an_unsanitized_in_memory_sample() {
    let unsanitized = "WING,10.20.30.40,MixerRoomA,RACK,NGC1234567,1.9.9 mac=aa:bb:cc:dd:ee:ff";
    let findings = redact::scan_str(unsanitized);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, redact::Finding::Serial(_))),
        "{findings:?}"
    );
    assert!(
        findings.iter().any(|f| matches!(f, redact::Finding::Ip(_))),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, redact::Finding::Mac(_))),
        "{findings:?}"
    );
}

fn load_fixture(name: &str) -> Fixture {
    fixtures_common::load(&fixtures_common::fixtures_dir().join(name))
}

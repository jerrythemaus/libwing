//! Raw binary-node capture/replay + toggle (`wGetBinaryNode`/`wSetBinaryNode`/
//! `wToggleTokenInt`).
//!
//! Exercised over `WingConsole::from_transports` with scripted transports, the same
//! pattern `tests/bulk_dump.rs` and `tests/attended_get.rs` use -- no real socket or
//! console involved. The harness is duplicated here rather than shared, matching how each
//! test file in this crate keeps its own fixtures self-contained.
//!
//! The key property under test is lossless round-trip: the de-escaped logical stream
//! `get_binary_node` captures, when handed back to `set_binary_node`, must re-escape to the
//! exact wire bytes the console originally sent -- including a data byte that collides with
//! the `0xdf` escape code.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "propmap")]
use libwing::NodeValue;
use libwing::{Transport, WingConsole};

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

/// Write-capturing transport that records each `write_all` call as its own chunk, so a test
/// can inspect the request write separately from a later replay write.
#[derive(Clone, Default)]
struct RecordingWriter {
    chunks: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingWriter {
    fn chunks(&self) -> Vec<Vec<u8>> {
        self.chunks.lock().unwrap().clone()
    }
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
        self.chunks.lock().unwrap().push(buf.to_vec());
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

fn console_with_script(bytes: Vec<u8>) -> (WingConsole, RecordingWriter) {
    let reader = ScriptReader::new(bytes);
    let writer = RecordingWriter::default();
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let console = WingConsole::from_transports(reader, writer.clone(), peer_ip);
    (console, writer)
}

/// A scripted subtree data reply (wire bytes, i.e. escaped) for two parameters, the first
/// carrying a value byte equal to the `0xdf` escape code so the escaping path is exercised.
///
/// Wire:  d7 <hash1> d4 00 00 00 df DE   d7 <hash2> d3 01 02   DE
///        \__ node __/\__ int32 0xdf _/  \__ node __/\_int16_/  \ end
/// where the lone `df` data byte is transmitted as `df de` (the console's escaping), and the
/// trailing `de` is the end-of-data token.
fn scripted_reply() -> Vec<u8> {
    vec![
        0xd7, 0x0a, 0x0b, 0x0c, 0x0d, // select node hash 0x0a0b0c0d
        0xd4, 0x00, 0x00, 0x00, 0xdf, 0xde, // int32 = 0x000000df (0xdf escaped as df de)
        0xd7, 0x11, 0x22, 0x33, 0x44, // select node hash 0x11223344
        0xd3, 0x01, 0x02, // int16 = 0x0102
        0xde, // end of data
    ]
}

/// The de-escaped logical stream `get_binary_node` should capture from `scripted_reply`:
/// identical except the escaped `df de` collapses back to a single `df`.
fn expected_logical() -> Vec<u8> {
    vec![
        0xd7, 0x0a, 0x0b, 0x0c, 0x0d, //
        0xd4, 0x00, 0x00, 0x00, 0xdf, //
        0xd7, 0x11, 0x22, 0x33, 0x44, //
        0xd3, 0x01, 0x02, //
        0xde,
    ]
}

#[test]
fn get_binary_node_captures_deescaped_stream() {
    let (mut console, writer) = console_with_script(scripted_reply());

    let captured = console
        .get_binary_node(0x0a0b0c0d, Duration::from_secs(5))
        .expect("capture should complete on the scripted end token");

    assert_eq!(captured, expected_logical());

    // The only write so far is the data request itself: d7 <hash> dc.
    let chunks = writer.chunks();
    assert_eq!(
        chunks.len(),
        1,
        "get should issue exactly one request write"
    );
    assert_eq!(chunks[0], vec![0xd7, 0x0a, 0x0b, 0x0c, 0x0d, 0xdc]);
}

#[test]
fn binary_node_round_trips_losslessly() {
    let (mut console, writer) = console_with_script(scripted_reply());

    let captured = console
        .get_binary_node(0x0a0b0c0d, Duration::from_secs(5))
        .expect("capture should complete");

    let written = console
        .set_binary_node(&captured)
        .expect("replay should write to the wire");

    // The replay re-escapes the lone 0xdf back to `df de`, so it is one byte longer than the
    // logical buffer and byte-for-byte equal to the console's original wire reply.
    assert_eq!(written, captured.len() + 1);
    let chunks = writer.chunks();
    assert_eq!(
        chunks.last().expect("a replay write"),
        &scripted_reply(),
        "replayed wire bytes must match the original reply exactly"
    );
}

#[test]
fn toggle_emits_click_token() {
    // No reply needed; toggle is write-only.
    let (mut console, writer) = console_with_script(Vec::new());

    console.toggle(0x11223344).expect("toggle should write");

    let chunks = writer.chunks();
    assert_eq!(chunks.len(), 1);
    // d7 <hash> d8  (0xd8 == native click/toggle token)
    assert_eq!(chunks[0], vec![0xd7, 0x11, 0x22, 0x33, 0x44, 0xd8]);
}

/// A `d7 <id> d5 <f32>` value pair (float, as a fader carries).
#[cfg(feature = "propmap")]
fn value_f32(id: i32, v: f32) -> Vec<u8> {
    let mut buf = vec![0xd7];
    buf.extend_from_slice(&id.to_be_bytes());
    buf.push(0xd5);
    buf.extend_from_slice(&v.to_be_bytes());
    buf
}

/// A read-back reply frame (value pair + end token) for `get_node_data` to consume.
#[cfg(feature = "propmap")]
fn reply_f32(id: i32, v: f32) -> Vec<u8> {
    let mut buf = value_f32(id, v);
    buf.push(0xde);
    buf
}

#[test]
#[cfg(feature = "propmap")]
fn verify_passes_when_readback_matches() {
    let fdr = WingConsole::name_to_id("/ch/1/fdr").expect("/ch/1/fdr in propmap");
    // Buffer says fdr = -6.0; the console reads back -6.0 -> no mismatch, no second pass.
    let mut buf = value_f32(fdr, -6.0);
    buf.push(0xde);
    let (mut console, _w) = console_with_script(reply_f32(fdr, -6.0));

    let report = console
        .verify_binary_node(&buf, Duration::from_secs(2), Duration::from_millis(1))
        .expect("verify should complete");
    assert!(
        report.mismatches.is_empty(),
        "unexpected mismatches: {report:?}"
    );
    assert_eq!(
        report.checked, 1,
        "should have checked the one writable leaf"
    );
}

#[test]
#[cfg(feature = "propmap")]
fn verify_flags_dropped_write() {
    let fdr = WingConsole::name_to_id("/ch/1/fdr").expect("/ch/1/fdr in propmap");
    // Buffer says fdr = -6.0, but the console still reports -3.0 (write didn't stick).
    // settle = ZERO -> single pass, first-pass suspects reported verbatim.
    let mut buf = value_f32(fdr, -6.0);
    buf.push(0xde);
    let (mut console, _w) = console_with_script(reply_f32(fdr, -3.0));

    let report = console
        .verify_binary_node(&buf, Duration::from_secs(2), Duration::ZERO)
        .expect("verify should complete");
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.mismatches[0].id, fdr);
    assert_eq!(report.mismatches[0].expected, NodeValue::Float(-6.0));
    assert_eq!(report.mismatches[0].actual, Some(NodeValue::Float(-3.0)));
}

#[test]
#[cfg(feature = "propmap")]
fn verify_reports_absent_node_as_mismatch() {
    let fdr = WingConsole::name_to_id("/ch/1/fdr").expect("/ch/1/fdr in propmap");
    let other = WingConsole::name_to_id("/ch/2/fdr").expect("/ch/2/fdr in propmap");
    // Buffer expects ch1 fdr, but the re-capture only carries ch2 fdr -> ch1 fdr is absent.
    let mut buf = value_f32(fdr, -6.0);
    buf.push(0xde);
    let (mut console, _w) = console_with_script(reply_f32(other, 0.0));

    let report = console
        .verify_binary_node(&buf, Duration::from_secs(2), Duration::ZERO)
        .expect("verify should complete");
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.mismatches[0].id, fdr);
    assert_eq!(report.mismatches[0].actual, None);
}

#[test]
#[cfg(feature = "propmap")]
fn verify_second_pass_filters_transient_mismatch() {
    let fdr = WingConsole::name_to_id("/ch/1/fdr").expect("/ch/1/fdr in propmap");
    // First capture: fdr still -3.0 (not settled). Second capture after settle: -6.0 (reconciled).
    // Models an async-applying head-amp param -> should NOT be reported.
    let mut buf = value_f32(fdr, -6.0);
    buf.push(0xde);
    let mut script = reply_f32(fdr, -3.0);
    script.extend(reply_f32(fdr, -6.0));
    let (mut console, _w) = console_with_script(script);

    let report = console
        .verify_binary_node(&buf, Duration::from_secs(2), Duration::from_millis(1))
        .expect("verify should complete");
    assert!(
        report.mismatches.is_empty(),
        "transient mismatch should reconcile on the second pass: {report:?}"
    );
    assert_eq!(report.checked, 1);
}

#[test]
#[cfg(feature = "propmap")]
fn verify_second_pass_keeps_persistent_mismatch() {
    let fdr = WingConsole::name_to_id("/ch/1/fdr").expect("/ch/1/fdr in propmap");
    // Both captures report -3.0 -> a genuinely dropped write survives the second pass.
    let mut buf = value_f32(fdr, -6.0);
    buf.push(0xde);
    let mut script = reply_f32(fdr, -3.0);
    script.extend(reply_f32(fdr, -3.0));
    let (mut console, _w) = console_with_script(script);

    let report = console
        .verify_binary_node(&buf, Duration::from_secs(2), Duration::from_millis(1))
        .expect("verify should complete");
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.mismatches[0].actual, Some(NodeValue::Float(-3.0)));
}

//! Encoding conformance suite (U13: R52).
//!
//! Captures the exact bytes `WingConsole` writes for each outbound message and
//! checks them against the wire format documented in
//! `references/WING_Remote_Protocols_V3.1-03.md` (pages 96-99) and mirrored in
//! `console.rs`'s own private unit tests -- but exercised here through the
//! *public* API, over a recording `Transport`, rather than the private
//! `set_*_message` builders directly.
//!
//! OSC packet encoding is out of scope: OSC has its own conformance suite in
//! `tests/osc_encode.rs` (U10).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libwing::{Meter, Transport, WingConsole};

/// Never has data to offer; every test here only inspects what was *written*.
struct EmptyReader;

impl Read for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no data"))
    }
}

impl Write for EmptyReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for EmptyReader {
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

/// Builds a `WingConsole` whose outbound bytes land in the returned buffer.
fn console_with_recorder() -> (WingConsole, Arc<Mutex<Vec<u8>>>) {
    let writer = RecordingWriter::default();
    let sink = writer.written.clone();
    let console =
        WingConsole::from_transports(EmptyReader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));
    (console, sink)
}

fn written(sink: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    sink.lock().unwrap().clone()
}

/// Wire-escapes a byte sequence the same way `console.rs`'s `extend_escaped`
/// write helper does: a literal `0xdf` becomes `0xdf 0xde`.
fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        out.push(b);
        if b == 0xdf {
            out.push(0xde);
        }
    }
    out
}

// === set_string / set_float / set_int ===

#[test]
fn set_string_emits_select_node_then_length_prefixed_escaped_value() {
    // id = 0x000000df: its low byte is 0xdf, forcing escaping in the id itself,
    // not just the value -- id bytes alone don't otherwise exercise escaping.
    let (mut console, sink) = console_with_recorder();
    console.set_string(0xdf, "hi").unwrap();

    let mut expected = vec![0xd7];
    expected.extend(escape(&0xdfi32.to_be_bytes()));
    expected.push(0x7f + 2); // short-string length token for a 2-byte value
    expected.extend(escape(b"hi"));
    assert_eq!(written(&sink), expected);
}

#[test]
fn set_string_escapes_a_literal_0xdf_in_the_value_too() {
    let (mut console, sink) = console_with_recorder();
    // 'a' + U+07FF (UTF-8: 0xdf 0xbf) -- only the leading 0xdf needs escaping.
    console.set_string(1, "a\u{7ff}").unwrap();
    assert_eq!(
        written(&sink),
        vec![0xd7, 0, 0, 0, 1, 0x82, b'a', 0xdf, 0xde, 0xbf]
    );
}

#[test]
fn set_string_rejects_values_over_256_bytes() {
    let (mut console, _sink) = console_with_recorder();
    assert!(matches!(
        console.set_string(1, &"x".repeat(257)),
        Err(libwing::Error::InvalidInput)
    ));
}

#[test]
fn set_float_emits_select_node_float_token_then_escaped_be_bytes() {
    let (mut console, sink) = console_with_recorder();
    // A float whose bit pattern's first byte is 0xdf, forcing value escaping.
    let value = f32::from_bits(0xdf000001);
    console.set_float(0xdf, value).unwrap();

    let mut expected = vec![0xd7];
    expected.extend(escape(&0xdfi32.to_be_bytes()));
    expected.push(0xd5);
    expected.extend(escape(&value.to_be_bytes()));
    assert_eq!(written(&sink), expected);
}

#[test]
fn set_int_uses_the_shortest_encoding_for_the_value_range() {
    let (mut console, sink) = console_with_recorder();

    // 0..=0x3f: inline token, no value bytes at all.
    console.set_int(2, 0x20).unwrap();
    assert_eq!(written(&sink), vec![0xd7, 0, 0, 0, 2, 0x20]);

    let (mut console, sink) = console_with_recorder();
    // i16 range: 0xd3 token + escaped i16 (id chosen to also force id escaping).
    console.set_int(0xdf, -8448).unwrap();
    let mut expected = vec![0xd7];
    expected.extend(escape(&0xdfi32.to_be_bytes()));
    expected.push(0xd3);
    expected.extend(escape(&(-8448i16).to_be_bytes()));
    assert_eq!(written(&sink), expected);

    let (mut console, sink) = console_with_recorder();
    // Outside i16 range: 0xd4 token + full escaped i32.
    console.set_int(3, 100_000).unwrap();
    let mut expected = vec![0xd7, 0, 0, 0, 3, 0xd4];
    expected.extend(escape(&100_000i32.to_be_bytes()));
    assert_eq!(written(&sink), expected);
}

// === request_node_data / request_node_definition ===

#[test]
fn request_node_definition_of_id_zero_uses_the_root_form() {
    let (mut console, sink) = console_with_recorder();
    console.request_node_definition(0).unwrap();
    assert_eq!(written(&sink), vec![0xda, 0xdd]);
}

#[test]
fn request_node_definition_of_a_nonzero_id_selects_then_requests() {
    let (mut console, sink) = console_with_recorder();
    console.request_node_definition(0xdf).unwrap();
    let mut expected = vec![0xd7];
    expected.extend(escape(&0xdfi32.to_be_bytes()));
    expected.push(0xdd);
    assert_eq!(written(&sink), expected);
}

#[test]
fn request_node_data_of_id_zero_uses_the_root_form() {
    let (mut console, sink) = console_with_recorder();
    console.request_node_data(0).unwrap();
    assert_eq!(written(&sink), vec![0xda, 0xdc]);
}

#[test]
fn request_node_data_of_a_nonzero_id_selects_then_requests() {
    let (mut console, sink) = console_with_recorder();
    console.request_node_data(42).unwrap();
    assert_eq!(written(&sink), vec![0xd7, 0, 0, 0, 42, 0xdc]);
}

// === meter request encoding ===

/// Reverses the outbound `0xdf`-escape enough to pull `n` logical bytes out of
/// `buf` starting at `*i`, advancing `*i` past however many wire bytes that
/// took. This is deliberately independent of (and simpler than) the receive
/// side's `decode_next` in `console.rs` -- there's no channel/index framing to
/// account for here, just the plain escape rule -- since the point is to parse
/// this test's own expectations back out of captured bytes, not to re-test the
/// decoder.
fn take_escaped(buf: &[u8], i: &mut usize, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let b = buf[*i];
        *i += 1;
        if b == 0xdf {
            assert_eq!(buf.get(*i), Some(&0xde), "lone 0xdf not escaped in capture");
            *i += 1;
        }
        out.push(b);
    }
    out
}

#[test]
fn request_meter_encodes_port_id_and_meter_tokens_structurally() {
    // The client UDP port is a real ephemeral port assigned by the OS when
    // `request_meter` binds its socket -- there's no accessor to read it back
    // directly, and asserting a fixed literal would be flaky (and wrong, since
    // it varies run to run). Instead this parses the emitted bytes structurally
    // and cross-checks that the same port value appears in both of its wire
    // positions, which is exactly what a byte-literal comparison would have
    // confirmed anyway.
    let (mut console, sink) = console_with_recorder();
    let meter_id = console
        .request_meter(&[Meter::Channel(1), Meter::Rta])
        .unwrap();
    assert_eq!(meter_id, 1, "first request_meter call yields meter id 1");

    let buf = written(&sink);
    let mut i = 0;

    assert_eq!(&buf[i..i + 3], &[0xdf, 0xd3, 0xd3]);
    i += 3;
    let port_a = take_escaped(&buf, &mut i, 2);

    assert_eq!(buf[i], 0xd4);
    i += 1;
    let id_bytes = take_escaped(&buf, &mut i, 2);
    assert_eq!(id_bytes, vec![0, 1], "meter id 1, as a big-endian u16");

    let port_b = take_escaped(&buf, &mut i, 2);
    assert_eq!(port_a, port_b, "the declared UDP port repeats identically");

    assert_eq!(buf[i], 0xdc);
    i += 1;

    // Meter::Channel(1): token 0xa0, then escaped zero-based wire index 0.
    assert_eq!(buf[i], 0xa0);
    i += 1;
    assert_eq!(take_escaped(&buf, &mut i, 1), vec![0]);

    // Meter::Rta: token 0xaa, no index.
    assert_eq!(buf[i], 0xaa);
    i += 1;

    assert_eq!(
        &buf[i..],
        &[0xde, 0xdf, 0xd1],
        "end-of-def then keepalive marker"
    );
}

// === meter renewal ===

#[test]
fn keep_alive_meters_renews_with_the_same_id_and_port_after_the_interval_expires() {
    // METERS_KEEP_ALIVE_SECONDS is 3s; there's no accessor to fast-forward the
    // renewal timer, so this sleeps past it for real. Flagging the timing
    // dependency rather than hiding it: a future record-replay harness (U14)
    // could inject a clock and drop this sleep, but for now this is the
    // pragmatic way to exercise the actual renewal encoding.
    let (mut console, sink) = console_with_recorder();
    console.request_meter(&[Meter::Rta]).unwrap();

    let first = written(&sink);
    let mut i = 3; // past [0xdf, 0xd3, 0xd3]
    let port = take_escaped(&first, &mut i, 2);

    std::thread::sleep(Duration::from_secs(4));
    console.keep_alive_meters().unwrap();

    let after = written(&sink);
    let renewal = &after[first.len()..];
    let mut j = 0;
    assert_eq!(&renewal[j..j + 3], &[0xdf, 0xd3, 0xd4]);
    j += 3;
    assert_eq!(take_escaped(renewal, &mut j, 2), vec![0, 1], "meter id 1");
    assert_eq!(
        take_escaped(renewal, &mut j, 2),
        port,
        "renewal repeats the same declared port"
    );
    assert_eq!(&renewal[j..], &[0xdf, 0xd1]);
}

#[test]
fn keep_alive_meters_is_a_no_op_before_the_interval_expires() {
    let (mut console, sink) = console_with_recorder();
    console.request_meter(&[Meter::Rta]).unwrap();
    let after_request = written(&sink).len();

    // Called again immediately: the 3s renewal timer hasn't expired, so this
    // must write nothing more.
    console.keep_alive_meters().unwrap();
    assert_eq!(written(&sink).len(), after_request);
}

// === data keepalive ===
//
// `keep_alive()` only fires (writing 0xdf 0xd1) once DATA_KEEP_ALIVE_SECONDS
// (7s) has elapsed since construction, and there's no accessor to fast-forward
// that timer. A 7s sleep is too long to spend on this in every CI run, so what's
// covered here is the documented no-op contract before expiry -- the actual
// fired-encoding is the same literal `[0xdf, 0xd1]` sequence `connect()` writes
// as its initial hello (see `console.rs::connect`), which isn't reachable
// offline. This is a known gap: U14's record-replay fixtures are the right
// place to exercise the fired path against a real elapsed-time (or injected
// clock) scenario.

#[test]
fn keep_alive_is_a_no_op_before_the_keepalive_interval_expires() {
    let (mut console, sink) = console_with_recorder();
    console.keep_alive().unwrap();
    assert!(
        written(&sink).is_empty(),
        "keep_alive must not write anything before DATA_KEEP_ALIVE_SECONDS elapses"
    );
}

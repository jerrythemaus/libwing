//! Parser conformance suite (U13: R51).
//!
//! Malformed/adversarial input coverage for the wire parser, beyond the offline
//! unit tests already in `src/node.rs` and `src/console.rs`. Two layers are
//! exercised, deliberately kept separate:
//!
//! - [`WingNodeDef::try_from_bytes`] -- a pure, in-memory parser with no I/O, so
//!   truncation and oversized-claim tests loop over prefix lengths directly with
//!   no risk of blocking.
//! - [`WingConsole::read`] over a scripted [`Transport`] -- exercised only with
//!   *complete* wire frames (extended lengths, escaping, unknown discriminants,
//!   boundary-sized strings). A script that runs dry mid-frame is, by design,
//!   indistinguishable from a live socket still waiting for more bytes: with no
//!   attended-get deadline active, `read()` correctly keeps waiting rather than
//!   erroring, so that scenario isn't something to conformance-test at this
//!   layer -- the truncation coverage below stays entirely at the pure-parser
//!   layer instead, where "ran out of bytes" and "waiting for more" aren't
//!   ambiguous.
//!
//! OSC packet encoding is out of scope here: OSC lands in U10/U11, and its
//! conformance tests belong in that unit's test suite, not this one.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use libwing::{Error, NodeType, NodeUnit, Transport, WingConsole, WingNodeDef, WingResponse};

// --- scripted-transport harness (mirrors tests/attended_get.rs) ---

/// Feeds pre-scripted wire bytes to the console's reader, reporting `TimedOut`
/// once exhausted (matching a real timed-out socket read) rather than blocking.
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
struct RecordingWriter;

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

fn console_with_script(bytes: Vec<u8>) -> WingConsole {
    let reader = ScriptReader::new(bytes);
    let writer = RecordingWriter;
    WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn describe(resp: &WingResponse) -> &'static str {
    match resp {
        WingResponse::RequestEnd => "RequestEnd",
        WingResponse::NodeDef(_) => "NodeDef",
        WingResponse::NodeData(_, _) => "NodeData",
    }
}

// --- def fixture builder (mirrors src/node.rs's own #[cfg(test)] DefBuilder) ---

struct DefBuilder<'a> {
    parent_id: i32,
    id: i32,
    index: u16,
    name: &'a str,
    long_name: &'a str,
    node_type: u8,
    unit: u8,
    read_only: bool,
    payload: Vec<u8>,
}

impl<'a> DefBuilder<'a> {
    fn new(id: i32, name: &'a str, long_name: &'a str, node_type: u8) -> Self {
        Self {
            parent_id: 0,
            id,
            index: 0,
            name,
            long_name,
            node_type,
            unit: 0,
            read_only: false,
            payload: Vec::new(),
        }
    }
    fn parent_id(mut self, parent_id: i32) -> Self {
        self.parent_id = parent_id;
        self
    }
    fn index(mut self, index: u16) -> Self {
        self.index = index;
        self
    }
    fn unit(mut self, unit: u8) -> Self {
        self.unit = unit;
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn i32(mut self, v: i32) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn f32(mut self, v: f32) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn str(mut self, s: &str) -> Self {
        self.payload.push(s.len() as u8);
        self.payload.extend_from_slice(s.as_bytes());
        self
    }
    fn build(self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.parent_id.to_be_bytes());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.push(self.name.len() as u8);
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(self.long_name.len() as u8);
        buf.extend_from_slice(self.long_name.as_bytes());
        let flags: u16 = ((self.node_type as u16 & 0x0F) << 4)
            | (self.unit as u16 & 0x0F)
            | if self.read_only { 1 << 9 } else { 0 };
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// Wire-escapes a byte sequence: a literal `0xdf` becomes `0xdf 0xde` (the same
/// rule `console.rs`'s `extend_escaped` write helper applies).
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

/// Wraps a decoded (unescaped) node-def body in the extended-length wire frame
/// (`0xdf 0xdf`, `len.w == 0` sentinel, `len.l` u32, then the body), escaping both
/// the length header and the body -- matching `console.rs`'s `read()` (the
/// `cmd == 0xdf` arm) and its `decode_next` escape handling.
fn extended_def_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xdf, 0xdf, 0, 0];
    frame.extend(escape(&(body.len() as u32).to_be_bytes()));
    frame.extend(escape(body));
    frame
}

// === Truncated defs at every structural boundary (pure parser, no I/O) ===

#[test]
fn truncated_node_def_never_panics_at_any_prefix_length() {
    // One fixture per NodeType variant with type-specific payload, so truncation
    // is exercised mid-parent_id, mid-name, mid-flags, and mid-payload for every
    // shape the parser understands. FaderLevel is deliberately excluded here --
    // its optional range payload gives it a different, dual-encoding contract,
    // covered separately below.
    let fixtures: Vec<Vec<u8>> = vec![
        DefBuilder::new(1, "n", "N", 0).parent_id(1).build(), // Node
        DefBuilder::new(2, "i", "I", 4).i32(-10).i32(10).build(), // Integer
        DefBuilder::new(3, "f", "F", 1)
            .f32(-1.0)
            .f32(1.0)
            .i32(100)
            .build(), // LinearFloat
        DefBuilder::new(4, "g", "G", 2)
            .f32(-1.0)
            .f32(1.0)
            .i32(100)
            .build(), // LogarithmicFloat
        DefBuilder::new(5, "e", "E", 5)
            .u16(2)
            .str("a")
            .str("Alpha")
            .str("b")
            .str("Bravo")
            .build(), // StringEnum
        DefBuilder::new(6, "fe", "FE", 6)
            .u16(1)
            .f32(0.5)
            .str("Half")
            .build(), // FloatEnum
        DefBuilder::new(7, "s", "S", 7).u16(64).build(),      // String
    ];

    for full in &fixtures {
        // Every strictly-shorter prefix must error, never panic: these fixtures
        // contain no padding, so any truncation removes a required field.
        for len in 0..full.len() {
            let res = WingNodeDef::try_from_bytes(&full[..len]);
            assert!(
                res.is_err(),
                "expected Err for truncated len {len} of {} (full len {})",
                full.len(),
                full.len()
            );
        }
        // The untruncated fixture itself must still parse.
        assert!(
            WingNodeDef::try_from_bytes(full).is_ok(),
            "full fixture unexpectedly failed to parse"
        );
    }
}

#[test]
fn truncated_fader_level_never_panics_and_accepts_both_encodings() {
    // FaderLevel is special (`src/node.rs`'s `from_bytes_inner`): live consoles
    // stream a min/max/steps range, but the embedded property-map snapshot
    // predates that and omits it, so the parser only reads the range when at
    // least 12 bytes remain after the base fields. That makes truncation's
    // contract different from every other type: anything at or past the base
    // fields is a *valid* short-form parse, not an error -- only truncating
    // into the base fields themselves (parent_id/id/index/name/flags) errors.
    let full = DefBuilder::new(8, "fdr", "Fdr", 3)
        .f32(-90.0)
        .f32(10.0)
        .i32(1024)
        .build();
    let base_len = full.len() - 12; // end of the base fields, start of the range payload

    for len in 0..base_len {
        assert!(
            WingNodeDef::try_from_bytes(&full[..len]).is_err(),
            "expected Err truncating into the base fields at len {len}"
        );
    }
    for len in base_len..=full.len() {
        let def = WingNodeDef::try_from_bytes(&full[..len]).unwrap_or_else(|e| {
            panic!("expected Ok at len {len} (short- or long-form FaderLevel), got {e}")
        });
        assert_eq!(def.name, "fdr");
        if len == full.len() {
            assert_eq!(def.min_float, Some(-90.0));
        } else {
            // Short-form: any partial/absent range payload is dropped, not
            // partially read.
            assert_eq!(def.min_float, None);
        }
    }
}

// === Extended node-definition lengths through WingConsole::read() ===

#[test]
fn extended_length_node_definition_parses_through_console_read() {
    let body = DefBuilder::new(2, "n", "N", 0)
        .parent_id(1)
        .index(3)
        .build();
    let mut console = console_with_script(extended_def_frame(&body));
    match console.read().unwrap() {
        WingResponse::NodeDef(def) => {
            assert_eq!(def.parent_id, 1);
            assert_eq!(def.id, 2);
            assert_eq!(def.index, 3);
            assert_eq!(def.name, "n");
        }
        other => panic!("expected NodeDef, got {}", describe(&other)),
    }
}

#[test]
fn oversized_extended_node_definition_length_is_a_typed_error() {
    // len.w == 0 sentinel, then a u32 length far past MAX_NODE_DEF_BYTES (1 MiB):
    // rejected before any body bytes are read, so this can't hang.
    let mut console = console_with_script(vec![0xdf, 0xdf, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(console.read(), Err(Error::InvalidData)));
}

// === Unknown type/unit discriminants preserved through WingConsole::read() ===
//
// `tests/value_compat.rs` already covers this at the pure-parser level
// (`WingNodeDef::from_bytes`); these add the console-level `read()` path.

#[test]
fn unknown_type_nibble_streamed_through_read_yields_unknown_not_error() {
    let body = DefBuilder::new(9, "future", "Future", 13).build(); // 13 is unassigned
    let mut console = console_with_script(extended_def_frame(&body));
    match console.read().unwrap() {
        WingResponse::NodeDef(def) => assert_eq!(def.node_type, NodeType::Unknown(13)),
        other => panic!("expected NodeDef, got {}", describe(&other)),
    }
}

#[test]
fn unknown_unit_nibble_streamed_through_read_yields_unknown_not_error() {
    let body = DefBuilder::new(10, "u", "U", 0).unit(12).build(); // 12 is unassigned
    let mut console = console_with_script(extended_def_frame(&body));
    match console.read().unwrap() {
        WingResponse::NodeDef(def) => assert_eq!(def.unit, NodeUnit::Unknown(12)),
        other => panic!("expected NodeDef, got {}", describe(&other)),
    }
}

// === Escaped bytes in both the length header and a string payload ===

#[test]
fn escaped_bytes_in_def_name_and_in_the_length_header_decode_correctly() {
    // "a\u{7ff}" is 'a' followed by the UTF-8 encoding of U+07FF (0xdf, 0xbf) --
    // the same escaping fixture `console.rs`'s own `set_string_escapes_payload`
    // unit test uses, just on the receive side here.
    let mut body = DefBuilder::new(11, "a\u{7ff}", "N", 0).build();
    // Pad with unused trailing bytes (ignored by a Node-type def, which has no
    // type-specific payload to read) until the body is exactly 0xdf (223) bytes
    // long, forcing the u32 length header's low byte to itself be 0xdf -- so the
    // length header needs escaping too, not just the payload.
    while body.len() < 0xdf {
        body.push(b'x');
    }
    assert_eq!(body.len(), 0xdf);

    let mut console = console_with_script(extended_def_frame(&body));
    match console.read().unwrap() {
        WingResponse::NodeDef(def) => {
            assert_eq!(def.id, 11);
            assert_eq!(def.name, "a\u{7ff}");
        }
        other => panic!("expected NodeDef, got {}", describe(&other)),
    }
}

// === Oversized strings: typed error, never a panic ===

#[test]
fn string_enum_long_item_length_exceeding_data_errors_without_panic() {
    // One item: item = "a" (present), but long_item_len claims 200 bytes with
    // nothing following. Mirrors src/node.rs's
    // `string_enum_count_larger_than_data_errors_without_panic` (which exceeds
    // the *item count*); this exceeds an individual long-item's *length* instead.
    let mut bytes = DefBuilder::new(20, "e", "E", 5).u16(1).str("a").build();
    bytes.push(200); // long_item_len, no bytes follow
    assert!(matches!(
        WingNodeDef::try_from_bytes(&bytes),
        Err(Error::InvalidData)
    ));
}

#[test]
fn nodedata_0xd1_256_byte_string_round_trips_through_read() {
    // 0xd1's length byte is (real_len - 1), so 0xff encodes the maximum: a
    // 256-byte string. Full data provided -- a boundary-value parse, not a
    // truncation case, so no hang risk.
    let value = "x".repeat(256);
    let mut script = vec![0xd1, 0xff];
    script.extend_from_slice(value.as_bytes());

    let mut console = console_with_script(script);
    match console.read().unwrap() {
        WingResponse::NodeData(_, data) => assert_eq!(data.get_string(), value),
        other => panic!("expected NodeData, got {}", describe(&other)),
    }
}

// === Id collisions: id_to_defs enumerates variants, name_to_def stays unique ===
//
// Light regression only -- heavy coverage lives in tests/propmap_consistency.rs.

#[test]
#[cfg(feature = "propmap")]
fn id_collision_yields_multiple_defs_but_name_lookup_stays_unique() {
    // /fx/1/EXT/egrp and /fx/1/HALL/pdel share this id (same id, mutually
    // exclusive per-model subtrees); also used by tests/model_resolution.rs and
    // tests/propmap_consistency.rs.
    const SHARED_ID: i32 = 638586229;

    let defs = WingConsole::id_to_defs(SHARED_ID).expect("id has known variants");
    assert!(
        defs.len() >= 2,
        "expected multiple candidates for a reused id, got {}",
        defs.len()
    );

    let def = WingConsole::name_to_def("/fx/1/HALL/pdel").expect("known path");
    assert_eq!(def.name, "pdel");
}

// === Dynamic-model metadata: a 'mdl' StringEnum selector parses with items intact ===

#[test]
fn dynamic_model_selector_named_mdl_parses_as_string_enum_with_items_intact() {
    // Fixture-driven (not a propmap lookup) so this runs under
    // `--no-default-features` too. Mirrors the shape of the real embedded
    // fixtures at /ch/1/eq/mdl, /ch/1/gate/mdl, /ch/1/flt/mdl (propmap.jsonl):
    // a `mdl`-named StringEnum whose items select the slot's active model.
    let bytes = DefBuilder::new(30, "mdl", "MODEL", 5)
        .u16(3)
        .str("STD")
        .str("WING EQ")
        .str("SOUL")
        .str("SOUL ANALOGUE")
        .str("E88")
        .str("EVEN 88 FORMANT")
        .build();

    let def = WingNodeDef::try_from_bytes(&bytes).unwrap();
    assert_eq!(def.name, "mdl");
    assert_eq!(def.node_type, NodeType::StringEnum);
    let items = def.string_enum.expect("string_enum items present");
    assert_eq!(items.len(), 3);
    assert_eq!(items[0].item, "STD");
    assert_eq!(items[0].long_item, "WING EQ");
    assert_eq!(items[2].item, "E88");
    assert_eq!(items[2].long_item, "EVEN 88 FORMANT");
}

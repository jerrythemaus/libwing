//! Bulk get/set + dump/restore helpers (U6: R18, R19).
//!
//! Exercised over `WingConsole::from_transports` with scripted transports, the
//! same pattern `tests/attended_get.rs` uses -- no real socket or console
//! involved. The scripted-transport harness (`ScriptReader`/`RecordingWriter`)
//! is duplicated here rather than shared, matching how each test file in this
//! crate already keeps its own fixtures self-contained (e.g.
//! `tests/value_compat.rs` duplicates `src/node.rs`'s `DefBuilder`).
//!
//! ## Read-only exclusion (R18) note
//!
//! `dump_subtree`'s read-only/container exclusion and `restore`'s
//! defense-in-depth read-only skip are both implemented against the embedded
//! property map. As of this map's current sweep it has zero read-only
//! definitions (verified while implementing this), so there's no real subtree
//! to build an end-to-end "dump excludes a read-only node" test against here.
//! That exclusion logic is instead unit-tested directly against a synthetic
//! fixture in `src/console.rs`
//! (`console::tests::dumpable_leaves_excludes_read_only_and_containers`).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libwing::{DumpEntry, Error, NodeDump, NodeValue, Transport, WingConsole};

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

/// Write-capturing transport that records each `write_all` call as its own
/// chunk (rather than one flat buffer), so callers can check *order* and
/// *count* between distinct writes (e.g. which of two `set_string` calls
/// happened first, or whether a request went out at all) without needing to
/// parse escaped wire bytes back out of a merged stream.
#[derive(Clone, Default)]
struct RecordingWriter {
    chunks: Arc<Mutex<Vec<Vec<u8>>>>,
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

/// A `NodeData` response frame carrying an i32 (mirrors `tests/attended_get.rs`).
fn node_data_i32(id: i32, value: i32) -> Vec<u8> {
    let mut buf = vec![0xd7];
    buf.extend_from_slice(&id.to_be_bytes());
    buf.push(0xd4);
    buf.extend_from_slice(&value.to_be_bytes());
    buf
}

#[test]
fn get_nodes_returns_values_in_requested_order() {
    let mut script = Vec::new();
    script.extend(node_data_i32(10, 111));
    script.extend(node_data_i32(20, 222));
    script.extend(node_data_i32(30, 333));

    let (mut console, _writer) = console_with_script(script);
    let results = console.get_nodes(&[10, 20, 30], Duration::from_millis(500));

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, 10);
    assert_eq!(results[0].1.as_ref().unwrap().get_int(), 111);
    assert_eq!(results[1].0, 20);
    assert_eq!(results[1].1.as_ref().unwrap().get_int(), 222);
    assert_eq!(results[2].0, 30);
    assert_eq!(results[2].1.as_ref().unwrap().get_int(), 333);
}

/// A `NodeData` for a later-requested id that arrives while waiting on an
/// earlier one is reused instead of triggering a second request for it.
#[test]
fn get_nodes_reuses_a_buffered_response_instead_of_re_requesting() {
    let mut script = Vec::new();
    script.extend(node_data_i32(20, 999)); // unrelated to the id=10 request, arrives first
    script.extend(node_data_i32(10, 111)); // satisfies the id=10 request
    script.extend(node_data_i32(30, 333)); // satisfies the id=30 request

    let (mut console, writer) = console_with_script(script);
    let results = console.get_nodes(&[10, 20, 30], Duration::from_millis(500));

    assert_eq!(results[0].0, 10);
    assert_eq!(results[0].1.as_ref().unwrap().get_int(), 111);
    assert_eq!(results[1].0, 20);
    assert_eq!(results[1].1.as_ref().unwrap().get_int(), 999);
    assert_eq!(results[2].0, 30);
    assert_eq!(results[2].1.as_ref().unwrap().get_int(), 333);

    // Only two `request_node_data` writes should have gone out -- id=20 was
    // satisfied entirely from what the id=10 request had already buffered.
    let chunks = writer.chunks.lock().unwrap();
    assert_eq!(
        chunks.len(),
        2,
        "expected exactly 2 requests, got {chunks:?}"
    );
    assert_eq!(chunks[0], vec![0xd7, 0, 0, 0, 10, 0xdc]);
    assert_eq!(chunks[1], vec![0xd7, 0, 0, 0, 30, 0xdc]);
}

/// A `get_node_data` timeout discards whatever was buffered while waiting
/// (there's no partial result on the `Err` path), so a timed-out id can't hand
/// anything forward to a later one -- but `get_nodes` must still continue to
/// the rest of the list instead of aborting after the first failure.
#[test]
fn get_nodes_continues_past_a_timeout_to_the_rest_of_the_ids() {
    let (mut console, _writer) = console_with_script(Vec::new());
    let results = console.get_nodes(&[10, 20], Duration::from_millis(30));

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, 10);
    assert!(matches!(results[0].1, Err(Error::Timeout)));
    assert_eq!(results[1].0, 20);
    assert!(matches!(results[1].1, Err(Error::Timeout)));
}

#[test]
fn set_nodes_applies_each_value_type_in_order() {
    let (mut console, writer) = console_with_script(Vec::new());
    let values = vec![
        (1, NodeValue::String("STD".to_string())),
        (2, NodeValue::Float(3.5)),
        (3, NodeValue::Int(42)),
    ];

    let results = console.set_nodes(&values);

    assert_eq!(
        results.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(results.iter().all(|(_, r)| r.is_ok()));
    assert_eq!(writer.chunks.lock().unwrap().len(), 3);
}

/// R18: `restore` applies model-selector (`mdl`) entries before non-selector
/// entries, and orders multiple selectors by ascending path depth (an outer
/// selector before one nested inside its own model-specific subtree) -- even
/// though the dump's entries here are given in the opposite order. No real
/// nested `mdl` exists in the embedded map's current sweep (checked while
/// implementing this), so `/fx/1/HALL/mdl` below is a synthetic stand-in
/// purely to exercise the depth-ordering rule; it doesn't need to resolve
/// against the embedded map since the entries carry their own ids.
#[test]
fn restore_applies_model_selectors_before_children_shallowest_first() {
    let dump = NodeDump {
        entries: vec![
            DumpEntry {
                fullname: "/fx/1/HALL/pdel".to_string(),
                id: 3,
                value: NodeValue::Int(7),
            },
            DumpEntry {
                fullname: "/fx/1/HALL/mdl".to_string(),
                id: 2,
                value: NodeValue::String("NESTED".to_string()),
            },
            DumpEntry {
                fullname: "/fx/1/mdl".to_string(),
                id: 1,
                value: NodeValue::String("HALL".to_string()),
            },
        ],
    };

    let (mut console, writer) = console_with_script(Vec::new());
    let results = console.restore(&dump);

    assert!(results.iter().all(|(_, r)| r.is_ok()), "{results:?}");

    let chunks = writer.chunks.lock().unwrap();
    assert_eq!(chunks.len(), 3);
    // Each set_string write starts with 0xd7 <4-byte id>; ids 1/2/3 need no escaping.
    assert!(
        chunks[0].starts_with(&[0xd7, 0, 0, 0, 1]),
        "expected outer /fx/1/mdl (id 1) applied first, got {:?}",
        chunks[0]
    );
    assert!(
        chunks[1].starts_with(&[0xd7, 0, 0, 0, 2]),
        "expected nested /fx/1/HALL/mdl (id 2) applied second, got {:?}",
        chunks[1]
    );
    assert!(
        chunks[2].starts_with(&[0xd7, 0, 0, 0, 3]),
        "expected /fx/1/HALL/pdel (id 3) applied last, got {:?}",
        chunks[2]
    );
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_walks_the_embedded_map_in_sorted_order() {
    // /cfg/amix has exactly two writable integer leaves in the embedded map,
    // x and y -- already alphabetically ordered, and small enough to script
    // exactly.
    let x_id = WingConsole::name_to_id("/cfg/amix/x").expect("propmap should know this path");
    let y_id = WingConsole::name_to_id("/cfg/amix/y").expect("propmap should know this path");

    let mut script = Vec::new();
    script.extend(node_data_i32(x_id, 11));
    script.extend(node_data_i32(y_id, 22));

    let (mut console, _writer) = console_with_script(script);
    let dump = console
        .dump_subtree("/cfg/amix", Duration::from_millis(500))
        .expect("dump should succeed");

    assert_eq!(dump.entries.len(), 2);
    assert_eq!(dump.entries[0].fullname, "/cfg/amix/x");
    assert_eq!(dump.entries[0].id, x_id);
    assert_eq!(dump.entries[0].value, NodeValue::Int(11));
    assert_eq!(dump.entries[1].fullname, "/cfg/amix/y");
    assert_eq!(dump.entries[1].id, y_id);
    assert_eq!(dump.entries[1].value, NodeValue::Int(22));
}

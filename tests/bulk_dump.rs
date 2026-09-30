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

#[cfg(feature = "propmap")]
use std::collections::HashSet;
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

#[cfg(feature = "propmap")]
#[derive(Default)]
struct ResponsiveState {
    responses: VecDeque<u8>,
    requested_ids: Vec<i32>,
    model_reads: usize,
    model_after_first: Option<&'static str>,
}

#[cfg(feature = "propmap")]
struct ResponsiveTransport {
    state: Arc<Mutex<ResponsiveState>>,
    model_id: i32,
}

#[cfg(feature = "propmap")]
impl ResponsiveTransport {
    fn response(id: i32, model_id: i32, model: &str) -> Vec<u8> {
        let mut response = vec![0xd7];
        for byte in id.to_be_bytes() {
            response.push(byte);
            if byte == 0xdf {
                response.push(byte);
            }
        }
        if id == model_id {
            response.push(0x80 | (model.len() as u8 - 1));
            response.extend(model.as_bytes());
        } else {
            response.push(1);
        }
        response
    }

    fn requested_id(buf: &[u8]) -> i32 {
        assert_eq!(buf.first(), Some(&0xd7));
        let mut bytes = [0; 4];
        let mut input = 1;
        for output in &mut bytes {
            *output = buf[input];
            input += if buf[input] == 0xdf { 2 } else { 1 };
        }
        i32::from_be_bytes(bytes)
    }
}

#[cfg(feature = "propmap")]
impl Read for ResponsiveTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        if state.responses.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request has no queued response",
            ));
        }
        let n = buf.len().min(state.responses.len());
        for slot in buf.iter_mut().take(n) {
            *slot = state.responses.pop_front().unwrap();
        }
        Ok(n)
    }
}

#[cfg(feature = "propmap")]
impl Write for ResponsiveTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let id = Self::requested_id(buf);
        let mut state = self.state.lock().unwrap();
        state.requested_ids.push(id);
        let model = if id == self.model_id {
            state.model_reads += 1;
            if state.model_reads > 1 {
                state.model_after_first.unwrap_or("HALL")
            } else {
                "HALL"
            }
        } else {
            "HALL"
        };
        state
            .responses
            .extend(Self::response(id, self.model_id, model));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "propmap")]
impl Transport for ResponsiveTransport {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
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
        unknown_models: Vec::new(),
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
fn restore_stops_after_a_model_selector_fails() {
    let dump = NodeDump {
        entries: vec![
            DumpEntry {
                fullname: "/fx/1/HALL/pdel".to_string(),
                id: 2,
                value: NodeValue::Int(7),
            },
            DumpEntry {
                fullname: "/fx/1/mdl".to_string(),
                id: 1,
                value: NodeValue::String("x".repeat(300)),
            },
        ],
        unknown_models: Vec::new(),
    };
    let (mut console, writer) = console_with_script(Vec::new());

    let results = console.restore(&dump);

    assert_eq!(results.len(), 2);
    assert!(results
        .iter()
        .all(|(_, result)| matches!(result, Err(Error::InvalidInput))));
    assert!(writer.chunks.lock().unwrap().is_empty());
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

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_includes_only_the_active_processing_model() {
    let model_id = WingConsole::name_to_id("/fx/1/mdl").expect("model selector must exist");
    let state = Arc::new(Mutex::new(ResponsiveState::default()));
    let reader = ResponsiveTransport {
        state: state.clone(),
        model_id,
    };
    let writer = ResponsiveTransport {
        state: state.clone(),
        model_id,
    };
    let mut console = WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));

    let dump = console
        .dump_subtree("/fx/1", Duration::from_millis(100))
        .expect("responsive transport should satisfy every requested leaf");

    assert!(
        dump.entries
            .iter()
            .any(|entry| entry.fullname == "/fx/1/HALL/pdel"),
        "active HALL parameters should be included"
    );
    let inactive_count = dump
        .entries
        .iter()
        .filter(|entry| {
            let relative = entry.fullname.strip_prefix("/fx/1/").unwrap();
            relative.contains('/') && !relative.starts_with("HALL/")
        })
        .count();
    let inactive_paths: Vec<_> = dump
        .entries
        .iter()
        .filter(|entry| {
            let relative = entry.fullname.strip_prefix("/fx/1/").unwrap();
            relative.contains('/') && !relative.starts_with("HALL/")
        })
        .map(|entry| entry.fullname.as_str())
        .take(5)
        .collect();
    assert!(
        inactive_count == 0,
        "dump contained {inactive_count} inactive model paths; first few: {inactive_paths:?}"
    );

    let ids: HashSet<_> = dump.entries.iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids.len(),
        dump.entries.len(),
        "a physical parameter id must appear only once in a dump"
    );
    let requested = &state.lock().unwrap().requested_ids;
    assert_eq!(requested.first(), Some(&model_id));
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_stores_a_model_selector_as_its_restorable_name() {
    let selector = WingConsole::name_to_def("/fx/1/mdl").unwrap();
    let hall_index = selector
        .string_enum
        .as_ref()
        .unwrap()
        .iter()
        .position(|item| item.item == "HALL")
        .unwrap() as i32;
    let response = node_data_i32(selector.id, hall_index);
    let (mut console, _) = console_with_script([response.clone(), response].concat());

    let dump = console
        .dump_subtree("/fx/1/mdl", Duration::from_millis(500))
        .unwrap();
    assert_eq!(dump.entries.len(), 1);
    assert_eq!(dump.entries[0].value, NodeValue::String("HALL".to_string()));
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_rejects_a_model_change_during_capture() {
    let model_id = WingConsole::name_to_id("/fx/1/mdl").unwrap();
    let state = Arc::new(Mutex::new(ResponsiveState {
        model_after_first: Some("EXT"),
        ..ResponsiveState::default()
    }));
    let reader = ResponsiveTransport {
        state: state.clone(),
        model_id,
    };
    let writer = ResponsiveTransport { state, model_id };
    let mut console = WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));

    assert!(matches!(
        console.dump_subtree("/fx/1", Duration::from_millis(100)),
        Err(Error::InvalidData)
    ));
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_preserves_an_unknown_nonselector_enum_index() {
    let id = WingConsole::name_to_id("/cfg/mainlink").unwrap();
    let (mut console, _) = console_with_script(node_data_i32(id, 99));

    let dump = console
        .dump_subtree("/cfg/mainlink", Duration::from_millis(500))
        .unwrap();
    assert_eq!(dump.entries[0].value, NodeValue::Int(99));
}

/// Answers every attended get: each id in `models` with that model label, anything else
/// with a small integer. Records the requested ids in order.
#[cfg(feature = "propmap")]
#[derive(Clone)]
struct MultiModelTransport {
    models: Arc<Vec<(i32, &'static str)>>,
    state: Arc<Mutex<(VecDeque<u8>, Vec<i32>)>>,
}

#[cfg(feature = "propmap")]
impl MultiModelTransport {
    fn new(models: &[(&str, &'static str)]) -> Self {
        let models = models
            .iter()
            .map(|(path, model)| (WingConsole::name_to_id(path).unwrap(), *model))
            .collect();
        Self {
            models: Arc::new(models),
            state: Arc::default(),
        }
    }

    fn console(&self) -> WingConsole {
        WingConsole::from_transports(self.clone(), self.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    fn requested(&self) -> Vec<i32> {
        self.state.lock().unwrap().1.clone()
    }
}

#[cfg(feature = "propmap")]
impl Read for MultiModelTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        if state.0.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request has no queued response",
            ));
        }
        let n = buf.len().min(state.0.len());
        for slot in buf.iter_mut().take(n) {
            *slot = state.0.pop_front().unwrap();
        }
        Ok(n)
    }
}

#[cfg(feature = "propmap")]
impl Write for MultiModelTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let id = ResponsiveTransport::requested_id(buf);
        let model = self.models.iter().find(|(model_id, _)| *model_id == id);
        let response = match model {
            Some((model_id, model)) => ResponsiveTransport::response(id, *model_id, model),
            None => ResponsiveTransport::response(id, !id, ""),
        };
        let mut state = self.state.lock().unwrap();
        state.1.push(id);
        state.0.extend(response);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "propmap")]
impl Transport for MultiModelTransport {
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

/// Paths in `dump` that sit under a known model branch other than the selected one.
#[cfg(feature = "propmap")]
fn inactive_branch_entries<'a>(dump: &'a NodeDump, selector: &str, selected: &str) -> Vec<&'a str> {
    let parent = selector.strip_suffix("/mdl").unwrap();
    let items = WingConsole::name_to_def(selector)
        .unwrap()
        .string_enum
        .clone()
        .unwrap();
    dump.entries
        .iter()
        .map(|entry| entry.fullname.as_str())
        .filter(|path| {
            path.strip_prefix(parent)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(|rest| {
                    rest.split('/')
                        .nth(1)
                        .map(|_| rest.split('/').next().unwrap())
                })
                .is_some_and(|branch| branch != selected && items.iter().any(|i| i.item == branch))
        })
        .collect()
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_follows_every_sibling_selector_under_one_root() {
    let models = [
        ("/ch/1/dyn/mdl", "E88"),
        ("/ch/1/eq/mdl", "SOUL"),
        ("/ch/1/flt/mdl", "MAX"),
        ("/ch/1/gate/mdl", "DUCK"),
    ];
    let transport = MultiModelTransport::new(&models);
    let dump = transport
        .console()
        .dump_subtree("/ch/1", Duration::from_millis(100))
        .unwrap();

    for (selector, model) in models {
        let entry = dump
            .entries
            .iter()
            .find(|entry| entry.fullname == selector)
            .expect("selector is captured");
        assert_eq!(entry.value, NodeValue::String(model.to_string()));
        let inactive = inactive_branch_entries(&dump, selector, model);
        assert!(
            inactive.is_empty(),
            "{selector}: inactive branches captured: {inactive:?}"
        );
    }
    assert!(dump
        .entries
        .iter()
        .any(|e| e.fullname == "/ch/1/flt/MAX/low"));
    assert!(dump.unknown_models.is_empty());

    let selector_ids: Vec<_> = models
        .iter()
        .map(|(path, _)| WingConsole::name_to_id(path).unwrap())
        .collect();
    assert_eq!(
        transport.requested()[..4],
        selector_ids[..],
        "selectors are read first"
    );
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_of_a_model_branch_depends_on_the_selector_above_it() {
    let selector_id = WingConsole::name_to_id("/ch/1/flt/mdl").unwrap();

    let active = MultiModelTransport::new(&[("/ch/1/flt/mdl", "MAX")]);
    let dump = active
        .console()
        .dump_subtree("/ch/1/flt/MAX", Duration::from_millis(100))
        .unwrap();
    assert!(!dump.entries.is_empty());
    assert!(dump
        .entries
        .iter()
        .all(|e| e.fullname.starts_with("/ch/1/flt/MAX/")));
    assert_eq!(active.requested().first(), Some(&selector_id));

    let inactive = MultiModelTransport::new(&[("/ch/1/flt/mdl", "TILT")]);
    let dump = inactive
        .console()
        .dump_subtree("/ch/1/flt/MAX", Duration::from_millis(100))
        .unwrap();
    assert!(
        dump.entries.is_empty(),
        "an inactive branch has nothing to capture"
    );
}

#[test]
#[cfg(feature = "propmap")]
fn dump_subtree_reports_a_model_the_embedded_map_does_not_know() {
    let transport = MultiModelTransport::new(&[("/fx/1/mdl", "FUTURE")]);
    let dump = transport
        .console()
        .dump_subtree("/fx/1", Duration::from_millis(100))
        .expect("an unknown model warns, it does not fail the dump");

    assert_eq!(dump.unknown_models, vec!["/fx/1/mdl".to_string()]);
    let selector = dump
        .entries
        .iter()
        .find(|e| e.fullname == "/fx/1/mdl")
        .unwrap();
    assert_eq!(selector.value, NodeValue::String("FUTURE".to_string()));
    let captured_branches = inactive_branch_entries(&dump, "/fx/1/mdl", "FUTURE");
    assert!(
        captured_branches.is_empty(),
        "known branches captured: {captured_branches:?}"
    );
}

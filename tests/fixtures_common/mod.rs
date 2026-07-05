//! Minimal loader for the `.wingcap` record-replay fixture format (see
//! `tests/fixtures/README.md` for the normative format description).
//!
//! Included via `#[path]` from `tests/replay.rs` only -- this is a test-only parser,
//! not a crate module, so it's kept intentionally small rather than promoted to
//! `src/` (U14 chose "the least clever working option" over adding a public,
//! versioned parsing API for a format nothing outside the test suite consumes).

use std::fs;
use std::path::{Path, PathBuf};

/// One parsed line from a `.wingcap` file (blank lines are dropped at load time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// `N>`: client -> console Native/TCP bytes the harness expects the console to
    /// have written.
    NativeOut(Vec<u8>),
    /// `N<`: console -> client Native/TCP bytes, scripted as the reader's input.
    NativeIn(Vec<u8>),
    /// `M<`: console -> client meter datagram body -- `i16` words, big-endian, in
    /// the same shape [`decode_frame`](libwing::decode_frame) expects (i.e. *after*
    /// the 4-byte meter-id header a real UDP datagram carries -- see
    /// [`crate::WingConsole::read_meters`]'s docs -- has already been stripped).
    MeterIn(Vec<u8>),
    /// `O<`: console -> client OSC datagram.
    OscIn(Vec<u8>),
    /// `O>`: client -> console OSC datagram (round-trip checked, not replayed
    /// against a live decoder).
    OscOut(Vec<u8>),
    /// `D<`: a WING discovery-reply UDP payload (ASCII, comma-separated).
    DiscoveryIn(Vec<u8>),
    /// `# expect: ...`: an assertion annotation, raw text after the prefix.
    Expect(String),
}

pub struct Fixture {
    pub path: PathBuf,
    /// Every `# key: value` header, in file order. Repeated keys (e.g. `note`,
    /// `request`) keep every occurrence -- see [`headers_all`](Self::headers_all).
    pub headers: Vec<(String, String)>,
    pub lines: Vec<Line>,
    /// Every raw non-blank line, verbatim, exactly as it appears in the file --
    /// used by the redaction guard, which scans independently of how this loader
    /// interprets each line.
    pub raw_lines: Vec<String>,
}

impl Fixture {
    /// The value of the first header matching `key`.
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every header value matching `key`, in file order.
    pub fn headers_all(&self, key: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Every `# expect: ...` annotation's text, in file order.
    pub fn expects(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::Expect(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Every `N<` line's bytes, concatenated in file order -- the full scripted
    /// input stream for a native scenario's reader.
    pub fn native_in(&self) -> Vec<u8> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::NativeIn(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Every `N>` line's bytes, one entry per line, in file order.
    pub fn native_out(&self) -> Vec<Vec<u8>> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::NativeOut(b) => Some(b.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Loads and parses a `.wingcap` file. Panics on any structural problem (unknown
/// line shape, bad hex) -- a malformed fixture is a bug in the fixture, not
/// something a replay test should have to handle gracefully.
pub fn load(path: &Path) -> Fixture {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    let mut headers = Vec::new();
    let mut lines = Vec::new();
    let mut raw_lines = Vec::new();

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        raw_lines.push(line.to_string());

        if let Some(rest) = line.strip_prefix("# expect:") {
            lines.push(Line::Expect(rest.trim().to_string()));
        } else if let Some(rest) = line.strip_prefix('#') {
            if let Some((key, value)) = rest.trim().split_once(':') {
                headers.push((key.trim().to_string(), value.trim().to_string()));
            }
            // A bare `#` comment with no `key: value` shape is decorative only.
        } else if let Some(rest) = line.strip_prefix("N>") {
            lines.push(Line::NativeOut(decode_hex(rest.trim())));
        } else if let Some(rest) = line.strip_prefix("N<") {
            lines.push(Line::NativeIn(decode_hex(rest.trim())));
        } else if let Some(rest) = line.strip_prefix("M<") {
            lines.push(Line::MeterIn(decode_hex(rest.trim())));
        } else if let Some(rest) = line.strip_prefix("O<") {
            lines.push(Line::OscIn(decode_hex(rest.trim())));
        } else if let Some(rest) = line.strip_prefix("O>") {
            lines.push(Line::OscOut(decode_hex(rest.trim())));
        } else if let Some(rest) = line.strip_prefix("D<") {
            lines.push(Line::DiscoveryIn(decode_hex(rest.trim())));
        } else {
            panic!("{path:?}: unrecognized fixture line: {line:?}");
        }
    }

    Fixture {
        path: path.to_path_buf(),
        headers,
        lines,
        raw_lines,
    }
}

pub fn decode_hex(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len() % 2 == 0, "odd-length hex string: {compact:?}");
    (0..compact.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&compact[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex byte {:?}: {e}", &compact[i..i + 2]))
        })
        .collect()
}

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Every `*.wingcap` path under [`fixtures_dir`], sorted for deterministic test
/// output.
pub fn all_fixture_paths() -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(fixtures_dir())
        .expect("tests/fixtures directory should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "wingcap"))
        .collect();
    paths.sort();
    paths
}

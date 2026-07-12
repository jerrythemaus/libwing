//! Capture-sanitization helper (U14: R81) -- redacts a raw `.wingcap` capture per
//! REDACTION.md, refusing to write an output file that would still fail the same scan
//! `tests/replay.rs`'s check-in guard runs, so nothing unsanitized can slip past this
//! tool and into a commit. See `tests/fixtures/README.md` for the full record ->
//! sanitize -> check-in workflow this feeds.
//!
//! ```text
//! Usage: wingcapture <input.raw.wingcap> <output.wingcap>
//!        wingcapture --record <host> <quarantine> <relative-output> [--seconds N]
//! ```
//!
//! `--record` is best-effort and untested against real hardware (none is reachable
//! from this environment): it opens a raw TCP connection to the console's Native port
//! and logs whatever arrives for `--seconds` (default 5) with nothing driving the
//! session, so it only captures unsolicited/keepalive traffic -- not a scripted
//! get/set exchange. It skips cleanly (prints a message, exits 0) if the console can't
//! be reached.
//!
//! Only the three mechanical classes REDACTION.md rule 3 names -- serials, IPv4
//! literals, MAC addresses -- are auto-detected and rewritten (see `redact.rs`).
//! Free-text identifiers (console/channel/show names) have no reliable pattern to
//! scan for; redact those by hand before running this tool.

#[path = "redact.rs"]
mod redact;
mod utils;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use libwing::native::{encode_channel, ChannelDecoder, NativeRequest, NativeRequestDecoder};

use utils::Args;

const SANITIZER_VERSION: &str = "wingcapture/2";
const REQUIRED_V2_HEADERS: [&str; 8] = [
    "scenario",
    "source",
    "console_model",
    "firmware",
    "capture_date",
    "sanitizer",
    "manual_redaction_attested",
    "expected_behavior",
];

fn main() {
    let mut args = Args::new(
        r#"
Usage: wingcapture <input.raw.wingcap> <output.wingcap>
       wingcapture --record <host> <quarantine> <relative-output> [--seconds N]
       wingcapture --init-quarantine <off-tree-directory>
       wingcapture --record-script <v2-script> <quarantine> <relative-output>
       wingcapture --sanitize-v2 <quarantine> <relative-raw> <candidate>
       wingcapture --preflight <candidate> <PROVENANCE.md>
       wingcapture --compare-v2 <hardware-candidate> <emulator-reference> <report>
       wingcapture --proxy-native <loopback-listen> <console-address> <quarantine> <relative-output> [--seconds N]
       wingcapture --capture-discovery <target> <quarantine> <relative-output> [--seconds N]
       wingcapture --capture-meters <native-proxy> <console-ip> <quarantine> <relative-output> --allow-state-changing [--seconds N]
       wingcapture --merge-v2 <quarantine> <relative-output> --allow-state-changing --destructive-write-approved=<true|false> --restore-verified --concurrent-definition-write-observed <partial>...
       wingcapture --dispose <relative-raw> <quarantine>
       wingcapture --purge-expired <quarantine> <hours>

  Sanitizes a raw wire-level capture per REDACTION.md (serials, non-TEST-NET IPs,
  MACs) and refuses to write an output file that still fails the check-in guard
  (tests/replay.rs) runs against every checked-in fixture. Free-text names
  (console/channel/show/scribble names) are NOT auto-detected -- redact those by
  hand per REDACTION.md's table before running this tool.

  --record is best-effort live capture; see the module doc comment in
  tools/wingcapture.rs. Skips cleanly if no console is reachable.
"#,
    );

    let first = args.next();
    let result = match first.as_str() {
        "--record" => {
            record(&mut args);
            return;
        }
        "--init-quarantine" => prepare_quarantine(
            Path::new(&args.next()),
            Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .map(|path| format!("private quarantine ready at {}", path.display())),
        "--record-script" => {
            let script = PathBuf::from(args.next());
            let quarantine = PathBuf::from(args.next());
            let output = PathBuf::from(args.next());
            record_script(&script, &quarantine, &output)
                .map(|path| format!("wrote sensitive raw capture to {}", path.display()))
        }
        "--sanitize-v2" => {
            let quarantine = PathBuf::from(args.next());
            let raw = PathBuf::from(args.next());
            let candidate = PathBuf::from(args.next());
            sanitize_from_quarantine(&quarantine, &raw, &candidate)
                .map(|_| format!("wrote sanitized candidate to {}", candidate.display()))
        }
        "--preflight" => {
            let candidate = PathBuf::from(args.next());
            let provenance = PathBuf::from(args.next());
            preflight(&candidate, &provenance).map(|_| "promotion preflight passed".to_string())
        }
        "--compare-v2" => {
            let hardware = PathBuf::from(args.next());
            let emulator = PathBuf::from(args.next());
            let report = PathBuf::from(args.next());
            compare_v2(&hardware, &emulator, &report)
                .map(|count| format!("wrote comparison report with {count} deviation(s)"))
        }
        "--proxy-native" => {
            proxy_native(&mut args);
            return;
        }
        "--capture-discovery" => {
            capture_discovery(&mut args);
            return;
        }
        "--capture-meters" => {
            capture_meters(&mut args);
            return;
        }
        "--merge-v2" => {
            merge_v2(&mut args);
            return;
        }
        "--dispose" => {
            let raw = PathBuf::from(args.next());
            let quarantine = PathBuf::from(args.next());
            quarantine_output(&quarantine, &raw)
                .and_then(|path| cleanup_raw(&path))
                .map(|_| "raw capture deleted".to_string())
        }
        "--purge-expired" => {
            let quarantine = PathBuf::from(args.next());
            let hours: u64 = args
                .next()
                .parse()
                .map_err(|e| format!("invalid retention hours: {e}"))
                .unwrap_or_else(|e| fail(&e));
            purge_expired(&quarantine, Duration::from_secs(hours.saturating_mul(3600)))
                .map(|paths| format!("deleted {} expired raw capture(s)", paths.len()))
        }
        _ => {
            let output_path = args.next();
            sanitize_file(&first, &output_path)
                .map(|_| format!("wrote sanitized capture to {output_path}"))
        }
    };
    match result {
        Ok(message) => println!("{message}"),
        Err(error) => fail(&error),
    }
}

fn fail(error: &str) -> ! {
    eprintln!("wingcapture: {error}");
    std::process::exit(1)
}

/// Reads `input_path` as a `.wingcap` file, redacts every payload line via
/// [`redact::redact_bytes`], verifies the result is clean, and writes `output_path`.
fn sanitize_file(input_path: &str, output_path: &str) -> Result<(), String> {
    let text = fs::read_to_string(input_path).map_err(|e| format!("reading {input_path}: {e}"))?;
    let mut out_lines = Vec::new();
    let mut saw_sanitizer_header = false;

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            // Header/comment lines are never expected to carry identifiers (the
            // format only puts model/firmware/scenario/dates there) -- reject
            // rather than silently rewrite free text that might be a show/channel
            // name embedded in a `# note:` line.
            let findings = redact::scan_str(rest);
            if !findings.is_empty() {
                return Err(format!(
                    "header/comment line carries un-redacted content, edit by hand: \
                     {line:?} ({findings:?})"
                ));
            }
            if rest.trim_start().starts_with("sanitizer:") {
                saw_sanitizer_header = true;
                out_lines.push(format!("# sanitizer: {SANITIZER_VERSION}"));
                continue;
            }
            out_lines.push(line.to_string());
            continue;
        }

        let (prefix, hex) = split_capture_line(line)
            .ok_or_else(|| format!("unrecognized fixture line: {line:?}"))?;
        let bytes = decode_hex(hex.trim()).map_err(|e| format!("{line:?}: {e}"))?;
        let redacted = redact::redact_bytes(&bytes).map_err(|e| format!("{line:?}: {e}"))?;
        out_lines.push(format!("{prefix} {}", encode_hex(&redacted)));
    }

    if !saw_sanitizer_header {
        out_lines.insert(0, format!("# sanitizer: {SANITIZER_VERSION}"));
    }

    // Refuse to emit anything the check-in guard (tests/replay.rs) would still
    // reject -- re-run the identical scan over what's about to be written.
    for line in &out_lines {
        if let Some(rest) = line.strip_prefix('#') {
            if !redact::scan_str(rest).is_empty() {
                return Err(format!("sanitized output still fails the scan: {line:?}"));
            }
        } else if let Some((_prefix, hex)) = split_capture_line(line) {
            if let Ok(bytes) = decode_hex(hex.trim()) {
                if !redact::scan(&bytes).is_empty() {
                    return Err(format!("sanitized output still fails the scan: {line:?}"));
                }
            }
        }
    }

    let mut output = out_lines.join("\n");
    output.push('\n');
    fs::write(output_path, output).map_err(|e| format!("writing {output_path}: {e}"))?;
    Ok(())
}

fn split_capture_line(line: &str) -> Option<(String, &str)> {
    if line.starts_with('@') {
        let mut fields = line.splitn(4, char::is_whitespace);
        let ordinal = fields.next()?;
        let offset = fields.next()?;
        let channel = fields.next()?;
        let hex = fields.next().unwrap_or("").trim();
        return Some((format!("{ordinal} {offset} {channel}"), hex));
    }
    split_prefix(line).map(|(prefix, hex)| (prefix.to_string(), hex))
}

/// Splits a data line into its 2-character channel prefix (`N>`, `N<`, `M<`, `O<`,
/// `O>`, `D<`) and the remaining hex text.
fn split_prefix(line: &str) -> Option<(&str, &str)> {
    for prefix in ["N>", "N<", "M<", "O<", "O>", "D<"] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return Some((prefix, rest));
        }
    }
    None
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, PartialEq, Eq)]
struct CaptureSummary {
    version: u8,
    event_count: usize,
}

const HARDWARE_MATRIX: &str = "wing-rack-3.1-v1";

#[derive(Default)]
struct MatrixEvidence {
    discovery_request: bool,
    discovery_reply: bool,
    native_in: Vec<u8>,
    native_out: Vec<u8>,
    meter_frames: usize,
    meter_tokens: BTreeSet<u32>,
    disconnect: bool,
}

fn validate_hardware_matrix(
    headers: &BTreeMap<String, String>,
    evidence: MatrixEvidence,
) -> Result<(), String> {
    let require_true = |key: &str| match headers.get(key).map(String::as_str) {
        Some("true") => Ok(()),
        _ => Err(format!("hardware matrix requires {key}: true")),
    };
    if headers.get("matrix_contract").map(String::as_str) != Some(HARDWARE_MATRIX) {
        return Err(format!(
            "hardware capture requires matrix_contract: {HARDWARE_MATRIX}"
        ));
    }
    require_true("state_changing_write_approved")?;
    match headers
        .get("destructive_write_approved")
        .map(String::as_str)
    {
        Some("true" | "false") => {}
        _ => {
            return Err(
                "hardware matrix requires explicit destructive_write_approved: true|false"
                    .to_string(),
            )
        }
    }
    require_true("restore_verified")?;
    require_true("concurrent_definition_write_observed")?;
    require_true("disconnect_observed")?;
    match headers.get("meter_cardinality_verdict").map(String::as_str) {
        Some("replaces" | "concurrent" | "ambiguous") => {}
        _ => {
            return Err(
                "hardware matrix requires meter_cardinality_verdict: replaces|concurrent|ambiguous"
                    .to_string(),
            )
        }
    }
    if !evidence.discovery_request || !evidence.discovery_reply {
        return Err("hardware matrix is missing discovery request/reply".to_string());
    }
    if evidence.native_in.is_empty() {
        return Err("hardware matrix is missing console-to-client Native traffic".to_string());
    }
    if evidence.meter_frames < 2 {
        return Err("hardware matrix requires at least two raw meter frames".to_string());
    }
    if !evidence.disconnect {
        return Err("hardware matrix is missing an explicit empty N< disconnect event".to_string());
    }
    let mut response_framing = ChannelDecoder::default();
    response_framing
        .push(&evidence.native_in)
        .map_err(|error| format!("invalid Native response framing: {error}"))?;
    response_framing
        .finish()
        .map_err(|error| format!("incomplete Native response framing: {error}"))?;

    let mut decoder = NativeRequestDecoder::default();
    let requests = decoder
        .push(&evidence.native_out)
        .map_err(|error| format!("invalid Native request stream: {error}"))?;
    decoder
        .finish()
        .map_err(|error| format!("incomplete Native request stream: {error}"))?;
    let mut get = false;
    let mut definition = false;
    let mut set = false;
    let mut subscribe = BTreeSet::new();
    let mut renew = BTreeSet::new();
    let mut keepalive = false;
    for request in requests {
        match request {
            NativeRequest::Get { .. } | NativeRequest::BulkData { .. } => get = true,
            NativeRequest::Definition { .. } | NativeRequest::BulkDefinition { .. } => {
                definition = true
            }
            NativeRequest::Set { .. }
            | NativeRequest::Toggle { .. }
            | NativeRequest::Step { .. } => set = true,
            NativeRequest::MeterSubscribe { report_id, .. } => {
                subscribe.insert(report_id);
            }
            NativeRequest::MeterRenew { report_id } => {
                renew.insert(report_id);
            }
            NativeRequest::KeepAlive { .. } => keepalive = true,
            _ => {}
        }
    }
    let missing = [
        (!get, "get/data"),
        (!definition, "definition"),
        (!set, "state-changing write"),
        (subscribe.len() < 2, "two distinct meter subscriptions"),
        (renew.len() < 2, "renewals for two distinct meter reports"),
        (
            !subscribe.iter().all(|id| renew.contains(id)),
            "a renewal for every subscribed meter report",
        ),
        (
            !subscribe
                .iter()
                .all(|id| evidence.meter_tokens.contains(&(id & 0xffff_0000))),
            "a raw frame for every subscribed meter report",
        ),
        (!keepalive, "Native keepalive/handshake"),
    ]
    .into_iter()
    .filter_map(|(missing, label)| missing.then_some(label))
    .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("hardware matrix is missing {}", missing.join(", ")))
    }
}

/// Parses the complete promotion-facing format. V1 remains accepted by the replay
/// loader and positional sanitizer, but only V2 is eligible for promotion.
fn parse_capture(text: &str) -> Result<CaptureSummary, String> {
    parse_capture_with_policy(text, true)
}

fn parse_capture_structure(text: &str) -> Result<CaptureSummary, String> {
    parse_capture_with_policy(text, false)
}

fn parse_capture_with_policy(text: &str, promotion: bool) -> Result<CaptureSummary, String> {
    let mut headers = BTreeMap::new();
    let mut channels = BTreeSet::new();
    let mut expected_ordinal = 1u64;
    let mut previous_offset = 0u64;
    let mut event_count = 0usize;
    let mut matrix = MatrixEvidence::default();

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if promotion && !redact::scan_str(rest).is_empty() {
                return Err(format!("sensitive identifier in metadata: {line:?}"));
            }
            if let Some((key, value)) = rest.trim().split_once(':') {
                headers
                    .entry(key.trim().to_string())
                    .or_insert_with(|| value.trim().to_string());
            }
            continue;
        }
        let (prefix, hex) = split_capture_line(line)
            .ok_or_else(|| format!("unrecognized capture line {line:?}"))?;
        if !prefix.starts_with('@') {
            continue;
        }
        let mut fields = prefix.split_whitespace();
        let ordinal = fields
            .next()
            .and_then(|value| value.strip_prefix('@'))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| format!("invalid event ordinal in {line:?}"))?;
        if ordinal != expected_ordinal {
            return Err(format!(
                "event ordinal {ordinal} is not the expected {expected_ordinal}"
            ));
        }
        expected_ordinal += 1;
        let offset = fields
            .next()
            .and_then(|value| value.strip_prefix('+'))
            .and_then(|value| value.strip_suffix("us"))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| format!("invalid event offset in {line:?}"))?;
        if offset < previous_offset {
            return Err(format!("event offsets are not monotonic in {line:?}"));
        }
        previous_offset = offset;
        let channel = fields
            .next()
            .ok_or_else(|| format!("missing event channel in {line:?}"))?;
        if !matches!(
            channel,
            "D>" | "D<" | "N>" | "N<" | "M>" | "M<" | "O>" | "O<"
        ) {
            return Err(format!("unknown event channel {channel:?}"));
        }
        let bytes = decode_hex(hex).map_err(|error| format!("{line:?}: {error}"))?;
        if channel == "M<" && bytes.len() < 4 {
            return Err("V2 meter input omits the four-byte report token".to_string());
        }
        if promotion && !redact::scan(&bytes).is_empty() {
            return Err(format!("sensitive identifier in event {ordinal}"));
        }
        channels.insert(channel.to_string());
        match channel {
            "D>" => matrix.discovery_request |= bytes.starts_with(b"WING?"),
            "D<" => matrix.discovery_reply |= bytes.starts_with(b"WING,"),
            "N>" => matrix.native_out.extend_from_slice(&bytes),
            "N<" => {
                matrix.native_in.extend_from_slice(&bytes);
                matrix.disconnect |= bytes.is_empty();
            }
            "M>" => matrix.native_out.extend_from_slice(&bytes),
            "M<" => {
                matrix.meter_frames += 1;
                if let Ok(token) = <[u8; 4]>::try_from(&bytes[..4]) {
                    matrix.meter_tokens.insert(u32::from_be_bytes(token));
                }
            }
            _ => {}
        }
        event_count += 1;
    }

    let version = headers
        .get("wingcap_version")
        .map(String::as_str)
        .unwrap_or("1")
        .parse::<u8>()
        .map_err(|error| format!("invalid wingcap_version: {error}"))?;
    if version != 2 {
        return Err("promotion requires wingcap_version: 2".to_string());
    }
    for key in REQUIRED_V2_HEADERS {
        let value = headers
            .get(key)
            .filter(|value| !value.is_empty() && !value.contains("FILL-ME-IN"))
            .ok_or_else(|| format!("missing required V2 metadata: {key}"))?;
        if promotion && key == "manual_redaction_attested" && value != "true" {
            return Err("manual free-text redaction attestation must be true".to_string());
        }
    }
    if promotion {
        for channel in ["D>", "D<", "N>", "N<", "M>", "M<"] {
            if !channels.contains(channel) {
                return Err(format!("complete V2 capture is missing {channel} events"));
            }
        }
    }
    if promotion
        && headers
            .get("source")
            .is_some_and(|source| source == "hardware")
        && headers
            .get("sanitizer")
            .is_none_or(|value| value == "n/a" || value.is_empty())
    {
        return Err("hardware capture is missing a sanitizer version".to_string());
    }
    if promotion
        && headers
            .get("source")
            .is_some_and(|source| source == "hardware")
    {
        validate_hardware_matrix(&headers, matrix)?;
    }
    Ok(CaptureSummary {
        version,
        event_count,
    })
}

fn preflight_text(text: &str) -> Result<CaptureSummary, String> {
    if text.to_ascii_lowercase().contains("wingemul") || text.to_ascii_lowercase().contains("wapi")
    {
        return Err("capture references a prohibited vendor-derived source".to_string());
    }
    parse_capture(text)
}

fn preflight(candidate: &Path, provenance: &Path) -> Result<(), String> {
    let text = fs::read_to_string(candidate)
        .map_err(|error| format!("reading candidate {}: {error}", candidate.display()))?;
    preflight_text(&text)?;
    let provenance_text = fs::read_to_string(provenance)
        .map_err(|error| format!("reading provenance {}: {error}", provenance.display()))?;
    let name = candidate
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "candidate has no UTF-8 file name".to_string())?;
    if !provenance_text.contains(name) {
        return Err(format!(
            "provenance record {} does not name {name}",
            provenance.display()
        ));
    }
    Ok(())
}

fn contract_events(text: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    parse_capture_structure(text)?;
    text.lines()
        .filter(|line| line.starts_with('@'))
        .map(|line| {
            let (prefix, hex) = split_capture_line(line)
                .ok_or_else(|| format!("unrecognized capture event: {line:?}"))?;
            let channel = prefix
                .split_whitespace()
                .nth(2)
                .ok_or_else(|| format!("missing channel in {line:?}"))?;
            Ok((channel.to_string(), decode_hex(hex)?))
        })
        .collect()
}

fn compare_v2(hardware: &Path, emulator: &Path, report: &Path) -> Result<usize, String> {
    const MAX_COMPARISON_EVENTS: usize = 100_000;
    const MAX_REPORTED_DEVIATIONS: usize = 1_024;
    let hardware_text = fs::read_to_string(hardware)
        .map_err(|error| format!("reading hardware candidate {}: {error}", hardware.display()))?;
    let emulator_text = fs::read_to_string(emulator)
        .map_err(|error| format!("reading emulator reference {}: {error}", emulator.display()))?;
    let hardware_events = contract_events(&hardware_text)?;
    let emulator_events = contract_events(&emulator_text)?;
    let count = hardware_events.len().max(emulator_events.len());
    if count > MAX_COMPARISON_EVENTS {
        return Err(format!(
            "comparison has {count} events, exceeding limit {MAX_COMPARISON_EVENTS}"
        ));
    }
    let mut deviations = Vec::new();
    let mut deviation_count = 0usize;
    for index in 0..count {
        match (hardware_events.get(index), emulator_events.get(index)) {
            (
                Some((hardware_channel, hardware_bytes)),
                Some((emulator_channel, emulator_bytes)),
            ) if hardware_channel == emulator_channel && hardware_bytes == emulator_bytes => {}
            (hardware_event, emulator_event) => {
                deviation_count += 1;
                if deviations.len() < MAX_REPORTED_DEVIATIONS {
                    deviations.push(format!(
                        "event {} hardware={} emulator={}",
                        index + 1,
                        describe_event(hardware_event),
                        describe_event(emulator_event)
                    ));
                }
            }
        }
    }
    let hardware_name = hardware
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("hardware");
    let emulator_name = emulator
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("emulator");
    let mut output = format!(
        "# WING capture deviation report\n# hardware: {}\n# emulator: {}\n# deviations: {}\n",
        hardware_name, emulator_name, deviation_count
    );
    for deviation in &deviations {
        output.push_str(deviation);
        output.push('\n');
    }
    if deviation_count > deviations.len() {
        output.push_str(&format!(
            "truncated: {} additional deviation(s)\n",
            deviation_count - deviations.len()
        ));
    }
    fs::write(report, output)
        .map_err(|error| format!("writing comparison report {}: {error}", report.display()))?;
    Ok(deviation_count)
}

fn describe_event(event: Option<&(String, Vec<u8>)>) -> String {
    event.map_or_else(
        || "<missing>".to_string(),
        |(channel, bytes)| format!("{channel}:{}", encode_hex(bytes)),
    )
}

fn is_synchronized(path: &Path) -> bool {
    const NAMES: [&str; 8] = [
        "dropbox",
        "onedrive",
        "google drive",
        "googledrive",
        "icloud drive",
        "mobile documents",
        "syncthing",
        "box sync",
    ];
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        NAMES.iter().any(|name| value.contains(name))
    })
}

fn prepare_quarantine(root: &Path, repository: &Path) -> Result<PathBuf, String> {
    if is_synchronized(root) {
        return Err("quarantine cannot use a known synchronized destination".to_string());
    }
    let repository = repository
        .canonicalize()
        .map_err(|error| format!("resolving repository: {error}"))?;
    if root.is_absolute() && root.starts_with(&repository) {
        return Err("quarantine must be outside the repository".to_string());
    }
    if root.exists()
        && root
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("quarantine root cannot be a symlink".to_string());
    }
    fs::create_dir_all(root)
        .map_err(|error| format!("creating quarantine {}: {error}", root.display()))?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolving quarantine {}: {error}", root.display()))?;
    if is_synchronized(&root) {
        return Err("quarantine cannot resolve into a synchronized destination".to_string());
    }
    if root.starts_with(&repository) || repository.starts_with(&root) {
        return Err("quarantine must be outside the repository".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("securing quarantine {}: {error}", root.display()))?;
    }
    validate_private_permissions(&root)?;
    Ok(root)
}

fn validate_private_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|error| format!("reading permissions for {}: {error}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is not owner-only (mode {mode:o})",
                path.display()
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(format!(
            "cannot verify owner-only permissions for {} on this platform",
            path.display()
        ))
    }
}

fn quarantine_output(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("capture path must be a plain relative path without traversal".to_string());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolving quarantine {}: {error}", root.display()))?;
    validate_private_permissions(&root)?;
    let candidate = root.join(relative);
    let mut parent = root.clone();
    let parent_components = relative
        .parent()
        .ok_or_else(|| "capture path has no parent".to_string())?;
    for component in parent_components.components() {
        parent.push(component);
        if parent.exists() {
            let metadata = parent
                .symlink_metadata()
                .map_err(|error| format!("reading capture directory: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("capture path escapes quarantine through an unsafe entry".to_string());
            }
        } else {
            fs::create_dir(&parent)
                .map_err(|error| format!("creating capture directory: {error}"))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("securing capture directory: {error}"))?;
        }
        validate_private_permissions(&parent)?;
        let resolved = parent
            .canonicalize()
            .map_err(|error| format!("resolving capture directory: {error}"))?;
        if !resolved.starts_with(&root) {
            return Err("capture path escapes quarantine through a symlink".to_string());
        }
    }
    if candidate.exists() {
        if candidate
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("capture path cannot be a symlink".to_string());
        }
        let resolved = candidate
            .canonicalize()
            .map_err(|error| format!("resolving capture path: {error}"))?;
        if !resolved.starts_with(&root) {
            return Err("capture path escapes quarantine".to_string());
        }
    }
    Ok(candidate)
}

fn write_private(root: &Path, relative: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let path = quarantine_output(root, relative)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("creating private capture {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("securing capture {}: {error}", path.display()))?;
    }
    file.write_all(bytes)
        .map_err(|error| format!("writing capture {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("syncing capture {}: {error}", path.display()))?;
    Ok(path)
}

fn record_script(script: &Path, quarantine: &Path, output: &Path) -> Result<PathBuf, String> {
    let text = fs::read_to_string(script)
        .map_err(|error| format!("reading script {}: {error}", script.display()))?;
    parse_capture_structure(&text)?;
    let quarantine = prepare_quarantine(quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))?;
    write_private(&quarantine, output, text.as_bytes())
}

fn sanitize_from_quarantine(quarantine: &Path, raw: &Path, candidate: &Path) -> Result<(), String> {
    let raw = quarantine_output(quarantine, raw)?;
    validate_private_permissions(quarantine)?;
    validate_review_candidate(candidate)?;
    sanitize_file(
        raw.to_str()
            .ok_or_else(|| "raw capture path is not UTF-8".to_string())?,
        candidate
            .to_str()
            .ok_or_else(|| "candidate path is not UTF-8".to_string())?,
    )?;
    preflight_text(
        &fs::read_to_string(candidate)
            .map_err(|error| format!("reading sanitized candidate: {error}"))?,
    )?;
    Ok(())
}

fn validate_review_candidate(candidate: &Path) -> Result<(), String> {
    if is_synchronized(candidate) {
        return Err("sanitized candidate cannot use a known synchronized destination".to_string());
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .map_err(|error| format!("resolving repository: {error}"))?;
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolving current directory: {error}"))?
            .join(candidate)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| "sanitized candidate has no parent directory".to_string())?;
    let parent = parent
        .canonicalize()
        .map_err(|error| format!("resolving sanitized review directory: {error}"))?;
    if parent.starts_with(&repository) || repository.starts_with(&parent) {
        return Err(
            "sanitized candidate must remain outside the repository until review".to_string(),
        );
    }
    Ok(())
}

fn cleanup_raw(path: &Path) -> Result<(), String> {
    fs::remove_file(path)
        .map_err(|error| format!("deleting raw capture {}: {error}", path.display()))
}

fn purge_expired(root: &Path, retention: Duration) -> Result<Vec<PathBuf>, String> {
    if root
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("quarantine root cannot be a symlink".to_string());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolving quarantine {}: {error}", root.display()))?;
    validate_private_permissions(&root)?;
    let now = SystemTime::now();
    let mut deleted = Vec::new();
    purge_directory(&root, &root, retention, now, &mut deleted)?;
    Ok(deleted)
}

fn purge_directory(
    root: &Path,
    directory: &Path,
    retention: Duration,
    now: SystemTime,
    deleted: &mut Vec<PathBuf>,
) -> Result<(), String> {
    validate_private_permissions(directory)?;
    let resolved = directory
        .canonicalize()
        .map_err(|error| format!("resolving {}: {error}", directory.display()))?;
    if !resolved.starts_with(root) {
        return Err(format!("{} escapes quarantine", directory.display()));
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("reading quarantine {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("reading quarantine entry: {error}"))?;
        let path = entry.path();
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("reading {} metadata: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("unsafe symlink in quarantine: {}", path.display()));
        }
        if metadata.is_dir() {
            purge_directory(root, &path, retention, now, deleted)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "unsafe non-file entry in quarantine: {}",
                path.display()
            ));
        }
        validate_private_permissions(&path)?;
        let resolved = path
            .canonicalize()
            .map_err(|error| format!("resolving {}: {error}", path.display()))?;
        if !resolved.starts_with(root) {
            return Err(format!("{} escapes quarantine", path.display()));
        }
        let age = now
            .duration_since(
                metadata
                    .modified()
                    .map_err(|error| format!("reading modified time: {error}"))?,
            )
            .unwrap_or_default();
        if age >= retention {
            cleanup_raw(&path)?;
            deleted.push(path);
        }
    }
    Ok(())
}

const PROXY_MAX_EVENTS: usize = 100_000;
const PROXY_MAX_BYTES: usize = 16 * 1024 * 1024;
type CapturedEvent = (u64, &'static str, Vec<u8>);

struct ProxyRecorder {
    started: Instant,
    events: Vec<CapturedEvent>,
    bytes: usize,
}

impl ProxyRecorder {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            events: Vec::new(),
            bytes: 0,
        }
    }

    fn record(&mut self, channel: &'static str, bytes: &[u8]) -> Result<(), String> {
        if self.events.len() >= PROXY_MAX_EVENTS
            || self.bytes.saturating_add(bytes.len()) > PROXY_MAX_BYTES
        {
            return Err(format!(
                "Native proxy capture exceeded {} events or {} bytes",
                PROXY_MAX_EVENTS, PROXY_MAX_BYTES
            ));
        }
        self.bytes += bytes.len();
        let offset = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.events.push((offset, channel, bytes.to_vec()));
        Ok(())
    }

    fn into_v2(self) -> String {
        events_to_v2(
            "native_proxy_raw",
            "bounded transparent Native proxy transcript",
            self.events,
        )
    }
}

fn events_to_v2(scenario: &str, expected_behavior: &str, events: Vec<CapturedEvent>) -> String {
    let mut output = format!(
        "# wingcap_version: 2\n\
         # scenario: {scenario}\n\
         # source: hardware\n\
         # console_model: pending-manual-entry\n\
         # firmware: pending-manual-entry\n\
         # capture_date: pending-manual-entry\n\
         # sanitizer: pending\n\
         # manual_redaction_attested: false\n\
         # expected_behavior: {expected_behavior}\n\
         # state_changing_write_approved: true\n\
         # destructive_write_approved: false\n"
    );
    for (index, (offset, channel, bytes)) in events.into_iter().enumerate() {
        output.push_str(&format!(
            "@{} +{}us {} {}\n",
            index + 1,
            offset,
            channel,
            encode_hex(&bytes)
        ));
    }
    output
}

fn proxy_direction(
    mut source: TcpStream,
    mut destination: TcpStream,
    channel: &'static str,
    recorder: Arc<Mutex<ProxyRecorder>>,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<(), String> {
    source
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|error| format!("setting proxy read timeout: {error}"))?;
    let mut buffer = [0u8; 8192];
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        match source.read(&mut buffer) {
            Ok(0) => {
                let record = recorder
                    .lock()
                    .map_err(|_| "Native proxy recorder lock poisoned".to_string())?
                    .record(channel, &[]);
                stop.store(true, Ordering::Release);
                let _ = destination.shutdown(Shutdown::Write);
                return record;
            }
            Ok(count) => {
                let record = recorder
                    .lock()
                    .map_err(|_| "Native proxy recorder lock poisoned".to_string())?
                    .record(channel, &buffer[..count]);
                if let Err(error) = record {
                    stop.store(true, Ordering::Release);
                    let _ = destination.shutdown(Shutdown::Both);
                    return Err(error);
                }
                if let Err(error) = destination.write_all(&buffer[..count]) {
                    if stop.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    stop.store(true, Ordering::Release);
                    let _ = destination.shutdown(Shutdown::Both);
                    return Err(format!("forwarding {channel}: {error}"));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) if stop.load(Ordering::Acquire) => return Ok(()),
            Err(error) => return Err(format!("reading {channel}: {error}")),
        }
    }
    stop.store(true, Ordering::Release);
    let _ = destination.shutdown(Shutdown::Both);
    Ok(())
}

fn run_native_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<String, String> {
    if !listener
        .local_addr()
        .map_err(|error| format!("reading proxy listener: {error}"))?
        .ip()
        .is_loopback()
    {
        return Err("Native capture proxy must listen on loopback".to_string());
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configuring proxy listener: {error}"))?;
    let deadline = Instant::now() + timeout;
    let client = loop {
        match listener.accept() {
            Ok((client, _)) => break client,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for Native proxy client".to_string());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("accepting Native proxy client: {error}")),
        }
    };
    let upstream = TcpStream::connect_timeout(&upstream, Duration::from_secs(2))
        .map_err(|error| format!("connecting Native proxy upstream: {error}"))?;
    let recorder = Arc::new(Mutex::new(ProxyRecorder::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let client_to_console = thread::spawn({
        let source = client
            .try_clone()
            .map_err(|error| format!("cloning proxy client: {error}"))?;
        let destination = upstream
            .try_clone()
            .map_err(|error| format!("cloning proxy upstream: {error}"))?;
        let recorder = Arc::clone(&recorder);
        let stop = Arc::clone(&stop);
        move || proxy_direction(source, destination, "N>", recorder, stop, deadline)
    });
    let console_to_client = thread::spawn({
        let recorder = Arc::clone(&recorder);
        let stop = Arc::clone(&stop);
        move || proxy_direction(upstream, client, "N<", recorder, stop, deadline)
    });
    for worker in [client_to_console, console_to_client] {
        worker
            .join()
            .map_err(|_| "Native proxy worker panicked".to_string())??;
    }
    let recorder = Arc::try_unwrap(recorder)
        .map_err(|_| "Native proxy recorder still shared during teardown".to_string())?
        .into_inner()
        .map_err(|_| "Native proxy recorder lock poisoned".to_string())?;
    Ok(recorder.into_v2())
}

fn proxy_native(args: &mut Args) {
    let listen: SocketAddr = args
        .next()
        .parse()
        .unwrap_or_else(|_| fail("invalid loopback proxy listen address"));
    if !listen.ip().is_loopback() {
        fail("Native capture proxy must listen on loopback");
    }
    let upstream: SocketAddr = args
        .next()
        .parse()
        .unwrap_or_else(|_| fail("invalid console socket address"));
    let quarantine = PathBuf::from(args.next());
    let relative_output = PathBuf::from(args.next());
    if args.next() != "--allow-state-changing" {
        fail("Native proxy requires explicit --allow-state-changing approval");
    }
    let mut seconds = 30u64;
    if args.has_next() {
        if args.next() != "--seconds" {
            fail("expected --seconds after --allow-state-changing");
        }
        seconds = args
            .next()
            .parse()
            .unwrap_or_else(|_| fail("invalid proxy duration"));
    }
    let quarantine = prepare_quarantine(&quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| fail(&error));
    let listener = TcpListener::bind(listen)
        .unwrap_or_else(|error| fail(&format!("binding Native proxy listener {listen}: {error}")));
    let effective = listener
        .local_addr()
        .unwrap_or_else(|error| fail(&format!("reading Native proxy listener: {error}")));
    println!("Native proxy ready at {effective}");
    let capture = run_native_proxy(listener, upstream, Duration::from_secs(seconds))
        .unwrap_or_else(|error| fail(&error));
    parse_capture_structure(&capture).unwrap_or_else(|error| fail(&error));
    let path = write_private(&quarantine, &relative_output, capture.as_bytes())
        .unwrap_or_else(|error| fail(&error));
    println!("wrote private Native transcript to {}", path.display());
}

fn capture_discovery_session(
    socket: UdpSocket,
    target: SocketAddr,
    timeout: Duration,
) -> Result<String, String> {
    let started = Instant::now();
    let deadline = started + timeout;
    socket
        .send_to(b"WING?", target)
        .map_err(|error| format!("sending discovery request: {error}"))?;
    let mut events = vec![(0, "D>", b"WING?".to_vec())];
    let mut buffer = [0u8; 2048];
    for _ in 0..100 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("discovery capture deadline expired".to_string());
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("setting discovery timeout: {error}"))?;
        let (count, source) = socket
            .recv_from(&mut buffer)
            .map_err(|error| format!("receiving discovery reply: {error}"))?;
        if source != target {
            continue;
        }
        let offset = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        events.push((offset, "D<", buffer[..count].to_vec()));
        return Ok(events_to_v2(
            "discovery_raw",
            "direct WING discovery request and reply",
            events,
        ));
    }
    Err("discovery capture exceeded 100 datagrams".to_string())
}

fn meter_subscribe_wire(port: u16, report_id: u32, meter: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload = vec![0xd3];
    payload.extend_from_slice(&port.to_be_bytes());
    payload.push(0xd4);
    payload.extend_from_slice(&report_id.to_be_bytes());
    payload.push(0xdc);
    payload.extend_from_slice(meter);
    payload.push(0xde);
    encode_channel(3, &payload).map_err(|error| format!("encoding meter subscription: {error}"))
}

fn meter_renew_wire(report_id: u32) -> Result<Vec<u8>, String> {
    let mut payload = vec![0xd4];
    payload.extend_from_slice(&report_id.to_be_bytes());
    let mut wire =
        encode_channel(3, &payload).map_err(|error| format!("encoding meter renewal: {error}"))?;
    wire.extend_from_slice(
        &encode_channel(1, &[]).map_err(|error| format!("flushing meter renewal: {error}"))?,
    );
    Ok(wire)
}

fn capture_meter_session(
    mut native: TcpStream,
    meter_socket: UdpSocket,
    expected_source: IpAddr,
    timeout: Duration,
) -> Result<String, String> {
    let port = meter_socket
        .local_addr()
        .map_err(|error| format!("reading meter socket: {error}"))?
        .port();
    let started = Instant::now();
    let deadline = started + timeout;
    let mut datagrams = 0usize;
    let mut events = Vec::new();
    let mut buffer = [0u8; 8192];
    for (token, meter) in [(1u16, &[0xa0, 0x00][..]), (2u16, &[0xaa][..])] {
        let report_id = u32::from(token) << 16 | u32::from(port);
        let subscribe = meter_subscribe_wire(port, report_id, meter)?;
        native
            .write_all(&subscribe)
            .map_err(|error| format!("sending meter subscription {report_id}: {error}"))?;
        events.push((
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "M>",
            subscribe,
        ));
        let count = loop {
            datagrams += 1;
            if datagrams > 100 {
                return Err("meter capture exceeded 100 datagrams".to_string());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("meter capture deadline expired".to_string());
            }
            meter_socket
                .set_read_timeout(Some(remaining))
                .map_err(|error| format!("setting meter timeout: {error}"))?;
            let (count, source) = meter_socket
                .recv_from(&mut buffer)
                .map_err(|error| format!("receiving meter report {report_id}: {error}"))?;
            if source.ip() == expected_source
                && count >= 4
                && u16::from_be_bytes(buffer[..2].try_into().expect("two bytes")) == token
                && buffer[2..4] == [0, 0]
            {
                break count;
            }
        };
        events.push((
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "M<",
            buffer[..count].to_vec(),
        ));
        let renew = meter_renew_wire(report_id)?;
        native
            .write_all(&renew)
            .map_err(|error| format!("sending meter renewal {report_id}: {error}"))?;
        events.push((
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "M>",
            renew,
        ));
    }
    let _ = native.shutdown(Shutdown::Both);
    Ok(events_to_v2(
        "meter_matrix_raw",
        "two Native meter subscriptions, token-bearing reports, and renewals",
        events,
    ))
}

fn capture_discovery(args: &mut Args) {
    let target: SocketAddr = args
        .next()
        .parse()
        .unwrap_or_else(|_| fail("invalid discovery target"));
    let quarantine = PathBuf::from(args.next());
    let output = PathBuf::from(args.next());
    let mut seconds = 5u64;
    if args.has_next() {
        if args.next() != "--seconds" {
            fail("expected --seconds");
        }
        seconds = args
            .next()
            .parse()
            .unwrap_or_else(|_| fail("invalid discovery duration"));
    }
    let quarantine = prepare_quarantine(&quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| fail(&error));
    let socket = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|error| fail(&format!("binding discovery socket: {error}")));
    let capture = capture_discovery_session(socket, target, Duration::from_secs(seconds))
        .unwrap_or_else(|error| fail(&error));
    let path = write_private(&quarantine, &output, capture.as_bytes())
        .unwrap_or_else(|error| fail(&error));
    println!("wrote private discovery transcript to {}", path.display());
}

fn capture_meters(args: &mut Args) {
    let native: SocketAddr = args
        .next()
        .parse()
        .unwrap_or_else(|_| fail("invalid Native proxy address"));
    if !native.ip().is_loopback() {
        fail("meter matrix driver must use the loopback Native proxy");
    }
    let expected_source: IpAddr = args
        .next()
        .parse()
        .unwrap_or_else(|_| fail("invalid console meter source IP"));
    let quarantine = PathBuf::from(args.next());
    let output = PathBuf::from(args.next());
    if args.next() != "--allow-state-changing" {
        fail("meter capture requires explicit --allow-state-changing approval");
    }
    let mut seconds = 5u64;
    if args.has_next() {
        if args.next() != "--seconds" {
            fail("expected --seconds after approval");
        }
        seconds = args
            .next()
            .parse()
            .unwrap_or_else(|_| fail("invalid meter duration"));
    }
    let quarantine = prepare_quarantine(&quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| fail(&error));
    let native = TcpStream::connect_timeout(&native, Duration::from_secs(2))
        .unwrap_or_else(|error| fail(&format!("connecting meter driver to Native proxy: {error}")));
    let meter = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|error| fail(&format!("binding meter capture socket: {error}")));
    let capture =
        capture_meter_session(native, meter, expected_source, Duration::from_secs(seconds))
            .unwrap_or_else(|error| fail(&error));
    let path = write_private(&quarantine, &output, capture.as_bytes())
        .unwrap_or_else(|error| fail(&error));
    println!("wrote private meter transcript to {}", path.display());
}

fn merge_partial_events(text: &str, base: u64) -> Result<Vec<CapturedEvent>, String> {
    parse_capture_structure(text)?;
    let mut events = Vec::new();
    for line in text.lines().filter(|line| line.starts_with('@')) {
        let (prefix, hex) = split_capture_line(line)
            .ok_or_else(|| format!("unrecognized partial event: {line:?}"))?;
        let mut fields = prefix.split_whitespace();
        let _ordinal = fields.next();
        let offset = fields
            .next()
            .and_then(|value| value.strip_prefix('+'))
            .and_then(|value| value.strip_suffix("us"))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| format!("invalid partial offset: {line:?}"))?;
        let channel = match fields.next() {
            Some("D>") => "D>",
            Some("D<") => "D<",
            Some("N>") => "N>",
            Some("N<") => "N<",
            Some("M>") => "M>",
            Some("M<") => "M<",
            other => return Err(format!("unsupported merge channel {other:?}")),
        };
        events.push((base.saturating_add(offset), channel, decode_hex(hex)?));
    }
    Ok(events)
}

fn build_merged_matrix(events: Vec<CapturedEvent>, destructive: bool) -> String {
    let disconnect = events
        .iter()
        .any(|(_, channel, bytes)| *channel == "N<" && bytes.is_empty());
    let mut capture = events_to_v2(
        "hardware_matrix_raw",
        "merged direct discovery, Native proxy, and raw meter evidence",
        events,
    );
    capture.insert_str(
        capture.find('@').unwrap_or(capture.len()),
        "# matrix_contract: wing-rack-3.1-v1\n\
         # restore_verified: true\n\
         # concurrent_definition_write_observed: true\n\
         # meter_cardinality_verdict: ambiguous\n",
    );
    capture.insert_str(
        capture.find('@').unwrap_or(capture.len()),
        &format!("# disconnect_observed: {disconnect}\n"),
    );
    if destructive {
        capture = capture.replace(
            "# destructive_write_approved: false",
            "# destructive_write_approved: true",
        );
    }
    capture
}

fn merge_v2(args: &mut Args) {
    let quarantine = PathBuf::from(args.next());
    let output = PathBuf::from(args.next());
    if args.next() != "--allow-state-changing" {
        fail("matrix merge requires explicit --allow-state-changing approval");
    }
    let destructive = match args.next().as_str() {
        "--destructive-write-approved=true" => true,
        "--destructive-write-approved=false" => false,
        _ => fail("matrix merge requires --destructive-write-approved=true|false"),
    };
    if args.next() != "--restore-verified" {
        fail("matrix merge requires explicit --restore-verified attestation");
    }
    if args.next() != "--concurrent-definition-write-observed" {
        fail("matrix merge requires explicit concurrent definition/write observation");
    }
    let quarantine = prepare_quarantine(&quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| fail(&error));
    let mut events = Vec::new();
    let mut base = 0u64;
    while args.has_next() {
        let partial = PathBuf::from(args.next());
        let path = quarantine_output(&quarantine, &partial).unwrap_or_else(|error| fail(&error));
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| fail(&format!("reading partial {}: {error}", path.display())));
        let mut next = merge_partial_events(&text, base).unwrap_or_else(|error| fail(&error));
        if let Some((last, _, _)) = next.last() {
            base = last.saturating_add(1);
        }
        events.append(&mut next);
    }
    if events.is_empty() {
        fail("matrix merge requires at least one partial capture");
    }
    let capture = build_merged_matrix(events, destructive);
    parse_capture_structure(&capture).unwrap_or_else(|error| fail(&error));
    let path = write_private(&quarantine, &output, capture.as_bytes())
        .unwrap_or_else(|error| fail(&error));
    println!("wrote private merged matrix to {}", path.display());
}

/// Best-effort live capture (see module docs): opens a raw TCP connection and logs
/// whatever traffic arrives, with nothing driving the session. Untested against real
/// hardware -- no WING Rack is reachable from this development environment.
fn record(args: &mut Args) {
    let host = args.next();
    let quarantine = PathBuf::from(args.next());
    let relative_output = PathBuf::from(args.next());
    let quarantine = prepare_quarantine(&quarantine, Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| fail(&error));
    quarantine_output(&quarantine, &relative_output).unwrap_or_else(|error| fail(&error));
    let mut seconds = 5u64;
    if args.has_next() {
        let flag = args.next();
        if flag == "--seconds" {
            seconds = args.next().parse().unwrap_or(5);
        }
    }

    let target = format!("{host}:2222");
    let addr = match target.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => {
            println!(
                "wingcapture --record: could not resolve {host}:2222; skipping \
                 (no hardware available to test this path against yet)"
            );
            return;
        }
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "wingcapture --record: console at {host} unreachable ({e}); skipping \
                 (no hardware available to test this path against yet)"
            );
            return;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut captured = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => captured.extend_from_slice(&buf[..n]),
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(_) => break,
        }
    }

    let lines = [
        "# scenario: recorded".to_string(),
        "# source: hardware".to_string(),
        "# console_model: FILL-ME-IN".to_string(),
        "# firmware: FILL-ME-IN".to_string(),
        "# capture_date: FILL-ME-IN (YYYY-MM-DD)".to_string(),
        format!("N< {}", encode_hex(&captured)),
    ];
    let output_path = write_private(
        &quarantine,
        &relative_output,
        (lines.join("\n") + "\n").as_bytes(),
    )
    .unwrap_or_else(|error| fail(&error));
    println!(
        "wrote {} bytes of raw (UNSANITIZED) capture to {} -- fill in the \
         model/firmware/date headers, then run \
         `wingcapture {} <sanitized-output>` before checking anything in",
        captured.len(),
        output_path.display(),
        output_path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("libwing-{label}-{}-{nonce}", std::process::id()))
    }

    fn complete_v2(attested: bool) -> String {
        format!(
            "# wingcap_version: 2\n\
             # scenario: test\n\
             # source: synthetic\n\
             # console_model: RACK\n\
             # firmware: 3.1\n\
             # capture_date: 2026-07-12\n\
             # sanitizer: wingcapture/2\n\
             # manual_redaction_attested: {attested}\n\
             # expected_behavior: complete synthetic exchange\n\
             @1 +0us D> 2f3f\n\
             @2 +1us D< 57494e47\n\
             @3 +2us N> df0100df\n\
             @4 +3us N< df0100df\n\
             @5 +4us M> dfd3\n\
             @6 +5us M< 000100000001\n"
        )
    }

    fn complete_hardware_matrix() -> String {
        let mut text = include_str!("../tests/fixtures/complete_session_v2.wingcap")
            .to_string()
            .replace("# source: synthetic", "# source: hardware")
            .replace("# sanitizer: n/a", "# sanitizer: wingcapture/2")
            .replace("@1 +0us D> 2f3f00002c000000", "@1 +0us D> 57494e473f")
            .replace("@3 +200us N> df0100df", "@3 +200us N> dfd1")
            .replace(
                "@5 +400us N> d7000004d2dc",
                "@5 +400us N> dfd1d7000004d2dc",
            )
            .replace(
                "@7 +600us N> d7000004d2dd",
                "@7 +600us N> dfd1d7000004d2dd",
            )
            .replace(
                "@9 +800us N> d7000004d22a",
                "@9 +800us N> dfd1d7000004d22a",
            )
            .replace("@14 +1300us N> df0100df", "@14 +1300us N> dfd1")
            .replace(
                "@11 +1000us M> dfd301d40001dfd2d40001df",
                "@11 +1000us M> dfd3d31234d400011234dca000dedfd1",
            )
            .replace(
                "@13 +1200us M> dfd3d40001d40001dfd1",
                "@13 +1200us M> dfd3d400011234dfd1",
            )
            .replace(
                "# expected_behavior: discovery, handshake, get, definition, set echo, meter frame, keepalive, disconnect",
                "# expected_behavior: complete reviewed hardware matrix\n\
                 # matrix_contract: wing-rack-3.1-v1\n\
                 # state_changing_write_approved: true\n\
                 # destructive_write_approved: false\n\
                 # restore_verified: true\n\
                 # concurrent_definition_write_observed: true\n\
                 # disconnect_observed: true\n\
                 # meter_cardinality_verdict: ambiguous",
        );
        text.push_str(
            "@17 +1600us M> dfd3d31234d400021234dca000dedfd1\n\
             @18 +1700us M> dfd3d400021234dfd1\n\
             @19 +1800us M< 000200000001\n",
        );
        text
    }

    #[test]
    fn v2_preflight_requires_metadata_attestation_and_provenance() {
        let parsed = parse_capture(&complete_v2(true)).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.event_count, 6);

        let missing = complete_v2(true).replace("# firmware: 3.1\n", "");
        assert!(parse_capture(&missing).unwrap_err().contains("firmware"));
        assert!(parse_capture(&complete_v2(false))
            .unwrap_err()
            .contains("attestation"));

        let root = temp_root("preflight");
        fs::create_dir_all(&root).unwrap();
        let capture = root.join("candidate.wingcap");
        fs::write(&capture, complete_v2(true)).unwrap();
        let provenance = root.join("PROVENANCE.md");
        fs::write(&provenance, "# no fixture entry\n").unwrap();
        assert!(preflight(&capture, &provenance)
            .unwrap_err()
            .contains("provenance"));
        fs::write(&provenance, "- `candidate.wingcap`: synthetic test\n").unwrap();
        preflight(&capture, &provenance).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hardware_promotion_requires_the_typed_complete_matrix() {
        let complete = complete_hardware_matrix();
        parse_capture(&complete).unwrap();

        let missing_approval = complete.replace("# state_changing_write_approved: true\n", "");
        assert!(parse_capture(&missing_approval)
            .unwrap_err()
            .contains("state_changing_write_approved"));

        let one_frame = complete.replace("@19 +1800us M< 000200000001\n", "@19 +1800us N< dfd1\n");
        assert!(parse_capture(&one_frame)
            .unwrap_err()
            .contains("two raw meter frames"));

        let no_second_renewal = complete.replace(
            "@18 +1700us M> dfd3d400021234dfd1",
            "@18 +1700us N> df0100df",
        );
        let error = parse_capture(&no_second_renewal).unwrap_err();
        assert!(
            error.contains("two meter renewals") || error.contains("incomplete Native request"),
            "{error}"
        );
    }

    #[test]
    fn quarantine_rejects_repo_sync_roots_and_symlink_escapes() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(prepare_quarantine(&repo.join("raw-captures"), repo).is_err());

        let sync = temp_root("Dropbox").join("Dropbox").join("captures");
        assert!(prepare_quarantine(&sync, repo)
            .unwrap_err()
            .contains("synchronized"));

        let private = temp_root("absolute-output");
        prepare_quarantine(&private, repo).unwrap();
        assert!(quarantine_output(&private, Path::new("/tmp/raw.wingcap"))
            .unwrap_err()
            .contains("relative path"));
        fs::remove_dir_all(private).unwrap();

        let root = temp_root("symlink");
        let quarantine = root.join("quarantine");
        let outside = root.join("outside");
        fs::create_dir_all(&quarantine).unwrap();
        fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, quarantine.join("escape")).unwrap();
            assert!(quarantine_output(&quarantine, Path::new("escape/raw.wingcap")).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sanitized_review_candidates_stay_outside_repo_and_sync_roots() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(validate_review_candidate(&repo.join("candidate.wingcap"))
            .unwrap_err()
            .contains("outside the repository"));

        let sync = temp_root("Dropbox").join("Dropbox");
        fs::create_dir_all(&sync).unwrap();
        assert!(validate_review_candidate(&sync.join("candidate.wingcap"))
            .unwrap_err()
            .contains("synchronized"));
        fs::remove_dir_all(sync.parent().unwrap()).unwrap();

        let review = temp_root("review");
        fs::create_dir_all(&review).unwrap();
        validate_review_candidate(&review.join("candidate.wingcap")).unwrap();
        fs::remove_dir_all(review).unwrap();
    }

    #[test]
    fn comparison_seam_records_deviations_without_rewriting_evidence() {
        let root = temp_root("compare");
        fs::create_dir_all(&root).unwrap();
        let hardware = root.join("hardware.wingcap");
        let emulator = root.join("emulator.wingcap");
        let report = root.join("deviations.txt");
        let hardware_text = complete_v2(true);
        let emulator_text = hardware_text.replace("@4 +3us N< df0100df", "@4 +3us N< dfd1");
        fs::write(&hardware, &hardware_text).unwrap();
        fs::write(&emulator, emulator_text).unwrap();

        assert_eq!(compare_v2(&hardware, &emulator, &report).unwrap(), 1);
        assert_eq!(fs::read_to_string(&hardware).unwrap(), hardware_text);
        let report = fs::read_to_string(report).unwrap();
        assert!(report.contains("# deviations: 1"));
        assert!(report.contains("event 4"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn localhost_native_proxy_captures_both_directions_disconnect_and_tears_down() {
        let fake_console = TcpListener::bind("127.0.0.1:0").unwrap();
        let console_addr = fake_console.local_addr().unwrap();
        let console = thread::spawn(move || {
            let (mut socket, _) = fake_console.accept().unwrap();
            let mut request = [0u8; 8];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request!");
            socket.write_all(b"response!").unwrap();
            socket.shutdown(Shutdown::Both).unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy = thread::spawn(move || {
            run_native_proxy(proxy_listener, console_addr, Duration::from_secs(2)).unwrap()
        });
        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.write_all(b"request!").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response!");

        console.join().unwrap();
        let capture = proxy.join().unwrap();
        parse_capture_structure(&capture).unwrap();
        assert!(capture
            .lines()
            .any(|line| line.ends_with("N> 7265717565737421")));
        assert!(capture
            .lines()
            .any(|line| line.ends_with("N< 726573706f6e736521")));
        assert!(capture.lines().any(|line| line.ends_with("N< ")));
        TcpListener::bind(proxy_addr).expect("proxy listener must be reusable after teardown");
    }

    #[test]
    fn native_proxy_is_bounded_and_loopback_only() {
        let mut recorder = ProxyRecorder::new();
        assert!(recorder
            .record("N>", &vec![0; PROXY_MAX_BYTES + 1])
            .unwrap_err()
            .contains("exceeded"));

        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        let upstream = "127.0.0.1:9".parse().unwrap();
        assert!(
            run_native_proxy(wildcard, upstream, Duration::from_millis(10))
                .unwrap_err()
                .contains("loopback")
        );
    }

    #[test]
    fn loopback_discovery_is_captured_directly_in_both_directions() {
        let console = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = console.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut buffer = [0u8; 32];
            let (count, peer) = console.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..count], b"WING?");
            console
                .send_to(b"WING,192.0.2.10,WING-FIXTURE,RACK,NGC0000000,3.1", peer)
                .unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let capture = capture_discovery_session(client, target, Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        parse_capture_structure(&capture).unwrap();
        assert!(capture.contains("D> 57494e473f"));
        assert!(capture.contains("D< 57494e472c"));
    }

    #[test]
    fn loopback_meter_driver_captures_two_tokens_and_renewals() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let native_addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut decoder = NativeRequestDecoder::default();
            let mut subscriptions = BTreeSet::new();
            let mut renewals = BTreeSet::new();
            let mut buffer = [0u8; 1024];
            while subscriptions.len() < 2 || renewals.len() < 2 {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                for request in decoder.push(&buffer[..count]).unwrap() {
                    match request {
                        NativeRequest::MeterSubscribe {
                            port, report_id, ..
                        } => {
                            subscriptions.insert(report_id);
                            let mut datagram = (report_id & 0xffff_0000).to_be_bytes().to_vec();
                            datagram.extend_from_slice(&[0; 16]);
                            sender
                                .send_to(&datagram, SocketAddr::new(peer.ip(), port))
                                .unwrap();
                        }
                        NativeRequest::MeterRenew { report_id } => {
                            renewals.insert(report_id);
                        }
                        _ => {}
                    }
                }
            }
            assert_eq!(subscriptions, renewals);
            assert_eq!(subscriptions.len(), 2);
            assert_eq!(
                subscriptions
                    .iter()
                    .map(|report_id| report_id >> 16)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([1, 2])
            );
        });
        let native = TcpStream::connect(native_addr).unwrap();
        let meter = UdpSocket::bind("127.0.0.1:0").unwrap();
        let capture = capture_meter_session(
            native,
            meter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_secs(1),
        )
        .unwrap();
        server.join().unwrap();
        parse_capture_structure(&capture).unwrap();
        assert_eq!(capture.matches(" M> ").count(), 4);
        assert!(capture.contains("M< 00010000"));
        assert!(capture.contains("M< 00020000"));
    }

    #[test]
    fn partial_merge_rebases_offsets_without_changing_bytes() {
        let discovery = "# wingcap_version: 2\n# scenario: d\n# source: hardware\n# console_model: pending\n# firmware: pending\n# capture_date: pending\n# sanitizer: pending\n# manual_redaction_attested: false\n# expected_behavior: d\n@1 +0us D> 57494e473f\n@2 +8us D< 57494e47\n";
        let native = "# wingcap_version: 2\n# scenario: n\n# source: hardware\n# console_model: pending\n# firmware: pending\n# capture_date: pending\n# sanitizer: pending\n# manual_redaction_attested: false\n# expected_behavior: n\n@1 +0us N> dfd1\n@2 +3us N< dfd1\n@3 +4us N< \n";
        let mut events = merge_partial_events(discovery, 0).unwrap();
        let base = events.last().unwrap().0 + 1;
        events.extend(merge_partial_events(native, base).unwrap());
        let merged = events_to_v2("merged", "test", events);
        parse_capture_structure(&merged).unwrap();
        assert!(merged.contains("@3 +9us N> dfd1"));
        assert!(merged.contains("@5 +13us N< "));
    }

    #[test]
    fn merged_matrix_becomes_preflight_ready_after_required_manual_review() {
        let events = merge_partial_events(&complete_hardware_matrix(), 0).unwrap();
        let reviewed = build_merged_matrix(events, false)
            .replace("pending-manual-entry", "RACK")
            .replace("# firmware: RACK", "# firmware: 3.1")
            .replace("# capture_date: RACK", "# capture_date: 2026-07-12")
            .replace("# sanitizer: pending", "# sanitizer: wingcapture/2")
            .replace(
                "# manual_redaction_attested: false",
                "# manual_redaction_attested: true",
            );
        parse_capture(&reviewed).unwrap();
    }

    #[test]
    fn quarantine_and_files_are_owner_only_where_supported() {
        let root = temp_root("private");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        prepare_quarantine(&root, repo).unwrap();
        let file = write_private(&root, Path::new("raw.wingcap"), b"sensitive").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(validate_private_permissions(&root).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_and_retention_fail_loudly() {
        let root = temp_root("cleanup");
        prepare_quarantine(&root, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        let raw = root.join("raw.wingcap");
        fs::write(&raw, "raw").unwrap();
        cleanup_raw(&raw).unwrap();
        assert!(!raw.exists());
        assert!(cleanup_raw(&raw)
            .unwrap_err()
            .contains("deleting raw capture"));
        assert!(purge_expired(&root, Duration::ZERO).unwrap().is_empty());
        assert!(cleanup_raw(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retention_recurses_and_rejects_unsafe_entries() {
        let root = temp_root("nested-retention");
        prepare_quarantine(&root, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        let nested = write_private(&root, Path::new("session/raw.wingcap"), b"raw").unwrap();
        let deleted = purge_expired(&root, Duration::ZERO).unwrap();
        assert_eq!(deleted, vec![nested.clone()]);
        assert!(!nested.exists());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("outside", root.join("unsafe-link")).unwrap();
            assert!(purge_expired(&root, Duration::ZERO)
                .unwrap_err()
                .contains("unsafe symlink"));
            fs::remove_file(root.join("unsafe-link")).unwrap();

            let alias = temp_root("quarantine-alias");
            std::os::unix::fs::symlink(&root, &alias).unwrap();
            assert!(purge_expired(&alias, Duration::ZERO)
                .unwrap_err()
                .contains("root cannot be a symlink"));
            fs::remove_file(alias).unwrap();

            use std::os::unix::fs::PermissionsExt;
            let unsafe_file = write_private(&root, Path::new("unsafe.raw"), b"raw").unwrap();
            fs::set_permissions(&unsafe_file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(purge_expired(&root, Duration::ZERO)
                .unwrap_err()
                .contains("not owner-only"));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sanitizer_rejects_sensitive_headers_and_redacts_payload_identifiers() {
        let root = temp_root("sanitize");
        fs::create_dir_all(&root).unwrap();
        let input = root.join("raw.wingcap");
        let output = root.join("clean.wingcap");
        let sensitive = complete_v2(true).replace(
            "57494e47",
            "4e4743313233343536372031302e32302e33302e34302061613a62623a63633a64643a65653a6666",
        );
        parse_capture_structure(&sensitive).unwrap();
        assert!(parse_capture(&sensitive).is_err());
        fs::write(&input, sensitive).unwrap();
        sanitize_file(input.to_str().unwrap(), output.to_str().unwrap()).unwrap();
        let clean = fs::read_to_string(&output).unwrap();
        assert!(!clean.contains("4e474331323334353637"));
        preflight_text(&clean).unwrap();

        fs::write(
            &input,
            complete_v2(true).replace("# scenario: test", "# scenario: 10.20.30.40"),
        )
        .unwrap();
        assert!(sanitize_file(input.to_str().unwrap(), output.to_str().unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

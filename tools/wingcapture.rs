//! Capture-sanitization helper (U14: R81) -- redacts a raw `.wingcap` capture per
//! REDACTION.md, refusing to write an output file that would still fail the same scan
//! `tests/replay.rs`'s check-in guard runs, so nothing unsanitized can slip past this
//! tool and into a commit. See `tests/fixtures/README.md` for the full record ->
//! sanitize -> check-in workflow this feeds.
//!
//! ```text
//! Usage: wingcapture <input.raw.wingcap> <output.wingcap>
//!        wingcapture --record <host> <output.raw.wingcap> [--seconds N]
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
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

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
       wingcapture --record <host> <output.raw.wingcap> [--seconds N]
       wingcapture --init-quarantine <off-tree-directory>
       wingcapture --record-script <v2-script> <quarantine> <relative-output>
       wingcapture --sanitize-v2 <quarantine> <relative-raw> <candidate>
       wingcapture --preflight <candidate> <PROVENANCE.md>
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
    for channel in ["D>", "D<", "N>", "N<", "M>", "M<"] {
        if !channels.contains(channel) {
            return Err(format!("complete V2 capture is missing {channel} events"));
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
    }
    Ok(())
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
    let parent = candidate
        .parent()
        .ok_or_else(|| "capture path has no parent".to_string())?;
    if parent.exists() {
        let parent = parent
            .canonicalize()
            .map_err(|error| format!("resolving capture parent: {error}"))?;
        if !parent.starts_with(&root) {
            return Err("capture path escapes quarantine through a symlink".to_string());
        }
    } else {
        fs::create_dir_all(parent)
            .map_err(|error| format!("creating capture directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("securing capture directory: {error}"))?;
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
    use std::io::Write;
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

fn cleanup_raw(path: &Path) -> Result<(), String> {
    fs::remove_file(path)
        .map_err(|error| format!("deleting raw capture {}: {error}", path.display()))
}

fn purge_expired(root: &Path, retention: Duration) -> Result<Vec<PathBuf>, String> {
    validate_private_permissions(root)?;
    let now = SystemTime::now();
    let mut deleted = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| format!("reading quarantine {}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("reading quarantine entry: {error}"))?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("reading {} metadata: {error}", entry.path().display()))?;
        if !metadata.is_file() {
            continue;
        }
        let age = now
            .duration_since(
                metadata
                    .modified()
                    .map_err(|error| format!("reading modified time: {error}"))?,
            )
            .unwrap_or_default();
        if age >= retention {
            cleanup_raw(&entry.path())?;
            deleted.push(entry.path());
        }
    }
    Ok(deleted)
}

/// Best-effort live capture (see module docs): opens a raw TCP connection and logs
/// whatever traffic arrives, with nothing driving the session. Untested against real
/// hardware -- no WING Rack is reachable from this development environment.
fn record(args: &mut Args) {
    let host = args.next();
    let output_path = args.next();
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
    if let Err(e) = fs::write(&output_path, lines.join("\n") + "\n") {
        eprintln!("wingcapture --record: failed to write {output_path}: {e}");
        return;
    }
    println!(
        "wrote {} bytes of raw (UNSANITIZED) capture to {output_path} -- fill in the \
         model/firmware/date headers, then run \
         `wingcapture {output_path} <sanitized-output>` before checking anything in",
        captured.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
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
             @6 +5us M< 000000010001\n"
        )
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
    fn quarantine_rejects_repo_sync_roots_and_symlink_escapes() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(prepare_quarantine(&repo.join("raw-captures"), repo).is_err());

        let sync = temp_root("Dropbox").join("Dropbox").join("captures");
        assert!(prepare_quarantine(&sync, repo)
            .unwrap_err()
            .contains("synchronized"));

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

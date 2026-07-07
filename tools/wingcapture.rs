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

use std::fs;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use utils::Args;

const SANITIZER_VERSION: &str = "wingcapture/1";

fn main() {
    let mut args = Args::new(
        r#"
Usage: wingcapture <input.raw.wingcap> <output.wingcap>
       wingcapture --record <host> <output.raw.wingcap> [--seconds N]

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
    if first == "--record" {
        record(&mut args);
        return;
    }
    let output_path = args.next();
    if let Err(e) = sanitize_file(&first, &output_path) {
        eprintln!("wingcapture: {e}");
        std::process::exit(1);
    }
    println!("wrote sanitized capture to {output_path}");
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
            }
            out_lines.push(line.to_string());
            continue;
        }

        let (prefix, hex) =
            split_prefix(line).ok_or_else(|| format!("unrecognized fixture line: {line:?}"))?;
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
        } else if let Some((_prefix, hex)) = split_prefix(line) {
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

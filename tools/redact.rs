//! Redaction-policy scanner and byte-level redactor (REDACTION.md rule 3): flags,
//! and can rewrite, un-sanitized serials, IPv4 literals, and MAC addresses in
//! `.wingcap` fixture content.
//!
//! Shared between the check-in guard (`tests/replay.rs`) and the capture-sanitization
//! helper (`tools/wingcapture.rs`) via `#[path = "redact.rs"] mod redact;` from both --
//! one set of rules, not two copies that could drift. Kept dependency-free (hand-rolled
//! byte scanning, no `regex` crate) per the no-new-deps constraint; everything operates
//! on `&[u8]` rather than `&str` so it never assumes the scanned buffer is valid UTF-8
//! (wire captures are arbitrary binary outside the ASCII runs it's actually looking
//! for).
//!
//! Not exhaustive by design: only the three *mechanical* classes REDACTION.md rule 3
//! names (serial/IP/MAC) are detected and auto-redacted here. Free-text identifiers
//! (console/channel/show names) have no reliable pattern to scan for and must be
//! redacted by hand per REDACTION.md's table before running the sanitizer -- see
//! `tests/fixtures/README.md`'s recording workflow.

/// One redaction-policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// An `NGC` serial with at least one non-zero digit (only the all-zero
    /// `NGC0000000` placeholder is allowed).
    Serial(String),
    /// An IPv4 literal outside TEST-NET-1 (`192.0.2.0/24`) and `0.0.0.0`/`127.0.0.1`.
    Ip(String),
    /// A MAC address outside the locally-administered `02:00:00:00:00:xx` block.
    Mac(String),
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::Serial(s) => write!(f, "un-redacted serial {s:?}"),
            Finding::Ip(s) => write!(f, "un-redacted IPv4 literal {s:?}"),
            Finding::Mac(s) => write!(f, "un-redacted MAC address {s:?}"),
        }
    }
}

/// A [`Finding`] together with the byte span it occupies in the scanned buffer, so
/// [`redact_bytes`] can rewrite it in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub finding: Finding,
}

/// Every redaction-policy violation in `bytes`, with position (used by
/// [`redact_bytes`]; [`scan`]/[`scan_str`] are the position-free convenience for
/// callers that only need to know *whether* something was found).
pub fn find_matches(bytes: &[u8]) -> Vec<Match> {
    let mut out = Vec::new();
    find_serials(bytes, &mut out);
    find_ips(bytes, &mut out);
    find_macs(bytes, &mut out);
    out
}

/// Scans `bytes` for every redaction-policy violation.
pub fn scan(bytes: &[u8]) -> Vec<Finding> {
    find_matches(bytes).into_iter().map(|m| m.finding).collect()
}

/// [`scan`] over a `&str` (e.g. a fixture's header/comment text, or a lossy-UTF8
/// interpretation of decoded payload bytes).
pub fn scan_str(s: &str) -> Vec<Finding> {
    scan(s.as_bytes())
}

/// Redacts every mechanical-class finding in `bytes` with a same-length
/// replacement, and returns the result. See the module docs for why only
/// serial/IP/MAC are handled, and [`fit_test_net_ip`] for why an IP without an
/// exact-length TEST-NET-1 candidate is a hard error rather than a silent
/// best-effort rewrite -- Native wire strings are length-prefixed elsewhere in
/// their frame, so a length-changing replacement would desync the stream.
pub fn redact_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = bytes.to_vec();
    // Re-scan after each pass rather than assuming one pass is enough: a
    // replacement value is chosen to never itself match (zeros, the fixed MAC, a
    // same-length TEST-NET-1 IP), but re-checking is cheap and turns any future
    // mistake in a replacement constant into a loud "still failing" error instead
    // of a silently-incomplete redaction.
    for _ in 0..4 {
        let matches = find_matches(&out);
        if matches.is_empty() {
            return Ok(out);
        }
        for m in &matches {
            let replacement = match &m.finding {
                Finding::Serial(s) => {
                    let digits = s.len() - 3; // strip the "NGC" prefix
                    format!("NGC{}", "0".repeat(digits))
                }
                Finding::Mac(_) => "02:00:00:00:00:00".to_string(),
                Finding::Ip(ip) => fit_test_net_ip(ip.len()).ok_or_else(|| {
                    format!(
                        "no same-length TEST-NET-1 replacement for IP literal {ip:?} \
                         (length {}); rewrite this fixture by hand per REDACTION.md",
                        ip.len()
                    )
                })?,
            };
            if replacement.len() != m.end - m.start {
                return Err(format!(
                    "internal error: replacement length mismatch for {:?}",
                    m.finding
                ));
            }
            out[m.start..m.end].copy_from_slice(replacement.as_bytes());
        }
    }
    Err("could not fully redact after repeated passes".to_string())
}

/// Finds a `192.0.2.<n>` literal whose *string* length equals `len` (9..=11 chars,
/// i.e. `192.0.2.0` through `192.0.2.255`). `None` outside that range: there is no
/// TEST-NET-1 literal of that length, so a same-length rewrite is impossible and the
/// caller must redact that occurrence by hand.
fn fit_test_net_ip(len: usize) -> Option<String> {
    (0..=255u32)
        .map(|n| format!("192.0.2.{n}"))
        .find(|s| s.len() == len)
}

fn find_serials(bytes: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"NGC" {
            let digits_start = i + 3;
            let mut j = digits_start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits_start && bytes[digits_start..j].iter().any(|&b| b != b'0') {
                out.push(Match {
                    start: i,
                    end: j,
                    finding: Finding::Serial(lossy(&bytes[i..j])),
                });
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

fn find_ips(bytes: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && is_boundary(bytes, i as isize - 1, is_ip_body) {
            if let Some(end) = parse_ipv4_end(bytes, i) {
                if is_boundary(bytes, end as isize, is_ip_body) {
                    let ip = lossy(&bytes[i..end]);
                    if !is_allowed_ip(&ip) {
                        out.push(Match {
                            start: i,
                            end,
                            finding: Finding::Ip(ip),
                        });
                    }
                }
                i = end.max(i + 1);
                continue;
            }
        }
        i += 1;
    }
}

fn find_macs(bytes: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = parse_mac_end(bytes, i) {
            if is_boundary(bytes, i as isize - 1, is_mac_body)
                && is_boundary(bytes, end as isize, is_mac_body)
            {
                let mac = lossy(&bytes[i..end]).to_ascii_lowercase();
                if !is_allowed_mac(&mac) {
                    out.push(Match {
                        start: i,
                        end,
                        finding: Finding::Mac(mac),
                    });
                }
            }
            i = end.max(i + 1);
            continue;
        }
        i += 1;
    }
}

fn lossy(bytes: &[u8]) -> String {
    // Every span passed in here is composed solely of ASCII digits/hex-digits/dots/
    // colons (see the parsers above), so this is always a lossless, valid-UTF8
    // conversion in practice -- `from_utf8_lossy` is just the convenient API.
    String::from_utf8_lossy(bytes).into_owned()
}

fn is_ip_body(b: u8) -> bool {
    b.is_ascii_digit() || b == b'.'
}

fn is_mac_body(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}

/// Whether the byte at `idx` (or "past an edge") is *not* part of a longer token of
/// `is_body` bytes -- i.e. `idx` is a valid start/end boundary for a match.
fn is_boundary(bytes: &[u8], idx: isize, is_body: fn(u8) -> bool) -> bool {
    if idx < 0 || idx as usize >= bytes.len() {
        return true;
    }
    !is_body(bytes[idx as usize])
}

/// Parses a leading `a.b.c.d` IPv4 literal (each octet 0-255) starting at `start`.
/// Returns the end offset (exclusive) on success.
fn parse_ipv4_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for octet_idx in 0..4 {
        let octet_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() && pos - octet_start < 3 {
            pos += 1;
        }
        if pos == octet_start {
            return None;
        }
        let value: u32 = std::str::from_utf8(&bytes[octet_start..pos])
            .ok()?
            .parse()
            .ok()?;
        if value > 255 {
            return None;
        }
        if octet_idx < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

fn is_allowed_ip(ip: &str) -> bool {
    if ip == "0.0.0.0" || ip == "127.0.0.1" {
        return true;
    }
    ip.strip_prefix("192.0.2.")
        .and_then(|rest| rest.parse::<u32>().ok())
        .map(|n| n <= 255)
        .unwrap_or(false)
}

/// Parses a leading `xx:xx:xx:xx:xx:xx` MAC address starting at `start`. Returns the
/// end offset (exclusive) on success.
fn parse_mac_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for group in 0..6 {
        if pos + 2 > bytes.len()
            || !bytes[pos].is_ascii_hexdigit()
            || !bytes[pos + 1].is_ascii_hexdigit()
        {
            return None;
        }
        pos += 2;
        if group < 5 {
            if pos >= bytes.len() || bytes[pos] != b':' {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

fn is_allowed_mac(mac: &str) -> bool {
    mac.strip_prefix("02:00:00:00:00:")
        .map(|last| last.len() == 2 && last.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_serial_is_allowed() {
        assert!(scan_str("NGC0000000").is_empty());
    }

    #[test]
    fn nonzero_serial_is_flagged() {
        let findings = scan_str("serial=NGC1234567");
        assert!(matches!(&findings[..], [Finding::Serial(s)] if s == "NGC1234567"));
    }

    #[test]
    fn test_net_1_ip_is_allowed_but_others_are_flagged() {
        assert!(scan_str("192.0.2.10").is_empty());
        assert!(scan_str("0.0.0.0").is_empty());
        assert!(scan_str("127.0.0.1").is_empty());
        let findings = scan_str("ip=10.20.30.40");
        assert!(matches!(&findings[..], [Finding::Ip(s)] if s == "10.20.30.40"));
    }

    #[test]
    fn locally_administered_mac_is_allowed_but_others_are_flagged() {
        assert!(scan_str("02:00:00:00:00:0a").is_empty());
        let findings = scan_str("mac=aa:bb:cc:dd:ee:ff");
        assert!(matches!(&findings[..], [Finding::Mac(s)] if s == "aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn version_looking_strings_do_not_false_positive_as_ips() {
        assert!(scan_str("firmware 3.1-03").is_empty());
        assert!(scan_str("V3.1.03 release").is_empty());
    }

    #[test]
    fn redact_bytes_rewrites_every_class_in_place_same_length() {
        let input = b"WING,10.20.30.40,MixerRoomA,RACK,NGC1234567,1.9.9";
        let out = redact_bytes(input).unwrap();
        assert_eq!(out.len(), input.len());
        let out_str = String::from_utf8(out).unwrap();
        assert!(
            scan_str(&out_str).is_empty(),
            "still fails scan: {out_str:?}"
        );
        assert!(out_str.contains("NGC0000000"));
        assert!(!out_str.contains("10.20.30.40"));
    }

    #[test]
    fn redact_bytes_refuses_an_unfittable_ip_length() {
        // "8.8.8.8" is 7 chars -- shorter than any TEST-NET-1 literal (9..=11).
        let err = redact_bytes(b"resolver=8.8.8.8").unwrap_err();
        assert!(err.contains("rewrite this fixture by hand"), "{err}");
    }
}

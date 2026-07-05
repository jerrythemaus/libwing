# Fixture Redaction Policy

This policy gates every wire-level capture checked into this repository
(`tests/fixtures/`), per origin requirement R81: **no capture lands until it
passes redaction**. The record-replay harness (`tests/replay.rs`) enforces the
mechanical parts with a check-in guard test; this document is the normative
list of what must be redacted and how.

## What must be redacted

| Class | Examples | Replacement convention |
| --- | --- | --- |
| Serial numbers | discovery reply token 5, `/$stat` identity nodes | `NGC0000000` (zeroed serial) |
| Network identifiers | IPs, MACs, hostnames, gateway/DNS config nodes | IPs → TEST-NET-1 (`192.0.2.x`); MACs → `02:00:00:00:00:xx` (locally administered); hostnames → `wing-fixture` |
| Console name | discovery reply token 2, `/cfg/name`-style nodes | `WING-FIXTURE` |
| Show / preset / snapshot content | library names, show file paths, snapshot names | `SHOW-01`, `PRESET-01`, … |
| User-entered strings | channel/bus/scribble names, tags, notes | factory defaults (`CH 1`, `BUS 1`, …) or `LABEL-nn` |

Not personal/identifying and therefore **kept as-is**: firmware version
strings, model identifiers (`RACK`, `FULL`, `CPT`), parameter values, node
ids/hashes, meter samples, schema structure.

## Rules

1. Redaction happens **before** a capture enters the working tree — run the
   sanitizer (`tools/` capture-sanitization helper) on the raw capture; never
   commit the raw file, never rely on history rewrites after the fact.
2. Replacements must preserve **wire-level validity**: same byte lengths where
   framing depends on them (pad/truncate replacement strings to the original
   length), valid UTF-8, recomputed lengths where the format carries them.
3. The check-in guard (`tests/replay.rs`) scans every fixture for: serial
   patterns (`NGC` followed by non-zero digits), non-TEST-NET IPv4 literals,
   MAC-address patterns outside `02:00:00:00:00:00/24`. A hit fails the test
   suite; extend the guard when a new identifier class appears.
4. A fixture's provenance (console model, firmware, capture date, sanitizer
   version/run) is recorded alongside it in `tests/fixtures/README` entries at
   check-in time. See `PROVENANCE.md`.
5. Redistribution: sanitized fixtures are treated as project artifacts (MIT,
   same as the crate). Raw captures are **not redistributable** and must not
   leave the capturing machine.

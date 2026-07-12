# Source Provenance

Sources the schema map, protocol implementation, and verification artifacts in
this repository derive from (origin R55). Non-publishable sources are recorded
as link/checksum only.

## Protocol specification

- **WING Remote Protocols V3.1-03** (Behringer/Music Tribe)
  - Path: `Wing-Remote-Protocols.pdf` (this repo); markdown conversion at
    `../references/WING_Remote_Protocols_V3.1-03.md` (wing-control repo)
  - SHA-256 (PDF): `17e1a2eca918c2901ad52a4c66c2aca050b1a2f8237b7a6cd573eeffca0866d4`
  - Version: V3.1-03. Retrieved: on/before 2026-07-05 (present in repo at
    implementation start).
  - Authority caveat: the document is known to drift from console behavior;
    record-replay fixtures (U14) and the pinned WING Rack baseline (U15) are
    the tie-breakers where they disagree. Spec-only claims not exhibited by
    the WING Rack are labeled spec-derived, not verified.
  - Redistribution: vendor publication; already distributed in the upstream
    libwing repository. Publishable: link/copy as upstream does.

## Schema sweep dataset

- **`propmap.jsonl`** (crate root) — full dynamic per-model sweep, 60,748 rows
  - SHA-256: `4b0fc20150247a45c2d27f7d49831722bb29445896a6061ffd1bfd51f847853a`
  - Source: destructive `wingschema` crawl of a Behringer WING Rack. The
    model attribution is fingerprinted from the data itself: the sweep carries
    24 local inputs (`/io/in/LCL/1..24`) and 8 local outputs — the WING
    Rack's physical I/O complement (full WING and Compact have 8 local ins).
  - Firmware baseline: **3.1** (`libwing::FIRMWARE_BASELINE`); the sweep
    contains the 3.1-added DEQ dual-band dynamic EQ (`/ch/1/gate/DEQ/*`),
    so it cannot predate 3.1. (An older README note attributed the previous
    35k-row default-only map to a Wing Compact on 3.0.5 — that claim applied
    to the superseded map, not this sweep.)
  - Known completeness caveat: the 3.1 release notes also list Even 88-Comp,
    LMT Compressor, and One Knob Compressor plugins; those model tokens are
    **absent** from this sweep. Either the sweep predates a point release that
    shipped them or they live outside the swept subtrees — re-sweep against a
    3.1 console to close this (tracked in `COVERAGE.md`).
  - `src/propmap.jsonl` + `src/propmap.rs` are generated from this file via
    `cargo run --example wingschema -- embed propmap.jsonl`; the
    `propmap_consistency` suite enforces field-for-field fidelity.
  - Redistribution: schema metadata only (no user data); shipped with the
    repo. The embedded map ships in the published crate.

## Firmware artifacts (wing-control repo, `references/`)

- **Behringer WING Firmware V3.1 release notes** (2025-11-07 PDF) and
  **`wing-rack-release-3.1-20251107.wingfw`** — the pinned baseline firmware.
  Redistribution: vendor binaries/documents — **link/checksum only, do not
  re-publish**.
- **`wing64x64_B_int_BK3_4.2.9.4`** (Dante `.dnt` update artifact) — Dante
  expansion-card firmware, unrelated to the control protocol surface; recorded
  for completeness only.

## Hardware verification captures

- **None yet.** No WING console was reachable during implementation
  (2026-07-05); the hardware verification tier (channel-meter layout, RTA
  scaling, OSC live exercise, redacted verification run per R70/R56) is
  pending. When captured, each fixture's model/firmware/date/sanitizer run is
  recorded here per `REDACTION.md` rule 4.

This means no capability may be distributed or documented as `hardware-captured` yet. Offline
replay success is synthetic evidence and does not satisfy the U12 hardware-only release gate.

## Synthetic capture contracts

- **`complete_session_v2.wingcap`**
  - Evidence class: synthetic
  - Source: synthetic
  - Review status: reviewed
  - Console model: RACK
  - Firmware: 3.1
  - Capture date: 2026-07-12
  - Sanitizer: n/a
  - Origin: independently hand-authored from the public protocol description and
    repository-owned codecs. It is not hardware evidence.
  - Covers the ordered bidirectional discovery, Native, and meter channel grammar,
    including the raw four-byte meter report token.
  - Expected behavior: format parsing, ordering, direction preservation, raw-meter
    framing, and legacy-v1 coexistence only.
  - No vendor emulator, firmware payload, `wapi` material, or user data was used.

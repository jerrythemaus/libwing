# Coverage

Per-surface implementation status for the v1 (wing-control-first) scope
(origin R55/R56). Four labels: **implemented** (offline-verified by tests),
**spec-derived** (implemented + tested against the WING Remote Protocols
V3.1-03 document, hardware verification pending), **best-effort** (works, not
a v1 gate), **deferred** (out of v1 scope, untouched).

## Surfaces

| Surface | Status | Notes |
| --- | --- | --- |
| Discovery (UDP broadcast scan) | implemented | pre-existing, hardened re-broadcast |
| Native TCP get/set/read | implemented | pre-existing + attended-get layer |
| Embedded property map (per-model) | implemented | 60,748 entries from the full 3.1 WING Rack sweep; consistency + field-fidelity suites |
| Offline map regeneration (`wingschema embed`) | implemented | reproducible without a console |
| Model-aware resolution (`Schema`) | implemented | id/path entry points, drift → explicit `Unknown` |
| Runtime subtree refresh (`LiveSchema`) | implemented | overlay tested offline; live wire path exercised via replay harness only |
| Firmware metadata + stale-map detection | implemented | baseline pinned at 3.1; unicast firmware probe is **spec-derived** (unicast `WING?` reply unverified on hardware) |
| Attended get (value/definition, by id/name) | implemented | timeout-bounded, buffers unrelated traffic |
| Reconnect + session recovery | implemented | localhost-TCP tested; `SessionGap` surfaces losses; adopted by wing-core |
| Typed enum + bulk + dump/restore helpers | implemented | model-first restore ordering |
| Compatibility-preserving value types | implemented | unknown type/unit/enum preserved, `#[non_exhaustive]` policy |
| Channel-meter frame decode (all families incl. V2) | spec-derived | layouts from spec pp.97–99; WING Rack capture pending |
| RTA decode + scaling | spec-derived | 120 bins, 1/256 dB; **bin→Hz mapping is spec-silent** (log 20 Hz–20 kHz assumed) |
| Meter keepalive ownership | implemented | caller-owned renewal documented; server-side expiry semantics hardware-pending |
| OSC codec + get/set/node ops | spec-derived | byte-exact against spec examples; live console behavior pending |
| OSC subscriptions + robustness | spec-derived | one-active/takeover semantics documented; renewal cadence tested offline |
| Native/OSC availability map | implemented | total over the v1 operation set with rationale |
| Risk taxonomy + confirmation hooks | implemented | |
| Destructive-crawl safeguards | implemented | snapshot/restore logic unit-tested; full live crawl hardware-pending |
| CI test gates | implemented | fmt, all-targets tests, no-default-features build+test on push/PR |
| Parser/encoding conformance | implemented | |
| Record-replay harness + redaction guard | implemented | fixtures currently **synthetic** (spec-derived); no hardware captures yet |
| C ABI | best-effort | connection/get-set/defs/meters/lookups/keepalive/last-error; **no** OSC, schema resolution, or dump/restore; header compiles as C and C++ |
| Docs (README/PROVENANCE/REDACTION/COVERAGE) | implemented | |

## Hardware verification tier — all pending

No WING console was reachable during implementation (2026-07-05). The
following remain open until a WING Rack session happens (Verification
Contract, hardware tier):

1. Channel-meter layout + RTA scaling confirmation against real captures.
2. OSC get/set + one renewable subscription exercised live.
3. Unicast discovery/firmware probe behavior.
4. A recorded, redacted verification run (model, firmware, traces, schema
   dumps, pass/fail) backing the 3.1 baseline claim (R70/R56).
5. Replacing synthetic replay fixtures with sanitized hardware captures
   (`REDACTION.md` gates check-in).

## Cross-model status

Full WING / WING-BK / WING Compact: **unverified** (origin OQ11). The map and
I/O-dependent surfaces are known-good for the WING Rack only.

## Known data caveats

- The 3.1 release notes list Even 88-Comp, LMT Compressor, and One Knob
  Compressor; their model tokens are absent from the current sweep — re-sweep
  against a 3.1 console to close (see `PROVENANCE.md`).
- Firmware newer than 3.1 will trip `Schema::staleness` → use `LiveSchema`
  refresh for drifted subtrees.

## Deferred surfaces (origin scope boundaries — untouched)

Offline/show-prep mode, automation/scripting surface, console emulator,
Dante/AES50 expansion control, full C ABI parity.

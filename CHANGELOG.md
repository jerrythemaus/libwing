# Change Log

## [Unreleased]

### Breaking

- `NodeDump` gains a public `unknown_models` field; struct literals must set it (or
  use `..Default::default()`).
- `dump_subtree` now captures StringEnum leaves (including model selectors) as
  `NodeValue::String(label)` instead of `NodeValue::Int(index)`. Restoring through
  `set_nodes`/`restore` and comparing through `values_match_at` treat both forms
  alike, but a stored dump compared byte-for-byte against one taken before this
  change will differ on every StringEnum entry.
- `request_meter` / `wing_console_request_meter` reject out-of-family meter
  indices and nonzero MONITOR/RTA indices instead of sending them; see the ranges
  documented beside `METER_ID` in `libwing.h`.

### Added

- `Error::Reconnecting` (C code 9): an operation was interrupted by a reconnect on
  another clone. Retry it; do not reconnect again.
- `WingNodeData::string_enum_item`: resolves a StringEnum value sent either as an
  index or as a label.

### Fixed

- `reconnect` no longer deadlocks against `keep_alive` on another clone.
- `reconnect` keeps the known firmware when its re-probe gets no reply.
- `dump_subtree` no longer fails on a model the embedded map does not know (newer
  firmware); it skips that model's branches and lists the selector in
  `NodeDump::unknown_models`. It also stops with `Error::Reconnecting` when another
  clone asks to reconnect instead of holding that reconnect for the whole sweep.
- OSC decode ignores the content of padding bytes (trailing bytes after the
  declared arguments are still rejected).

## [2.0.0] - 2026-07-05

The wing-control-first v1 release: dynamic firmware-aware schema, a higher-level
Rust API, typed metering, an OSC transport, and safety tooling. See
`COVERAGE.md` for per-surface status and `PROVENANCE.md` for source provenance.

### Breaking

- `NodeType` and `NodeUnit` are no longer `#[repr(C)]`, gain a data-carrying
  `Unknown(u8)` variant (novel firmware discriminants are preserved, not coerced),
  and are now `#[non_exhaustive]`. `Error` is also `#[non_exhaustive]` with new
  variants (`Timeout`, `MeterFrameLength`). Matches on these enums now require a
  wildcard arm.
- C ABI: `wing_node_definition_get_type`/`get_unit` now return `FfiNodeType` /
  `FfiNodeUnit` (repr(C) mirrors keeping the header's 0-7 values, adding
  `Unknown = 8`) instead of the no-longer-repr(C) Rust enums.

### Added

- Embedded property map regenerated from the full per-model sweep (60,748
  entries, WING Rack firmware 3.1) + offline `wingschema embed` regeneration.
- Model-aware resolution (`Schema::resolve_id`/`resolve_path`), runtime overlay
  (`LiveSchema`), firmware metadata + stale-map detection.
- Attended get (`get_node_data`/`get_node_definition` + by-name) with timeouts;
  injectable `Transport` + `from_transports` for replay/testing.
- `reconnect` with bounded backoff + `SessionGap`; typed enum/bulk/dump-restore
  helpers; typed meter-frame decode (all families + RTA); the `osc` module
  (get/set, node ops, subscriptions, robustness, availability map).
- Operation risk taxonomy + confirmation hooks; destructive-crawl safeguards.
- C ABI: reverse lookups, keepalives, structured last-error.

## [1.0.4] - 2025-03-04

- removed eframe dependency from libwing

## [1.0.3] - 2025-03-03

- Close read socket when dropping WingConsole

## [1.0.2] - 2025-03-03

- Made public fields of WingConsoleHandle and ResponseHandle

## [1.0.1] - 2025-03-03

- Exposed ffi WingConsoleHandle and ResponseHandle so you can write async wrappers around read()

## [1.0.0] - 2025-03-03

- Calls are thread safe now
- NodeData no longer contains a channel ID (the first parameter), which was always the same before.
- Updates docs

## [unreleased] - 2025-02-17
- Added meters API

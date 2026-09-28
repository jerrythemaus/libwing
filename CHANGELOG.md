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
- `osc::WingOscClient::request_with_policy` sends a relative write (`osc::toggle`,
  i.e. any single `,i -1` argument) exactly once and returns `OscError::Timeout`, not
  `OscError::RetriesExhausted`, when its reply is lost: a retry would toggle back.
- `read_meters` returns `Error::Timeout` when no meter frame arrives for one keepalive
  interval (3 s) instead of waiting forever; the C meter reads return -1 with code 7.
  Loops that treat every error as fatal must treat `Timeout` as "keep reading".
- Each `request_meter` replaces the previous subscription: the meter keepalive renews
  only the most recent report id, so earlier ids stop streaming. A failed subscribe no
  longer spends an id, and ids wrap (skipping 0) instead of failing at `u16::MAX`.
- `DiscoveryInfo::ip` from `scan` is the reply's source address, not the address the reply
  claims; `scan` lists each console once instead of once per rebroadcast.
- `read()` no longer returns a node-name selector token (0xc0-0xcf) as a string value, and
  ignores bytes on any Native channel other than the Audio Engine.
- `reconnect` on a clone that waited for another clone's reconnect returns that session
  (`attempts == 0`) instead of replacing it a second time.

### Added

- `Error::Reconnecting` (C code 9): an operation was interrupted by a reconnect on
  another clone. Retry it; do not reconnect again.
- `WingNodeData::string_enum_item`: resolves a StringEnum value sent either as an
  index or as a label.
- `native::BoundedResponseEncoder::wire_len`: the length of the frame `finish`
  would return now.
- `osc::UNSOLICITED_CAP` and `osc::WingOscClient::take_unsolicited_dropped`: the
  unsolicited buffer's size limit and how many messages it has dropped.
- `WingConsole::read_meters_timeout` and `WingConsole::read_meters_into` (decodes into a
  caller buffer; the C meter reads now allocate nothing per frame).
- C: `wing_console_read_timeout`; last-error code -2 for a Rust panic caught at the FFI
  boundary; `libwing.h` states the threading contract (never destroy a handle while
  another thread is inside a call on it).

### Fixed

- `reconnect` no longer deadlocks against `keep_alive` on another clone.
- `reconnect` keeps the known firmware when its re-probe gets no reply.
- `dump_subtree` no longer fails on a model the embedded map does not know (newer
  firmware); it skips that model's branches and lists the selector in
  `NodeDump::unknown_models`. It also stops with `Error::Reconnecting` when another
  clone asks to reconnect instead of holding that reconnect for the whole sweep.
- OSC decode ignores the content of padding bytes (trailing bytes after the
  declared arguments are still rejected).
- `native::BoundedResponseEncoder::push` keeps a running wire length instead of
  rescanning the whole batch on every push (quadratic for large batches). Output and
  the size cap are unchanged.
- `native::NativeRequestDecoder` finds a meter collection's terminator without
  rescanning the buffered collection on every byte (quadratic up to
  `max_buffered_bytes`).
- `native::NativeRequestDecoder::push` resets the decoder on every error. Before, only
  limit violations did; other errors (for example `max_meter_entries`, a bad meter
  family, or invalid UTF-8) left the rejected bytes buffered, so every later push
  failed until the caller called `reset`.
- OSC `request`/`request_with_policy` skip a datagram that fails to decode instead of
  aborting the wait on it.
- The OSC unsolicited buffer keeps at most `UNSOLICITED_CAP` (1024) messages, dropping
  the oldest, instead of growing until `take_unsolicited` drains it.
- OSC reply matching ignores a `/%<port>` reply-port prefix, and a `/#<hash>` request
  also accepts a reply on the hash's plain path from the embedded property map.
- `set_string` escapes the length byte of a 224-byte string (0xdf). Before, a body starting
  with 0xd0-0xdd (UTF-8 lead bytes for Cyrillic, Hebrew, Arabic, ...) was read by the
  console as a channel switch. Client value encoding now shares the server encoder.
- An attended get (`get_node_data`, `get_node_definition`, and `get_nodes`/`dump_subtree`
  on top of them) fails with `InvalidData` after 64 Ki unrelated responses instead of
  buffering without bound, and one that times out hands what it buffered to the next
  `read()` instead of dropping it.
- `LiveSchema::refresh_subtree` honors its timeout even when the console never answers
  (it held the shared read gate forever), and hands interleaved `NodeData` to the next
  `read()` instead of dropping it.
- `read_meters` no longer holds the meter lock while waiting for a frame, so
  `keep_alive_meters`/`request_meter` on another clone never wait behind it.
- The firmware probe ignores replies from any host but the console.
- Every C entry point catches Rust panics instead of aborting the host process.
- `WingConsole`'s drop shuts its sockets down even when a lock was poisoned.
- The embedded property map is allocated at its final size (no rehashing at startup).

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

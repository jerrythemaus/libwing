# Record-replay fixtures (`.wingcap`)

Checked-in wire-level captures the offline conformance suite (`tests/replay.rs`)
replays through the real decoders/encoders with no WING Rack attached (U14: R71-R73,
R78). Every capture here is gated by `REDACTION.md` -- see "Redaction guard" below.

As of this writing every fixture is `# source: synthetic`: no hardware capture exists
yet, so each was hand-built from the same spec-derived wire encodings the rest of the
offline suite uses (`tests/attended_get.rs`'s frame helpers, `tests/osc_encode.rs`'s
golden vectors, `src/meters.rs`'s documented word layouts). They prove the
record-replay *machinery* end-to-end, ready to accept a real sanitized capture the
moment one exists.

## Format

A `.wingcap` file is plain text, one scenario per file: `# key: value` header lines,
followed by data lines and `# expect:` assertion annotations. Blank lines are ignored.
Loader: `tests/fixtures_common/mod.rs`.

### Headers

| Key | Meaning |
| --- | --- |
| `scenario` | Free-text name (documentation only). |
| `source` | `synthetic` or `hardware` (required). |
| `console_model`, `firmware`, `capture_date` | Provenance; required when `source: hardware`, meaningless (omit or `n/a`) for synthetic fixtures. |
| `sanitizer` | The sanitizer version/run that produced this file (`tools/wingcapture.rs`'s `SANITIZER_VERSION`), or `n/a` for a synthetic fixture that never went through it. |
| `note` | Free text, repeatable, documentation only. |
| `meters` | Meter scenario only: comma-separated meter requests in `Meter`-enum shorthand, e.g. `channel:1,rta`, `monitor`, `dca:2`. Order matters -- it's the same order `decode_frame` expects. |
| `request` | Native scenario only, repeatable, in order: one of `get_node_data id=<i32>`, `get_node_definition id=<i32>`, `set_int id=<i32> value=<i32>`, `set_float id=<i32> value=<f32>`, `set_string id=<i32> value=<string>` (no spaces in the value -- keep test strings single-token). Each drives one call against the replayed `WingConsole`. |

### Data lines

One channel + direction per 2-character prefix, followed by hex bytes:

| Prefix | Direction | Payload |
| --- | --- | --- |
| `N>` | client -> console | Native/TCP bytes the harness expects the console transport to have *written*, one line per `request:` header, in the same order. |
| `N<` | console -> client | Native/TCP bytes fed into the scripted reader; all `N<` lines concatenate into one input stream. |
| `M<` | console -> client | One meter datagram's *body* -- `i16` words, big-endian -- in the shape `decode_frame` consumes (i.e. **not** the raw UDP datagram: the 4-byte meter-id header `read_meters` strips is already gone). |
| `O<` | console -> client | One OSC datagram, decoded via `osc::decode` and checked against its paired `# expect: Osc ...`. |
| `O>` | client -> console | One OSC datagram; checked only for `decode(bytes)` succeeding and `encode(decode(bytes))` round-tripping byte-exact -- no value assertion. |
| `D<` | console -> client | A WING discovery-reply UDP payload (plain ASCII, comma-separated -- shares its `WING,ip,name,model,serial,firmware` body with the OSC `/?` console-info reply, so the discovery scenario reuses `osc::parse_console_info` rather than a separate tokenizer). |

### `# expect:` annotations

Vocabulary is scenario-specific and deliberately minimal:

- **Native**: `NodeData id=<i32> int=<i32>|float=<f32>|string=<value>`, `NodeDef id=<i32> name=<name>`, `RequestEnd` -- one per decoded `WingResponse`, in the order `console.read()` should produce them after every `request:` has been driven.
- **Meter**: `Channel input_l=.. input_r=.. output_l=.. output_r=.. gate_key=.. gate_gain=.. dyn_key=.. dyn_gain=..` (same field set for `Aux`/`Bus`/`Main`/`Matrix`, tagged by the leading keyword), or `Rta len=<n> first=<i16> last=<i16>` -- one per requested meter, in `meters:` order.
- **OSC**: `Osc addr=<addr> args=<n>` -- one per `O<` line, in order.
- **Discovery**: `Discovery ip=<ip> name=<name> model=<model> serial=<serial> firmware=<firmware>` -- exactly one per file.

## Redaction guard

`tests/replay.rs::every_checked_in_fixture_passes_redaction` scans **every** checked-in
`.wingcap` file -- both the header/comment text and the decoded payload bytes of every
data line -- for the three mechanical classes `REDACTION.md` rule 3 names: non-zero
`NGC` serials, IPv4 literals outside TEST-NET-1 (`192.0.2.0/24`) and
`0.0.0.0`/`127.0.0.1`, and MAC addresses outside `02:00:00:00:00:xx`. A hit fails the
test suite. The scanner itself lives in `tools/redact.rs`, shared with the sanitizer
below; `redaction_scanner_flags_an_unsanitized_in_memory_sample` is the guard's own
negative test (an in-memory sample, never a checked-in file).

Free-text identifiers -- console/channel/show/scribble names -- have no reliable
mechanical pattern and are **not** caught by this scanner. Redact those by hand per
`REDACTION.md`'s replacement table before a capture is sanitized.

## Recording and checking in a real hardware capture

No WING Rack is reachable from this development environment, so this is written for
whoever runs it first, on real hardware:

1. **Capture the raw traffic.** For unsolicited/keepalive Native traffic:
   ```sh
   cargo run --example wingcapture -- --record <console-ip> capture.raw.wingcap --seconds 10
   ```
   For a scripted get/set or OSC exchange, there's no capture-while-driving tool yet --
   run the exchange with `wingprop`/`wingschema`/`wingmon` while independently
   packet-capturing the session (e.g. `tcpdump -i <iface> host <console-ip> and (port
   2222 or port 2223) -w capture.pcap`), then hand-transcribe the relevant frames into
   `.wingcap` hex lines (see the format above). `capture.raw.wingcap` from `--record`
   is a starting template either way -- it already has the header/line shape, just
   with placeholder `FILL-ME-IN` provenance fields.
2. **Fill in provenance.** Edit the raw file's `console_model` / `firmware` /
   `capture_date` headers.
3. **Redact free-text identifiers by hand.** Replace any console/channel/show/scribble
   name per `REDACTION.md`'s table (`WING-FIXTURE`, `CH 1`, `SHOW-01`, ...) -- the
   sanitizer below does not do this for you.
4. **Run the sanitizer**, which handles the three mechanical classes and refuses to
   emit a file that would still fail the check-in guard:
   ```sh
   cargo run --example wingcapture -- capture.raw.wingcap capture.wingcap
   ```
5. **Verify and check in.**
   ```sh
   cargo test --test replay
   ```
   Add `capture.wingcap` to `tests/fixtures/`, record it in `PROVENANCE.md`, and delete
   the raw (unsanitized) file -- it must never leave the capturing machine
   (`REDACTION.md` rule 5).

### Length-sensitivity note (for anyone touching the sanitizer)

`tools/wingcapture.rs`'s automatic rewriting only ever substitutes same-byte-length
replacements: zero-filled serials, a fixed `02:00:00:00:00:00` MAC, and (for IPv4) a
`192.0.2.<n>` literal chosen to match the original string's length exactly. If no
TEST-NET-1 literal has that exact length (only 9-11 characters are reachable --
`192.0.2.0` through `192.0.2.255`), the tool refuses to emit output rather than
guess. This is deliberate: Native wire strings carry their length as an explicit
prefix byte elsewhere in the frame (see `console.rs`'s `set_string_message`), so a
length-changing rewrite would desync the stream. Standalone datagrams (discovery
replies, whole OSC messages) don't have that constraint -- their length is only the
UDP payload's own length -- but the sanitizer doesn't special-case them differently
today; it applies the same conservative same-length rule everywhere. A fixture that
hits the "no same-length replacement" error needs its IP redacted by hand instead.

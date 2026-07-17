# Hardware differential run — refine & verify the emulator against a real WING

This is the operator runbook for the differential harness: drive one deterministic protocol
battery against **both** a real WING console and `wing-emulator`, record each as a `.wingcap`
transcript, and diff them to find where the emulator diverges from real hardware. Feed the
deviations back into the emulator profile/logic until they're gone, then lock the win in as a
regression fixture.

It builds on the record-replay pipeline documented in `README.md` (quarantine, sanitize,
preflight, promotion) — read that first. The new pieces are the **deterministic driver**
(`wingdrive`) and the **fidelity-aware comparison** (`wingcapture --compare-fidelity`).

Everything below runs from the `libwing/` submodule directory unless noted. The emulator binary
lives in the parent workspace (`cargo run -p wing-emulator --bin wing-emulator -- …`).

## 0. Why this works

`wingdrive` derives its request battery from the *compiled* property map and hard-coded
constants — never wall-clock, randomness, or live state — so the **same binary drives an
identical client→console (`N>`) request stream every run**. Point it at the emulator once and at
the console once, and the two `N<` (console→client) response streams are directly comparable:
every difference on the deterministic legs is a real emulator-fidelity gap.

## 1. One-time setup

```sh
# Off-tree, non-synchronized private quarantine for raw captures (see README.md rules).
cargo run --example wingcapture -- --init-quarantine /private/local/wing-quarantine
```

## 2. Emulator reference capture (no console needed — the CI-safe sanity floor)

Terminal A — boot the emulator on a fixed loopback control port:

```sh
cargo run -p wing-emulator --bin wing-emulator -- --control 127.0.0.1:34500 --seed 0
```

Terminal B — start the bounded Native proxy pointed at the emulator, then drive it through the
proxy's printed loopback address:

```sh
cargo run --example wingcapture -- --proxy-native 127.0.0.1:0 127.0.0.1:34500 \
  /private/local/wing-quarantine emu-native.raw.wingcap --allow-state-changing --seconds 90
# → prints: "Native proxy ready at 127.0.0.1:<EPHEMERAL>"

cargo run --example wingdrive -- --target 127.0.0.1:<EPHEMERAL> --allow-state-changing
```

The proxy writes the emulator-side transcript to the quarantine. (Its header says
`source: hardware` — that label is cosmetic here; the emulator reference is only ever an input to
`--compare-fidelity`, never promoted.) Discovery and meter legs, if you want them in the same
transcript, use `--capture-discovery` / `--capture-meters` against the emulator and `--merge-v2`
to assemble — same as the hardware flow in `README.md`.

Sanity check the loop end-to-end with **two** emulator captures and confirm zero control
deviations (emulator-vs-itself is the floor):

```sh
cargo run --example wingcapture -- --compare-fidelity \
  emu-a.wingcap emu-b.wingcap /private/local/wing-review/floor.txt   # expect: deviations: 0
```

Both this floor and a known-divergence case are automated in
`libwing/tests/differential_selftest.sh` (no console needed) — run it in CI to guard the loop.

## 3. Hardware capture (the real oracle)

Same battery, proxy upstream pointed at the console's Native port (`<CONSOLE-IP>:2222`):

```sh
cargo run --example wingcapture -- --proxy-native 127.0.0.1:0 <CONSOLE-IP>:2222 \
  /private/local/wing-quarantine hw-native.raw.wingcap --allow-state-changing --seconds 90
# note the printed proxy address, then:
cargo run --example wingdrive -- --target 127.0.0.1:<EPHEMERAL> --allow-state-changing
```

`wingdrive` is safe on live hardware: the write leg touches only cosmetic leaves
(`/ch/1/{col,icon,name}`), each captured and restored, and it **aborts loudly** if any leaf does
not return to its original value. Start read-only (drop `--allow-state-changing`) on the very
first run if you want to watch it before letting it write.

Then promote the raw capture per `README.md`: manually redact free-text (console/channel/show
names), `--sanitize-v2`, and `--preflight <candidate> PROVENANCE.md`.

## 4. Compare → get the deviation report

```sh
cargo run --example wingcapture -- --compare-fidelity \
  /private/local/wing-review/hw.wingcap \
  /private/local/wing-review/emu.wingcap \
  /private/local/wing-review/deviations.txt
```

The report header carries the event counts, total deviation count, and a meter-cardinality
verdict; each following line is one deviation, most-useful first:
- `value path=<name> id=<id> hw=<v> emu=<v>` — a `NodeData` value differs,
- `missing path=<name> id=<id> hw=<present|missing> emu=<…>` — a node observed on only one side,
- `definition …` / `request-end count …` / `meter frame …` — definition, framing, and structural
  meter differences.
Meter frames are compared structurally (token presence + word count), never by raw sample value;
timestamps and keepalives are ignored.

## 5. Close the loop

Each deviation names a node path — fix it at the source:
- **data** gaps (wrong default/range/value): `crates/wing-emulator/profiles/wing-rack-3.1.evidence.json`
  and `…schema.jsonl`.
- **behavior** gaps: `crates/wing-emulator/src/server.rs` / `state.rs`.

Re-run §2–4 until the report is clean, then **promote one curated hardware capture** as a
checked-in regression fixture (place under `tests/fixtures/`, `cargo test -p libwing --test
replay`), and immediately `--dispose` the raw capture. Now the fidelity gain is locked in.

## Known findings (living list)

- **Definition request for model-variant/exotic nodes drops the emulator session.** The emulator
  tolerates *gets* for unknown nodes but fatally disconnects on a *definition* request for
  model-variant leaves (e.g. `/fx/1/*SOUL*/lmq`, `/ch/17/gate/DEQ2/1-mode`). `wingdrive`'s DEF leg
  is therefore curated to simple base leaves (`DEF_CORE`) for a clean baseline; widen it
  deliberately to probe/verify this divergence against real hardware, then fix in the emulator.

## Factory-default capture (one-time, needs a resettable console)

The emulator previously guessed defaults as range-minimums (`default_value`), which was wrong for
bipolar controls, master faders, model selectors, and processing-model params. Real defaults are
now captured from a factory-reset console and baked into `wing-rack-3.1.defaults.jsonl`:

```sh
# 1. Back up the show, factory-reset the console (Setup -> Initialize), reconnect.
# 2. Capture every distinct node id's value + all model selectors:
cargo run --example wingdrive -- --target <console-ip>:2222 --timeout-ms 80 \
  --dump-defaults factory-defaults.json
# 3. Resolve shared ids to their active-model paths -> the emulator artifact:
crates/wing-emulator/tools/resolve_defaults.py libwing/propmap.jsonl \
  factory-defaults.json crates/wing-emulator/profiles/wing-rack-3.1.defaults.jsonl
# 4. main.rs loads it via Profile::with_defaults; reset() prefers a captured default over the guess.
```

A factory-reset console only populates each slot's **factory-default model**. To capture the
**non-default models'** defaults (2250/BLISS/etc.), cycle a representative slot per family through
every model (non-destructive: each selector is restored), then propagate across the family:

```sh
# Cycle one representative per family (ch/bus/aux/main/mtx dyn/gate/eq/flt) through all models:
cargo run --example wingdrive -- --target <console-ip>:2222 --allow-state-changing \
  --timeout-ms 80 --capture-models model-defaults.jsonl
# Propagate each representative to all family instances and merge into the artifact:
crates/wing-emulator/tools/propagate_models.py libwing/propmap.jsonl model-defaults.jsonl \
  crates/wing-emulator/profiles/wing-rack-3.1.defaults.jsonl merged.jsonl
mv merged.jsonl crates/wing-emulator/profiles/wing-rack-3.1.defaults.jsonl
```

FX slots are covered too (2026-07-17): `--capture-models` now includes `/fx/1..16` — the
selector is at `/fx/N/mdl` (sub-path ""), `/fx/1` carries the union model set so it represents
the slot-9..16 subset as well, and template pseudo-models (`*EVEN*`, ...) are skipped.
Propagation expands `/fx/1` captures to all 16 slots (existing per-instance captures win).
The artifact now holds 64,044 values including ~8,100 FX defaults; differential-verified on
HALL/AMBI/ANGEL/PIA across slots 1/9/16. Verify with the differential harness: emulator clean
state vs a reset console should compare to ~0 control deviations.

## Model-switch repopulation (verified on hardware 2026-07-17)

Setting a `/…/mdl` selector repopulates the newly selected model's params with their **factory
defaults** and pushes each one (edited params do NOT survive leaving + re-entering a model —
verified: SOUL/lg=5, switch to STD and back, reads 0 again). The pushes arrive in **schema tree
order** (child index), not lexical path order. The emulator mirrors this in
`state.rs::repopulate_on_model_switch` (defaults from the captured artifact, ordered by
`Profile::tree_index`), differential-verified: identical GET results and identical repopulation
push sequences (modulo the origin mdl-echo deviation). Regression:
`state::tests::model_switch_repopulates_the_new_models_params_with_defaults` and the updated
`wing_control::model_switch_atomically_changes_reused_id_data_and_definition`.

## Behavioral probe (set-echo fidelity)

Beyond static values, the emulator must coerce *set* values like hardware — clamp to range,
quantize to the step grid, snap enums. Probe it:

```sh
# Boundary/off-grid sets on a type-diverse set of leaves, recording the ECHO (restorable):
cargo run --example wingdrive -- --target <ip>:2222 --allow-state-changing --probe-echo hw.jsonl
cargo run --example wingdrive -- --target 127.0.0.1:<emu-port> --allow-state-changing --probe-echo emu.jsonl
crates/wing-emulator/tools/diff_echo.py hw.jsonl emu.jsonl   # mismatches = behavioral divergences
```

This found (and drove the fix for) two systematic bugs: the emulator stored raw out-of-range
values instead of clamping, and didn't quantize floats to their step grid. `coerce_to_definition`
in `state.rs` now clamps + quantizes (linear/log) + snaps float-enums + rejects invalid
string-enums, matching hardware (107/109 probe records; the residual 2 are selector state).

The `--exec` mode (scripted `set`/`get`/`watch <ms>`) also surfaced that hardware pushes
**effective `$`-mirrors** (`$fdr`, `$mute`) whenever the source changes, asynchronously. The
emulator now emits them too (`commit_mutation` -> `apply_group_effects`, broadcast in `server.rs`)
including DCA/mute-group offsets (see below). Not yet modeled: model-switch repopulation and
channel linking (configuration-driven, see below).

## DCA & mute groups (verified on hardware 2026-07-17, firmware 3.1)

Membership is carried by each strip's free-text `tags` leaf (`/ch/N/tags`, also on
bus/aux/mtx/main; `/dca` and `/mgrp` strips have no tags) — there is **no** hidden membership
matrix node (a full-desk `get_binary_node(0)` sweep shows no unmapped group ids; `/cfg/dcamgrp`
is just an int toggle). Tokens are comma-separated; `#D1`..`#D16` = DCA membership,
`#M1`..`#M8` = mute-group membership, case-insensitive, leading spaces after a comma are
trimmed but a token with trailing junk (`#D16 `, `#D16x`, `#D016`, `x#D16`, `#D16;x`) does NOT
match. Out-of-range (`#D17`, `#M9`) is ignored. Duplicate tags count once.

Verified semantics (all via `--exec` probes against the factory-reset console):
- `$fdr` = own `fdr` + **sum** of member DCA faders (dB, f32 arithmetic), pushed change-driven.
  A -inf (-144) own fader absorbs any offset (stays -144). Sums are top-clamped to +10 and snap
  to -144 when the taper position falls below 1/1024 (dB <= about -89.5313). Raising works too
  (-85 + 10 -> -75).
- `$mute` tri-state: 1 = self-mute (always wins), 2 = any member group (DCA or MGRP) muted,
  0 = otherwise. One PUSH per change; no push if the derived value didn't change.
- `$muteovr` (override): settable only while group-muted and not self-muted — engaging makes
  `$mute` push 0 while group mutes stay on. A rejected engage (idle strip / self-muted strip)
  reverts to 0 with a corrective PUSH. The override **auto-clears (with a push) whenever the
  muting-group set changes** (any group mute toggles on or off, or membership changes) or when
  self-mute engages; it survives DCA fader moves and membership-preserving tag rewrites.
- `/cfg/dcamgrp` (factory default 1): with 1, a muted member DCA tri-states `$mute` (=2). With
  0, DCA mute becomes **fader kill**: `$fdr` is pushed to -144 and `$mute` stays 0. Mute groups
  tri-state `$mute` in both modes. Toggling `/cfg/dcamgrp` immediately re-derives and pushes
  both mirrors of every affected strip.
- Cosmetic `$`-leaves (`$col`/`$name`/`$icon`) do NOT follow their sources — they only change
  via source-select (`$`-actuals). The emulator therefore derives ONLY `$fdr`/`$mute`/`$muteovr`.
- Push scope: `set` echoes go to all sessions EXCEPT the origin (origin gets `RequestEnd`
  only); derived `$`-mirror pushes go to ALL sessions including the origin. A same-value write
  produces no echo and no derived push on hardware. (Emulator still echoes same-value writes to
  observers and echoes the coerced value to the origin — a small known deviation.)

Emulator model: `state.rs::recompute_strip` (+ `parse_group_tags`, `apply_group_effects`),
covered by `state::tests::{dca_membership_offsets_and_tristate_mute_follow_hardware,
muteovr_only_latches_group_mutes_and_autoclears_on_change,
dcamgrp_off_turns_dca_mute_into_fader_kill, group_tag_tokens_match_hardware_parsing}`.
Differential-verified side-by-side (identical GET results and `$`-push sequences for the
50-step probe battery, minus the two known deviations above).

## Fader-taper quantization (verified on hardware 2026-07-17)

FaderLevel sets quantize by round-tripping the WING taper in f32: dB -> position (4 linear
segments: >=-10 `(db+30)*0.025`, >=-30 `(db+50)*0.0125`, >=-60 `(db+70)*(1/160)`, else
`(db+90)*(1/480)`) -> dB. Position < 1/1024 snaps to -144; +10 is the ceiling. The
multiply-by-reciprocal form is bit-for-bit what the console computes (a 150-point echo sweep
matches exactly; the divide form differs in 16/150 points). `state.rs::quantize_fader` (also
applied to the DCA-offset sum), tests `state::tests::fader_sets_quantize_to_the_wing_taper`.

## Known behavioral gap: channel linking is configuration-driven

Investigated with `wingdrive --exec` (scripted set/get): setting `/ch/1/clink` (CUST LINK) to 1
does NOT make ch2 follow ch1's fader/mute/pan. WING linking is driven by a link-group / stereo
configuration, not a per-channel toggle, so modeling it faithfully is a dedicated
reverse-engineering + stateful-modeling effort (which channels are grouped, per-param mirror
semantics incl. inverted pan) rather than a contained fix. The emulator models no linking today.
`--exec` is raw (no auto-restore) -- use only on a free console.

## RESOLVED (2026-07-17): "channel linking" decoded -- clink is customization link, not audio link

Follow-up on the gap above, verified on the reset console. There is **no channel-to-channel
fader/mute linking on the WING at all** -- not via `clink`, not via stereo sources:
- A stereo source (`/io/in/<grp>/<n>/mode` = ST or M/S) makes ONE channel carry the stereo
  signal; the adjacent channel stays fully independent (fader/mute/pan verified independent
  with source stereo + both clink states).
- `/cfg/mainlink` (OFF/"2"/"2-3"/"2-4") is the only strip-linking config, and it works exactly
  like a DCA on mains 2..N with main/1 as master: main/1's fader is a dB **offset** on the
  member's `$fdr` (member's own `fdr` unchanged), main/1's mute makes the member's `$mute` = 2.
  Unlike tag groups the member CANNOT latch `$muteovr` against a mainlink mute (engage reverts
  with a corrective push). Unlink re-derives members from their own state. Pan is NOT mirrored.

`clink` (CUST LINK, factory default **1**) selects the source of a strip's customization
actuals `$name`/`$col`/`$icon`:
- clink=1: actuals follow the ACTIVE source's `name`/`col`/`icon` (`/io/in/<grp>/<n>/…`).
  "Active" honors `in/set/altsrc` (ALT INPUT) and repatching `in/conn/{grp,in,altgrp,altin}` --
  each re-derives + pushes. Unpatched (grp OFF) shows ""/1/0. Source-cosmetic writes push the
  actuals of EVERY strip patched to that source.
- clink=0: actuals follow the strip's OWN `name`/`col`/`icon`.
- Strips without an input connector (bus/main/mtx; no clink node) always use their own leaves,
  and additionally alias their cosmetics into the read-only stereo-pair io sources
  (`/bus/N` -> `/io/in/$BUS/{2N-1,2N}/{name,col,icon}`, same for $MAIN/$MTX) so they can be
  patched as inputs elsewhere.
- `{strip}/in/set/$mode` mirrors the active source's `mode` ("M" when unpatched), pushed on
  source-mode change and on repatch.

Input pairing: setting either side of an odd/even io-input pair to ST/M-S mirrors the mode to
its partner (verified LCL, AES50-A, USR). **Forming** a pair copies the setter's cosmetics onto
the partner; **while paired**, cosmetic edits on either side mirror live to the other; unpairing
leaves both sides with the last shared cosmetics.

All of this is modeled in `state.rs` (`derive_customization`, `mirror_io_mode_to_partner`,
`mirror_io_cosmetic_to_partner`, mainlink handling in `recompute_strip`) and covered by
`state::tests::{clink_switches_customization_between_source_and_own_leaves,
io_mode_mirrors_to_partner_and_strip_effective_mode,
pair_formation_copies_and_live_mirrors_io_cosmetics,
mainlink_chains_main_faders_and_mutes_like_a_dca}`. Differential batteries (customization,
pairing, mainlink) verify identical GET results console-vs-emulator; push streams match modulo
the known origin-echo/same-value deviations and one hardware quirk not modeled (pair formation
re-broadcasts the pre-existing cosmetics of the partner side it just overwrote).

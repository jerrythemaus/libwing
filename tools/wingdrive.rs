//! wingdrive -- deterministic WING conformance driver (differential-harness driver leg, U12).
//!
//! Runs one fixed, ordered protocol battery against a target Native endpoint. Because the
//! battery is derived from the *compiled* property map and hard-coded constants -- never from
//! wall-clock, randomness, or live state -- the same binary drives an identical client->console
//! (`N>`) request stream on every run. Point it (through `wingcapture --proxy-native`) at a real
//! console once and at `wing-emulator` once, and the two recorded `.wingcap` transcripts are
//! directly comparable: every console->client (`N<`) difference on the deterministic legs is a
//! real emulator-fidelity gap. See `tests/fixtures/HARDWARE_RUN.md` for the full loop.
//!
//! The battery mirrors the `wing-rack-3.1-v1` matrix contract: bulk gets, definition fetches,
//! restorable state-changing writes, two meter subscriptions + two renewals, and an explicit
//! disconnect.
//!
//! ```text
//! Usage: wingdrive --target <IP:PORT> [--allow-state-changing]
//!                  [--gets N] [--timeout-ms N] [--meter-frames N] [--meter-secs N]
//!                  [--dump-scenario <path>]
//! ```
//!
//! Read-only by default. The write phase runs only with `--allow-state-changing`; it snapshots
//! each target, applies a fixed cosmetic value, then restores -- and aborts loudly if any
//! restore read-back fails to return the console to its original value, so a real console is
//! never left mutated.
//!
//! `--dump-scenario <path>` captures the target's live state as a `wing-emulator` scenario JSON
//! (then stops), so the emulator can be booted mirroring a real console for a like-for-like
//! comparison. It writes ALL model selectors (`/mdl`) -- so the emulator loads the same model per
//! slot and resolves shared ids (WING ids are reused across model variants) to the same variant --
//! plus the unique-id (non-model-variant) leaves observed by the GET battery. Read-only leaves are
//! skipped (the emulator rejects them).

mod utils;
use utils::Args;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use libwing::{Meter, NodeType, WingConsole, WingNodeData, WingNodeDef, WingResponse};

/// Cosmetic, always-writable leaves used for the restorable-write leg. Chosen because they are
/// silent (no audio/routing impact) and round-trip losslessly through `dump_subtree`/`restore`.
const WRITE_TARGETS: &[(&str, WriteVal)] = &[
    ("/ch/1/col", WriteVal::Int(7)),
    ("/ch/1/icon", WriteVal::Int(42)),
    ("/ch/1/name", WriteVal::Str("WINGDIFF")),
];

/// Meter subscription requested twice (two subscriptions) then renewed twice, per the contract.
const METER_SET: &[Meter] = &[Meter::Channel(1), Meter::Main(1), Meter::Rta];

/// Definition-phase targets: simple, always-present base leaves (no model variance) whose defs
/// encode cleanly. The broad GET sweep tolerates unknown nodes, but a definition request for an
/// unsupported/exotic node currently drops the emulator session, so the DEF leg stays curated for
/// a clean baseline. Widening this set is a good way to probe that exact divergence deliberately.
const DEF_CORE: &[&str] = &[
    "/ch/1/fdr",
    "/ch/1/mute",
    "/ch/1/pan",
    "/ch/1/col",
    "/ch/1/name",
    "/ch/1/icon",
    "/main/1/fdr",
    "/main/1/mute",
    "/main/1/pan",
];

#[derive(Clone, Copy)]
enum WriteVal {
    Int(i32),
    Str(&'static str),
}

/// A leaf's value in whichever facet it carried, for before/after restore verification.
#[derive(Debug, PartialEq)]
enum Snap {
    Str(String),
    Float(f32),
    Int(i32),
}

/// A connection-level failure during a request phase, tagged with the phase, request index, and
/// node so a mid-battery disconnect points straight at the culprit instead of surfacing later.
fn fatal(
    phase: &str,
    index: usize,
    name: &str,
    error: libwing::Error,
) -> Box<dyn std::error::Error> {
    format!("{phase} phase: connection lost at request #{index} ({name}): {error}").into()
}

fn snap(data: &WingNodeData) -> Snap {
    if data.has_string() {
        Snap::Str(data.get_string())
    } else if data.has_float() {
        Snap::Float(data.get_float())
    } else {
        Snap::Int(data.get_int())
    }
}

/// Deterministic, leaf-only sample spread evenly across the compiled property map. The same
/// binary yields the same list on every invocation and on both console and emulator, so the
/// recorded `N>` request stream is identical by construction.
///
/// `*MODEL*` template pseudo-nodes (e.g. `/fx/1/*SOUL*/lmq`) are excluded: they are not concrete
/// addressable leaves in a clean scene -- they only exist when the slot is loaded with that model
/// -- so requesting them exercises undefined territory rather than baseline fidelity. A dedicated
/// model-loaded sweep can target them deliberately later.
fn battery_nodes(count: usize) -> Vec<&'static str> {
    let mut leaves: Vec<&'static str> = WingConsole::propmap_iter()
        .filter(|(name, def)| def.node_type != NodeType::Node && !name.contains('*'))
        .map(|(name, _)| name)
        .collect();
    leaves.sort_unstable();
    if leaves.is_empty() || count == 0 {
        return Vec::new();
    }
    let stride = (leaves.len() / count).max(1);
    leaves.into_iter().step_by(stride).take(count).collect()
}

/// Writes the observed live values as an emulator scenario JSON (see `Value` in
/// `wing-emulator/src/state.rs`: `{"type":"float|int|string","value":...}`). Non-finite floats are
/// skipped (not representable as JSON numbers). Hand-rolled JSON keeps `libwing` dependency-free.
fn write_scenario(path: &str, observed: &[(&str, Snap)]) -> Result<(), Box<dyn std::error::Error>> {
    let entries: Vec<String> = observed
        .iter()
        .filter_map(|(node, value)| {
            // Read-only leaves can't be set via a scenario (the emulator rejects them) and reflect
            // computed/status values, not settable state -- skip them.
            if WingConsole::name_to_def(node)
                .map(|def| def.read_only)
                .unwrap_or(false)
            {
                return None;
            }
            let encoded = match value {
                Snap::Int(v) => format!("{{ \"type\": \"int\", \"value\": {v} }}"),
                Snap::Float(v) if v.is_finite() => {
                    format!("{{ \"type\": \"float\", \"value\": {v} }}")
                }
                Snap::Float(_) => return None,
                Snap::Str(s) => {
                    format!(
                        "{{ \"type\": \"string\", \"value\": \"{}\" }}",
                        json_escape(s)
                    )
                }
            };
            Some(format!("    \"{}\": {encoded}", json_escape(node)))
        })
        .collect();
    let json = format!(
        "{{\n  \"name\": \"hardware-mirror\",\n  \"reset\": \"profile-and-scenario\",\n  \"values\": {{\n{}\n  }}\n}}\n",
        entries.join(",\n")
    );
    std::fs::write(path, json)?;
    Ok(())
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

/// Whether `path`'s node id maps to exactly one path -- i.e. it is NOT a model-variant slot whose
/// id is shared across models. Only unique-id leaves are mirrored by value (a shared one can't be
/// pinned to a single path here without knowing the active model).
fn is_unique_id(path: &str) -> bool {
    WingConsole::name_to_def(path)
        .and_then(|def| WingConsole::id_to_defs(def.id))
        .map(|defs| defs.len() == 1)
        .unwrap_or(false)
}

/// Captures the full factory-default state of `wing` (intended: a factory-reset console). Records
/// every distinct value-leaf id once (requested by id), plus all model selectors by path so an
/// offline step can map each id to its active-model path. A per-id timeout means the console
/// doesn't hold that node -- skipped, not fatal.
fn capture_defaults(
    wing: &mut WingConsole,
    path: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut mdl: Vec<(&str, String)> = Vec::new();
    for (name, _) in WingConsole::propmap_iter().filter(|(name, _)| name.ends_with("/mdl")) {
        if let Ok((data, _)) = wing.get_node_data_by_name(name, timeout) {
            mdl.push((name, data.get_string()));
        }
    }
    let ids: BTreeSet<i32> = WingConsole::propmap_iter()
        .filter(|(name, def)| def.node_type != NodeType::Node && !name.contains('*'))
        .map(|(_, def)| def.id)
        .collect();
    let total = ids.len();
    let mut by_id: Vec<(i32, Snap)> = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        if let Ok((data, _)) = wing.get_node_data(*id, timeout) {
            by_id.push((*id, snap(&data)));
        }
        if (index + 1) % 4000 == 0 {
            eprintln!(
                "wingdrive: defaults {}/{total} ids probed, {} captured",
                index + 1,
                by_id.len()
            );
        }
    }
    write_defaults(path, &mdl, &by_id)?;
    println!(
        "wingdrive: wrote factory defaults to {path} ({} selectors + {} values / {total} ids)",
        mdl.len(),
        by_id.len()
    );
    Ok(())
}

/// Writes captured defaults as JSON: `{ "mdl": {path: model}, "by_id": [{id, type, value}] }`.
/// Non-finite floats are skipped (not representable as JSON numbers).
fn write_defaults(
    path: &str,
    mdl: &[(&str, String)],
    by_id: &[(i32, Snap)],
) -> Result<(), Box<dyn std::error::Error>> {
    let selectors: Vec<String> = mdl
        .iter()
        .map(|(node, model)| format!("    \"{}\": \"{}\"", json_escape(node), json_escape(model)))
        .collect();
    let values: Vec<String> = by_id
        .iter()
        .filter_map(|(id, value)| {
            let (kind, encoded) = match value {
                Snap::Int(v) => ("int", v.to_string()),
                Snap::Float(v) if v.is_finite() => ("float", v.to_string()),
                Snap::Float(_) => return None,
                Snap::Str(s) => ("string", format!("\"{}\"", json_escape(s))),
            };
            Some(format!(
                "    {{ \"id\": {id}, \"type\": \"{kind}\", \"value\": {encoded} }}"
            ))
        })
        .collect();
    let json = format!(
        "{{\n  \"mdl\": {{\n{}\n  }},\n  \"by_id\": [\n{}\n  ]\n}}\n",
        selectors.join(",\n"),
        values.join(",\n")
    );
    std::fs::write(path, json)?;
    Ok(())
}

/// Captures every model's default parameters by cycling one representative slot per family
/// (channel/bus/aux/main/mtx dyn/gate/eq/flt, and the fx slots) through each model. Setting a
/// slot's `/mdl` populates that model's params with their defaults; we read them, then restore
/// the selector to its original value. Template pseudo-models (`*EVEN*`, ...) are skipped. An
/// offline step propagates each representative to all instances in its family. Writes JSONL of
/// {path, value}.
fn capture_models(
    wing: &mut WingConsole,
    out_path: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Representative slot (lowest index) per (section, sub-path) family. FX slots have their
    // selector directly at /fx/N/mdl (sub-path ""); /fx/1 supports the union of all FX models,
    // so it representatively covers the smaller slot-9..16 model set too.
    let mut reps: BTreeMap<(String, String), (u32, String)> = BTreeMap::new();
    for (name, def) in WingConsole::propmap_iter() {
        if !name.ends_with("/mdl") || def.string_enum.is_none() {
            continue;
        }
        let slot = &name[..name.len() - "/mdl".len()];
        let parts: Vec<&str> = slot.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        let Ok(index) = parts[2].parse::<u32>() else {
            continue;
        };
        let key = (
            parts[1].to_string(),
            parts.get(3..).unwrap_or_default().join("/"),
        );
        let entry = reps.entry(key).or_insert((u32::MAX, String::new()));
        if index < entry.0 {
            *entry = (index, slot.to_string());
        }
    }
    let rep_slots: BTreeSet<String> = reps.into_values().map(|(_, slot)| slot).collect();

    // Concrete param paths per (representative slot, model).
    let mut params: BTreeMap<(String, String), Vec<&'static str>> = BTreeMap::new();
    for (name, def) in WingConsole::propmap_iter() {
        if def.node_type == NodeType::Node || name.contains('*') {
            continue;
        }
        for slot in &rep_slots {
            let Some(tail) = name
                .strip_prefix(slot.as_str())
                .and_then(|t| t.strip_prefix('/'))
            else {
                continue;
            };
            if let Some((model, leaf)) = tail.split_once('/') {
                if !leaf.is_empty() {
                    params
                        .entry((slot.clone(), model.to_string()))
                        .or_default()
                        .push(name);
                }
            }
            break;
        }
    }

    let mut captured: Vec<(&str, Snap)> = Vec::new();
    let mut restored = 0usize;
    for slot in &rep_slots {
        let mdl_path = format!("{slot}/mdl");
        let Some(mdl_def) = WingConsole::name_to_def(&mdl_path) else {
            continue;
        };
        let mdl_id = mdl_def.id;
        let original = wing
            .get_node_data(mdl_id, timeout)
            .ok()
            .map(|(data, _)| data.get_string());
        let models: Vec<String> = mdl_def
            .string_enum
            .as_ref()
            .map(|items| items.iter().map(|item| item.item.clone()).collect())
            .unwrap_or_default();
        for model in &models {
            // Template pseudo-models (*EVEN*, *SOUL*, ...) are placeholders, not loadable models.
            if model.contains('*') {
                continue;
            }
            if wing.set_string(mdl_id, model).is_err() {
                continue;
            }
            let _ = read_settled(wing, mdl_id, timeout); // barrier: selector applied
            if let Some(paths) = params.get(&(slot.clone(), model.clone())) {
                for path in paths {
                    if let Ok((data, _)) = wing.get_node_data_by_name(path, timeout) {
                        captured.push((path, snap(&data)));
                    }
                }
            }
        }
        if let Some(original) = original {
            if wing.set_string(mdl_id, &original).is_ok() {
                restored += 1;
            }
        }
        eprintln!(
            "wingdrive: models captured for {slot} ({} models)",
            models.len()
        );
    }

    write_path_values(out_path, &captured)?;
    println!(
        "wingdrive: wrote {} model-param defaults from {} representative slots (restored {}) to {out_path}",
        captured.len(),
        rep_slots.len(),
        restored
    );
    Ok(())
}

/// Writes `path -> value` pairs as JSONL (`{"path":..,"value":{"type":..,"value":..}}` per line),
/// matching the emulator's defaults artifact. Non-finite floats are skipped.
fn write_path_values(
    path: &str,
    values: &[(&str, Snap)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::new();
    for (node, value) in values {
        let encoded = match value {
            Snap::Int(v) => format!("{{\"type\":\"int\",\"value\":{v}}}"),
            Snap::Float(v) if v.is_finite() => format!("{{\"type\":\"float\",\"value\":{v}}}"),
            Snap::Float(_) => continue,
            Snap::Str(s) => format!("{{\"type\":\"string\",\"value\":\"{}\"}}", json_escape(s)),
        };
        out.push_str(&format!(
            "{{\"path\":\"{}\",\"value\":{encoded}}}\n",
            json_escape(node)
        ));
    }
    std::fs::write(path, out)?;
    Ok(())
}

/// A test value written during behavioral echo probing.
enum SetVal {
    Float(f32),
    Int(i32),
    Str(String),
}

/// Groups a node type into a probe bucket, or `None` for types we don't probe (containers,
/// free-text strings, unknown).
fn type_key(node_type: NodeType) -> Option<&'static str> {
    match node_type {
        NodeType::LinearFloat => Some("linear-float"),
        NodeType::LogarithmicFloat => Some("log-float"),
        NodeType::FaderLevel => Some("fader"),
        NodeType::Integer => Some("integer"),
        NodeType::FloatEnum => Some("float-enum"),
        NodeType::StringEnum => Some("string-enum"),
        _ => None,
    }
}

/// Boundary/off-grid test inputs for a param, chosen to expose clamping, step quantization, and
/// enum coercion. Deterministic from the definition, so console and emulator get identical inputs.
fn probe_inputs(def: &WingNodeDef) -> Vec<SetVal> {
    match def.node_type {
        NodeType::LinearFloat | NodeType::LogarithmicFloat | NodeType::FaderLevel => {
            let min = def.min_float.unwrap_or(-144.0);
            let max = def.max_float.unwrap_or(10.0);
            if !(max > min) {
                return Vec::new();
            }
            let span = max - min;
            vec![
                SetVal::Float(min - 0.1 * span),   // below min -> clamp
                SetVal::Float(max + 0.1 * span),   // above max -> clamp
                SetVal::Float(min + 0.371 * span), // off-grid -> quantize
            ]
        }
        NodeType::Integer => {
            let min = def.min_int.unwrap_or(0);
            let max = def.max_int.unwrap_or(1);
            vec![
                SetVal::Int(min.saturating_sub(1)),
                SetVal::Int(max.saturating_add(1)),
                SetVal::Int(min + (max - min) / 2),
            ]
        }
        NodeType::FloatEnum => match def.float_enum.as_ref() {
            Some(items) if items.len() >= 2 => vec![
                SetVal::Float((items[0].item + items[1].item) / 2.0), // between items -> snap
                SetVal::Float(items[0].item - 1.0),                   // below -> clamp/snap
                SetVal::Float(items[items.len() - 1].item + 1.0),     // above -> clamp/snap
            ],
            _ => Vec::new(),
        },
        NodeType::StringEnum => match def.string_enum.as_ref() {
            Some(items) if items.len() >= 2 => vec![
                SetVal::Str("__wingdrive_invalid__".to_string()), // invalid -> reject/ignore?
                SetVal::Str(items[1].item.clone()),               // valid, non-first item
            ],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Behavioral echo probe: for the first few writable leaves of each node type, write boundary and
/// off-grid values and record the ECHO the target adopts (after clamp/quantize/coerce), restoring
/// the original afterward. Run against console and emulator, then diff the echoes.
fn probe_echo(
    wing: &mut WingConsole,
    out_path: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    const PER_TYPE: usize = 8;
    let mut leaves: Vec<(&'static str, &'static WingNodeDef)> = WingConsole::propmap_iter()
        .filter(|(name, def)| {
            type_key(def.node_type).is_some()
                && !def.read_only
                && !name.contains('*')
                && !name.contains('$') // skip system/action nodes ($savenow, cf_load, ...)
                && is_unique_id(name) // skip model-variant (shared-id) params: active-model-confounded
        })
        .collect();
    leaves.sort_by_key(|(name, _)| *name);
    let mut per_type: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut targets: Vec<(&'static str, &'static WingNodeDef)> = Vec::new();
    for (name, def) in leaves {
        let key = type_key(def.node_type).expect("filtered to probed types");
        let count = per_type.entry(key).or_default();
        if *count < PER_TYPE {
            *count += 1;
            targets.push((name, def));
        }
    }

    let mut records: Vec<(&'static str, SetVal, Snap)> = Vec::new();
    for (path, def) in &targets {
        let id = def.id;
        let original = wing
            .get_node_data(id, timeout)
            .ok()
            .map(|(data, _)| snap(&data));
        for input in probe_inputs(def) {
            let sent = match &input {
                SetVal::Float(v) => wing.set_float(id, *v),
                SetVal::Int(v) => wing.set_int(id, *v),
                SetVal::Str(v) => wing.set_string(id, v),
            };
            if sent.is_err() {
                continue;
            }
            if let Ok(echo) = read_settled(wing, id, timeout) {
                records.push((path, input, echo));
            }
        }
        if let Some(original) = original {
            let _ = match original {
                Snap::Float(v) => wing.set_float(id, v),
                Snap::Int(v) => wing.set_int(id, v),
                Snap::Str(s) => wing.set_string(id, &s),
            };
        }
    }
    write_echo_records(out_path, &records)?;
    println!(
        "wingdrive: probed {} leaves, wrote {} echo records to {out_path}",
        targets.len(),
        records.len()
    );
    Ok(())
}

/// Writes echo probe records as JSONL: `{"path":..,"set":{type,value},"echo":{type,value}}`.
/// Records containing a non-finite float (not JSON-representable) are skipped.
fn write_echo_records(
    path: &str,
    records: &[(&str, SetVal, Snap)],
) -> Result<(), Box<dyn std::error::Error>> {
    let float = |v: f32| {
        if v.is_finite() {
            Some(v.to_string())
        } else {
            None
        }
    };
    let mut out = String::new();
    for (node, set, echo) in records {
        let set_json = match set {
            SetVal::Float(v) => match float(*v) {
                Some(v) => format!("{{\"type\":\"float\",\"value\":{v}}}"),
                None => continue,
            },
            SetVal::Int(v) => format!("{{\"type\":\"int\",\"value\":{v}}}"),
            SetVal::Str(s) => format!("{{\"type\":\"string\",\"value\":\"{}\"}}", json_escape(s)),
        };
        let echo_json = match echo {
            Snap::Float(v) => match float(*v) {
                Some(v) => format!("{{\"type\":\"float\",\"value\":{v}}}"),
                None => continue,
            },
            Snap::Int(v) => format!("{{\"type\":\"int\",\"value\":{v}}}"),
            Snap::Str(s) => format!("{{\"type\":\"string\",\"value\":\"{}\"}}", json_escape(s)),
        };
        out.push_str(&format!(
            "{{\"path\":\"{}\",\"set\":{set_json},\"echo\":{echo_json}}}\n",
            json_escape(node)
        ));
    }
    std::fs::write(path, out)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::new(
        r#"
Usage: wingdrive --target <IP:PORT> [--allow-state-changing]
                 [--gets N] [--timeout-ms N] [--meter-frames N] [--meter-secs N]
                 [--dump-scenario <path>]

  Drives one deterministic conformance battery against a WING Native endpoint (a real console,
  the emulator, or a wingcapture --proxy-native loopback address). Read-only unless
  --allow-state-changing is given, in which case a small set of cosmetic leaves are written and
  restored. With --dump-scenario, writes the observed live values as a wing-emulator scenario and
  stops (for like-for-like state mirroring). See the module doc in tools/wingdrive.rs.
"#,
    );

    let mut target: Option<SocketAddr> = None;
    let mut allow_state_changing = false;
    let mut gets = 128usize;
    let mut timeout = Duration::from_millis(400);
    let mut meter_frames = 2usize;
    let mut meter_secs = 5u64;
    let mut dump_scenario: Option<String> = None;
    let mut dump_defaults: Option<String> = None;
    let mut capture_models_out: Option<String> = None;
    let mut probe_echo_out: Option<String> = None;
    let mut exec_script: Option<String> = None;

    while args.has_next() {
        match args.next().as_str() {
            "--target" => target = Some(args.next().parse()?),
            "--allow-state-changing" => allow_state_changing = true,
            "--gets" => gets = args.next().parse()?,
            "--timeout-ms" => timeout = Duration::from_millis(args.next().parse()?),
            "--meter-frames" => meter_frames = args.next().parse()?,
            "--meter-secs" => meter_secs = args.next().parse()?,
            "--dump-scenario" => dump_scenario = Some(args.next()),
            "--dump-defaults" => dump_defaults = Some(args.next()),
            "--capture-models" => capture_models_out = Some(args.next()),
            "--probe-echo" => probe_echo_out = Some(args.next()),
            "--exec" => exec_script = Some(args.next()),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let target = target.ok_or("--target <IP:PORT> is required")?;
    println!("wingdrive: connecting to {target}");
    let mut wing = WingConsole::connect_addr(target)?;
    println!("wingdrive: connected (firmware {:?})", wing.firmware());

    // Comprehensive factory-default capture: every distinct value-leaf id captured once (by id),
    // plus the model selectors so an offline step can resolve each id to its active-model path.
    // Intended to run against a factory-reset console; stops after writing.
    if let Some(path) = dump_defaults {
        capture_defaults(&mut wing, &path, timeout)?;
        return Ok(());
    }

    // Per-model default capture: cycle one representative slot per family through every model
    // (which populates that model's defaults) and record them. STATE-CHANGING but restorable --
    // each selector is set back to its original value. Offline propagation expands representatives
    // to all family instances. Requires --allow-state-changing.
    if let Some(path) = capture_models_out {
        if !allow_state_changing {
            return Err(
                "--capture-models writes model selectors; pass --allow-state-changing".into(),
            );
        }
        capture_models(&mut wing, &path, timeout)?;
        return Ok(());
    }

    // Behavioral probe: for a type-diverse set of writable leaves, send boundary/off-grid values
    // (below-min, above-max, between-steps, mid-enum) and record the console's ECHO -- the value it
    // actually adopts after clamping/quantization/enum coercion. STATE-CHANGING but restorable. Run
    // against console and emulator, then diff the echoes to find behavioral divergences.
    if let Some(path) = probe_echo_out {
        if !allow_state_changing {
            return Err("--probe-echo writes test values; pass --allow-state-changing".into());
        }
        probe_echo(&mut wing, &path, timeout)?;
        return Ok(());
    }

    // Scripted set/get investigation: run lines of `set <path> <int|float|string> <val>` / `get
    // <path>` / `# comment` and print each get result. Raw (no auto-restore) -- for use on a free
    // console. Requires --allow-state-changing if the script sets anything.
    if let Some(script_path) = exec_script {
        let script = std::fs::read_to_string(&script_path)?;
        for line in script.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            match tokens.as_slice() {
                ["get", path] => match wing.get_node_data_by_name(path, timeout) {
                    Ok((data, _)) => println!("GET {path} = {:?}", snap(&data)),
                    Err(error) => println!("GET {path} ERR {error}"),
                },
                // Raw wire capture of a node's reply stream (hex) -- for reverse-engineering
                // binary/matrix nodes whose format the typed getters can't represent.
                ["bin", path] => {
                    let Some(def) = WingConsole::name_to_def(path) else {
                        println!("BIN {path} ERR unknown path");
                        continue;
                    };
                    match wing.get_binary_node(def.id, timeout) {
                        Ok(bytes) => {
                            println!("BIN {path} ({} bytes)", bytes.len());
                            for chunk in bytes.chunks(16) {
                                let hex: Vec<String> =
                                    chunk.iter().map(|b| format!("{b:02x}")).collect();
                                println!("  {}", hex.join(" "));
                            }
                        }
                        Err(error) => println!("BIN {path} ERR {error}"),
                    }
                }
                // Decoded binary capture: parse the raw stream into (id, value) pairs and label
                // each id with its propmap path(s) -- ids absent from the propmap print as raw
                // hashes, exposing hidden nodes (e.g. membership matrices).
                ["bindecode", path] => {
                    // Root ("/") captures the whole desk -- get_binary_node(0) special-case.
                    let id = if *path == "/" {
                        0
                    } else if let Some(def) = WingConsole::name_to_def(path) {
                        def.id
                    } else {
                        println!("BINDECODE {path} ERR unknown path");
                        continue;
                    };
                    match wing.get_binary_node(id, timeout) {
                        Ok(bytes) => match libwing::parse_binary_values(&bytes) {
                            Ok(pairs) => {
                                println!("BINDECODE {path} ({} pairs)", pairs.len());
                                for (id, value) in pairs {
                                    let name = WingConsole::id_to_defs(id)
                                        .and_then(|defs| defs.into_iter().map(|(p, _)| p).min())
                                        .unwrap_or_else(|| format!("<unmapped id={id}>"));
                                    println!("  {name} = {value:?}");
                                }
                            }
                            Err(error) => println!("BINDECODE {path} PARSE-ERR {error}"),
                        },
                        Err(error) => println!("BINDECODE {path} ERR {error}"),
                    }
                }
                ["watch", ms] => {
                    // Read the async push stream for `ms` and print every NodeData the console
                    // emits (set echoes + derived $-mirror pushes).
                    let deadline = Instant::now() + Duration::from_millis(ms.parse()?);
                    while Instant::now() < deadline {
                        match wing.read_timeout(Duration::from_millis(50)) {
                            Ok(WingResponse::NodeData(id, data)) => {
                                let name = WingConsole::id_to_defs(id)
                                    .and_then(|defs| defs.into_iter().map(|(p, _)| p).min())
                                    .unwrap_or_else(|| format!("id={id}"));
                                println!("PUSH {name} = {:?}", snap(&data));
                            }
                            Ok(_) => {}
                            Err(libwing::Error::Timeout) => {}
                            Err(error) => {
                                println!("WATCH ERR {error}");
                                break;
                            }
                        }
                    }
                }
                // Like watch, but prints EVERY response variant (RequestEnd, defs, ...) --
                // for pinning down the exact per-request response contract.
                ["watchall", ms] => {
                    let deadline = Instant::now() + Duration::from_millis(ms.parse()?);
                    while Instant::now() < deadline {
                        match wing.read_timeout(Duration::from_millis(50)) {
                            Ok(WingResponse::NodeData(id, data)) => {
                                let name = WingConsole::id_to_defs(id)
                                    .and_then(|defs| defs.into_iter().map(|(p, _)| p).min())
                                    .unwrap_or_else(|| format!("id={id}"));
                                println!("RESP NodeData {name} = {:?}", snap(&data));
                            }
                            Ok(WingResponse::RequestEnd) => println!("RESP RequestEnd"),
                            Ok(WingResponse::NodeDef(def)) => {
                                println!("RESP NodeDef {}", def.name)
                            }
                            Err(libwing::Error::Timeout) => {}
                            Err(error) => {
                                println!("WATCH ERR {error}");
                                break;
                            }
                        }
                    }
                }
                ["set", path, kind, rest @ ..] if !rest.is_empty() => {
                    let joined = rest.join(" ");
                    let value = &joined;
                    if !allow_state_changing {
                        return Err("script sets values; pass --allow-state-changing".into());
                    }
                    let Some(def) = WingConsole::name_to_def(path) else {
                        println!("SET {path} ERR unknown path");
                        continue;
                    };
                    // `""` denotes the empty string (whitespace-split tokens can't carry it).
                    let value = if *kind == "string" && *value == "\"\"" {
                        ""
                    } else {
                        value
                    };
                    let result = match *kind {
                        "int" => wing.set_int(def.id, value.parse()?),
                        "float" => wing.set_float(def.id, value.parse()?),
                        "string" => wing.set_string(def.id, value),
                        other => return Err(format!("unknown set kind {other}").into()),
                    };
                    println!("SET {path} {kind} {value} -> {result:?}");
                }
                _ => return Err(format!("unrecognized script line: {line}").into()),
            }
        }
        return Ok(());
    }

    // The GET battery is the curated core set (always requested, so their *values* are observed
    // and diffable -- definitions alone don't carry current values) followed by the broad strided
    // sweep for breadth. Deduplicated, deterministic order.
    let mut nodes: Vec<&str> = DEF_CORE.to_vec();
    for name in battery_nodes(gets) {
        if !nodes.contains(&name) {
            nodes.push(name);
        }
    }

    // 1) GET phase -- request each leaf's current value. A per-node timeout means the emulator
    //    /console simply doesn't hold that node (a fidelity finding, not an error): the request
    //    bytes were already written, so the N> stream stays deterministic regardless. A genuine
    //    connection loss, by contrast, is fatal and reported with the exact index it happened at.
    let mut got = 0usize;
    let mut observed: Vec<(&str, Snap)> = Vec::new();
    for (index, name) in nodes.iter().enumerate() {
        match wing.get_node_data_by_name(name, timeout) {
            Ok((data, _)) => {
                got += 1;
                if dump_scenario.is_some() {
                    observed.push((name, snap(&data)));
                }
            }
            Err(libwing::Error::Timeout) => {}
            Err(error) => return Err(fatal("get", index, name, error)),
        }
    }
    println!("wingdrive: gets: {got}/{} resolved", nodes.len());

    // Scenario-mirror mode: capture the console's live state as an emulator scenario, then stop.
    //   * ALL model selectors (`/mdl`) -- so the emulator loads the same model per slot and
    //     resolves shared ids (WING ids are reused across model variants) to the same variant.
    //     This removes the bulk of the false type/model "deviations".
    //   * only UNIQUE-id leaves from the GET battery -- a model-variant param shares its id with
    //     every model's param at that slot, so it can't be pinned to one path here; with the
    //     selector mirrored it resolves to the right variant and keeps that model's default, so a
    //     residual diff is a genuine value/default question rather than model confusion.
    if let Some(path) = dump_scenario {
        let mut mirror: Vec<(&str, Snap)> = Vec::new();
        for (name, _) in WingConsole::propmap_iter().filter(|(name, _)| name.ends_with("/mdl")) {
            if let Ok((data, _)) = wing.get_node_data_by_name(name, timeout) {
                mirror.push((name, snap(&data)));
            }
        }
        let selectors = mirror.len();
        mirror.extend(observed.into_iter().filter(|(name, _)| is_unique_id(name)));
        write_scenario(&path, &mirror)?;
        println!(
            "wingdrive: wrote scenario mirror to {path} ({selectors} model selectors + {} unique-id values)",
            mirror.len() - selectors
        );
        return Ok(());
    }

    // 2) DEFINITION phase -- fetch definitions for a curated core set (see DEF_CORE).
    let mut defs = 0usize;
    for (index, name) in DEF_CORE.iter().enumerate() {
        match wing.get_node_definition_by_name(name, timeout) {
            Ok(_) => defs += 1,
            Err(libwing::Error::Timeout) => {}
            Err(error) => return Err(fatal("def", index, name, error)),
        }
    }
    println!("wingdrive: defs: {defs}/{} resolved", DEF_CORE.len());

    // 3) WRITE phase (opt-in) -- snapshot, apply a fixed cosmetic value, then restore. Aborts if
    //    the console is not returned to its original value.
    if allow_state_changing {
        for (path, val) in WRITE_TARGETS {
            drive_restorable_write(&mut wing, path, *val, timeout)?;
        }
        println!(
            "wingdrive: writes: {} target(s) applied and restored",
            WRITE_TARGETS.len()
        );
    } else {
        println!("wingdrive: writes: skipped (read-only; pass --allow-state-changing to enable)");
    }

    // 4) METER phase -- two subscriptions, two renewals, then drain frames.
    wing.request_meter(METER_SET)?;
    wing.request_meter(METER_SET)?;
    wing.keep_alive_meters()?;
    wing.keep_alive_meters()?;
    let mut frames = 0usize;
    let deadline = Instant::now() + Duration::from_secs(meter_secs);
    while frames < meter_frames && Instant::now() < deadline {
        if let Ok((_id, words)) = wing.read_meters() {
            if !words.is_empty() {
                frames += 1;
            }
        }
    }
    println!("wingdrive: meters: {frames}/{meter_frames} frame(s) received");

    // 5) DISCONNECT -- dropping the console closes the TCP stream, which the proxy records as the
    //    contract's explicit empty N< disconnect event.
    drop(wing);
    println!("wingdrive: disconnected; battery complete");
    Ok(())
}

/// Read `path`'s current value, write `val`, then write the original back -- verifying the
/// console returns to its original value. A restore failure is a hard error so a real console is
/// never left mutated. Restoring the captured leaf value directly (rather than a subtree dump)
/// keeps the footprint to exactly one leaf, which is the safest thing to do on live hardware.
fn drive_restorable_write(
    wing: &mut WingConsole,
    path: &str,
    val: WriteVal,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let def =
        WingConsole::name_to_def(path).ok_or_else(|| format!("unknown write target {path}"))?;
    let id = def.id;

    let (before_data, _) = wing.get_node_data(id, timeout)?;
    let before = snap(&before_data);

    match val {
        WriteVal::Int(v) => wing.set_int(id, v)?,
        WriteVal::Str(s) => wing.set_string(id, s)?,
    }

    // Restore the captured original value.
    match &before {
        Snap::Str(s) => wing.set_string(id, s)?,
        Snap::Float(f) => wing.set_float(id, *f)?,
        Snap::Int(i) => wing.set_int(id, *i)?,
    }

    let after = read_settled(wing, id, timeout)?;
    if after != before {
        return Err(format!("RESTORE FAILED for {path}: before={before:?} after={after:?}").into());
    }
    Ok(())
}

/// Reads a node's settled value after writes. The WING protocol echoes every `set` as a
/// `NodeData` event, so a plain `get` can match a stale echo of our own write; taking the *last*
/// `NodeData(id)` seen within `window` reflects the value after all queued writes have applied.
fn read_settled(wing: &mut WingConsole, id: i32, window: Duration) -> Result<Snap, libwing::Error> {
    wing.request_node_data(id)?;
    let deadline = Instant::now() + window;
    let mut last: Option<Snap> = None;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match wing.read_timeout(deadline - now) {
            Ok(WingResponse::NodeData(rid, data)) if rid == id => last = Some(snap(&data)),
            Ok(_) => {}
            Err(libwing::Error::Timeout) => break,
            Err(error) => return Err(error),
        }
    }
    last.ok_or(libwing::Error::Timeout)
}

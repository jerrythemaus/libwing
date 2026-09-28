mod utils;
use utils::Args;
#[path = "atomic_write.rs"]
mod atomic_write;
use atomic_write::{publish_outputs, staged_path};

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::result::Result;

use libwing::{NodeType, WingConsole, WingNodeData, WingNodeDef, WingResponse};

/// One model selector's pre-crawl state: its node id, its full path (for
/// reporting), and the value it held before the crawl started flipping it.
#[derive(Clone)]
struct SelectorSnapshot {
    id: i32,
    fullname: String,
    value: String,
    def: WingNodeDef,
}

/// Read a node's current value directly (`request_node_data` + read loop),
/// bypassing the propmap so this works during the crawl itself, before any
/// def has been embedded. Returns `None` if the console never replies with
/// data for `id` (e.g. a write-only node).
fn read_node_data(wing: &mut WingConsole, id: i32) -> Option<WingNodeData> {
    wing.request_node_data(id).ok()?;
    let mut found = None;
    loop {
        match wing.read().ok()? {
            WingResponse::NodeData(rid, data) => {
                if rid == id {
                    found = Some(data);
                }
            }
            WingResponse::NodeDef(_) => {}
            WingResponse::RequestEnd => break,
        }
    }
    found
}

/// Pure: dedup a snapshot by node id, keeping the first (closest to true
/// pre-crawl) value recorded for each. Separating "what to restore" from
/// "how to restore it" keeps this testable without a console.
fn plan_restore(snapshot: &[SelectorSnapshot]) -> Vec<SelectorSnapshot> {
    let mut seen = std::collections::HashSet::new();
    snapshot
        .iter()
        .filter(|entry| seen.insert(entry.id))
        .cloned()
        .collect()
}

fn selector_value(data: &WingNodeData, def: &WingNodeDef) -> String {
    data.display_string(def)
}

fn selector_snapshot(
    fullname: &str,
    def: &WingNodeDef,
    data: Option<WingNodeData>,
) -> Result<SelectorSnapshot, String> {
    let data = data.ok_or_else(|| {
        format!(
            "could not read current value of {fullname} ({}) before crawl; refusing to mutate it",
            def.id
        )
    })?;
    let value = if def.node_type == NodeType::StringEnum {
        data.string_enum_item(def)
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "{fullname} returned unknown StringEnum value {:?}; refusing to guess its restore value",
                    data.get_string()
                )
            })?
    } else {
        selector_value(&data, def)
    };
    Ok(SelectorSnapshot {
        id: def.id,
        fullname: fullname.to_string(),
        value,
        def: def.clone(),
    })
}

/// Outcome of one restore attempt, used to build a [`RestoreReport`].
struct RestoreOutcome {
    id: i32,
    fullname: String,
    restored: bool,
}

/// Summary of a snapshot-restore pass (R32/OQ8): a full restore is never
/// assumed, only reported once every selector's outcome is known.
struct RestoreReport {
    attempted: usize,
    failed: Vec<(i32, String)>,
}

impl RestoreReport {
    /// Pure: builds the report from already-executed outcomes.
    fn from_outcomes(outcomes: &[RestoreOutcome]) -> Self {
        RestoreReport {
            attempted: outcomes.len(),
            failed: outcomes
                .iter()
                .filter(|o| !o.restored)
                .map(|o| (o.id, o.fullname.clone()))
                .collect(),
        }
    }

    fn is_degraded(&self) -> bool {
        !self.failed.is_empty()
    }
}

/// Restore every snapshotted selector to its pre-crawl value on a
/// best-effort basis: one failure doesn't stop the rest from being
/// attempted, and every outcome is recorded for the degraded report.
fn restore_selectors(wing: &mut WingConsole, snapshot: &[SelectorSnapshot]) -> RestoreReport {
    let outcomes: Vec<RestoreOutcome> = plan_restore(snapshot)
        .into_iter()
        .map(|entry| {
            let write_result = wing.set_string(entry.id, &entry.value);
            let readback = if write_result.is_ok() {
                read_node_data(wing, entry.id).map(|data| selector_value(&data, &entry.def))
            } else {
                None
            };
            restore_outcome_from_readback(
                entry.id,
                &entry.fullname,
                &entry.value,
                write_result,
                readback.as_deref(),
            )
        })
        .collect();
    RestoreReport::from_outcomes(&outcomes)
}

fn restore_outcome_from_readback(
    id: i32,
    fullname: &str,
    expected: &str,
    write_result: Result<(), libwing::Error>,
    readback: Option<&str>,
) -> RestoreOutcome {
    RestoreOutcome {
        id,
        fullname: fullname.to_string(),
        restored: write_result.is_ok() && readback == Some(expected),
    }
}

/// Append one `[flag u8][namelen u16][name][deflen u16][def]` entry to the raw
/// blob that gets embedded into `propmap.rs`. Shared by the live sweep and the
/// offline `embed` path so both produce byte-identical envelopes.
fn push_entry(raw: &mut Vec<u8>, flag: u8, fullname: &str, def_bytes: &[u8]) {
    raw.push(flag);
    raw.extend_from_slice(&(fullname.len() as u16).to_be_bytes());
    raw.extend_from_slice(fullname.as_bytes());
    raw.extend_from_slice(&(def_bytes.len() as u16).to_be_bytes());
    raw.extend_from_slice(def_bytes);
}

/// Write the `propmap.rs` source that embeds `raw` as a `NAME_TO_DEF` lazy static.
/// The loader emitted here must stay in lockstep with the one already compiled
/// into `src/propmap.rs` (and `src/empty-propmap.rs`'s empty fallback).
fn write_propmap_rs(rust_file: &mut impl Write, raw: &[u8]) -> std::io::Result<()> {
    // rustfmt import order (crate before std), so a fmt pass over the
    // generated file is a no-op and regeneration produces no diff noise.
    writeln!(rust_file, "use crate::node::WingNodeDef;")?;
    writeln!(rust_file, "use std::collections::HashMap;")?;
    writeln!(rust_file, "lazy_static::lazy_static! {{")?;
    writeln!(
        rust_file,
        "    pub static ref NAME_TO_DEF: HashMap<String, WingNodeDef> = {{"
    )?;
    writeln!(rust_file, "        let mut m = HashMap::new();")?;
    write!(rust_file, "        let d = b\"")?;
    for b in raw {
        write!(rust_file, "\\x{:02X}", b)?;
    }
    writeln!(rust_file, "\";")?;
    writeln!(rust_file, "        let mut i = 0;")?;
    writeln!(rust_file, "        while i < d.len() {{")?;
    writeln!(rust_file, "            let _is_fake = d[i];")?;
    writeln!(rust_file, "            i += 1;")?;
    writeln!(
        rust_file,
        "            let namelen = u16::from_be_bytes([d[i], d[i + 1]]) as usize;"
    )?;
    writeln!(rust_file, "            i += 2;")?;
    writeln!(
        rust_file,
        "            let name = String::from_utf8(d[i..i + namelen].to_vec()).unwrap();"
    )?;
    writeln!(rust_file, "            i += namelen;")?;
    writeln!(
        rust_file,
        "            let deflen = u16::from_be_bytes([d[i], d[i + 1]]) as usize;"
    )?;
    writeln!(rust_file, "            i += 2;")?;
    // Use the raw-free constructor: the property map never reads WingNodeDef::raw back,
    // and retaining it here would duplicate the entire embedded blob on the heap.
    writeln!(rust_file, "            let def = WingNodeDef::from_bytes_without_raw(&d[i..i + deflen]).expect(\"valid embedded propmap definition\");")?;
    writeln!(rust_file, "            i += deflen;")?;
    writeln!(rust_file, "            m.insert(name, def);")?;
    writeln!(rust_file, "        }}")?;
    writeln!(rust_file, "        m")?;
    writeln!(rust_file, "    }};")?;
    writeln!(rust_file, "}}")?;
    Ok(())
}

fn get_node_def(wing: &mut WingConsole, parents: Vec<i32>) -> Vec<Vec<WingNodeDef>> {
    for parent in &parents {
        wing.request_node_definition(*parent).unwrap();
    }

    let mut ret = Vec::new();
    for parent in &parents {
        let mut ret2 = Vec::new();
        loop {
            match wing.read().unwrap() {
                WingResponse::NodeData(_, _) => {}
                WingResponse::NodeDef(def) => {
                    if def.parent_id == *parent {
                        ret2.push(def);
                    }
                }
                WingResponse::RequestEnd => {
                    break;
                }
            }
        }
        ret.push(ret2);
    }
    ret
}

#[allow(clippy::too_many_arguments)]
fn add(
    cnt: usize,
    wing: &mut WingConsole,
    json_file: &mut File,
    raw: &mut Vec<u8>,
    parent_fullname: &str,
    nodes: &[WingNodeDef],
    ignore: bool,
    snapshot: &mut Vec<SelectorSnapshot>,
) -> usize {
    let mut cnt = cnt;
    if !ignore {
        if let Some(mdl_def) = nodes
            .iter()
            .find(|x| &x.name == "mdl" && x.node_type == libwing::NodeType::StringEnum)
        {
            let children = get_node_def(wing, nodes.iter().map(|x| x.id).collect());
            cnt += children.len();

            for (i, def) in nodes.iter().enumerate() {
                if def.index != 0 {
                    continue;
                }
                let fullname = if def.name.is_empty() {
                    String::new() + parent_fullname + "/" + &def.index.to_string()[..]
                } else {
                    String::new() + parent_fullname + "/" + &def.name[..]
                };

                let mut json = def.to_json();
                json.insert("fullname", fullname.clone()).unwrap();
                // println!("{}", jzon::stringify(json.clone()));
                writeln!(json_file, "{}", jzon::stringify(json)).unwrap();
                push_entry(raw, 0, &fullname, &def.raw);

                cnt = add(
                    cnt,
                    wing,
                    json_file,
                    raw,
                    &fullname,
                    &children[i],
                    false,
                    snapshot,
                );
            }

            // This is the crawl's one destructive act: it's about to flip `mdl_def`
            // through every model in turn. Capture what it's currently set to
            // (resolved to the enum item's name via `display_string`, since a
            // StringEnum's raw NodeData is an index, not the name `set_string`
            // expects) before the first mutation, so it can be restored after.
            let mdl_fullname = String::new() + parent_fullname + "/mdl";
            let captured =
                selector_snapshot(&mdl_fullname, mdl_def, read_node_data(wing, mdl_def.id))
                    .unwrap_or_else(|error| panic!("{error}"));
            snapshot.push(captured);

            for item in mdl_def.string_enum.as_ref().unwrap().iter() {
                let parent_fullname = String::new() + parent_fullname + "/" + &item.item;
                wing.set_string(mdl_def.id, &item.item).unwrap();
                let children = get_node_def(wing, Vec::from([mdl_def.parent_id]));
                cnt = add(
                    cnt,
                    wing,
                    json_file,
                    raw,
                    &parent_fullname,
                    &children[0],
                    true,
                    snapshot,
                );
            }

            return cnt;
        }
    }

    let children = get_node_def(wing, nodes.iter().map(|x| x.id).collect());
    cnt += children.len();

    for (i, def) in nodes.iter().enumerate() {
        // skip mdl and other nodes since we handled them above
        if !ignore || def.index != 0 {
            let fullname = if def.name.is_empty() {
                String::new() + parent_fullname + "/" + &def.index.to_string()[..]
            } else {
                String::new() + parent_fullname + "/" + &def.name[..]
            };

            let mut json = def.to_json();
            json.insert("fullname", fullname.clone()).unwrap();
            // println!("{}", jzon::stringify(json.clone()));
            writeln!(json_file, "{}", jzon::stringify(json)).unwrap();
            push_entry(
                raw,
                if ignore { def.index as u8 } else { 0 },
                &fullname,
                &def.raw,
            );

            cnt = add(
                cnt,
                wing,
                json_file,
                raw,
                &fullname,
                &children[i],
                false,
                snapshot,
            );
        }
    }
    print!("\rReceived {} nodes", cnt);
    cnt
}

// ---------------------------------------------------------------------------
// Offline regeneration: `wingschema embed [sweep.jsonl]`
//
// Rebuilds src/propmap.rs and src/propmap.jsonl from an existing full-sweep
// JSONL file (the format `add()` above already writes: one `to_json()` object
// per line, plus a "fullname"). No live console involved. This exists so the
// embedded map can be regenerated reproducibly from a checked-in sweep dataset
// instead of only from a fresh (destructive) live crawl.
// ---------------------------------------------------------------------------

/// Walk up `fullname`'s path segments to find the nearest ancestor that is
/// itself a row in the sweep, and return its id. Per-model subtrees insert a
/// synthetic path segment (the model name, e.g. `/fx/1/HALL`) that never has
/// its own row — the live sweep's real parent for those children is the node
/// one level up (`/fx/1`) — so a single-segment strip isn't enough; we need to
/// walk until we hit a real row. Falls back to `0` (root scope) when nothing
/// matches.
fn parent_id_for(fullname: &str, id_by_fullname: &HashMap<String, i32>) -> i32 {
    let mut cur = fullname;
    while let Some(idx) = cur.rfind('/') {
        cur = &cur[..idx];
        if cur.is_empty() {
            return 0;
        }
        if let Some(&id) = id_by_fullname.get(cur) {
            return id;
        }
    }
    0
}

fn type_code(t: &str) -> u8 {
    match t {
        "node" => 0,
        "linear float" => 1,
        "log float" => 2,
        "fader level" => 3,
        "integer" => 4,
        "string enum" => 5,
        "float enum" => 6,
        "string" => 7,
        other => panic!("unknown node type `{other}` in sweep row"),
    }
}

fn unit_code(u: Option<&str>) -> u8 {
    match u {
        None => 0,
        Some("dB") => 1,
        Some("%") => 2,
        Some("ms") => 3,
        Some("Hz") => 4,
        Some("meters") => 5,
        Some("seconds") => 6,
        Some("octaves") => 7,
        Some(other) => panic!("unknown unit `{other}` in sweep row"),
    }
}

/// Correctly-rounded f32 from a jzon number. `JsonValue::as_f32` computes
/// `mantissa * 10^exponent` in floating-point, which drifts by 1 ULP once the
/// decimal mantissa exceeds f64's 53-bit precision (e.g. the 17-digit repr of
/// f32 `1.2` re-parses as `1.19999993`). Round-tripping through the decimal
/// text and Rust's correctly-rounded `str::parse::<f32>` recovers the exact
/// original f32 that `to_json` serialized.
fn json_f32(v: &jzon::JsonValue) -> f32 {
    v.dump().parse().unwrap_or(0.0)
}

/// Build the type-specific tail of the wire encoding that `WingNodeDef::from_bytes`
/// expects after the flags word, mirroring `node.rs`'s `from_bytes_inner` parse
/// (kept in sync by hand since the sweep JSON has no raw bytes to copy from).
fn build_payload(row: &jzon::JsonValue, tcode: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    match tcode {
        1 | 2 => {
            payload.extend_from_slice(&json_f32(&row["minfloat"]).to_be_bytes());
            payload.extend_from_slice(&json_f32(&row["maxfloat"]).to_be_bytes());
            payload.extend_from_slice(&row["steps"].as_i32().unwrap_or(0).to_be_bytes());
        }
        3 => {
            // Fader level range is optional on the wire (see from_bytes_inner); only
            // emit it when the sweep row actually carries one.
            if row.has_key("minfloat") {
                payload.extend_from_slice(&json_f32(&row["minfloat"]).to_be_bytes());
                payload.extend_from_slice(&json_f32(&row["maxfloat"]).to_be_bytes());
                payload.extend_from_slice(&row["steps"].as_i32().unwrap_or(0).to_be_bytes());
            }
        }
        4 => {
            payload.extend_from_slice(&row["minint"].as_i32().unwrap_or(0).to_be_bytes());
            payload.extend_from_slice(&row["maxint"].as_i32().unwrap_or(0).to_be_bytes());
        }
        5 => {
            let items: Vec<_> = row["items"].members().collect();
            payload.extend_from_slice(&(items.len() as u16).to_be_bytes());
            for item in items {
                let s = item["item"].as_str().unwrap_or("");
                payload.push(s.len() as u8);
                payload.extend_from_slice(s.as_bytes());
                let l = item["longitem"].as_str().unwrap_or("");
                payload.push(l.len() as u8);
                payload.extend_from_slice(l.as_bytes());
            }
        }
        6 => {
            let items: Vec<_> = row["items"].members().collect();
            payload.extend_from_slice(&(items.len() as u16).to_be_bytes());
            for item in items {
                payload.extend_from_slice(&json_f32(&item["item"]).to_be_bytes());
                let l = item["longitem"].as_str().unwrap_or("");
                payload.push(l.len() as u8);
                payload.extend_from_slice(l.as_bytes());
            }
        }
        7 => {
            payload.extend_from_slice(&row["maxstringlen"].as_u16().unwrap_or(0).to_be_bytes());
        }
        _ => {}
    }
    payload
}

#[allow(clippy::too_many_arguments)]
fn encode_def_bytes(
    parent_id: i32,
    id: i32,
    index: u16,
    name: &str,
    long_name: &str,
    tcode: u8,
    ucode: u8,
    read_only: bool,
    payload: &[u8],
) -> Vec<u8> {
    assert!(name.len() <= 255, "name `{name}` too long to encode");
    assert!(
        long_name.len() <= 255,
        "longname `{long_name}` too long to encode"
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&parent_id.to_be_bytes());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&index.to_be_bytes());
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    buf.push(long_name.len() as u8);
    buf.extend_from_slice(long_name.as_bytes());
    let flags: u16 =
        ((tcode as u16 & 0x0F) << 4) | (ucode as u16 & 0x0F) | if read_only { 1 << 9 } else { 0 };
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn embed_from_sweep_to(
    input_path: &str,
    json_output_path: &Path,
    rust_output_path: &Path,
) -> Result<(), libwing::Error> {
    let text = std::fs::read_to_string(input_path)?;

    // First pass: parse every row once and index by fullname, both to catch
    // duplicate paths early and to resolve parent ids in the second pass.
    let mut rows = Vec::new();
    let mut id_by_fullname: HashMap<String, i32> = HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row = jzon::parse(line)
            .unwrap_or_else(|e| panic!("{input_path}:{}: invalid JSON: {e}", lineno + 1));
        let fullname = row["fullname"]
            .as_str()
            .unwrap_or_else(|| panic!("{input_path}:{}: row missing fullname", lineno + 1))
            .to_string();
        let id = row["id"]
            .as_i32()
            .unwrap_or_else(|| panic!("{input_path}:{}: row missing id", lineno + 1));
        if let Some(prev_id) = id_by_fullname.insert(fullname.clone(), id) {
            panic!(
                "duplicate fullname `{fullname}` in {input_path} (ids {prev_id} and {id}) — \
                 the embedded map is keyed by fullname, so this would silently drop one entry"
            );
        }
        rows.push((fullname, line.to_string(), row));
    }

    let mut raw = Vec::<u8>::new();
    let mut json_output = Vec::new();

    for (fullname, line, row) in &rows {
        let id = row["id"].as_i32().unwrap();
        let index = row["index"].as_u16().unwrap_or(0);
        let name = row["name"].as_str().unwrap_or("");
        let long_name = row["longname"].as_str().unwrap_or("");
        let type_str = row["type"]
            .as_str()
            .unwrap_or_else(|| panic!("{fullname}: row missing type"));
        let tcode = type_code(type_str);
        let ucode = unit_code(row["unit"].as_str());
        let read_only = row["read_only"].as_bool().unwrap_or(false);
        let payload = build_payload(row, tcode);
        let parent_id = parent_id_for(fullname, &id_by_fullname);

        let def_bytes = encode_def_bytes(
            parent_id, id, index, name, long_name, tcode, ucode, read_only, &payload,
        );
        push_entry(&mut raw, 0, fullname, &def_bytes);
        writeln!(json_output, "{line}")?;
    }

    let mut rust_output = Vec::new();
    write_propmap_rs(&mut rust_output, &raw)?;
    publish_outputs(&[
        (json_output_path, json_output.as_slice()),
        (rust_output_path, rust_output.as_slice()),
    ])?;

    println!(
        "Embedded {} entries from {input_path} into src/propmap.rs and src/propmap.jsonl",
        rows.len()
    );
    Ok(())
}

fn embed_from_sweep(input_path: &str) -> Result<(), libwing::Error> {
    embed_from_sweep_to(
        input_path,
        Path::new("src/propmap.jsonl"),
        Path::new("src/propmap.rs"),
    )
}

fn main() -> Result<(), libwing::Error> {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if cli_args.first().map(String::as_str) == Some("embed") {
        let input_path = cli_args
            .get(1)
            .map(String::as_str)
            .unwrap_or("propmap.jsonl");
        return embed_from_sweep(input_path);
    }

    let mut args = Args::new(
        r#"
Usage: wingschema [-h host] [--yes]
       wingschema embed [sweep.jsonl]

   -h host : IP address or hostname of Wing mixer. Default is to discover and connect to the first mixer found.
   --yes   : Skip the interactive confirmation prompt (for automation). The crawl is still
             destructive; only pass this once you've accepted that.
   embed   : Offline regeneration. Rebuilds src/propmap.rs and src/propmap.jsonl from an
             existing full-sweep JSONL file (default: propmap.jsonl in the current directory)
             without connecting to a live console.
"#,
    );
    let mut host = None;
    let mut skip_confirm = false;
    while args.has_next() {
        match args.next().as_str() {
            "-h" => host = Some(args.next()),
            "--yes" => skip_confirm = true,
            other => {
                args.print_help(Some(&format!("unknown argument: {other}")));
                std::process::exit(1);
            }
        }
    }

    // Warn that this sweep is destructive (it flips every model selector on the
    // console — RiskClass::DestructiveSchemaCrawl) and require confirmation,
    // either interactively or via `--yes` for automation.
    println!(
        r#"
This tool will connect to a Behringer Wing Mixer on your network and get the
schema of all properties. It will change the properties of the device in a
destructive manner, so you should have had a saved snapshot you can restore
after this process is complete.

THIS IS A DESTRUCTIVE OPERATION. The crawl snapshots each model selector's
current value before flipping it and restores it afterward on a best-effort
basis, but if the restore itself fails partway through, recovering fully may
require reinitializing your mixer from a backup.

Do you have a backup snapshot you can restore after, and want to continue?
"#
    );
    if skip_confirm {
        println!("--yes passed: skipping interactive confirmation.");
    } else {
        print!("Enter 'yes' to continue: ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim().to_lowercase() != "yes" {
            println!("Aborting");
            return Ok(());
        }
    }

    let mut wing = WingConsole::connect(host.as_deref())?;

    let json_temp = staged_path(Path::new("propmap.jsonl"), "crawl");
    let mut json_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&json_temp)
        .unwrap();

    let mut raw = Vec::<u8>::new();
    let mut snapshot: Vec<SelectorSnapshot> = Vec::new();
    let children = get_node_def(&mut wing, Vec::from([0]));

    // The crawl mutates every model selector it finds. If it panics partway
    // through (e.g. a dropped connection hitting one of its `.unwrap()`s),
    // still restore whatever selectors were captured before the panic rather
    // than leaving the console in a half-swept state with no attempt made.
    let crawl_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        add(
            1,
            &mut wing,
            &mut json_file,
            &mut raw,
            "",
            &children[0],
            false,
            &mut snapshot,
        )
    }));

    print!(
        "\nRestoring {} pre-crawl model selector(s)... ",
        snapshot.len()
    );
    std::io::stdout().flush().unwrap();
    let report = restore_selectors(&mut wing, &snapshot);
    println!("done");

    if crawl_result.is_err() {
        let _ = std::fs::remove_file(&json_temp);
        eprintln!("\nSchema crawl aborted partway through (see panic above).");
    } else {
        print!("\nFinishing up... ");
        std::io::stdout().flush().unwrap();
        json_file.flush().unwrap();
        let json_output = std::fs::read(&json_temp).unwrap();
        let mut rust_output = Vec::new();
        write_propmap_rs(&mut rust_output, &raw).unwrap();
        publish_outputs(&[
            (Path::new("propmap.jsonl"), json_output.as_slice()),
            (Path::new("propmap.rs"), rust_output.as_slice()),
        ])
        .unwrap();
        let _ = std::fs::remove_file(&json_temp);
        println!("done");
    }

    if report.is_degraded() {
        eprintln!(
            "\nDEGRADED: {} of {} selector(s) could not be restored:",
            report.failed.len(),
            report.attempted
        );
        for (id, fullname) in &report.failed {
            eprintln!("  - {fullname} (id {id})");
        }
        std::process::exit(1);
    }

    if crawl_result.is_err() {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    #[cfg(feature = "propmap")]
    fn snap(id: i32, fullname: &str, value: &str) -> SelectorSnapshot {
        SelectorSnapshot {
            id,
            fullname: fullname.to_string(),
            value: value.to_string(),
            def: WingConsole::name_to_def("/fx/1/mdl").unwrap().clone(),
        }
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn plan_restore_dedups_by_id_keeping_first_value() {
        let snapshot = vec![
            snap(1, "/fx/1/mdl", "HALL"),
            snap(2, "/fx/2/mdl", "PLATE"),
            // A later (bogus) duplicate entry for id 1 must not shadow the
            // real pre-crawl value captured first.
            snap(1, "/fx/1/mdl", "SPRING"),
        ];
        let plan = plan_restore(&snapshot);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].id, 1);
        assert_eq!(plan[0].fullname, "/fx/1/mdl");
        assert_eq!(plan[0].value, "HALL");
        assert_eq!(plan[1].id, 2);
        assert_eq!(plan[1].fullname, "/fx/2/mdl");
        assert_eq!(plan[1].value, "PLATE");
    }

    #[test]
    fn report_is_not_degraded_when_all_outcomes_succeed() {
        let outcomes = vec![
            RestoreOutcome {
                id: 1,
                fullname: "/fx/1/mdl".to_string(),
                restored: true,
            },
            RestoreOutcome {
                id: 2,
                fullname: "/fx/2/mdl".to_string(),
                restored: true,
            },
        ];
        let report = RestoreReport::from_outcomes(&outcomes);
        assert_eq!(report.attempted, 2);
        assert!(!report.is_degraded());
        assert!(report.failed.is_empty());
    }

    #[test]
    fn report_is_degraded_and_lists_failures() {
        let outcomes = vec![
            RestoreOutcome {
                id: 1,
                fullname: "/fx/1/mdl".to_string(),
                restored: true,
            },
            RestoreOutcome {
                id: 2,
                fullname: "/fx/2/mdl".to_string(),
                restored: false,
            },
        ];
        let report = RestoreReport::from_outcomes(&outcomes);
        assert_eq!(report.attempted, 2);
        assert!(report.is_degraded());
        assert_eq!(report.failed, vec![(2, "/fx/2/mdl".to_string())]);
    }

    #[test]
    fn successful_restore_write_without_matching_readback_is_degraded() {
        let outcome = restore_outcome_from_readback(42, "/fx/1/mdl", "HALL", Ok(()), Some("PLATE"));
        let report = RestoreReport::from_outcomes(&[outcome]);

        assert!(report.is_degraded());
        assert_eq!(report.failed, vec![(42, "/fx/1/mdl".to_string())]);
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn selector_readback_uses_enum_label_instead_of_raw_index() {
        let def = WingConsole::name_to_def("/fx/1/mdl").unwrap();
        let expected = def.string_enum.as_ref().unwrap()[1].item.clone();
        let data = WingNodeData::with_i32(1);

        assert_eq!(selector_value(&data, def), expected);
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn missing_selector_snapshot_aborts_before_mutation() {
        let def = WingConsole::name_to_def("/fx/1/mdl").unwrap();
        let result = selector_snapshot("/fx/1/mdl", def, None);

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn unknown_selector_enum_index_aborts_before_mutation() {
        let def = WingConsole::name_to_def("/fx/1/mdl").unwrap();
        let unknown_index = def.string_enum.as_ref().unwrap().len() as i32 + 10;
        let result = selector_snapshot(
            "/fx/1/mdl",
            def,
            Some(WingNodeData::with_i32(unknown_index)),
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn selector_carried_as_a_known_label_is_restorable() {
        let def = WingConsole::name_to_def("/fx/1/mdl").unwrap();
        let label = def.string_enum.as_ref().unwrap()[1].item.clone();
        let snapshot = selector_snapshot(
            "/fx/1/mdl",
            def,
            Some(WingNodeData::with_string(label.clone())),
        )
        .unwrap();

        assert_eq!(snapshot.value, label);
    }

    #[test]
    #[cfg(feature = "propmap")]
    fn selector_without_integer_index_aborts_before_mutation() {
        let def = WingConsole::name_to_def("/fx/1/mdl").unwrap();
        let result = selector_snapshot(
            "/fx/1/mdl",
            def,
            Some(WingNodeData::with_string("unexpected".to_string())),
        );

        assert!(result.is_err());
    }

    #[test]
    fn embed_failure_preserves_both_last_known_good_outputs() {
        let temp =
            std::env::temp_dir().join(format!("wingschema-staged-output-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let sweep = Path::new("src/propmap.jsonl");
        let json_output = temp.join("propmap.jsonl");
        let rust_output = temp.join("propmap.rs");
        std::fs::write(&json_output, "known-good-json\n").unwrap();
        std::fs::create_dir(&rust_output).unwrap();
        std::fs::write(rust_output.join("keep"), "not replaceable").unwrap();

        assert!(embed_from_sweep_to(sweep.to_str().unwrap(), &json_output, &rust_output).is_err());
        assert_eq!(
            std::fs::read_to_string(&json_output).unwrap(),
            "known-good-json\n"
        );
        assert_eq!(
            std::fs::read_to_string(rust_output.join("keep")).unwrap(),
            "not replaceable"
        );
    }
}

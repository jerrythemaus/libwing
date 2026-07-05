mod utils;
use utils::Args;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::result::Result;

use libwing::{WingConsole, WingNodeDef, WingResponse};

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
fn write_propmap_rs(rust_file: &mut File, raw: &[u8]) -> std::io::Result<()> {
    writeln!(rust_file, "use std::collections::HashMap;")?;
    writeln!(rust_file, "use crate::node::WingNodeDef;")?;
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

fn add(
    cnt: usize,
    wing: &mut WingConsole,
    json_file: &mut File,
    raw: &mut Vec<u8>,
    parent_fullname: &str,
    nodes: &[WingNodeDef],
    ignore: bool,
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

                cnt = add(cnt, wing, json_file, raw, &fullname, &children[i], false);
            }

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

            cnt = add(cnt, wing, json_file, raw, &fullname, &children[i], false);
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

fn embed_from_sweep(input_path: &str) -> Result<(), libwing::Error> {
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
    let mut json_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("src/propmap.jsonl")?;

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
        writeln!(json_file, "{line}")?;
    }

    let mut rust_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("src/propmap.rs")?;
    write_propmap_rs(&mut rust_file, &raw)?;

    println!(
        "Embedded {} entries from {input_path} into src/propmap.rs and src/propmap.jsonl",
        rows.len()
    );
    Ok(())
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
Usage: wingschema [-h host]
       wingschema embed [sweep.jsonl]

   -h host : IP address or hostname of Wing mixer. Default is to discover and connect to the first mixer found.
   embed   : Offline regeneration. Rebuilds src/propmap.rs and src/propmap.jsonl from an
             existing full-sweep JSONL file (default: propmap.jsonl in the current directory)
             without connecting to a live console.
"#,
    );
    let mut host = None;
    if args.has_next() && args.next() == "-h" {
        host = Some(args.next());
    }

    // print out a message asking the user if it is ok to connect and get the schema, which WILL
    // change the properties of the device, so you should have had a saved snapshot. ask them on
    // the commandline and let them type "yes" to continue.
    println!(
        r#"
This tool will connect to a Behringer Wing Mixer on your network and get the
schema of all properties. It will change the properties of the device in a
destructive manner, so you should have had a saved snapshot you can restore
after this process is complete.

THIS IS A DESTRUCTIVE OPERATION AND CAN NOT BE UNDONE WITHOUT
REINITIALIZING YOUR MIXER FROM SCRATCH.

Do you have a backup snapshot you can restore after, and want to continue?
"#
    );
    print!("Enter 'yes' to continue: ");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() != "yes" {
        println!("Aborting");
        return Ok(());
    }

    let mut wing = WingConsole::connect(host.as_deref())?;

    let mut json_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("propmap.jsonl")
        .unwrap();

    let mut rust_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("propmap.rs")
        .unwrap();

    let mut raw = Vec::<u8>::new();
    let children = get_node_def(&mut wing, Vec::from([0]));
    add(
        1,
        &mut wing,
        &mut json_file,
        &mut raw,
        "",
        &children[0],
        false,
    );
    print!("\nFinishing up... ");
    std::io::stdout().flush().unwrap();

    write_propmap_rs(&mut rust_file, &raw).unwrap();

    println!("done");
    Ok(())
}

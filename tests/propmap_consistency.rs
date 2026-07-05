//! Consistency checks for the embedded property map (U1: R8, R9, R30, R31).
//!
//! `src/propmap.rs` and `src/propmap.jsonl` are regenerated from the full,
//! per-model sweep at `propmap.jsonl` via:
//!
//!     cargo run --example wingschema -- embed propmap.jsonl
//!
//! These tests guard against the embedded map silently drifting from that
//! source sweep again (which is exactly what happened before: the embedded
//! map was built from a default-model-only sweep and was missing per-model
//! subtrees like `/fx/1/HALL/...`).

use libwing::WingConsole;
use std::collections::HashSet;
use std::path::PathBuf;

/// The full, per-model sweep that `src/propmap.rs` / `src/propmap.jsonl` are
/// regenerated from. Excluded from the packaged crate (see Cargo.toml), but
/// present in the repo checkout that these tests run from.
fn sweep_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("propmap.jsonl")
}

/// Every `fullname` in the source sweep, in file order (duplicates preserved,
/// so callers can tell a genuine duplicate row apart from a merely-large file).
fn sweep_fullnames() -> Vec<String> {
    let text = std::fs::read_to_string(sweep_path())
        .expect("propmap.jsonl sweep file present at crate root");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let row = jzon::parse(line).expect("valid JSON line in propmap.jsonl");
            row["fullname"]
                .as_str()
                .expect("sweep row has a fullname")
                .to_string()
        })
        .collect()
}

#[test]
fn embedded_row_count_matches_sweep() {
    let fullnames = sweep_fullnames();
    let unique: HashSet<&str> = fullnames.iter().map(String::as_str).collect();

    // The sweep itself must have no duplicate fullnames: NAME_TO_DEF is keyed by
    // fullname, so a duplicate would silently drop one of the two rows.
    assert_eq!(
        fullnames.len(),
        unique.len(),
        "propmap.jsonl has {} duplicate fullname rows",
        fullnames.len() - unique.len()
    );

    assert_eq!(
        WingConsole::propmap_len(),
        fullnames.len(),
        "embedded NAME_TO_DEF entry count must equal the full sweep row count \
         (no undocumented exclusions)"
    );
}

#[test]
fn every_sweep_path_is_unique_and_resolvable() {
    for fullname in sweep_fullnames() {
        assert!(
            WingConsole::name_to_def(&fullname).is_some(),
            "sweep fullname `{fullname}` did not make it into the embedded map"
        );
    }
}

#[test]
fn id_collision_enumerates_all_model_variants() {
    // /fx/1/EXT and /fx/1/HALL are different reverb/effect models on the same
    // fx slot; the Wing protocol reuses parameter ids across mutually
    // exclusive per-model subtrees, so this id must resolve to both.
    const SHARED_ID: i32 = 638586229;

    let defs = WingConsole::id_to_defs(SHARED_ID).expect("id has known variants");
    let names: HashSet<&str> = defs.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        names.contains("/fx/1/EXT/egrp"),
        "expected /fx/1/EXT/egrp among variants, got {names:?}"
    );
    assert!(
        names.contains("/fx/1/HALL/pdel"),
        "expected /fx/1/HALL/pdel among variants, got {names:?}"
    );
}

#[test]
fn dynamic_per_model_subtrees_are_present() {
    // These only exist because the embedded map now carries per-model
    // subtrees; the old default-model-only map had none of them.
    assert!(
        WingConsole::name_to_def("/fx/1/HALL/pdel").is_some(),
        "missing /fx/1/HALL/pdel (fx reverb model subtree)"
    );
    assert!(
        WingConsole::name_to_def("/ch/1/eq/STD/lg").is_some(),
        "missing /ch/1/eq/STD/lg (channel EQ model subtree)"
    );
    assert!(
        WingConsole::name_to_def("/ch/1/gate/GATE/thr").is_some(),
        "missing /ch/1/gate/GATE/thr (channel gate/dyn model subtree)"
    );
}

#[test]
fn embedded_defs_round_trip_every_sweep_row_field_for_field() {
    // The offline embed path *reconstructs* each def's wire bytes from the sweep
    // JSON (it has no captured raw bytes), so this guards the reconstruction:
    // re-serializing every embedded def through the same `to_json()` that produced
    // the sweep rows must reproduce each row exactly — any dropped or mangled
    // field (type, unit, range, steps, enum items, read_only, index) shows up as
    // an inequality here.
    let text = std::fs::read_to_string(sweep_path()).expect("sweep file present");
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row = jzon::parse(line).expect("valid JSON row");
        let fullname = row["fullname"].as_str().expect("row has fullname");
        let def = WingConsole::name_to_def(fullname)
            .unwrap_or_else(|| panic!("`{fullname}` missing from embedded map"));
        let mut json = def.to_json();
        json.insert("fullname", fullname).unwrap();
        assert_eq!(
            json,
            row,
            "embedded def for `{fullname}` (line {}) does not round-trip its sweep row",
            lineno + 1
        );
    }
}

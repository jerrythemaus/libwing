//! Firmware metadata + stale-map detection + runtime overlay tests (U3: R8,
//! R12, R35-R39).
//!
//! Compiles as an external crate against `libwing`, exercising the real
//! public-API contract for `Schema::metadata`/`staleness` and `LiveSchema`.
//! `WingNodeDef`'s fields are all `pub`, so fixtures here are built as plain
//! struct literals rather than wire-format bytes (contrast
//! `tests/value_compat.rs`'s `DefBuilder`, which exists specifically to
//! exercise the wire *parser*; that's not needed here).

use libwing::{
    LiveSchema, NodeType, NodeUnit, Provenance, Resolution, Schema, Staleness, WingConsole,
    WingNodeDef,
};

fn def(id: i32, parent_id: i32, name: &str, min: f32, max: f32) -> WingNodeDef {
    WingNodeDef {
        id,
        parent_id,
        index: 0,
        name: name.to_string(),
        long_name: name.to_uppercase(),
        node_type: NodeType::LinearFloat,
        unit: NodeUnit::Db,
        read_only: false,
        min_float: Some(min),
        max_float: Some(max),
        steps: None,
        min_int: None,
        max_int: None,
        max_string_len: None,
        string_enum: None,
        float_enum: None,
        raw: Vec::new(),
    }
}

fn assert_confirmed(
    res: Resolution,
    expected_fullname: &str,
    expected_provenance: Provenance,
) -> WingNodeDef {
    match res {
        Resolution::Confirmed {
            fullname,
            def,
            provenance,
        } => {
            assert_eq!(fullname, expected_fullname);
            assert_eq!(provenance, expected_provenance);
            def
        }
        Resolution::Unknown { id, model } => panic!(
            "expected Confirmed({expected_fullname}), got Unknown {{ id: {id}, model: {model:?} }}"
        ),
        _ => panic!("unhandled Resolution variant"),
    }
}

// --- R38/R39: staleness ---

#[test]
fn matching_firmware_is_current() {
    assert_eq!(Schema::staleness("3.1"), Staleness::Current);
}

#[test]
fn newer_console_firmware_is_map_older() {
    assert_eq!(Schema::staleness("3.2"), Staleness::MapOlder);
    assert_eq!(Schema::staleness("4.0.1"), Staleness::MapOlder);
}

#[test]
fn older_console_firmware_is_map_newer() {
    assert_eq!(Schema::staleness("3.0"), Staleness::MapNewer);
}

// --- version-compare edge cases ---

#[test]
fn trailing_zero_segment_is_still_current() {
    // "3.1" == "3.1.0": a missing trailing segment compares as 0.
    assert_eq!(Schema::staleness("3.1.0"), Staleness::Current);
}

#[test]
fn suffix_after_leading_digits_is_ignored() {
    // "1-beta2" parses as 1, suffix dropped -- same as plain "3.1".
    assert_eq!(Schema::staleness("3.1-beta2"), Staleness::Current);
}

#[test]
fn comparison_is_numeric_not_lexicographic() {
    // "3.10" > "3.1" numerically (10 > 1), even though it sorts lower as a
    // plain string. Confirms segments are parsed as integers, not compared
    // as strings.
    assert_eq!(Schema::staleness("3.10"), Staleness::MapOlder);
}

#[test]
fn garbage_input_is_unknown_not_current() {
    assert_eq!(Schema::staleness("banana"), Staleness::Unknown);
    assert_eq!(Schema::staleness(""), Staleness::Unknown);
}

#[test]
fn non_numeric_leading_segment_is_unknown() {
    // A leading segment with no digits at all (e.g. a "v"-prefixed firmware
    // string) fails to parse entirely -- deliberately not stripped, since
    // this crate has never seen that format and shouldn't guess at it.
    assert_eq!(Schema::staleness("v3.1"), Staleness::Unknown);
}

// --- R8, R35, R36: map metadata ---

#[test]
fn metadata_reports_pinned_baseline_and_entry_count() {
    let meta = Schema::metadata();
    assert_eq!(meta.firmware_baseline, "3.1");
    assert_eq!(meta.entry_count, WingConsole::propmap_len());
    assert!(meta.entry_count > 0);
    assert!(!meta.source.is_empty());
}

// --- Firmware-3.1 fixture (origin R67, folded in as a fixture per U3) ---
//
// Per Behringer's WING Firmware V3.1 (7 Nov 2025) release notes ("Added: New
// dual-band dynamic EQ plugin available in the Gate and Compressor slot"),
// `/ch/1/gate/DEQ/*` is a 3.1-introduced dynamics model. It shares its `thr`
// id with the pre-existing `GATE` model but has a different range
// (-60..0 vs -80..0), the same reused-id-per-model pattern the rest of the
// embedded map relies on.

const GATE_DEQ_THR_ID: i32 = -1952441044;

#[test]
fn firmware_3_1_dual_band_dynamic_eq_addition_resolves() {
    let deq = assert_confirmed(
        Schema::resolve_id(GATE_DEQ_THR_ID, Some("DEQ")).expect("id is in the embedded map"),
        "/ch/1/gate/DEQ/thr",
        Provenance::Embedded,
    );
    assert_eq!(deq.min_float, Some(-60.0));

    let gate = assert_confirmed(
        Schema::resolve_id(GATE_DEQ_THR_ID, Some("GATE")).expect("id is in the embedded map"),
        "/ch/1/gate/GATE/thr",
        Provenance::Embedded,
    );
    assert_eq!(gate.min_float, Some(-80.0));
}

// --- R12: LiveSchema overlay ---

#[test]
fn overlay_hit_resolves_live_untouched_id_still_resolves_embedded() {
    let mut live = LiveSchema::new();

    // A synthetic id that will never collide with the embedded map (it's
    // outside the range real WING node ids occupy in practice).
    const NEW_ID: i32 = i32::MIN + 1;
    live.apply_node_def(
        &def(NEW_ID, 0, "gain", -20.0, 20.0),
        Some("/ch/1/eq/NEWMODEL/gain"),
    );

    assert_confirmed(
        live.resolve_id(NEW_ID, Some("NEWMODEL"))
            .expect("id was just ingested into the overlay"),
        "/ch/1/eq/NEWMODEL/gain",
        Provenance::Live,
    );
    assert_confirmed(
        live.resolve_path("/ch/1/eq/NEWMODEL/gain", Some("NEWMODEL"))
            .expect("path was just ingested into the overlay"),
        "/ch/1/eq/NEWMODEL/gain",
        Provenance::Live,
    );

    // An id the overlay never saw still falls through to the embedded map.
    let gate_thr_id = WingConsole::name_to_id("/ch/1/gate/GATE/thr").expect("known path");
    assert_confirmed(
        live.resolve_id(gate_thr_id, Some("GATE"))
            .expect("id is in the embedded map"),
        "/ch/1/gate/GATE/thr",
        Provenance::Embedded,
    );
}

/// R12: simulates a live `mdl` change -- the same id exposed under two
/// mutually-exclusive per-model paths, mirroring the reused-id collision
/// pattern -- and confirms the overlay disambiguates by model exactly like
/// the embedded map does, just with `Provenance::Live`.
#[test]
fn overlay_disambiguates_reused_id_by_model_after_simulated_change() {
    let mut live = LiveSchema::new();
    const SLOT_ID: i32 = i32::MIN + 2;

    live.apply_node_def(
        &def(SLOT_ID, 0, "pdel", 0.0, 500.0),
        Some("/fx/9/HALL/pdel"),
    );
    live.apply_node_def(&def(SLOT_ID, 0, "egrp", 0.0, 1.0), Some("/fx/9/EXT/egrp"));

    let hall = assert_confirmed(
        live.resolve_id(SLOT_ID, Some("HALL")).expect("ingested"),
        "/fx/9/HALL/pdel",
        Provenance::Live,
    );
    assert_eq!(hall.name, "pdel");

    let ext = assert_confirmed(
        live.resolve_id(SLOT_ID, Some("EXT")).expect("ingested"),
        "/fx/9/EXT/egrp",
        Provenance::Live,
    );
    assert_eq!(ext.name, "egrp");

    // Unmatched model value: still Unknown, never a default candidate.
    match live.resolve_id(SLOT_ID, Some("NOPE")) {
        Some(Resolution::Unknown { id, model }) => {
            assert_eq!(id, SLOT_ID);
            assert_eq!(model.as_deref(), Some("NOPE"));
        }
        Some(Resolution::Confirmed { fullname, .. }) => {
            panic!("expected Unknown for an unmodeled model value, got Confirmed({fullname})")
        }
        None => panic!("expected Unknown, got None"),
        _ => panic!("unhandled Resolution variant"),
    }
}

#[test]
fn apply_node_def_synthesizes_fullname_from_known_parent() {
    let mut live = LiveSchema::new();
    const PARENT_ID: i32 = i32::MIN + 3;
    const CHILD_ID: i32 = i32::MIN + 4;

    live.apply_node_def(&def(PARENT_ID, 0, "slot", 0.0, 0.0), Some("/ch/9"));
    // No explicit fullname for the child: synthesized from the parent's
    // known path + the child def's own name.
    live.apply_node_def(&def(CHILD_ID, PARENT_ID, "lvl", -80.0, 10.0), None);

    assert_confirmed(
        live.resolve_id(CHILD_ID, None).expect("ingested"),
        "/ch/9/lvl",
        Provenance::Live,
    );
    assert_confirmed(
        live.resolve_path("/ch/9/lvl", None)
            .expect("synthesized path is registered"),
        "/ch/9/lvl",
        Provenance::Live,
    );
}

#[test]
fn apply_node_def_falls_back_to_id_only_when_parent_unknown() {
    let mut live = LiveSchema::new();
    const ORPHAN_ID: i32 = i32::MIN + 5;
    const UNKNOWN_PARENT: i32 = i32::MIN + 6;

    // Parent was never ingested and isn't in the embedded map either, so no
    // fullname can be synthesized.
    live.apply_node_def(&def(ORPHAN_ID, UNKNOWN_PARENT, "x", 0.0, 1.0), None);

    // Still resolvable by id (with a placeholder fullname), just not by any
    // real path.
    let resolved = assert_confirmed(
        live.resolve_id(ORPHAN_ID, None).expect("ingested by id"),
        "#-2147483643",
        Provenance::Live,
    );
    assert_eq!(resolved.name, "x");
}

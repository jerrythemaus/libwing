//! Model-aware resolution tests (U2: R10, R11, R13, R15).
//!
//! The WING console reuses a parameter id across the mutually exclusive model
//! variants of a slot (an fx slot's `mdl` selector set to `EXT` exposes id
//! `638586229` at `/fx/1/EXT/egrp`; set to `HALL` the same id is
//! `/fx/1/HALL/pdel`). These tests exercise `libwing::Schema::resolve_id`/
//! `resolve_path` picking the candidate that matches the live model value,
//! rather than defaulting to whichever candidate the map happens to list
//! first.

use libwing::{Provenance, Resolution, Schema, WingConsole};

/// Shared id also used by `tests/propmap_consistency.rs` to assert the
/// `/fx/1/EXT` vs `/fx/1/HALL` collision exists in the embedded map at all.
const FX_REVERB_ID: i32 = 638586229;

fn assert_confirmed(res: Resolution, expected_fullname: &str) -> libwing::WingNodeDef {
    match res {
        Resolution::Confirmed {
            fullname,
            def,
            provenance,
        } => {
            assert_eq!(fullname, expected_fullname);
            assert_eq!(provenance, Provenance::Embedded);
            def
        }
        Resolution::Unknown { id, model } => {
            panic!("expected Confirmed({expected_fullname}), got Unknown {{ id: {id}, model: {model:?} }}")
        }
        _ => panic!("unhandled Resolution variant"),
    }
}

#[test]
fn model_selects_correct_reused_id_variant() {
    let def = assert_confirmed(
        Schema::resolve_id(FX_REVERB_ID, Some("HALL")).expect("id is in the embedded map"),
        "/fx/1/HALL/pdel",
    );
    assert_eq!(def.name, "pdel");

    // Same id, EXT model: a completely different parameter (egrp vs pdel),
    // never the HALL candidate.
    let def = assert_confirmed(
        Schema::resolve_id(FX_REVERB_ID, Some("EXT")).expect("id is in the embedded map"),
        "/fx/1/EXT/egrp",
    );
    assert_eq!(def.name, "egrp");
}

/// R11: same id, different models, different type/range metadata.
#[test]
fn same_id_different_models_differ_in_type_or_range() {
    // /ch/1/gate/GATE/thr and /ch/1/gate/E88/thr share an id but have
    // different min/max ranges for the same "thr" parameter name.
    let gate_thr_id = WingConsole::name_to_id("/ch/1/gate/GATE/thr").expect("known path");

    let gate_def = assert_confirmed(
        Schema::resolve_id(gate_thr_id, Some("GATE")).expect("id is in the embedded map"),
        "/ch/1/gate/GATE/thr",
    );
    let e88_def = assert_confirmed(
        Schema::resolve_id(gate_thr_id, Some("E88")).expect("id is in the embedded map"),
        "/ch/1/gate/E88/thr",
    );
    assert_eq!(gate_def.min_float, Some(-80.0));
    assert_eq!(gate_def.max_float, Some(0.0));
    assert_eq!(e88_def.min_float, Some(-40.0));
    assert_eq!(e88_def.max_float, Some(0.0));
    assert_ne!(gate_def.min_float, e88_def.min_float);

    // /ch/1/eq/STD/lg (linear float) vs /ch/1/eq/F110/peq (integer): same id,
    // different type entirely.
    let eq_id = WingConsole::name_to_id("/ch/1/eq/STD/lg").expect("known path");
    let std_def = assert_confirmed(
        Schema::resolve_id(eq_id, Some("STD")).expect("id is in the embedded map"),
        "/ch/1/eq/STD/lg",
    );
    let f110_def = assert_confirmed(
        Schema::resolve_id(eq_id, Some("F110")).expect("id is in the embedded map"),
        "/ch/1/eq/F110/peq",
    );
    assert!(matches!(std_def.node_type, libwing::NodeType::LinearFloat));
    assert!(matches!(f110_def.node_type, libwing::NodeType::Integer));
}

/// Edge: a model value with no matching candidate is explicit drift, never a
/// wrong-model default.
#[test]
fn unmatched_model_value_is_unknown_not_a_default() {
    match Schema::resolve_id(FX_REVERB_ID, Some("NOPE")).expect("id is in the embedded map") {
        Resolution::Unknown { id, model } => {
            assert_eq!(id, FX_REVERB_ID);
            assert_eq!(model.as_deref(), Some("NOPE"));
        }
        Resolution::Confirmed { fullname, .. } => {
            panic!("expected Unknown for an unmodeled model value, got Confirmed({fullname})")
        }
        _ => panic!("unhandled Resolution variant"),
    }
}

/// Edge: a slot with model variants queried without a model value can't be
/// disambiguated -- also Unknown, never a silent default.
#[test]
fn missing_model_context_is_unknown_when_variants_exist() {
    match Schema::resolve_id(FX_REVERB_ID, None).expect("id is in the embedded map") {
        Resolution::Unknown { id, model } => {
            assert_eq!(id, FX_REVERB_ID);
            assert_eq!(model, None);
        }
        Resolution::Confirmed { fullname, .. } => {
            panic!("expected Unknown without model context, got Confirmed({fullname})")
        }
        _ => panic!("unhandled Resolution variant"),
    }
}

/// Edge: a base/always-present node (no `mdl` sibling, single candidate)
/// resolves directly, with no model context required.
#[test]
fn base_node_resolves_without_model_context() {
    let fader_id = WingConsole::name_to_id("/ch/1/fdr").expect("known path");
    assert_confirmed(
        Schema::resolve_id(fader_id, None).expect("id is in the embedded map"),
        "/ch/1/fdr",
    );
}

/// R15: path-first and id-first entry points return the same def for the
/// same live state, including when the given path carries a stale/wrong
/// model segment -- only the id is used, so the live model wins.
#[test]
fn path_first_and_id_first_agree() {
    let by_id = assert_confirmed(
        Schema::resolve_id(FX_REVERB_ID, Some("HALL")).expect("id is in the embedded map"),
        "/fx/1/HALL/pdel",
    );
    let by_path = assert_confirmed(
        Schema::resolve_path("/fx/1/HALL/pdel", Some("HALL")).expect("path is in the embedded map"),
        "/fx/1/HALL/pdel",
    );
    assert_eq!(by_id.id, by_path.id);
    assert_eq!(by_id.name, by_path.name);

    // Stale path (EXT segment) but live model is HALL: resolves via the id,
    // not the path's own (wrong) model segment.
    let by_stale_path = assert_confirmed(
        Schema::resolve_path("/fx/1/EXT/egrp", Some("HALL")).expect("path is in the embedded map"),
        "/fx/1/HALL/pdel",
    );
    assert_eq!(by_stale_path.name, "pdel");
}

#[test]
fn resolve_path_returns_none_for_unknown_path() {
    assert!(Schema::resolve_path("/not/a/real/path", Some("HALL")).is_none());
}

#[test]
fn resolve_id_returns_none_for_unknown_id() {
    assert!(Schema::resolve_id(i32::MAX, Some("HALL")).is_none());
}

/// Verification gate: wing-core's `mapper.rs` documents per-model EQ/gate/dyn
/// params as unresolvable ("Phase 1" gap). Confirm this API resolves them.
#[test]
fn resolves_wing_core_phase1_gap_params() {
    let gate_thr_id = WingConsole::name_to_id("/ch/1/gate/GATE/thr").expect("known path");
    assert_confirmed(
        Schema::resolve_id(gate_thr_id, Some("GATE")).expect("id is in the embedded map"),
        "/ch/1/gate/GATE/thr",
    );

    let eq_1g_id = WingConsole::name_to_id("/ch/1/eq/STD/1g").expect("known path");
    assert_confirmed(
        Schema::resolve_id(eq_1g_id, Some("STD")).expect("id is in the embedded map"),
        "/ch/1/eq/STD/1g",
    );
}

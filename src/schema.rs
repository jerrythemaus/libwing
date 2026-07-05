//! Model-aware resolution of parameter definitions (U2: R10, R11, R13, R15).
//!
//! The WING console reuses a parameter's numeric id across the mutually
//! exclusive model variants of the same slot: an FX slot's `mdl` selector set
//! to `EXT` exposes id `638586229` at `/fx/1/EXT/egrp`, but set to `HALL` the
//! *same* id is `/fx/1/HALL/pdel`. `WingConsole::id_to_defs` already returns
//! every candidate definition sharing an id; this module picks the one
//! candidate that matches the slot's live model value instead of leaving
//! callers to guess (or silently default to whichever candidate sorts first).

use crate::console::WingConsole;
use crate::node::WingNodeDef;

/// How a [`Resolution`] was derived (R13).
///
/// `#[non_exhaustive]`: U3 adds a `Live` variant (introspected from a
/// connected console) without this being a breaking change for callers who
/// already match with a wildcard arm (same compatibility policy as
/// [`crate::NodeType`]/[`crate::NodeUnit`], R21).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Looked up in the property map embedded at build time (U1's regenerated
    /// full sweep).
    Embedded,
}

/// The outcome of resolving a parameter id/path against a live model value.
///
/// `#[non_exhaustive]` for the same reason as [`Provenance`]: later units may
/// add variants (e.g. a distinct ambiguous-map case) without breaking callers.
#[non_exhaustive]
#[derive(Clone)]
pub enum Resolution {
    /// Exactly one candidate definition matched.
    Confirmed {
        fullname: String,
        def: WingNodeDef,
        provenance: Provenance,
    },
    /// `id` is a real, known parameter id, but the live model value didn't
    /// identify exactly one candidate: either none of the per-model subtrees
    /// matched (firmware drift, or a model string this map has never seen),
    /// or a slot was queried without a model value even though it has model
    /// variants. Never falls back to a default candidate (KTD2).
    Unknown { id: i32, model: Option<String> },
}

/// Namespace for model-aware resolution. Resolution is static over the
/// embedded map (no connection needed), so this holds no state -- see
/// [`WingConsole`] for the underlying id/path lookups it builds on.
pub struct Schema;

impl Schema {
    /// Resolve `id` to its live definition, given the slot's current model
    /// value (e.g. the live value of that slot's `mdl` selector, such as
    /// `"HALL"`). Pass `None` for base nodes that have no per-model variants.
    ///
    /// Returns `None` if `id` isn't present in the map at all (mirrors
    /// [`WingConsole::id_to_defs`]); returns `Some(Resolution::Unknown {..})`
    /// if `id` is known but the live model doesn't identify a single
    /// candidate.
    pub fn resolve_id(id: i32, model: Option<&str>) -> Option<Resolution> {
        let candidates = WingConsole::id_to_defs(id)?;
        Some(resolve_candidates(id, model, candidates))
    }

    /// Resolve `fullname` to its live definition, given the slot's current
    /// model value. `fullname` need not already carry the correct model
    /// segment: only its id is used, so a stale or default-model path
    /// resolves identically to [`Schema::resolve_id`] for that id (R15).
    ///
    /// Returns `None` if `fullname` isn't present in the map at all.
    pub fn resolve_path(fullname: &str, model: Option<&str>) -> Option<Resolution> {
        let id = WingConsole::name_to_id(fullname)?;
        Self::resolve_id(id, model)
    }
}

/// Picks the candidate whose `fullname` embeds `model` as a run of path
/// segments.
///
/// A per-model path is the slot's base path with the model value spliced in,
/// followed by the parameter's own name -- e.g. slot `/fx/1` + model `HALL` +
/// param `pdel` -> `/fx/1/HALL/pdel`. WING model values can themselves contain
/// `/` (the FX model `DEL/REV` produces `/fx/1/DEL/REV/time`), so matching
/// isn't a single-segment comparison; instead this matches the literal
/// substring `/{model}/`. That's exactly equivalent to matching a contiguous
/// run of path segments, because every `/` inside `model` lines up with a real
/// segment boundary in `fullname`, and it needs no prior knowledge of where
/// the slot's base path ends or the parameter name begins.
fn resolve_candidates(
    id: i32,
    model: Option<&str>,
    candidates: Vec<(String, WingNodeDef)>,
) -> Resolution {
    // A single candidate is unambiguous regardless of model context: either a
    // base node with no `mdl` sibling, or (incidentally) a slot where only one
    // model exposes this id.
    if candidates.len() == 1 {
        let (fullname, def) = candidates.into_iter().next().unwrap();
        return Resolution::Confirmed {
            fullname,
            def,
            provenance: Provenance::Embedded,
        };
    }

    let Some(model) = model else {
        return Resolution::Unknown { id, model: None };
    };

    let needle = format!("/{model}/");
    let mut matches = candidates
        .into_iter()
        .filter(|(fullname, _)| fullname.contains(&needle));
    match (matches.next(), matches.next()) {
        (Some((fullname, def)), None) => Resolution::Confirmed {
            fullname,
            def,
            provenance: Provenance::Embedded,
        },
        _ => Resolution::Unknown {
            id,
            model: Some(model.to_string()),
        },
    }
}

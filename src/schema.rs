//! Model-aware resolution of parameter definitions (U2: R10, R11, R13, R15),
//! plus map provenance metadata, stale-map detection, and a runtime overlay
//! for live-refreshed subtrees (U3: R8, R12, R35-R39).
//!
//! The WING console reuses a parameter's numeric id across the mutually
//! exclusive model variants of the same slot: an FX slot's `mdl` selector set
//! to `EXT` exposes id `638586229` at `/fx/1/EXT/egrp`, but set to `HALL` the
//! *same* id is `/fx/1/HALL/pdel`. `WingConsole::id_to_defs` already returns
//! every candidate definition sharing an id; this module picks the one
//! candidate that matches the slot's live model value instead of leaving
//! callers to guess (or silently default to whichever candidate sorts first).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::console::WingConsole;
use crate::node::WingNodeDef;
use crate::safety::Operation;
use crate::{Error, Result, WingResponse};

/// The firmware version the checked-in embedded map (`src/propmap.jsonl` /
/// `src/propmap.rs`) was swept from. A single obvious const so downstream
/// consumers (release reports, docs) and [`Schema::staleness`] have exactly
/// one place to cite/compare against.
pub const FIRMWARE_BASELINE: &str = "3.1";

/// How a [`Resolution`] was derived (R13).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Looked up in the property map embedded at build time (U1's regenerated
    /// full sweep), sourced from firmware [`FIRMWARE_BASELINE`].
    Embedded,
    /// Looked up in a [`LiveSchema`] overlay populated from `NodeDef`
    /// responses read off a connected console (U3), shadowing the embedded
    /// map for the ids/paths it has ingested.
    Live,
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

/// Snapshot of the embedded map's provenance (R8, R35, R36): the firmware it
/// was swept from, where it came from, and how many entries it holds. Cite
/// this in release notes/coverage reports rather than hardcoding the numbers
/// separately (U15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapMetadata {
    pub firmware_baseline: &'static str,
    pub source: &'static str,
    pub entry_count: usize,
}

/// Result of comparing a connected console's reported firmware against the
/// embedded map's [`FIRMWARE_BASELINE`] (R37, R38, R39).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staleness {
    /// Console firmware matches the baseline the embedded map was swept from.
    Current,
    /// Console firmware is newer than the baseline: the embedded map may be
    /// missing parameters/models added since. Callers can fall back to live
    /// introspection ([`LiveSchema::refresh_subtree`]) for affected subtrees.
    MapOlder,
    /// Console firmware is older than the baseline (the console predates the
    /// firmware the map was swept from). Not an error by itself -- the map's
    /// per-model coverage is then a superset of what this console exposes --
    /// but is still surfaced distinctly from `Current` since it means the map
    /// may describe models/params this console doesn't actually have.
    MapNewer,
    /// Either version string wasn't parseable as dotted-numeric (see
    /// [`Schema::staleness`]'s doc for the exact grammar). Deliberately not
    /// treated as `Current`: an unparseable firmware string is itself a
    /// signal something is off, not a "assume everything's fine" default.
    Unknown,
}

/// Namespace for model-aware resolution over the embedded map, plus map
/// metadata and staleness detection. Resolution here is static (no
/// connection needed); see [`LiveSchema`] for a per-connection overlay that
/// can be refreshed from a live console, and [`WingConsole`] for the
/// underlying id/path lookups this builds on.
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
        Some(resolve_candidates(
            id,
            model,
            candidates,
            Provenance::Embedded,
        ))
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

    /// Provenance/coverage snapshot of the embedded map (R8, R35, R36).
    pub fn metadata() -> MapMetadata {
        MapMetadata {
            firmware_baseline: FIRMWARE_BASELINE,
            source: "full per-model sweep (propmap.jsonl), embedded at build time",
            entry_count: WingConsole::propmap_len(),
        }
    }

    /// Compare a connected console's reported firmware against the embedded
    /// map's [`FIRMWARE_BASELINE`] (R37, R38, R39).
    ///
    /// Versions are compared as dotted-numeric sequences: each `.`-separated
    /// segment's *leading digit run* is parsed as an integer and any trailing
    /// non-digit suffix on that segment is ignored (`"3.1-beta2"` compares as
    /// `3.1`, same as `"3.1"`). Missing trailing segments compare as `0`
    /// (`"3.1"` == `"3.1.0"`). A segment with no leading digits at all makes
    /// the whole string unparseable -> [`Staleness::Unknown`], not a silent
    /// `Current`/default: firmware strings this crate has never seen are a
    /// signal to consult live introspection, not to assume compatibility.
    pub fn staleness(console_firmware: &str) -> Staleness {
        match (
            parse_version(FIRMWARE_BASELINE),
            parse_version(console_firmware),
        ) {
            (Some(baseline), Some(console)) => match compare_versions(&console, &baseline) {
                Ordering::Greater => Staleness::MapOlder,
                Ordering::Less => Staleness::MapNewer,
                Ordering::Equal => Staleness::Current,
            },
            _ => Staleness::Unknown,
        }
    }
}

/// Parses a dotted-numeric version string into its per-segment integers,
/// tolerating a trailing non-digit suffix per segment (see
/// [`Schema::staleness`]). Returns `None` if the first segment has no leading
/// digits at all (nothing sane to compare).
fn parse_version(s: &str) -> Option<Vec<u32>> {
    let mut parts = Vec::new();
    for segment in s.split('.') {
        let digits: String = segment.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// Lexicographic comparison of parsed version segments, treating a shorter
/// sequence's missing trailing segments as `0` (`[3, 1]` == `[3, 1, 0]`).
fn compare_versions(a: &[u32], b: &[u32]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let ord = a
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&b.get(i).copied().unwrap_or(0));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// A runtime resolution overlay that shadows the embedded map with
/// definitions ingested from live `NodeDef` responses (R12). Resolution
/// checks the overlay first and falls back to [`Schema`]'s embedded-map
/// lookups, so a `LiveSchema` degrades gracefully to purely-embedded
/// behavior for anything it hasn't ingested.
///
/// One `LiveSchema` is expected per connection/session; it holds no
/// reference to the console itself (`refresh_subtree` takes one by
/// reference), so it can be created before connecting and reused across
/// reconnects.
#[derive(Default)]
pub struct LiveSchema {
    /// Mirrors `WingConsole::id_to_defs`'s shape: every candidate definition
    /// this overlay has seen for a given id, across models.
    by_id: HashMap<i32, Vec<(String, WingNodeDef)>>,
    /// fullname -> id, populated only for entries with a real (not
    /// synthesized-placeholder) fullname; backs `resolve_path`.
    by_path: HashMap<String, i32>,
}

impl LiveSchema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one `NodeDef` (as read from `WingConsole::read()`) into the
    /// overlay.
    ///
    /// `fullname` should be passed when the caller already knows the node's
    /// full path (e.g. it requested a specific known path). When `None`,
    /// this tries to synthesize one from the def's `parent_id` -- looking up
    /// the parent's path in this overlay, then in the embedded map -- joined
    /// with the def's own `name`. That only works when the parent resolves
    /// to exactly one unambiguous path; a def whose parent has multiple
    /// per-model candidates (or is itself not yet known) is stored keyed by
    /// id only, under a `"#<id>"` placeholder fullname, and is therefore
    /// resolvable via [`LiveSchema::resolve_id`] but not
    /// [`LiveSchema::resolve_path`] until a real fullname is supplied.
    pub fn apply_node_def(&mut self, def: &WingNodeDef, fullname: Option<&str>) {
        let resolved = fullname
            .map(|s| s.to_string())
            .or_else(|| self.synthesize_fullname(def));
        let key = resolved.clone().unwrap_or_else(|| format!("#{}", def.id));

        let candidates = self.by_id.entry(def.id).or_default();
        match candidates.iter_mut().find(|(name, _)| *name == key) {
            Some(slot) => slot.1 = def.clone(),
            None => candidates.push((key.clone(), def.clone())),
        }

        if let Some(fullname) = resolved {
            self.by_path.insert(fullname, def.id);
        }
    }

    fn synthesize_fullname(&self, def: &WingNodeDef) -> Option<String> {
        let parent_path = self
            .by_id
            .get(&def.parent_id)
            .map(|v| v.as_slice())
            .and_then(single_path)
            .or_else(|| WingConsole::id_to_defs(def.parent_id).and_then(|v| single_path(&v)))?;
        Some(format!("{parent_path}/{}", def.name))
    }

    /// Overlay-aware equivalent of [`Schema::resolve_id`]: checks this
    /// overlay's ingested definitions first (returning
    /// [`Provenance::Live`]), then falls back to the embedded map.
    pub fn resolve_id(&self, id: i32, model: Option<&str>) -> Option<Resolution> {
        match self.by_id.get(&id) {
            Some(candidates) => Some(resolve_candidates(
                id,
                model,
                candidates.clone(),
                Provenance::Live,
            )),
            None => Schema::resolve_id(id, model),
        }
    }

    /// Overlay-aware equivalent of [`Schema::resolve_path`]. Only resolves
    /// via the overlay for fullnames it actually has (placeholder
    /// `"#<id>"` keys from un-synthesizable defs are deliberately not
    /// path-addressable); otherwise falls back to the embedded map.
    pub fn resolve_path(&self, fullname: &str, model: Option<&str>) -> Option<Resolution> {
        match self.by_path.get(fullname) {
            Some(&id) => self.resolve_id(id, model),
            None => Schema::resolve_path(fullname, model),
        }
    }

    /// Refresh a subtree live: requests `subtree_root_id`'s definition and
    /// ingests every `NodeDef` the console streams back (a WING console
    /// responds to a definition request for a container node with the
    /// definitions of its descendants, terminated by `RequestEnd`), applying
    /// each via [`LiveSchema::apply_node_def`] with no caller-supplied
    /// fullname (synthesized from parent path where possible). Returns the
    /// number of definitions ingested.
    ///
    /// `timeout` bounds the wall-clock time this call is willing to wait
    /// *between* reads; it's checked before each `WingConsole::read()` call,
    /// not during one. `WingConsole::read()` itself has no read-timeout of
    /// its own -- it blocks until data arrives, sending keep-alives as
    /// needed -- so a console that never replies to this request (versus one
    /// that replies slowly) can still block past `timeout` on a single
    /// stalled read. That matches `read()`'s existing behavior elsewhere in
    /// this crate; tightening it is future work if it proves necessary in
    /// practice.
    pub fn refresh_subtree(
        &mut self,
        console: &mut WingConsole,
        subtree_root_id: i32,
        timeout: Duration,
    ) -> Result<usize> {
        let deadline = Instant::now() + timeout;
        console.request_node_definition(subtree_root_id)?;

        let mut count = 0;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            match console.read()? {
                WingResponse::NodeDef(def) => {
                    self.apply_node_def(&def, None);
                    count += 1;
                }
                WingResponse::RequestEnd => return Ok(count),
                WingResponse::NodeData(..) => {
                    // Unsolicited data interleaved with the definition stream
                    // (e.g. from another in-flight request); not part of this
                    // refresh, so it's dropped here rather than buffered --
                    // callers needing both should use the attended-get layer
                    // (U4) instead of a raw refresh.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transport availability map (U11: R6)
// ---------------------------------------------------------------------------

/// Which transport(s) can perform a given [`Operation`] (R6): the Native TCP session in
/// `console.rs` (port 2222), the OSC UDP transport in `osc.rs` (port 2223), both, or
/// neither.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportAvailability {
    /// Only Native can perform this operation today.
    NativeOnly,
    /// Only OSC can perform this operation today.
    OscOnly,
    /// Either transport can perform an equivalent operation. "Equivalent" doesn't
    /// always mean byte-identical output -- see [`transport_availability`]'s per-arm
    /// doc comments for the operations where the two routes differ in shape.
    Both,
    /// Not a network request at all, so no transport applies.
    NonNetwork,
}

/// Total mapping from [`Operation`] to which transport(s) can perform it (R6). Every
/// variant gets exactly one label plus a rationale below; an exhaustiveness check lives
/// as an in-crate `#[cfg(test)]` unit test in this module (not an external integration
/// test), since `Operation` is `#[non_exhaustive]` and can't be matched without a
/// wildcard arm from outside this crate.
pub fn transport_availability(op: Operation) -> TransportAvailability {
    match op {
        // Native: `WingConsole::request_node_data`/`get_node_data`. OSC:
        // `osc::get_param`/`WingOscClient::request`. Both read a single node's current
        // value; the wire shapes differ (raw+display vs display/raw/real facets) but
        // the operation -- "read this node" -- is available either way.
        Operation::ReadNodeData => TransportAvailability::Both,

        // Native: `WingConsole::request_node_definition` returns the full binary
        // `WingNodeDef` schema (type, min/max, units, access). OSC:
        // `osc::node_describe`/`node_describe_with_values` return a text/display
        // description, not that binary schema. Labeled `Both` because OSC *can* fetch
        // definition-shaped information for a node, but callers relying on
        // `WingNodeDef`'s specific fields should treat the OSC route as informational,
        // not a substitute -- same caveat as `SchemaCrawl` below.
        Operation::ReadNodeDefinition => TransportAvailability::Both,

        // Native only: `WingConsole::scan` broadcasts a UDP discovery probe with no
        // prior knowledge of a console's address. OSC's equivalent-looking `/?`
        // (`osc::console_info`) requires already having a console's IP:port to send to
        // (it's a unicast request-reply, not a broadcast) -- it can confirm a console
        // at a known address, but it cannot discover one.
        Operation::Discover => TransportAvailability::NativeOnly,

        // Native only: `WingConsole::connect` opens the stateful Native TCP session
        // this crate's `WingConsole` is built around. OSC is connectionless UDP --
        // `WingOscClient::connect`/`connect_addr` just resolve an address and bind a
        // local socket, with no session/handshake concept to "connect" in the same
        // sense.
        Operation::Connect => TransportAvailability::NativeOnly,

        // Native only: meter levels are the Native binary channel-3 UDP stream
        // (`console.rs`'s `request_meter`). OSC has no meter-level stream at all --
        // `osc.rs` has no meter concept.
        Operation::SubscribeMeters => TransportAvailability::NativeOnly,

        // Native only: reads the Native meter socket (`WingConsole::read_meters`); same
        // reasoning as `SubscribeMeters` -- there is no OSC meter data to read.
        Operation::ReadMeters => TransportAvailability::NativeOnly,

        // Native only: `WingConsole::keep_alive`/`keep_alive_meters` are this crate's
        // Native session/meter keepalive cadence. OSC's analogous idea is subscription
        // renewal (`WingOscClient::subscribe`/`renew`/`poll_event`, R4) -- a different
        // mechanism (re-sending a subscribe message, not a keepalive byte) that isn't
        // modeled as this `Operation` variant, so it doesn't make this `Both`.
        Operation::KeepAlive => TransportAvailability::NativeOnly,

        // Both: Native `set_string`/`set_float`/`set_int` and OSC's equivalents
        // (`osc::set_string`/`set_float`/`set_int`/`toggle`/`set_enum_by_name`/
        // `set_enum_by_index`) write a node's value; either transport can do it.
        Operation::SetNodeValue => TransportAvailability::Both,

        // Both, with the same caveat as `ReadNodeDefinition`: `wingschema`'s live sweep
        // walks Native node definitions; OSC's `node_describe`/`node_describe_with_values`
        // ('?'/'#') can enumerate a node's children with descriptions too. Labeled
        // `Both` because the crawl *operation* -- discover a subtree's structure -- is
        // possible over either transport, but OSC's descriptions are display-oriented
        // text, not wingschema's persisted binary `WingNodeDef` schema, so it is not a
        // drop-in substitute for wingschema's current Native-only implementation.
        Operation::SchemaCrawl => TransportAvailability::Both,
    }
}

fn single_path(candidates: &[(String, WingNodeDef)]) -> Option<String> {
    match candidates {
        [(name, _)] => Some(name.clone()),
        _ => None,
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
    provenance: Provenance,
) -> Resolution {
    // A single candidate is unambiguous regardless of model context: either a
    // base node with no `mdl` sibling, or (incidentally) a slot where only one
    // model exposes this id.
    if candidates.len() == 1 {
        let (fullname, def) = candidates.into_iter().next().unwrap();
        return Resolution::Confirmed {
            fullname,
            def,
            provenance,
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
            provenance,
        },
        _ => Resolution::Unknown {
            id,
            model: Some(model.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Operation` is `#[non_exhaustive]`, so an external crate (like an integration
    /// test in `tests/`) can't write a `match` over it without a wildcard arm --
    /// which would defeat the point of an exhaustiveness check. Living in-crate as a
    /// unit test, this can match without one, so `transport_availability`'s own
    /// `match` (also wildcard-free) is the thing actually enforcing totality; this
    /// test just pins that every variant is covered by *some* case here too, so
    /// adding an `Operation` variant without updating this list fails to compile.
    #[test]
    fn availability_map_covers_every_operation() {
        for op in [
            Operation::ReadNodeData,
            Operation::ReadNodeDefinition,
            Operation::Discover,
            Operation::Connect,
            Operation::SubscribeMeters,
            Operation::ReadMeters,
            Operation::KeepAlive,
            Operation::SetNodeValue,
            Operation::SchemaCrawl,
        ] {
            // Just exercising that every variant maps to a single, deterministic
            // label -- `transport_availability`'s match arms (no wildcard) are what
            // actually guarantee totality at compile time.
            let a = transport_availability(op);
            let b = transport_availability(op);
            assert_eq!(a, b, "{op:?} must map to exactly one availability");
        }
    }

    #[test]
    fn native_only_and_both_ops_are_labeled_correctly() {
        assert_eq!(
            transport_availability(Operation::SubscribeMeters),
            TransportAvailability::NativeOnly
        );
        assert_eq!(
            transport_availability(Operation::Discover),
            TransportAvailability::NativeOnly
        );
        assert_eq!(
            transport_availability(Operation::SetNodeValue),
            TransportAvailability::Both
        );
        assert_eq!(
            transport_availability(Operation::ReadNodeData),
            TransportAvailability::Both
        );
    }
}

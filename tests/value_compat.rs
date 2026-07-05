//! Compatibility-preserving value types (U7: R14, R20, R21).
//!
//! Compiles as an external crate against `libwing`, so these tests exercise the
//! real public-API contract: `NodeType`/`NodeUnit` are `#[non_exhaustive]`, a novel
//! wire discriminant must surface as an explicit `Unknown` rather than being
//! coerced into a known variant, and the value facets the protocol actually
//! provides (raw vs. display) must be distinguishable.

use libwing::{NodeType, NodeUnit, WingNodeData, WingNodeDef};

/// Minimal builder for a node-definition byte stream in the wire format that
/// `WingNodeDef::from_bytes` parses. Mirrors the format documented in
/// `src/node.rs`'s own unit tests, but built from scratch here since integration
/// tests can't reach that private test helper.
struct DefBuilder<'a> {
    parent_id: i32,
    id: i32,
    index: u16,
    name: &'a str,
    long_name: &'a str,
    node_type: u8,
    unit: u8,
    payload: Vec<u8>,
}

impl<'a> DefBuilder<'a> {
    fn new(id: i32, name: &'a str, long_name: &'a str, node_type: u8) -> Self {
        Self {
            parent_id: 0,
            id,
            index: 0,
            name,
            long_name,
            node_type,
            unit: 0,
            payload: Vec::new(),
        }
    }
    fn unit(mut self, unit: u8) -> Self {
        self.unit = unit;
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn i32(mut self, v: i32) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn f32(mut self, v: f32) -> Self {
        self.payload.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn str(mut self, s: &str) -> Self {
        self.payload.push(s.len() as u8);
        self.payload.extend_from_slice(s.as_bytes());
        self
    }
    fn build(self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.parent_id.to_be_bytes());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.push(self.name.len() as u8);
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(self.long_name.len() as u8);
        buf.extend_from_slice(self.long_name.as_bytes());
        let flags: u16 = ((self.node_type as u16 & 0x0F) << 4) | (self.unit as u16 & 0x0F);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

// --- R20: novel discriminants are preserved, never coerced ---

#[test]
fn novel_node_type_discriminant_is_preserved_not_coerced() {
    // 9 is an unassigned type nibble (0-7 are the only known types today).
    let bytes = DefBuilder::new(1, "n", "N", 9).build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();
    assert_eq!(def.node_type, NodeType::Unknown(9));
    // Never silently mapped to a known type such as `Node`.
    assert_ne!(def.node_type, NodeType::Node);
    // The full framed def round-trips verbatim, even though libwing doesn't know
    // how to interpret its type-specific payload.
    assert_eq!(def.raw, bytes);
}

#[test]
fn novel_node_unit_discriminant_is_preserved_not_coerced() {
    // 11 is an unassigned unit nibble (0-7 are the only known units today).
    let bytes = DefBuilder::new(2, "u", "U", 0).unit(11).build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();
    assert_eq!(def.unit, NodeUnit::Unknown(11));
    assert_ne!(def.unit, NodeUnit::None);
}

#[test]
fn novel_type_and_unit_with_valid_framing_parses_ok_not_error() {
    // Structurally valid framing (lengths/bounds all check out) with only the
    // *meaning* of the type/unit nibbles being unrecognized must still parse
    // successfully as Unknown, not be rejected as a framing error.
    let bytes = DefBuilder::new(3, "future", "Future Node", 13)
        .unit(12)
        .build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();
    assert_eq!(def.node_type, NodeType::Unknown(13));
    assert_eq!(def.unit, NodeUnit::Unknown(12));
    assert_eq!(def.name, "future");
}

#[test]
fn genuine_framing_errors_still_error() {
    // A claimed name length that runs past the end of the buffer is a real framing
    // error (not a novel-discriminant case) and must still fail, even though
    // unknown-type parsing was relaxed elsewhere.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0i32.to_be_bytes()); // parent_id
    bytes.extend_from_slice(&1i32.to_be_bytes()); // id
    bytes.extend_from_slice(&0u16.to_be_bytes()); // index
    bytes.push(200); // name_len claims 200 bytes but none follow
    assert!(WingNodeDef::try_from_bytes(&bytes).is_err());
}

// --- R14: raw / display value facets are distinguishable ---

#[test]
fn string_enum_raw_and_display_facets_are_distinct() {
    // node_type 5 = StringEnum, 2 items: index 0 = "a"/"Alpha", index 1 = "b"/"Bravo".
    let bytes = DefBuilder::new(10, "e", "E", 5)
        .u16(2)
        .str("a")
        .str("Alpha")
        .str("b")
        .str("Bravo")
        .build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();

    let data = WingNodeData::with_i32(1);
    // Raw facet: the wire value is the enum index.
    assert_eq!(data.get_int(), 1);
    assert_eq!(data.get_string(), "1");
    // Display facet: resolved through the def to the item's label.
    assert_eq!(data.display_string(&def), "b");
}

#[test]
fn float_enum_raw_and_display_facets_are_distinct() {
    // node_type 6 = FloatEnum, 2 items.
    let bytes = DefBuilder::new(11, "fe", "FE", 6)
        .u16(2)
        .f32(0.25)
        .str("Quarter")
        .f32(0.5)
        .str("Half")
        .build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();

    let data = WingNodeData::with_float(0.5);
    assert_eq!(data.get_float(), 0.5);
    assert_eq!(data.get_string(), "0.5");
    assert_eq!(data.display_string(&def), "Half");
}

#[test]
fn fader_level_raw_value_is_the_real_engineering_value() {
    // node_type 3 = FaderLevel, unit 1 = Db, range -90..10.
    let bytes = DefBuilder::new(12, "fdr", "Fader", 3)
        .unit(1)
        .f32(-90.0)
        .f32(10.0)
        .i32(1024)
        .build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();
    assert_eq!(def.unit, NodeUnit::Db);

    // The wire protocol carries no separate normalized (0..1) encoding for
    // FaderLevel/LinearFloat/LogarithmicFloat nodes distinct from the raw value:
    // the float libwing decodes is already the real dB value, bounded by the
    // def's min/max. Raw and display therefore coincide for non-enum types.
    let data = WingNodeData::with_float(-6.0);
    assert_eq!(data.get_float(), -6.0);
    assert_eq!(data.display_string(&def), "-6");
}

#[test]
fn display_string_falls_back_to_raw_for_out_of_range_enum_index() {
    // A StringEnum index beyond what this def snapshot knows about (e.g. a value
    // added by newer firmware) must not be silently mislabeled; it falls back to
    // the raw rendering rather than panicking or guessing a neighboring label.
    let bytes = DefBuilder::new(13, "e2", "E2", 5)
        .u16(1)
        .str("only")
        .str("Only")
        .build();
    let def = WingNodeDef::from_bytes(&bytes).unwrap();

    let data = WingNodeData::with_i32(5);
    assert_eq!(data.display_string(&def), "5");
}

// --- R21: additive, non-exhaustive public enums ---

#[test]
fn non_exhaustive_match_requires_wildcard_and_routes_unknown_safely() {
    // NodeType/NodeUnit are #[non_exhaustive] (R21). Because this test file
    // compiles as a separate crate against libwing, the compiler actually enforces
    // the wildcard arm below (removing it is a compile error: "non-exhaustive
    // patterns: `_` not covered") — this is the mechanism that lets a future
    // libwing release add a variant without breaking downstream matches.
    fn describe(t: NodeType) -> &'static str {
        match t {
            NodeType::Node => "node",
            NodeType::LinearFloat => "linear float",
            NodeType::LogarithmicFloat => "log float",
            NodeType::FaderLevel => "fader level",
            NodeType::Integer => "integer",
            NodeType::StringEnum => "string enum",
            NodeType::FloatEnum => "float enum",
            NodeType::String => "string",
            _ => "unknown",
        }
    }

    assert_eq!(describe(NodeType::Node), "node");
    assert_eq!(describe(NodeType::Unknown(9)), "unknown");
}

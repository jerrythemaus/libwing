//! Typed enum encode/decode helpers (U6: R18, R19).
//!
//! Compiles as an external crate against `libwing` -- `WingNodeDef` and its
//! `StringEnumItem`/`FloatEnumItem` fields are all `pub`, so fixtures here are
//! built as plain struct literals (same approach `tests/stale_map.rs` uses for
//! `WingNodeDef` itself), no wire-format bytes needed.
//!
//! None of this needs the embedded property map, so nothing here is
//! feature-gated -- it all runs the same under `--no-default-features`.

use libwing::{
    decode_enum, encode_enum, EnumDecode, EnumKey, EnumValue, FloatEnumItem, NodeType, NodeUnit,
    RawEnumValue, StringEnumItem, WingNodeData, WingNodeDef,
};

fn string_enum_def(items: &[(&str, &str)]) -> WingNodeDef {
    WingNodeDef {
        id: 1,
        parent_id: 0,
        index: 0,
        name: "mdl".to_string(),
        long_name: "Model".to_string(),
        node_type: NodeType::StringEnum,
        unit: NodeUnit::None,
        read_only: false,
        min_float: None,
        max_float: None,
        steps: None,
        min_int: None,
        max_int: None,
        max_string_len: None,
        string_enum: Some(
            items
                .iter()
                .map(|(item, long_item)| StringEnumItem {
                    item: item.to_string(),
                    long_item: long_item.to_string(),
                })
                .collect(),
        ),
        float_enum: None,
        raw: Vec::new(),
    }
}

fn float_enum_def(items: &[(f32, &str)]) -> WingNodeDef {
    WingNodeDef {
        id: 2,
        parent_id: 0,
        index: 0,
        name: "amt".to_string(),
        long_name: "Amount".to_string(),
        node_type: NodeType::FloatEnum,
        unit: NodeUnit::None,
        read_only: false,
        min_float: None,
        max_float: None,
        steps: None,
        min_int: None,
        max_int: None,
        max_string_len: None,
        string_enum: None,
        float_enum: Some(
            items
                .iter()
                .map(|(item, long_item)| FloatEnumItem {
                    item: *item,
                    long_item: long_item.to_string(),
                })
                .collect(),
        ),
        raw: Vec::new(),
    }
}

#[test]
fn string_enum_item_long_item_index_encode_to_the_same_wire_value() {
    let def = string_enum_def(&[("a", "Alpha"), ("b", "Bravo"), ("c", "Charlie")]);

    let by_item = encode_enum(&def, EnumKey::Item("b")).unwrap();
    let by_long_item = encode_enum(&def, EnumKey::LongItem("Bravo")).unwrap();
    let by_index = encode_enum(&def, EnumKey::Index(1)).unwrap();

    assert_eq!(by_item, EnumValue::Str("b".to_string()));
    assert_eq!(by_item, by_long_item);
    assert_eq!(by_item, by_index);
}

#[test]
fn string_enum_encode_rejects_unknown_key() {
    let def = string_enum_def(&[("a", "Alpha")]);
    assert_eq!(encode_enum(&def, EnumKey::Item("nope")), None);
    assert_eq!(encode_enum(&def, EnumKey::LongItem("Nope")), None);
    assert_eq!(encode_enum(&def, EnumKey::Index(99)), None);
}

#[test]
fn string_enum_decode_round_trips_to_a_stable_form() {
    let def = string_enum_def(&[("a", "Alpha"), ("b", "Bravo")]);
    let data = WingNodeData::with_i32(1); // StringEnum values arrive as an index.

    assert_eq!(
        decode_enum(&def, &data),
        EnumDecode::StringEnum {
            item: "b".to_string(),
            long_item: "Bravo".to_string(),
            index: 1,
        }
    );
}

/// R20: an index this def's item list doesn't have (e.g. a value a newer
/// firmware added) must decode to an explicit `Unknown`, never be coerced to
/// the nearest known item.
#[test]
fn string_enum_unknown_index_is_preserved_not_coerced() {
    let def = string_enum_def(&[("a", "Alpha"), ("b", "Bravo")]);
    let data = WingNodeData::with_i32(5);

    assert_eq!(
        decode_enum(&def, &data),
        EnumDecode::Unknown(RawEnumValue::Index(5))
    );
}

#[test]
fn float_enum_long_item_and_index_encode_to_the_same_wire_value() {
    let def = float_enum_def(&[(0.25, "Quarter"), (0.5, "Half")]);

    let by_long_item = encode_enum(&def, EnumKey::LongItem("Half")).unwrap();
    let by_index = encode_enum(&def, EnumKey::Index(1)).unwrap();

    assert_eq!(by_long_item, EnumValue::Float(0.5));
    assert_eq!(by_long_item, by_index);
}

/// `FloatEnum` has no separate short item-name string (its `item` field *is*
/// the float value) -- `EnumKey::Item` is StringEnum-only.
#[test]
fn float_enum_encode_rejects_item_key() {
    let def = float_enum_def(&[(0.25, "Quarter")]);
    assert_eq!(encode_enum(&def, EnumKey::Item("0.25")), None);
}

#[test]
fn float_enum_decode_round_trips_to_a_stable_form() {
    let def = float_enum_def(&[(0.25, "Quarter"), (0.5, "Half")]);
    let data = WingNodeData::with_float(0.5);

    assert_eq!(
        decode_enum(&def, &data),
        EnumDecode::FloatEnum {
            item: 0.5,
            long_item: "Half".to_string(),
            index: 1,
        }
    );
}

/// R20: same unknown-preservation guarantee as the StringEnum case, for a
/// float value with no matching entry.
#[test]
fn float_enum_unknown_value_is_preserved_not_coerced() {
    let def = float_enum_def(&[(0.25, "Quarter"), (0.5, "Half")]);
    let data = WingNodeData::with_float(0.99);

    assert_eq!(
        decode_enum(&def, &data),
        EnumDecode::Unknown(RawEnumValue::Float(0.99))
    );
}

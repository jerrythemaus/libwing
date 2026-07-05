//! Typed enum encode/decode helpers (U6: R18, R19).
//!
//! A `StringEnum`/`FloatEnum` node can be addressed three equivalent ways from a
//! caller's point of view -- by its short item name, its long (display) label, or
//! its position in `def.string_enum`/`def.float_enum` -- but the wire only accepts
//! one canonical form per type. [`encode_enum`] normalizes any of the three into
//! that form; [`decode_enum`] does the reverse, turning a raw [`WingNodeData`]
//! back into a stable, all-three-facets user-facing shape.
//!
//! ## Verified StringEnum write form
//!
//! `tools/wingschema.rs`'s schema crawl -- the one piece of code in this
//! repository that has actually driven a live console through every value of a
//! `mdl` selector -- writes StringEnum values with `wing.set_string(mdl_def.id,
//! &item.item)`, i.e. the item's short name as a string, never a raw integer
//! index. `WingNodeData::display_string`'s read path confirms the asymmetry: a
//! StringEnum's raw wire value comes back as an *index* (`self.int_value`), but
//! going the other direction the console expects the *name*. Since there is no
//! confirmed evidence anywhere in this codebase that the console also accepts a
//! raw integer index as a StringEnum write, [`encode_enum`] resolves all three
//! key forms -- including [`EnumKey::Index`] -- to that same verified string
//! form. This also directly satisfies R19's requirement that item/long-item/index
//! all produce the *same* wire value: they're not just equivalent, they're
//! identical.
//!
//! `FloatEnum` has no separate short "item name" string (its `item` field *is*
//! the float value); [`EnumKey::Item`] is therefore StringEnum-only and
//! [`encode_enum`] returns `None` for it against a `FloatEnum` def.

use crate::node::{NodeType, WingNodeData, WingNodeDef};
use crate::{Result, WingConsole};

/// How to look up one entry in a `StringEnum`/`FloatEnum` def. All three forms
/// that apply to a given def resolve to the same [`EnumValue`] -- see the module
/// docs for why.
#[derive(Clone, Copy, Debug)]
pub enum EnumKey<'a> {
    /// Short item name (`StringEnumItem::item`). `StringEnum` only -- `FloatEnum`
    /// has no equivalent string field, so [`encode_enum`] returns `None` for this
    /// key against a `FloatEnum` def.
    Item(&'a str),
    /// Long/display label (`StringEnumItem::long_item` / `FloatEnumItem::long_item`).
    LongItem(&'a str),
    /// Position in the def's item list.
    Index(usize),
}

/// The wire-ready form an [`EnumKey`] resolves to (R19): a `StringEnum` always
/// encodes to its item name string; a `FloatEnum` always encodes to its item's
/// float value. Write it with [`WingConsole::set_string`] / [`WingConsole::set_float`]
/// respectively -- or use [`write_enum`] to do that dispatch automatically.
#[derive(Clone, Debug, PartialEq)]
pub enum EnumValue {
    Str(String),
    Float(f32),
}

/// Resolves `key` against `def`'s enum items to the wire value that would
/// select the same entry, or `None` if `def` isn't an enum type, has no items,
/// or `key` doesn't match any entry (an out-of-range index, or a name/label not
/// present in this def).
pub fn encode_enum(def: &WingNodeDef, key: EnumKey) -> Option<EnumValue> {
    match def.node_type {
        NodeType::StringEnum => {
            let items = def.string_enum.as_ref()?;
            let item = match key {
                EnumKey::Item(name) => items.iter().find(|i| i.item == name)?,
                EnumKey::LongItem(name) => items.iter().find(|i| i.long_item == name)?,
                EnumKey::Index(idx) => items.get(idx)?,
            };
            Some(EnumValue::Str(item.item.clone()))
        }
        NodeType::FloatEnum => {
            let items = def.float_enum.as_ref()?;
            let item = match key {
                EnumKey::Item(_) => return None,
                EnumKey::LongItem(name) => items.iter().find(|i| i.long_item == name)?,
                EnumKey::Index(idx) => items.get(idx)?,
            };
            Some(EnumValue::Float(item.item))
        }
        _ => None,
    }
}

/// [`encode_enum`] followed by the matching `set_string`/`set_float` write.
/// Returns `Err(Error::InvalidInput)` if `key` doesn't resolve (see [`encode_enum`]).
pub fn write_enum(
    console: &mut WingConsole,
    id: i32,
    def: &WingNodeDef,
    key: EnumKey,
) -> Result<()> {
    match encode_enum(def, key).ok_or(crate::Error::InvalidInput)? {
        EnumValue::Str(s) => console.set_string(id, &s),
        EnumValue::Float(f) => console.set_float(id, f),
    }
}

/// A raw enum-typed value that didn't match any entry in its def (R20): newer
/// firmware may report an index/value this def snapshot has never seen. Carried
/// verbatim rather than coerced to a neighboring entry.
#[derive(Clone, Debug, PartialEq)]
pub enum RawEnumValue {
    /// An unmatched `StringEnum` index.
    Index(i32),
    /// An unmatched `FloatEnum` value.
    Float(f32),
    /// `data` didn't carry the facet `def`'s type expects at all (e.g. a
    /// non-enum def, or an enum def with no items) -- falls back to
    /// [`WingNodeData::get_string`]'s raw rendering, same fallback
    /// `display_string` uses.
    Other(String),
}

/// Stable, user-facing decode of an enum node's raw value (R19), preserving
/// unknown values explicitly instead of guessing (R20). Complements
/// [`WingNodeData::display_string`] (same matching rules) but also returns the
/// entry's index, which `display_string` doesn't expose.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum EnumDecode {
    StringEnum {
        item: String,
        long_item: String,
        index: usize,
    },
    FloatEnum {
        item: f32,
        long_item: String,
        index: usize,
    },
    Unknown(RawEnumValue),
}

pub fn decode_enum(def: &WingNodeDef, data: &WingNodeData) -> EnumDecode {
    match def.node_type {
        NodeType::StringEnum => match (&def.string_enum, data.has_int()) {
            (Some(items), true) => {
                let idx = data.get_int();
                match usize::try_from(idx).ok().map(|i| (i, items.get(i))) {
                    Some((index, Some(item))) => EnumDecode::StringEnum {
                        item: item.item.clone(),
                        long_item: item.long_item.clone(),
                        index,
                    },
                    _ => EnumDecode::Unknown(RawEnumValue::Index(idx)),
                }
            }
            _ => EnumDecode::Unknown(RawEnumValue::Other(data.get_string())),
        },
        NodeType::FloatEnum => match (&def.float_enum, data.has_float()) {
            (Some(items), true) => {
                let value = data.get_float();
                match items.iter().enumerate().find(|(_, i)| i.item == value) {
                    Some((index, item)) => EnumDecode::FloatEnum {
                        item: item.item,
                        long_item: item.long_item.clone(),
                        index,
                    },
                    None => EnumDecode::Unknown(RawEnumValue::Float(value)),
                }
            }
            _ => EnumDecode::Unknown(RawEnumValue::Other(data.get_string())),
        },
        _ => EnumDecode::Unknown(RawEnumValue::Other(data.get_string())),
    }
}

//! A view over the embedded property-map blob that does no work at startup.
//!
//! The blob (`propmap.bin`, written by `wingschema`'s `write_propmap_bin`) is the sweep's
//! `[flag u8][namelen u16][name][deflen u16][def]` records plus precomputed index tables, so
//! a name lookup is one hash and a probe or two over `&'static` bytes, and a definition is
//! parsed the first time it is asked for. Parsed definitions are leaked into a per-entry `OnceLock`: the old
//! eager map was a process-lifetime static too, and this keeps every returned reference
//! `'static` and every read lock-free.
//!
//! Layout, all integers big-endian:
//!
//! ```text
//! "WPM2"  count:u32  entries_len:u32
//! entries                      entries_len bytes, the records above
//! offsets  count x u32         record offsets, sorted by name bytes (an entry's index in this
//!                              table is its "ordinal")
//! by_id    count x u32         ordinals, sorted by (definition id, ordinal)
//! hash     slots x u32         open-addressing table of ordinals, linear probing, EMPTY
//!                              (u32::MAX) for a free slot; slots = (count * 2).next_power_of_two()
//!                              (0 when count is 0), keyed by [`name_hash`]
//! ```

use std::sync::OnceLock;

use crate::node::WingNodeDef;

#[cfg(feature = "propmap")]
const MAGIC: &[u8; 4] = b"WPM2";
#[cfg(feature = "propmap")]
const HEADER_LEN: usize = 12;

pub(crate) struct PropIndex {
    entries: &'static [u8],
    offsets: &'static [u8],
    by_id: &'static [u8],
    hash: &'static [u8],
    defs: Box<[OnceLock<&'static WingNodeDef>]>,
}

fn be32(bytes: &[u8], at: usize) -> usize {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize
}

fn be16(bytes: &[u8], at: usize) -> usize {
    u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize
}

const EMPTY: usize = u32::MAX as usize;

/// FNV-1a over the name bytes, folded to 32 bits. `wingschema` has the same function to build
/// the table; `canonical_encoder_regenerates_committed_map_byte_for_byte` and the lookup tests
/// fail if the two ever drift.
fn name_hash(name: &[u8]) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    (h ^ (h >> 32)) as usize
}

#[cfg(feature = "propmap")]
fn hash_slots(count: usize) -> usize {
    if count == 0 {
        0
    } else {
        (count * 2).next_power_of_two()
    }
}

/// First index in `0..len` for which `pred` is false, given `pred` is true then false.
fn partition_point(len: usize, pred: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

impl PropIndex {
    /// An index with no entries (the `propmap` feature off).
    #[cfg(not(feature = "propmap"))]
    pub(crate) fn empty() -> Self {
        Self {
            entries: &[],
            offsets: &[],
            by_id: &[],
            hash: &[],
            defs: Box::default(),
        }
    }

    /// Reads the header of an embedded blob. Panics on a malformed blob: it is a build-time
    /// constant, and `tests/propmap_consistency.rs` plus the generator test cover it.
    #[cfg(feature = "propmap")]
    pub(crate) fn new(data: &'static [u8]) -> Self {
        assert!(
            data.len() >= HEADER_LEN && &data[..4] == MAGIC,
            "embedded propmap blob has no WPM1 header"
        );
        let count = be32(data, 4);
        let entries_len = be32(data, 8);
        assert_eq!(
            data.len(),
            HEADER_LEN + entries_len + count * 8 + hash_slots(count) * 4,
            "embedded propmap blob length does not match its header"
        );
        let (entries, tables) = data[HEADER_LEN..].split_at(entries_len);
        let (offsets, tables) = tables.split_at(count * 4);
        let (by_id, hash) = tables.split_at(count * 4);
        Self {
            entries,
            offsets,
            by_id,
            hash,
            defs: (0..count).map(|_| OnceLock::new()).collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.defs.len()
    }

    /// `(name bytes, definition bytes)` of the entry at `ordinal`.
    fn raw(&self, ordinal: usize) -> (&'static [u8], &'static [u8]) {
        let entries: &'static [u8] = self.entries;
        let mut i = be32(self.offsets, ordinal * 4) + 1; // skip the flag byte
        let name_len = be16(entries, i);
        i += 2;
        let name = &entries[i..i + name_len];
        i += name_len;
        let def_len = be16(entries, i);
        i += 2;
        (name, &entries[i..i + def_len])
    }

    fn name(&self, ordinal: usize) -> &'static str {
        std::str::from_utf8(self.raw(ordinal).0).expect("embedded propmap names are UTF-8")
    }

    /// The entry's definition id, read straight from the wire bytes (`parent_id` then `id`)
    /// without parsing the definition.
    fn id_at(&self, ordinal: usize) -> i32 {
        let def = self.raw(ordinal).1;
        i32::from_be_bytes([def[4], def[5], def[6], def[7]])
    }

    fn def(&self, ordinal: usize) -> &'static WingNodeDef {
        self.defs[ordinal].get_or_init(|| {
            let parsed = WingNodeDef::from_bytes_without_raw(self.raw(ordinal).1)
                .expect("valid embedded propmap definition");
            Box::leak(Box::new(parsed))
        })
    }

    fn find(&self, name: &str) -> Option<usize> {
        let slots = self.hash.len() / 4;
        if slots == 0 {
            return None;
        }
        let name = name.as_bytes();
        let mut slot = name_hash(name) & (slots - 1);
        loop {
            let ordinal = be32(self.hash, slot * 4);
            if ordinal == EMPTY {
                return None;
            }
            if self.raw(ordinal).0 == name {
                return Some(ordinal);
            }
            slot = (slot + 1) & (slots - 1);
        }
    }

    pub(crate) fn get(&self, name: &str) -> Option<&'static WingNodeDef> {
        self.find(name).map(|o| self.def(o))
    }

    /// The id for `name`, without parsing its definition.
    pub(crate) fn id_of(&self, name: &str) -> Option<i32> {
        self.find(name).map(|o| self.id_at(o))
    }

    /// Every entry, in name order. Parses (and caches) each definition it yields.
    pub(crate) fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (&'static str, &'static WingNodeDef)> + '_ {
        (0..self.len()).map(|o| (self.name(o), self.def(o)))
    }

    /// Every entry whose definition has `id`, in name order; `None` when there is none.
    pub(crate) fn by_id(
        &self,
        id: i32,
    ) -> Option<impl ExactSizeIterator<Item = (&'static str, &'static WingNodeDef)> + '_> {
        let ordinal = |k: usize| be32(self.by_id, k * 4);
        let start = partition_point(self.len(), |k| self.id_at(ordinal(k)) < id);
        let end = partition_point(self.len(), |k| self.id_at(ordinal(k)) <= id);
        (start < end).then(|| {
            (start..end).map(move |k| {
                let o = ordinal(k);
                (self.name(o), self.def(o))
            })
        })
    }
}

#[cfg(all(test, feature = "propmap"))]
mod tests {
    use crate::propmap::NAME_TO_DEF;

    /// Every embedded record parses, names are strictly sorted (what `find` relies on), and
    /// each lookup path agrees with the others.
    #[test]
    fn index_is_sorted_and_every_lookup_path_agrees() {
        let mut previous: Option<&str> = None;
        let mut seen = 0;
        for (name, def) in NAME_TO_DEF.iter() {
            assert!(previous.is_none_or(|p| p < name), "{name} out of order");
            previous = Some(name);
            assert_eq!(NAME_TO_DEF.get(name).map(|d| d.id), Some(def.id), "{name}");
            assert_eq!(NAME_TO_DEF.id_of(name), Some(def.id), "{name}");
            assert!(
                NAME_TO_DEF
                    .by_id(def.id)
                    .is_some_and(|mut same| same.any(|(n, _)| n == name)),
                "{name} missing from its id group"
            );
            seen += 1;
        }
        assert_eq!(seen, NAME_TO_DEF.len());
    }

    #[test]
    fn misses_and_near_misses_return_none() {
        assert!(NAME_TO_DEF.get("").is_none());
        assert!(NAME_TO_DEF.get("/definitely/not/a/node").is_none());
        assert!(
            NAME_TO_DEF.get("/ch/1/fd").is_none(),
            "prefix is not a match"
        );
        assert!(NAME_TO_DEF.id_of("/ch/1/fdrr").is_none());
        assert!(NAME_TO_DEF.by_id(i32::MIN).is_none());
    }

    #[test]
    fn by_id_groups_are_name_ordered_and_complete() {
        let total: usize = {
            let mut ids: Vec<i32> = NAME_TO_DEF.iter().map(|(_, d)| d.id).collect();
            ids.sort_unstable();
            ids.dedup();
            ids.iter()
                .map(|&id| {
                    let names: Vec<_> = NAME_TO_DEF.by_id(id).unwrap().map(|(n, _)| n).collect();
                    assert!(names.windows(2).all(|w| w[0] < w[1]));
                    names.len()
                })
                .sum()
        };
        assert_eq!(total, NAME_TO_DEF.len());
    }
}

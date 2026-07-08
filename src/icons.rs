//! WING icon index ↔ name map, decoded from the WING Remote Protocols appendix ("WING Icons").
//!
//! The console stores a strip icon as an integer `0..=999` (the `/…/icon` nodes). This module maps
//! the documented icons to stable slug names, resolves names/aliases back to indices, and reports
//! the category range. Each category in the spec is a 5-wide grid numbered left-to-right,
//! top-to-bottom from the range start. Instrument / mic / drum / key entries are high-confidence
//! glyph reads; a few speaker and "general" entries are approximate (noted in the spec appendix).

/// `(index, slug)` for every documented icon.
pub const ICONS: &[(u16, &str)] = &[
    // General [0..=14]
    (0, "none"),
    (2, "jack-plug"),
    (3, "jack-trs"),
    (4, "jack-mini"),
    (5, "fader"),
    (6, "fx"),
    (7, "routing"),
    (8, "bass-clef"),
    (9, "treble-clef"),
    (10, "matrix"),
    (11, "layers"),
    (12, "list"),
    (13, "smiley"),
    (14, "wing-logo"),
    // Vocals & Mics [100..=114]
    (100, "mic-handheld-dynamic"),
    (101, "mic-handheld"),
    (102, "mic-wireless-handheld"),
    (103, "mic-lavalier"),
    (104, "mic-broadcast-round"),
    (105, "mic-desk-boundary"),
    (106, "mic-podium"),
    (107, "headset-boom"),
    (108, "headphones"),
    (109, "mic-studio-condenser"),
    (110, "mic-ribbon"),
    (111, "mic-vintage"),
    (112, "singers-group"),
    (113, "singer-headset"),
    (114, "singer"),
    // Drums & Percussion [200..=224]
    (200, "kick-drum"),
    (201, "bass-drum"),
    (202, "snare-drum"),
    (203, "tom"),
    (204, "drum"),
    (205, "hi-hat"),
    (206, "tom-high"),
    (207, "tom-mid"),
    (208, "tom-low"),
    (209, "tom-floor"),
    (210, "drum-kit"),
    (211, "cymbal-crash"),
    (212, "cymbal-ride"),
    (213, "claves"),
    (214, "tambourine"),
    (215, "bongos"),
    (216, "congas"),
    (217, "timbale"),
    (218, "cajon"),
    (219, "maracas"),
    (220, "xylophone"),
    (221, "handpan"),
    (222, "triangle"),
    (223, "drum-machine"),
    (224, "clap"),
    // Strings & Winds [300..=319]
    (300, "guitar-electric"),
    (301, "guitar-acoustic"),
    (302, "violin"),
    (303, "banjo"),
    (304, "guitar-classical"),
    (305, "guitar-lespaul"),
    (306, "guitar-explorer"),
    (307, "guitar-flying-v"),
    (308, "cello-bowed"),
    (309, "guitar-electric-2"),
    (310, "violin-bow"),
    (311, "clarinet-oboe"),
    (312, "saxophone"),
    (313, "trombone"),
    (314, "trumpet"),
    (315, "harp"),
    (316, "accordion"),
    (317, "harmonica"),
    (318, "flute"),
    (319, "clarinet"),
    // Keys [400..=409]
    (400, "grand-piano"),
    (401, "upright-piano"),
    (402, "synthesizer"),
    (403, "keyboard"),
    (404, "synth"),
    (405, "organ"),
    (406, "synth-module"),
    (407, "stage-piano"),
    (408, "keyboard-stand"),
    (409, "piano-keys"),
    // Speakers [500..=524] (510+ approximate)
    (500, "amp-combo"),
    (501, "cabinet-4x"),
    (502, "cabinet"),
    (503, "monitor"),
    (504, "speakers-pair"),
    (505, "speaker-pole"),
    (506, "subwoofer"),
    (507, "monitor-ported"),
    (508, "monitors-pair"),
    (509, "speakers-on-stands"),
    (510, "line-array"),
    (511, "pa-speaker"),
    (512, "speaker-mic"),
    (513, "speakers-stands"),
    (514, "delay-speaker"),
    (515, "speaker-h"),
    (516, "speaker-small"),
    (517, "speaker-pair-h"),
    (518, "cabinet-v"),
    (519, "speaker-stack"),
    (520, "stage-wedge"),
    (521, "wedge"),
    (522, "speaker-upright"),
    (523, "line-array-curved"),
    (524, "subwoofer-round"),
    // Specials [600..=614]
    (600, "rock-hand"),
    (601, "ear"),
    (602, "headphones-2"),
    (603, "talkback-a"),
    (604, "talkback-b"),
    (605, "laptop"),
    (606, "media-player"),
    (607, "phone"),
    (608, "usb-stick"),
    (609, "sd-card"),
    (610, "cd"),
    (611, "turntable"),
    (612, "tape-machine"),
    (613, "cassette"),
    (614, "rack"),
];

/// Category ranges (inclusive), in spec order.
pub const CATEGORIES: &[(&str, u16, u16)] = &[
    ("general", 0, 14),
    ("vocals_mics", 100, 114),
    ("drums_percussion", 200, 224),
    ("strings_winds", 300, 319),
    ("keys", 400, 409),
    ("speakers", 500, 524),
    ("specials", 600, 614),
];

/// Natural-language aliases → index, layered on top of the canonical slugs.
const ALIASES: &[(&str, u16)] = &[
    ("guitar", 304),
    ("acoustic-guitar", 301),
    ("electric-guitar", 300),
    ("bass", 301),
    ("vihuela", 303),
    ("fiddle", 310),
    ("cello", 308),
    ("viola", 310),
    ("harp", 315),
    ("trumpet", 314),
    ("trombone", 313),
    ("sax", 312),
    ("saxophone", 312),
    ("flute", 318),
    ("clarinet", 319),
    ("accordion", 316),
    ("harmonica", 317),
    ("piano", 400),
    ("keys", 403),
    ("organ", 405),
    ("vocal", 100),
    ("vocal-lead", 100),
    ("voice", 100),
    ("mic", 100),
    ("microphone", 100),
    ("studio-mic", 109),
    ("kick", 200),
    ("snare", 202),
    ("drums", 210),
    ("percussion", 219),
    ("maracas", 219),
    ("congas", 216),
    ("speaker", 503),
    ("wedge", 520),
    ("sub", 506),
];

/// The canonical slug for an icon index, if it is documented.
pub fn icon_name(index: u16) -> Option<&'static str> {
    ICONS.iter().find(|&&(i, _)| i == index).map(|&(_, n)| n)
}

/// Resolve an icon name or alias (case-insensitive) to its `0..=999` index. Canonical slugs win
/// over aliases.
pub fn icon_index(name: &str) -> Option<u16> {
    let n = name.trim().to_ascii_lowercase();
    let n = n.as_str();
    ICONS
        .iter()
        .find(|&&(_, s)| s == n)
        .map(|&(i, _)| i)
        .or_else(|| ALIASES.iter().find(|&&(a, _)| a == n).map(|&(_, i)| i))
}

/// The category name for an icon index, if it falls in a documented range.
pub fn icon_category(index: u16) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|&&(_, lo, hi)| index >= lo && index <= hi)
        .map(|&(c, _, _)| c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_resolve() {
        assert_eq!(icon_index("trumpet"), Some(314));
        assert_eq!(icon_index("Violin"), Some(302)); // canonical slug, case-insensitive
        assert_eq!(icon_index("fiddle"), Some(310)); // alias -> the bowed-violin glyph
        assert_eq!(icon_index("harp"), Some(315));
        assert_eq!(icon_index("guitar-lespaul"), Some(305)); // canonical slug
        assert_eq!(icon_index("nope"), None);
    }

    #[test]
    fn indices_resolve() {
        assert_eq!(icon_name(314), Some("trumpet"));
        assert_eq!(icon_name(315), Some("harp"));
        assert_eq!(icon_name(1), None); // undocumented index
        assert_eq!(icon_category(310), Some("strings_winds"));
        assert_eq!(icon_category(100), Some("vocals_mics"));
        assert_eq!(icon_category(50), None);
    }
}

//! Typed decode layer over the raw meter frames [`WingConsole::read_meters`](crate::WingConsole::read_meters)
//! returns (U8/U9).
//!
//! **Provenance:** every layout, word count, and scaling constant here is *spec-derived*
//! (WING Remote Protocols V3.1-03, pages 98-99 and 122-124) — none of it has been confirmed
//! against a physical WING Rack. Treat it as the best available reading of the spec, not a
//! hardware-verified contract, until a captured fixture replaces the hand-built ones in
//! `tests/meter_decode.rs` / `tests/rta_decode.rs`.
//!
//! [`WingConsole::read_meters`](crate::WingConsole::read_meters) itself stays untyped (a raw
//! `Vec<i16>`) — that transport-level contract is unchanged. This module adds [`decode_frame`],
//! which splits that raw frame into one [`MeterFrameEntry`] per meter in the *request* that
//! produced it (order matters: the console echoes meters back in request order, and there is no
//! per-meter framing on the wire to recover that split otherwise).

use crate::console::Meter;
use crate::{Error, Result};

/// Level in dB from a raw `i16` meter sample (1/256 dB, spec p.98/122).
pub fn level_db(raw: i16) -> f32 {
    raw as f32 / 256.0
}

/// FX-processor band gain-reduction in dB from a raw state-meter `i16` (spec p.98: `dB = value *
/// 6.0 / 2048.0`). Only meaningful for [`FxMeter::state`] entries 0..5 (band GR); entry 5 is not
/// documented as GR and is passed through undecoded.
pub fn fx_band_gr_db(raw: i16) -> f32 {
    raw as f32 * 6.0 / 2048.0
}

/// Word count of the (channel/aux/bus/main/matrix) family: 8 `i16`s.
pub const CHANNEL_WORDS: usize = 8;
/// Word count of the `dca` family: 4 `i16`s.
pub const DCA_WORDS: usize = 4;
/// Word count of the `fx` family: 10 `i16`s.
pub const FX_WORDS: usize = 10;
/// Word count of the `source` family: 8 `i16`s.
pub const SOURCE_WORDS: usize = 8;
/// Word count of the `output` family: 8 `i16`s.
pub const OUTPUT_WORDS: usize = 8;
/// Word count of the `monitor` family: 6 `i16`s.
pub const MONITOR_WORDS: usize = 6;
/// Word count of the `rta` family: 120 `i16`s.
pub const RTA_WORDS: usize = 120;
/// Word count of the V2 (channel/aux/bus/main/matrix) family: 11 `i16`s.
pub const CHANNEL_V2_WORDS: usize = 11;

/// One (channel/aux/bus/main/matrix) meter object: 8 words (spec p.98/122).
///
/// **Gain scaling caveat:** `gate_gain`/`dyn_gain` are returned in 1/256 steps, but the value
/// that maps to "full" gain reduction is model-dependent — the spec states 1.0 (256) *typically*
/// maps to 20 dB, while the standard WING gate spans 60 dB. Don't assume a fixed dB scale for
/// these two fields without confirming the active model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelMeter {
    pub input_l: i16,
    pub input_r: i16,
    pub output_l: i16,
    pub output_r: i16,
    pub gate_key: i16,
    pub gate_gain: i16,
    pub dyn_key: i16,
    pub dyn_gain: i16,
}

impl ChannelMeter {
    /// Decode one `CHANNEL_WORDS`-sized (8) slice. Panics (as an internal invariant, not a data
    /// error) if `words.len() != CHANNEL_WORDS`; callers should slice on family-size boundaries
    /// first (see [`decode_frame`]).
    pub fn from_slice(words: &[i16]) -> Self {
        assert_eq!(words.len(), CHANNEL_WORDS);
        ChannelMeter {
            input_l: words[0],
            input_r: words[1],
            output_l: words[2],
            output_r: words[3],
            gate_key: words[4],
            gate_gain: words[5],
            dyn_key: words[6],
            dyn_gain: words[7],
        }
    }
}

/// One `dca` meter object: 4 words (spec p.98/122).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DcaMeter {
    pub pre_fader_l: i16,
    pub pre_fader_r: i16,
    pub post_fader_l: i16,
    pub post_fader_r: i16,
}

impl DcaMeter {
    pub fn from_slice(words: &[i16]) -> Self {
        assert_eq!(words.len(), DCA_WORDS);
        DcaMeter {
            pre_fader_l: words[0],
            pre_fader_r: words[1],
            post_fader_l: words[2],
            post_fader_r: words[3],
        }
    }
}

/// One `fx` meter object: 10 words (spec p.98/122) — 4 levels + 6 state meters. The first 5
/// state entries are band gain-reduction (convert with [`fx_band_gr_db`]); the 6th is undocumented.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FxMeter {
    pub input_l: i16,
    pub input_r: i16,
    pub output_l: i16,
    pub output_r: i16,
    pub state: [i16; 6],
}

impl FxMeter {
    pub fn from_slice(words: &[i16]) -> Self {
        assert_eq!(words.len(), FX_WORDS);
        FxMeter {
            input_l: words[0],
            input_r: words[1],
            output_l: words[2],
            output_r: words[3],
            state: [words[4], words[5], words[6], words[7], words[8], words[9]],
        }
    }
}

/// One `monitor` meter object: 6 words (spec p.98/122; no index — single global object).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonitorMeter {
    pub solo_l: i16,
    pub solo_r: i16,
    pub mon1_l: i16,
    pub mon1_r: i16,
    pub mon2_l: i16,
    pub mon2_r: i16,
}

impl MonitorMeter {
    pub fn from_slice(words: &[i16]) -> Self {
        assert_eq!(words.len(), MONITOR_WORDS);
        MonitorMeter {
            solo_l: words[0],
            solo_r: words[1],
            mon1_l: words[2],
            mon1_r: words[3],
            mon2_l: words[4],
            mon2_r: words[5],
        }
    }
}

/// One V2 (channel/aux/bus/main/matrix) meter object: 11 words (spec p.98/122). `gate_led` and
/// `dyn_state` are 0/1 flags, not levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelMeterV2 {
    pub input_l: i16,
    pub input_r: i16,
    pub output_l: i16,
    pub output_r: i16,
    pub gate_key: i16,
    pub gate_gain: i16,
    pub gate_led: i16,
    pub dyn_key: i16,
    pub dyn_gain: i16,
    pub dyn_state: i16,
    pub automix_gain: i16,
}

impl ChannelMeterV2 {
    pub fn from_slice(words: &[i16]) -> Self {
        assert_eq!(words.len(), CHANNEL_V2_WORDS);
        ChannelMeterV2 {
            input_l: words[0],
            input_r: words[1],
            output_l: words[2],
            output_r: words[3],
            gate_key: words[4],
            gate_gain: words[5],
            gate_led: words[6],
            dyn_key: words[7],
            dyn_gain: words[8],
            dyn_state: words[9],
            automix_gain: words[10],
        }
    }
}

/// One decoded meter object, tagged by which requested [`Meter`] it came from (so a caller
/// matching on this enum can tell e.g. `Channel` from `Aux` even though both carry a
/// [`ChannelMeter`]).
///
/// `#[non_exhaustive]`: new families (or corrected variants) may be added without that being a
/// breaking change for callers who already match with a wildcard arm.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum MeterFrameEntry {
    Channel(ChannelMeter),
    Aux(ChannelMeter),
    Bus(ChannelMeter),
    Main(ChannelMeter),
    Matrix(ChannelMeter),
    Dca(DcaMeter),
    Fx(FxMeter),
    Source([i16; 8]),
    Output([i16; 8]),
    Monitor(MonitorMeter),
    /// `rta` slot meters (spec-derived count: 120; see module docs).
    Rta(Vec<i16>),
    Channel2(ChannelMeterV2),
    Aux2(ChannelMeterV2),
    Bus2(ChannelMeterV2),
    Main2(ChannelMeterV2),
    Matrix2(ChannelMeterV2),
}

/// Word count of the family a given [`Meter`] request element decodes to.
fn family_words(meter: &Meter) -> usize {
    match meter {
        Meter::Channel(_) | Meter::Aux(_) | Meter::Bus(_) | Meter::Main(_) | Meter::Matrix(_) => {
            CHANNEL_WORDS
        }
        Meter::Dca(_) => DCA_WORDS,
        Meter::Fx(_) => FX_WORDS,
        Meter::Source(_) => SOURCE_WORDS,
        Meter::Output(_) => OUTPUT_WORDS,
        Meter::Monitor => MONITOR_WORDS,
        Meter::Rta => RTA_WORDS,
        Meter::Channel2(_)
        | Meter::Aux2(_)
        | Meter::Bus2(_)
        | Meter::Main2(_)
        | Meter::Matrix2(_) => CHANNEL_V2_WORDS,
    }
}

/// Splits a raw meter frame (the `Vec<i16>` from
/// [`WingConsole::read_meters`](crate::WingConsole::read_meters)) into one [`MeterFrameEntry`]
/// per element of `request`, in request order (the order the console echoes meters back in —
/// see spec p.98: "Specified meters are sent back in the sequence corresponding to the request
/// message").
///
/// `request` must be the *same* meter list passed to
/// [`WingConsole::request_meter`](crate::WingConsole::request_meter) that produced `raw` —
/// there's no per-meter framing on the wire, so the split is entirely dependent on knowing what
/// was asked for.
///
/// Validates the frame length up front: if `raw.len()` doesn't match the sum of each requested
/// meter's family word count, returns [`Error::MeterFrameLength`] naming both the expected and
/// actual word count (feeds R28 — a caller can surface this as a clear "insufficient capacity"
/// signal rather than a panic or silently-misaligned decode).
pub fn decode_frame(request: &[Meter], raw: &[i16]) -> Result<Vec<MeterFrameEntry>> {
    let expected: usize = request.iter().map(family_words).sum();
    if raw.len() != expected {
        return Err(Error::MeterFrameLength {
            expected,
            actual: raw.len(),
        });
    }

    let mut out = Vec::with_capacity(request.len());
    let mut offset = 0;
    for meter in request {
        let n = family_words(meter);
        let words = &raw[offset..offset + n];
        out.push(match meter {
            Meter::Channel(_) => MeterFrameEntry::Channel(ChannelMeter::from_slice(words)),
            Meter::Aux(_) => MeterFrameEntry::Aux(ChannelMeter::from_slice(words)),
            Meter::Bus(_) => MeterFrameEntry::Bus(ChannelMeter::from_slice(words)),
            Meter::Main(_) => MeterFrameEntry::Main(ChannelMeter::from_slice(words)),
            Meter::Matrix(_) => MeterFrameEntry::Matrix(ChannelMeter::from_slice(words)),
            Meter::Dca(_) => MeterFrameEntry::Dca(DcaMeter::from_slice(words)),
            Meter::Fx(_) => MeterFrameEntry::Fx(FxMeter::from_slice(words)),
            Meter::Source(_) => {
                MeterFrameEntry::Source(words.try_into().expect("SOURCE_WORDS == 8"))
            }
            Meter::Output(_) => {
                MeterFrameEntry::Output(words.try_into().expect("OUTPUT_WORDS == 8"))
            }
            Meter::Monitor => MeterFrameEntry::Monitor(MonitorMeter::from_slice(words)),
            Meter::Rta => MeterFrameEntry::Rta(words.to_vec()),
            Meter::Channel2(_) => MeterFrameEntry::Channel2(ChannelMeterV2::from_slice(words)),
            Meter::Aux2(_) => MeterFrameEntry::Aux2(ChannelMeterV2::from_slice(words)),
            Meter::Bus2(_) => MeterFrameEntry::Bus2(ChannelMeterV2::from_slice(words)),
            Meter::Main2(_) => MeterFrameEntry::Main2(ChannelMeterV2::from_slice(words)),
            Meter::Matrix2(_) => MeterFrameEntry::Matrix2(ChannelMeterV2::from_slice(words)),
        });
        offset += n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_db_scales_by_256() {
        assert_eq!(level_db(0), 0.0);
        assert_eq!(level_db(-256), -1.0);
        assert_eq!(level_db(256 * 6), 6.0);
    }

    #[test]
    fn fx_band_gr_scales_per_spec_formula() {
        assert_eq!(fx_band_gr_db(0), 0.0);
        // value * 6.0 / 2048.0
        assert!((fx_band_gr_db(2048) - 6.0).abs() < 1e-6);
    }

    #[test]
    fn channel_meter_decodes_word_order() {
        let words: [i16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let m = ChannelMeter::from_slice(&words);
        assert_eq!(
            m,
            ChannelMeter {
                input_l: 1,
                input_r: 2,
                output_l: 3,
                output_r: 4,
                gate_key: 5,
                gate_gain: 6,
                dyn_key: 7,
                dyn_gain: 8,
            }
        );
    }

    #[test]
    fn decode_frame_single_channel() {
        let raw = [1i16, 2, 3, 4, 5, 6, 7, 8];
        let entries = decode_frame(&[Meter::Channel(1)], &raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            MeterFrameEntry::Channel(ChannelMeter {
                input_l: 1,
                input_r: 2,
                output_l: 3,
                output_r: 4,
                gate_key: 5,
                gate_gain: 6,
                dyn_key: 7,
                dyn_gain: 8,
            })
        );
    }

    #[test]
    fn decode_frame_length_mismatch_is_typed_error() {
        let raw = [0i16; 7]; // one short of CHANNEL_WORDS
        let err = decode_frame(&[Meter::Channel(1)], &raw).unwrap_err();
        match err {
            Error::MeterFrameLength { expected, actual } => {
                assert_eq!(expected, 8);
                assert_eq!(actual, 7);
            }
            other => panic!("expected MeterFrameLength, got {other:?}"),
        }
    }
}

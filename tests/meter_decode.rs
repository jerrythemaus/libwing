//! Fixture-driven coverage for the typed meter decode layer (U8, R5).
//!
//! **Provenance:** every fixture here is *spec-derived* (WING Remote Protocols V3.1-03, pages
//! 98-99 and 122-124), not captured from a physical WING Rack — hardware verification is
//! pending (see `libwing::meters` module docs).

use libwing::{decode_frame, ChannelMeter, ChannelMeterV2, Error, Meter, MeterFrameEntry};

/// A synthetic 8-word channel/aux/bus/main/matrix object: input L/R, output L/R, gate key/gain,
/// dyn key/gain, offset by `base` so distinct objects in a multi-meter frame are distinguishable.
fn channel_words(base: i16) -> [i16; 8] {
    [
        base,
        base + 1,
        base + 2,
        base + 3,
        base + 4,
        base + 5,
        base + 6,
        base + 7,
    ]
}

fn channel_meter(base: i16) -> ChannelMeter {
    ChannelMeter {
        input_l: base,
        input_r: base + 1,
        output_l: base + 2,
        output_r: base + 3,
        gate_key: base + 4,
        gate_gain: base + 5,
        dyn_key: base + 6,
        dyn_gain: base + 7,
    }
}

#[test]
fn decodes_two_channel_objects_in_request_order() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&channel_words(0));
    raw.extend_from_slice(&channel_words(100));

    let entries = decode_frame(&[Meter::Channel(1), Meter::Channel(2)], &raw).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], MeterFrameEntry::Channel(channel_meter(0)));
    assert_eq!(entries[1], MeterFrameEntry::Channel(channel_meter(100)));
}

#[test]
fn decodes_mixed_family_request_at_correct_offsets() {
    // Channel (8) + Fx (10) + Rta (120), concatenated in request order.
    let mut raw = Vec::new();
    raw.extend_from_slice(&channel_words(0)); // channel 1
    raw.extend_from_slice(&[10, 11, 12, 13, 100, 200, 300, 400, 500, 600]); // fx 1
    let rta_frame: Vec<i16> = (0..120).map(|i| i as i16 * 2 - 256).collect(); // rta
    raw.extend_from_slice(&rta_frame);

    let entries = decode_frame(&[Meter::Channel(1), Meter::Fx(1), Meter::Rta], &raw).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0], MeterFrameEntry::Channel(channel_meter(0)));
    match &entries[1] {
        MeterFrameEntry::Fx(fx) => {
            assert_eq!(fx.input_l, 10);
            assert_eq!(fx.input_r, 11);
            assert_eq!(fx.output_l, 12);
            assert_eq!(fx.output_r, 13);
            assert_eq!(fx.state, [100, 200, 300, 400, 500, 600]);
        }
        other => panic!("expected Fx, got {other:?}"),
    }
    match &entries[2] {
        MeterFrameEntry::Rta(bins) => assert_eq!(bins, &rta_frame),
        other => panic!("expected Rta, got {other:?}"),
    }
}

#[test]
fn short_frame_reports_expected_vs_actual() {
    // Requesting Channel + Fx implies 8 + 10 = 18 words; supply only 17.
    let raw = vec![0i16; 17];
    let err = decode_frame(&[Meter::Channel(1), Meter::Fx(1)], &raw).unwrap_err();
    match err {
        Error::MeterFrameLength { expected, actual } => {
            assert_eq!(expected, 18);
            assert_eq!(actual, 17);
        }
        other => panic!("expected MeterFrameLength, got {other:?}"),
    }
}

#[test]
fn long_frame_is_also_a_length_mismatch() {
    let raw = vec![0i16; 9]; // one more than CHANNEL_WORDS
    let err = decode_frame(&[Meter::Channel(1)], &raw).unwrap_err();
    match err {
        Error::MeterFrameLength { expected, actual } => {
            assert_eq!(expected, 8);
            assert_eq!(actual, 9);
        }
        other => panic!("expected MeterFrameLength, got {other:?}"),
    }
}

#[test]
fn decodes_channel_v2_family() {
    // 11 words: input L/R, output L/R, gate key/gain/led, dyn key/gain/state, automix gain.
    let words: [i16; 11] = [1, 2, 3, 4, 5, 6, 1, 7, 8, 0, 9];
    let entries = decode_frame(&[Meter::Channel2(1)], &words).unwrap();
    assert_eq!(
        entries[0],
        MeterFrameEntry::Channel2(ChannelMeterV2 {
            input_l: 1,
            input_r: 2,
            output_l: 3,
            output_r: 4,
            gate_key: 5,
            gate_gain: 6,
            gate_led: 1,
            dyn_key: 7,
            dyn_gain: 8,
            dyn_state: 0,
            automix_gain: 9,
        })
    );
}

#[test]
fn decodes_dca_source_output_and_monitor_families() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&[1, 2, 3, 4]); // dca
    raw.extend_from_slice(&[10, 20, 30, 40, 50, 60, 70, 80]); // source
    raw.extend_from_slice(&[11, 21, 31, 41, 51, 61, 71, 81]); // output
    raw.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // monitor

    let entries = decode_frame(
        &[
            Meter::Dca(1),
            Meter::Source(1),
            Meter::Output(1),
            Meter::Monitor,
        ],
        &raw,
    )
    .unwrap();

    match &entries[0] {
        MeterFrameEntry::Dca(dca) => {
            assert_eq!(dca.pre_fader_l, 1);
            assert_eq!(dca.pre_fader_r, 2);
            assert_eq!(dca.post_fader_l, 3);
            assert_eq!(dca.post_fader_r, 4);
        }
        other => panic!("expected Dca, got {other:?}"),
    }
    assert_eq!(
        entries[1],
        MeterFrameEntry::Source([10, 20, 30, 40, 50, 60, 70, 80])
    );
    assert_eq!(
        entries[2],
        MeterFrameEntry::Output([11, 21, 31, 41, 51, 61, 71, 81])
    );
    match &entries[3] {
        MeterFrameEntry::Monitor(m) => {
            assert_eq!(m.solo_l, 1);
            assert_eq!(m.mon2_r, 6);
        }
        other => panic!("expected Monitor, got {other:?}"),
    }
}

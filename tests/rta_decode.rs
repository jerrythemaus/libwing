//! RTA meter decode coverage (U9, R5).
//!
//! **Provenance:** the 120-slot count and 1/256 dB level scaling are *spec-derived* (WING Remote
//! Protocols V3.1-03, pages 98-99, 122-124); bin -> Hz mapping is spec-silent (not documented at
//! all) and hardware verification of all of it is pending — see `libwing::meters` module docs.

use libwing::{decode_frame, level_db, Error, Meter, MeterFrameEntry};

const RTA_BINS: usize = 120;

#[test]
fn decodes_120_bins_with_expected_db_values() {
    // -256 -> -1.0 dB per the spec's 1/256 dB scaling; use a distinct value per bin so
    // ordering (not just count) is checked.
    let raw: Vec<i16> = (0..RTA_BINS as i16).map(|i| -256 - i).collect();
    let entries = decode_frame(&[Meter::Rta], &raw).unwrap();
    assert_eq!(entries.len(), 1);
    match &entries[0] {
        MeterFrameEntry::Rta(bins) => {
            assert_eq!(bins.len(), RTA_BINS);
            assert_eq!(bins, &raw);
            assert_eq!(level_db(bins[0]), -1.0);
            assert_eq!(level_db(bins[1]), -1.00390625); // -257 / 256
        }
        other => panic!("expected Rta, got {other:?}"),
    }
}

#[test]
fn mixed_rta_and_channel_request_decodes_each_at_its_offset() {
    let mut raw = Vec::new();
    let rta_frame = vec![-256i16; RTA_BINS]; // uniform -1.0 dB
    raw.extend_from_slice(&rta_frame);
    raw.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // channel 1

    let entries = decode_frame(&[Meter::Rta, Meter::Channel(1)], &raw).unwrap();
    assert_eq!(entries.len(), 2);
    match &entries[0] {
        MeterFrameEntry::Rta(bins) => {
            assert_eq!(bins.len(), RTA_BINS);
            assert!(bins.iter().all(|&b| level_db(b) == -1.0));
        }
        other => panic!("expected Rta, got {other:?}"),
    }
    match &entries[1] {
        MeterFrameEntry::Channel(ch) => assert_eq!(ch.input_l, 1),
        other => panic!("expected Channel, got {other:?}"),
    }
}

#[test]
fn short_rta_frame_is_a_typed_length_error() {
    let raw = vec![0i16; RTA_BINS - 1];
    let err = decode_frame(&[Meter::Rta], &raw).unwrap_err();
    match err {
        Error::MeterFrameLength { expected, actual } => {
            assert_eq!(expected, RTA_BINS);
            assert_eq!(actual, RTA_BINS - 1);
        }
        other => panic!("expected MeterFrameLength, got {other:?}"),
    }
}

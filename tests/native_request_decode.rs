use libwing::native::{
    NativeLimits, NativeRequest, NativeRequestDecoder, NativeValue, PathElement,
};
use libwing::{Error, Meter};

fn framed(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0xdf, 0xd0 + channel];
    for &byte in payload {
        wire.push(byte);
        if byte == 0xdf {
            wire.push(0xde);
        }
    }
    wire
}

#[test]
fn decodes_fragmented_and_coalesced_audio_requests() {
    let mut wire = framed(1, &[0xd7, 0, 0, 0, 42, 0xdc]);
    wire.extend(framed(1, &[0xd7, 0, 0, 0, 7, 0xd5, 0x3f, 0x80, 0, 0]));
    wire.extend(framed(1, &[0xd7, 0, 0, 0, 8, 0xd8]));
    wire.extend(framed(1, &[0xd7, 0, 0, 0, 9, 0xd9, 0xff]));

    let mut decoder = NativeRequestDecoder::default();
    let mut requests = Vec::new();
    for chunk in wire.chunks(3) {
        requests.extend(decoder.push(chunk).unwrap());
    }
    decoder.finish().unwrap();

    assert!(matches!(
        requests[0],
        NativeRequest::KeepAlive { channel: 1 }
    ));
    assert_eq!(requests[1], NativeRequest::Get { id: 42 });
    assert_eq!(
        requests[3],
        NativeRequest::Set {
            id: 7,
            value: NativeValue::Float(1.0),
        }
    );
    assert_eq!(requests[5], NativeRequest::Toggle { id: 8 });
    assert_eq!(requests[7], NativeRequest::Step { id: 9, amount: -1 });
}

#[test]
fn decodes_strings_bulk_navigation_unknown_ops_and_escaped_values() {
    let mut decoder = NativeRequestDecoder::default();
    let mut wire = framed(
        1,
        &[
            0xd7, 0, 0, 0, 1, 0x82, b'a', 0xdf, 0xbf, // three-byte string
            0xda, 0xc1, b'c', b'h', 0x40, 0xdc, // /ch/1 subtree data
            0xea, // future operation
        ],
    );
    // `framed` escaped the literal 0xdf in the UTF-8 string.
    let requests = decoder.push(&wire).unwrap();
    decoder.finish().unwrap();

    assert_eq!(
        requests[1],
        NativeRequest::Set {
            id: 1,
            value: NativeValue::String("a\u{7ff}".to_owned()),
        }
    );
    assert_eq!(
        requests[2],
        NativeRequest::BulkData {
            path: vec![PathElement::Name("ch".to_owned()), PathElement::Index(1)],
        }
    );
    assert_eq!(
        requests[3],
        NativeRequest::Unknown {
            channel: 1,
            opcode: 0xea,
        }
    );

    // Keep the binding mutable in this golden: callers commonly reuse it after finish.
    wire.clear();
}

#[test]
fn decodes_meter_subscription_and_renewal() {
    let mut decoder = NativeRequestDecoder::default();
    let mut wire = framed(3, &[0xd3, 0x37, 0x37]);
    wire.extend(framed(
        3,
        &[0xd4, 0, 0, 0, 2, 0xdc, 0xa0, 0, 1, 8, 0xaa, 0xde],
    ));
    wire.extend(framed(3, &[0xd4, 0, 0, 0, 2]));

    let mut requests = decoder.push(&wire).unwrap();
    requests.extend(decoder.flush().unwrap());
    decoder.finish().unwrap();

    assert_eq!(
        requests[3],
        NativeRequest::MeterSubscribe {
            port: 0x3737,
            report_id: 2,
            meters: vec![
                Meter::Channel(1),
                Meter::Channel(2),
                Meter::Channel(9),
                Meter::Rta,
            ],
        }
    );
    assert_eq!(requests[5], NativeRequest::MeterRenew { report_id: 2 });
}

#[test]
fn rejects_limits_truncation_and_recovers_after_reset() {
    let limits = NativeLimits {
        max_buffered_bytes: 16,
        max_string_bytes: 2,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);

    let err = decoder
        .push(&framed(1, &[0xd7, 0, 0, 0, 1, 0x82, b'a', b'b', b'c']))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidData));

    decoder.reset();
    let requests = decoder.push(&framed(1, &[0xd7, 0, 0, 0, 2, 1])).unwrap();
    assert_eq!(
        requests.last(),
        Some(&NativeRequest::Set {
            id: 2,
            value: NativeValue::Integer(1),
        })
    );

    let mut truncated = NativeRequestDecoder::default();
    truncated
        .push(&framed(1, &[0xd7, 0, 0, 0, 1, 0xd4, 0, 0]))
        .unwrap();
    assert!(matches!(truncated.finish(), Err(Error::InvalidData)));

    let mut bad_channel = NativeRequestDecoder::default();
    assert!(matches!(
        bad_channel.push(&[0xdf, 0xef]),
        Err(Error::InvalidData)
    ));
}

#[test]
fn rejects_index_path_flood_and_recovers_after_automatic_reset() {
    let limits = NativeLimits {
        max_path_elements: 2,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);

    assert!(matches!(
        decoder.push(&framed(1, &[0xda, 0x40, 0x41, 0x42])),
        Err(Error::InvalidData)
    ));

    let requests = decoder.push(&framed(1, &[0xda, 0x40, 0xdc])).unwrap();
    assert_eq!(
        requests.last(),
        Some(&NativeRequest::BulkData {
            path: vec![PathElement::Index(1)],
        })
    );
}

#[test]
fn go_up_removes_an_index_before_appending_the_next_path_element() {
    let mut decoder = NativeRequestDecoder::default();
    let requests = decoder
        .push(&framed(
            1,
            &[
                0xda, 0xc1, b'c', b'h', 0x40, 0xdb, 0xc2, b'b', b'u', b's', 0xdc,
            ],
        ))
        .unwrap();

    assert_eq!(
        requests.last(),
        Some(&NativeRequest::BulkData {
            path: vec![
                PathElement::Name("ch".to_owned()),
                PathElement::Name("bus".to_owned()),
            ],
        })
    );
}

#[test]
fn rejects_named_path_byte_flood_and_recovers_after_automatic_reset() {
    let limits = NativeLimits {
        max_path_bytes: 2,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);

    assert!(matches!(
        decoder.push(&framed(1, &[0xda, 0xc1, b'a', b'b', 0xc0, b'c'])),
        Err(Error::InvalidData)
    ));

    let requests = decoder.push(&framed(1, &[0xda, 0xc0, b'x', 0xdc])).unwrap();
    assert_eq!(
        requests.last(),
        Some(&NativeRequest::BulkData {
            path: vec![PathElement::Name("x".to_owned())],
        })
    );
}

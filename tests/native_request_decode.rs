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

#[test]
fn rejects_batch_request_flood_and_recovers_after_automatic_reset() {
    let limits = NativeLimits {
        max_batch_requests: 2,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);

    // KeepAlive plus three Gets is four requests from one push.
    assert!(matches!(
        decoder.push(&framed(1, &[0xd7, 0, 0, 0, 1, 0xdc, 0xdc, 0xdc])),
        Err(Error::InvalidData)
    ));

    let requests = decoder.push(&framed(1, &[0xd7, 0, 0, 0, 2, 0xdc])).unwrap();
    assert_eq!(
        requests,
        vec![
            NativeRequest::KeepAlive { channel: 1 },
            NativeRequest::Get { id: 2 },
        ]
    );
}

#[test]
fn rejects_meter_entry_flood_and_recovers_after_automatic_reset() {
    let limits = NativeLimits {
        max_meter_entries: 2,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);

    assert!(matches!(
        decoder.push(&framed(
            3,
            &[0xd3, 0, 1, 0xd4, 0, 0, 0, 1, 0xdc, 0xa0, 0, 1, 2, 0xde],
        )),
        Err(Error::InvalidData)
    ));

    let requests = decoder
        .push(&framed(
            3,
            &[0xd3, 0, 1, 0xd4, 0, 0, 0, 1, 0xdc, 0xa0, 0, 1, 0xde],
        ))
        .unwrap();
    assert_eq!(
        requests.last(),
        Some(&NativeRequest::MeterSubscribe {
            port: 1,
            report_id: 1,
            meters: vec![Meter::Channel(1), Meter::Channel(2)],
        })
    );
    decoder.finish().unwrap();
}

/// Many requests of every token family, with escaped bytes in ids, values,
/// strings, and report ids.
fn mixed_stream() -> Vec<u8> {
    let mut wire = Vec::new();
    for i in 0..400u32 {
        let mut audio = vec![0xd7];
        audio.extend((0xdf00_00df ^ i).to_be_bytes());
        audio.extend([
            0xdc, 0xd4, 0xdf, 0, 0, 0xdf, 0xd5, 0x3f, 0x80, 0, 0, 0xd8, 0xd9, 0xdf,
        ]);
        audio.extend([0x82, b'a', 0xdf, 0xbf, 0xd0, 7]);
        audio.extend([0xd1, 69]);
        audio.extend([b'x'; 70]);
        audio.extend([
            0xda, 0xc1, b'c', b'h', 0xd2, 0, i as u8, 0xdd, 0xdb, 0xdc, 0xea,
        ]);
        wire.extend(framed(1, &audio));
        wire.extend(framed(
            3,
            &[
                0xd3, 0x37, 0xdf, 0xd4, 0, 0, 0, i as u8, 0xdc, 0xa0, 0, 1, 0xa9, 0xde, 0xd4, 0, 0,
                0xdf, 1,
            ],
        ));
    }
    // A channel select resolves the trailing meter renewal.
    wire.extend(framed(1, &[0xda, 0xdc]));
    wire
}

fn decode_in_chunks(wire: &[u8], mut next_len: impl FnMut() -> usize) -> Vec<NativeRequest> {
    let limits = NativeLimits {
        max_batch_requests: usize::MAX,
        ..NativeLimits::default()
    };
    let mut decoder = NativeRequestDecoder::new(limits);
    let mut requests = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(next_len().min(rest.len()));
        requests.extend(decoder.push(chunk).unwrap());
        rest = tail;
    }
    decoder.finish().unwrap();
    requests
}

#[test]
fn decodes_a_large_stream_identically_whole_bytewise_and_in_random_chunks() {
    let wire = mixed_stream();
    let whole = decode_in_chunks(&wire, || usize::MAX);
    assert_eq!(
        whole
            .iter()
            .filter(|request| matches!(request, NativeRequest::MeterRenew { report_id: 0xdf01 }))
            .count(),
        400
    );
    assert!(whole.contains(&NativeRequest::Set {
        id: 0xdf00_00df_u32 as i32,
        value: NativeValue::String("a\u{7ff}".to_owned()),
    }));

    assert_eq!(decode_in_chunks(&wire, || 1), whole);
    let mut seed = 0x2545_f491_u32;
    let random = decode_in_chunks(&wire, || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (seed >> 24) as usize % 97 + 1
    });
    assert_eq!(random, whole);
}

//! OSC subscription + robustness conformance suite (U11: R4, R6, R75).
//!
//! Everything here is offline: a loopback UDP socket stands in for the console, driven
//! by a small thread that plays a scripted fault (duplicate/out-of-order/lost
//! datagrams) rather than a real WING. See `tests/osc_encode.rs` for the basic
//! encode/decode and golden-vector suite this one builds on.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use libwing::osc::{
    self, decode, encode, node_set_local, OscArg, OscError, OscEvent, OscMessage, OscNodeError,
    ParamFacets, RequestPolicy, SubscriptionFormat, WingOscClient, MAX_PACKET_BYTES,
};
use libwing::{transport_availability, Operation, TransportAvailability};

// ---------------------------------------------------------------------------
// R75: duplicate replies
// ---------------------------------------------------------------------------

#[test]
fn duplicate_reply_does_not_corrupt_next_request() {
    // Fake console: for every request it receives, sends the same reply twice
    // back-to-back. `request()` must return once per call, and the leftover
    // duplicate from the first call must not leak into the second call's result.
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let responder = std::thread::spawn(move || {
        for expected_value in [-1.0f32, -2.0f32] {
            let mut buf = [0u8; 1024];
            let (n, from) = console_sock.recv_from(&mut buf).unwrap();
            let request = decode(&buf[..n]).unwrap();
            assert_eq!(request.addr, "/ch/1/fdr");

            let reply = OscMessage::new(
                "/ch/1/fdr",
                vec![
                    OscArg::Str(format!("{expected_value}")),
                    OscArg::Float(0.5),
                    OscArg::Float(expected_value),
                ],
            );
            let bytes = encode(&reply).unwrap();
            // Send the exact same reply datagram twice.
            console_sock.send_to(&bytes, from).unwrap();
            console_sock.send_to(&bytes, from).unwrap();
        }
    });

    let get_fdr = osc::get_param("/ch/1/fdr").unwrap();

    let first = client.request(&get_fdr, Duration::from_secs(2)).unwrap();
    match osc::parse_param_reply(&first).unwrap().facets {
        ParamFacets::Float { value, .. } => assert_eq!(value, -1.0),
        other => panic!("expected Float facets, got {other:?}"),
    }

    // The duplicate from the first exchange must have been drained, not left to
    // answer this second, unrelated request.
    let second = client.request(&get_fdr, Duration::from_secs(2)).unwrap();
    match osc::parse_param_reply(&second).unwrap().facets {
        ParamFacets::Float { value, .. } => assert_eq!(value, -2.0),
        other => panic!("expected Float facets, got {other:?}"),
    }

    // No stray duplicate should have ended up misclassified as unsolicited traffic.
    assert!(client.take_unsolicited().is_empty());

    responder.join().unwrap();
}

// ---------------------------------------------------------------------------
// R75: out-of-order replies
// ---------------------------------------------------------------------------

#[test]
fn out_of_order_reply_buffers_unsolicited_and_still_returns_the_match() {
    // Fake console: sends an unrelated event first, then the actual reply.
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let (n, from) = console_sock.recv_from(&mut buf).unwrap();
        let request = decode(&buf[..n]).unwrap();
        assert_eq!(request.addr, "/ch/1/fdr");

        // Unrelated interleaved traffic (e.g. another node's unsolicited value).
        let unrelated = OscMessage::new("/ch/2/mute", vec![OscArg::Int(1)]);
        console_sock
            .send_to(&encode(&unrelated).unwrap(), from)
            .unwrap();

        let reply = OscMessage::new(
            "/ch/1/fdr",
            vec![
                OscArg::Str("-3.0".to_string()),
                OscArg::Float(0.4),
                OscArg::Float(-3.0),
            ],
        );
        console_sock
            .send_to(&encode(&reply).unwrap(), from)
            .unwrap();
    });

    let reply = client
        .request(
            &osc::get_param("/ch/1/fdr").unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
    match osc::parse_param_reply(&reply).unwrap().facets {
        ParamFacets::Float { value, .. } => assert_eq!(value, -3.0),
        other => panic!("expected Float facets, got {other:?}"),
    }

    // The unrelated message arrived first on the wire but must be exposed (in arrival
    // order), not dropped.
    let unsolicited = client.take_unsolicited();
    assert_eq!(unsolicited.len(), 1);
    assert_eq!(unsolicited[0].addr, "/ch/2/mute");

    responder.join().unwrap();
}

// ---------------------------------------------------------------------------
// R75: lost request/reply + retry policy
// ---------------------------------------------------------------------------

#[test]
fn lost_reply_succeeds_after_retry() {
    // Fake console: ignores the first request entirely, answers the second.
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        // Drop the first datagram on the floor.
        let (_n, _from) = console_sock.recv_from(&mut buf).unwrap();
        // Answer the retry.
        let (n, from) = console_sock.recv_from(&mut buf).unwrap();
        let request = decode(&buf[..n]).unwrap();
        assert_eq!(request.addr, "/ch/1/fdr");
        let reply = OscMessage::new(
            "/ch/1/fdr",
            vec![
                OscArg::Str("-4.0".to_string()),
                OscArg::Float(0.3),
                OscArg::Float(-4.0),
            ],
        );
        console_sock
            .send_to(&encode(&reply).unwrap(), from)
            .unwrap();
    });

    let policy = RequestPolicy {
        attempts: 3,
        timeout_per_attempt: Duration::from_millis(300),
    };
    let started = Instant::now();
    let reply = client
        .request_with_policy(&osc::get_param("/ch/1/fdr").unwrap(), policy)
        .unwrap();
    // At least one full per-attempt timeout must have elapsed for the retry to have
    // been sent at all.
    assert!(started.elapsed() >= Duration::from_millis(300));
    match osc::parse_param_reply(&reply).unwrap().facets {
        ParamFacets::Float { value, .. } => assert_eq!(value, -4.0),
        other => panic!("expected Float facets, got {other:?}"),
    }

    responder.join().unwrap();
}

#[test]
fn every_attempt_lost_returns_typed_retries_exhausted_error() {
    // Fake console: never answers at all.
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let policy = RequestPolicy {
        attempts: 3,
        timeout_per_attempt: Duration::from_millis(100),
    };
    let started = Instant::now();
    let err = client
        .request_with_policy(&osc::get_param("/ch/1/fdr").unwrap(), policy)
        .unwrap_err();
    let elapsed = started.elapsed();

    match err {
        OscError::RetriesExhausted { attempts } => assert_eq!(attempts, 3),
        other => panic!("expected RetriesExhausted, got {other:?}"),
    }
    // Roughly attempts * timeout_per_attempt (300ms), generously bounded.
    assert!(elapsed >= Duration::from_millis(300));
    assert!(elapsed < Duration::from_secs(2));

    // console_sock is dropped here without ever responding.
    drop(console_sock);
}

// ---------------------------------------------------------------------------
// R4: subscriptions
// ---------------------------------------------------------------------------

#[test]
fn subscribe_message_bytes_are_exact() {
    // Page 30: "/*b~", "/*s~", "/*S~" -- bare 4-byte addresses, same compact shape as
    // any other zero-argument GET.
    let cases = [
        (SubscriptionFormat::Binary, "/*b"),
        (SubscriptionFormat::OscTriplet, "/*s"),
        (SubscriptionFormat::OscNative, "/*S"),
    ];
    for (format, addr) in cases {
        let msg = osc::subscribe(format);
        assert_eq!(msg.addr, addr);
        assert!(msg.args.is_empty());
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(decode(&bytes).unwrap(), msg);
    }
}

#[test]
fn poll_event_classifies_triplet_binary_and_raw_traffic() {
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        // The subscribe message itself.
        let (n, from) = console_sock.recv_from(&mut buf).unwrap();
        let sub = decode(&buf[..n]).unwrap();
        assert_eq!(sub.addr, "/*s");

        // A /*s triplet event.
        let triplet = OscMessage::new(
            "/ch/1/fdr",
            vec![
                OscArg::Str("-1.0".to_string()),
                OscArg::Float(0.5),
                OscArg::Float(-1.0),
            ],
        );
        console_sock
            .send_to(&encode(&triplet).unwrap(), from)
            .unwrap();

        // A /*b-shaped binary event: address "/", single blob arg.
        let binary = OscMessage::new("/", vec![OscArg::Blob(vec![1, 2, 3, 4])]);
        console_sock
            .send_to(&encode(&binary).unwrap(), from)
            .unwrap();

        // Something unrecognized (e.g. a stray node ack) -- must surface as Raw, not
        // be dropped.
        let ack = OscMessage::new("/*", vec![OscArg::Str("OK".to_string())]);
        console_sock.send_to(&encode(&ack).unwrap(), from).unwrap();
    });

    client.subscribe(SubscriptionFormat::OscTriplet).unwrap();

    match client.poll_event(Duration::from_secs(2)).unwrap() {
        OscEvent::Param(reply) => {
            assert_eq!(reply.path, "/ch/1/fdr");
            match reply.facets {
                ParamFacets::Float { value, .. } => assert_eq!(value, -1.0),
                other => panic!("expected Float facets, got {other:?}"),
            }
        }
        other => panic!("expected Param event, got {other:?}"),
    }

    match client.poll_event(Duration::from_secs(2)).unwrap() {
        OscEvent::Binary(data) => assert_eq!(data, vec![1, 2, 3, 4]),
        other => panic!("expected Binary event, got {other:?}"),
    }

    match client.poll_event(Duration::from_secs(2)).unwrap() {
        OscEvent::Raw(msg) => assert_eq!(msg.addr, "/*"),
        other => panic!("expected Raw event, got {other:?}"),
    }

    responder.join().unwrap();
}

#[test]
fn poll_event_classifies_native_single_tag_events() {
    // /*S events: bare ",f"/",i" -- no display/raw facet.
    let float_event = OscMessage::new("/ch/1/fdr", vec![OscArg::Float(-6.0)]);
    match osc::parse_param_reply(&float_event).unwrap().facets {
        ParamFacets::NativeFloat(v) => assert_eq!(v, -6.0),
        other => panic!("expected NativeFloat, got {other:?}"),
    }

    let int_event = OscMessage::new("/ch/1/mute", vec![OscArg::Int(1)]);
    match osc::parse_param_reply(&int_event).unwrap().facets {
        ParamFacets::NativeInt(v) => assert_eq!(v, 1),
        other => panic!("expected NativeInt, got {other:?}"),
    }
}

#[test]
fn poll_event_requires_an_active_subscription() {
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let err = client.poll_event(Duration::from_millis(50)).unwrap_err();
    assert!(matches!(err, OscError::Malformed(_)));
}

#[test]
fn poll_event_renews_the_subscription_on_a_short_injected_cadence() {
    // Drive renewal on a short, deterministic interval (rather than the real 10s
    // expiry) and assert the subscribe message is re-sent that often while
    // `poll_event` is blocked waiting (with no events ever arriving).
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    console_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    client
        .subscribe_with_renewal(SubscriptionFormat::OscTriplet, Duration::from_millis(50))
        .unwrap();

    let mut buf = [0u8; 1024];
    let mut renewals = 0;
    let deadline = Instant::now() + Duration::from_millis(400);
    while Instant::now() < deadline && renewals < 3 {
        // poll_event will renew internally while blocked; give it a small timeout so
        // this loop can also keep receiving on the fake-console socket.
        let _ = client.poll_event(Duration::from_millis(60));
        if let Ok((n, _from)) = console_sock.recv_from(&mut buf) {
            let msg = decode(&buf[..n]).unwrap();
            assert_eq!(msg.addr, "/*s");
            renewals += 1;
        }
    }

    assert!(
        renewals >= 2,
        "expected at least 2 renewals (initial subscribe already sent separately), got {renewals}"
    );
}

// ---------------------------------------------------------------------------
// R75: local port conflict
// ---------------------------------------------------------------------------

#[test]
fn bind_reply_port_on_an_occupied_port_returns_a_typed_error() {
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();

    let target = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();

    let client = WingOscClient::connect_addr(target_addr).unwrap();
    match client.bind_reply_port(port) {
        Err(OscError::Io(_)) => {}
        Ok(_) => panic!("expected a bind conflict on an already-occupied port"),
        Err(other) => panic!("expected OscError::Io, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R75: 32KB overflow
// ---------------------------------------------------------------------------

#[test]
fn oversized_node_set_local_payload_fails_to_encode() {
    let huge_value = "x".repeat(MAX_PACKET_BYTES);
    let msg = node_set_local("/ch/1", &[("name", &huge_value)]).unwrap();
    match encode(&msg) {
        Err(OscError::TooLarge(size)) => assert!(size > MAX_PACKET_BYTES),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn buffer_overflow_ack_parses_to_its_variant() {
    let ack = OscMessage::new("/*", vec![OscArg::Str("BUFFER OVERFLOW".to_string())]);
    match osc::parse_node_ack(&ack) {
        Err(OscError::Node(OscNodeError::BufferOverflow)) => {}
        other => panic!("expected Node(BufferOverflow), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R75: wildcard-path validation
// ---------------------------------------------------------------------------

#[test]
fn get_param_rejects_wildcard_paths() {
    for bad in [
        "/ch/*/fdr",
        "/ch/?/fdr",
        "/ch/[1-2]/fdr",
        "/ch/{1,2}/fdr",
        "/ch/1 /fdr",
    ] {
        match osc::get_param(bad) {
            Err(OscError::Malformed(_)) => {}
            other => panic!("expected Malformed for {bad:?}, got {other:?}"),
        }
    }
}

#[test]
fn get_param_by_id_and_reply_port_forms_are_unaffected() {
    // These are the two deliberate non-literal address forms the spec documents; they
    // must never be rejected by the wildcard validator.
    let by_id = osc::get_param_by_id(0xf50f69f8u32 as i32);
    assert_eq!(by_id.addr, "/#f50f69f8");

    let normal = osc::get_param("/ch/1/fdr").unwrap();
    let redirected = osc::with_reply_port(23456, normal);
    assert_eq!(redirected.addr, "/%23456/ch/1/fdr");
}

// ---------------------------------------------------------------------------
// R6: transport availability map
// ---------------------------------------------------------------------------

#[test]
fn availability_map_labels_a_native_only_and_a_both_operation() {
    assert_eq!(
        transport_availability(Operation::SubscribeMeters),
        TransportAvailability::NativeOnly
    );
    assert_eq!(
        transport_availability(Operation::SetNodeValue),
        TransportAvailability::Both
    );
}

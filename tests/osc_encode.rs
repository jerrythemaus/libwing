//! OSC encode/decode conformance suite (U10: R3).
//!
//! Golden hex vectors are taken directly from
//! `references/WING_Remote_Protocols_V3.1-03.md`'s "WING OSC protocol data interface"
//! chapter (pages 19-25); each test cites the page/example it checks. Everything here
//! is offline: no hardware, no network beyond a loopback socket pair in the
//! `WingOscClient::request` round-trip test at the bottom.

use std::net::UdpSocket;
use std::time::Duration;

use libwing::osc::{
    self, decode, encode, node_set_local, node_set_root, parse_console_info, parse_node_ack,
    parse_node_dump, parse_param_reply, with_reply_port, OscArg, OscError, OscMessage,
    OscNodeError, ParamFacets, WingOscClient, MAX_PACKET_BYTES,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Basic type / padding round-trips
// ---------------------------------------------------------------------------

#[test]
fn round_trips_every_arg_type() {
    let msg = OscMessage::new(
        "/ch/1/fdr",
        vec![
            OscArg::Int(-1),
            OscArg::Float(-144.0),
            OscArg::Str("hello".to_string()),
            OscArg::Blob(vec![1, 2, 3, 4, 5]),
        ],
    );
    let bytes = encode(&msg).unwrap();
    assert_eq!(decode(&bytes).unwrap(), msg);
}

#[test]
fn round_trips_addr_len_already_multiple_of_four() {
    // "/ch/1" is 5 chars -> needs a full 4-byte pad (5 + 1 = 6 -> 8).
    // "/$ctl/user/1/1/enc/mode" is 23 chars -> 23 + 1 = 24, already a multiple of 4:
    // exactly one NUL terminator, no extra padding bytes.
    for addr in ["/ch/1", "/$ctl/user/1/1/enc/mode", "/?"] {
        let msg = OscMessage::new(addr, vec![OscArg::Int(1)]);
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(decode(&bytes).unwrap(), msg);
    }
}

#[test]
fn round_trips_empty_string_arg() {
    let msg = OscMessage::new("/ch/1/name", vec![OscArg::Str(String::new())]);
    let bytes = encode(&msg).unwrap();
    // addr "/ch/1/name" (10 chars) -> pad 12; tag ",s" -> pad 4; empty string -> pad 4.
    assert_eq!(bytes.len(), 12 + 4 + 4);
    assert_eq!(decode(&bytes).unwrap(), msg);
}

#[test]
fn round_trips_blob_padding_edge_cases() {
    // Exercise blob lengths that land on every padding remainder (0, 1, 2, 3 extra bytes).
    for len in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        let data = vec![0xABu8; len];
        let msg = OscMessage::new("/fx/1", vec![OscArg::Blob(data.clone())]);
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes.len() % 4, 0);
        match decode(&bytes).unwrap().args.as_slice() {
            [OscArg::Blob(got)] => assert_eq!(*got, data, "blob len {len}"),
            other => panic!("unexpected decode for blob len {len}: {other:?}"),
        }
    }
}

#[test]
fn decode_accepts_omitted_and_explicit_empty_type_tag() {
    // Page 20: "/?~~" (tag omitted) and "/?~~,~~~" (explicit empty tag) both mean the
    // same bare GET.
    let omitted = decode(&[0x2f, 0x3f, 0x00, 0x00]).unwrap();
    assert_eq!(omitted, OscMessage::new("/?", vec![]));

    let explicit = decode(&[0x2f, 0x3f, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(explicit, OscMessage::new("/?", vec![]));
}

#[test]
fn decode_rejects_non_slash_address() {
    // Also covers OSC bundles ("#bundle...") -- WING supports messages only (page 19).
    // Built as raw wire bytes (rather than through `encode`, which doesn't validate
    // the leading '/' -- that's a decode-time, untrusted-input concern) since bundle
    // framing isn't something this crate's builders would ever produce.
    let mut bytes = b"#bundle\0".to_vec();
    bytes.resize(bytes.len() + 8, 0); // OSC time-tag, irrelevant -- decode should bail first.
    assert!(matches!(decode(&bytes), Err(OscError::Malformed(_))));
}

#[test]
fn encode_rejects_oversized_packet() {
    let huge = OscMessage::new("/fx/1", vec![OscArg::Blob(vec![0u8; MAX_PACKET_BYTES])]);
    match encode(&huge) {
        Err(OscError::TooLarge(size)) => assert!(size > MAX_PACKET_BYTES),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Golden vectors (byte-exact against the spec's own hex dumps)
// ---------------------------------------------------------------------------

#[test]
fn golden_console_info_request() {
    // Page 20: "->W, 4 B: /?~~" == 2f3f0000
    let bytes = encode(&osc::console_info()).unwrap();
    assert_eq!(hex(&bytes), "2f3f0000");
    assert_eq!(bytes.len(), 4);
}

#[test]
fn golden_console_info_reply() {
    // Page 20: 80-byte reply hex dump.
    let wire = "2f3f00002c73000057494e472c3139322e3136382e312e37312c50474d2c6e67632d66756c6c2c4e4f5f53455249414c2c312e30372e322d34302d6731623162323932623a646576656c6f7000000000";
    let bytes: Vec<u8> = (0..wire.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), 80);

    let msg = decode(&bytes).unwrap();
    let info = parse_console_info(&msg).unwrap();
    assert_eq!(info.ip, "192.168.1.71");
    assert_eq!(info.name, "PGM");
    assert_eq!(info.model, "ngc-full");
    assert_eq!(info.serial, "NO_SERIAL");
    assert_eq!(info.firmware, "1.07.2-40-g1b1b292b:develop");
}

#[test]
fn golden_get_param_request() {
    // Page 21: "->W, 12 B: /ch/1/fdr~~~" == 2f63682f312f666472000000
    let bytes = encode(&osc::get_param("/ch/1/fdr")).unwrap();
    assert_eq!(hex(&bytes), "2f63682f312f666472000000");
    assert_eq!(bytes.len(), 12);
}

#[test]
fn golden_get_param_float_reply() {
    // Page 21: 32-byte ",sff" reply for the channel 1 fader at -oo / 0.0 / -144.0 dB.
    let wire = "2f63682f312f6664720000002c736666000000002d6f6f0000000000c3100000";
    let bytes: Vec<u8> = (0..wire.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), 32);

    let msg = decode(&bytes).unwrap();
    assert_eq!(msg.addr, "/ch/1/fdr");
    let reply = parse_param_reply(&msg).unwrap();
    match reply.facets {
        ParamFacets::Float {
            display,
            raw,
            value,
        } => {
            assert_eq!(display, "-oo");
            assert_eq!(raw, 0.0);
            assert_eq!(value, -144.0);
        }
        other => panic!("expected Float facets, got {other:?}"),
    }
}

#[test]
fn golden_toggle_request() {
    // Page 22: "->W, 20 B: /ch/1/mute~~,i~~[-1]"
    let bytes = encode(&osc::toggle("/ch/1/mute")).unwrap();
    assert_eq!(hex(&bytes), "2f63682f312f6d75746500002c690000ffffffff");
    assert_eq!(bytes.len(), 20);
}

#[test]
fn golden_enum_by_name_request() {
    // Page 23: "/$ctl/user/1/1/enc/mode ,s FX" -> 32 bytes.
    let bytes = encode(&osc::set_enum_by_name("/$ctl/user/1/1/enc/mode", "FX")).unwrap();
    assert_eq!(
        hex(&bytes),
        "2f2463746c2f757365722f312f312f656e632f6d6f6465002c73000046580000"
    );
    assert_eq!(bytes.len(), 32);
}

#[test]
fn golden_enum_by_index_request() {
    // Page 23: "/$ctl/user/1/1/enc/mode ,i 6" -> 32 bytes.
    let bytes = encode(&osc::set_enum_by_index("/$ctl/user/1/1/enc/mode", 6)).unwrap();
    assert_eq!(
        hex(&bytes),
        "2f2463746c2f757365722f312f312f656e632f6d6f6465002c69000000000006"
    );
    assert_eq!(bytes.len(), 32);
}

#[test]
fn golden_bulk_node_set_root() {
    // Page 23: "->W, 44 B: /~~~,s~~/ch.1.fdr=-1,mute=0,.2.fdr=0,mute=1~"
    let msg = node_set_root("/ch.1.fdr=-1,mute=0,.2.fdr=0,mute=1");
    let bytes = encode(&msg).unwrap();
    assert_eq!(bytes.len(), 44);
    assert_eq!(
        hex(&bytes),
        "2f0000002c7300002f63682e312e6664723d2d312c6d7574653d302c2e322e6664723d302c6d7574653d3100"
    );
    assert_eq!(decode(&bytes).unwrap(), msg);
}

#[test]
fn golden_node_local_set() {
    // Page 24: "->W, 20 B: /ch/1~~~,s~~fdr=3~~~"
    let msg = node_set_local("/ch/1", &[("fdr", "3")]);
    let bytes = encode(&msg).unwrap();
    assert_eq!(bytes.len(), 20);
    assert_eq!(hex(&bytes), "2f63682f310000002c7300006664723d33000000");

    // Page 24: "->W, 28 B: /ch/1~~~,s~~fdr=4,mute=1~~~~"
    let msg2 = node_set_local("/ch/1", &[("fdr", "4"), ("mute", "1")]);
    let bytes2 = encode(&msg2).unwrap();
    assert_eq!(bytes2.len(), 28);
}

#[test]
fn golden_node_dump_parse() {
    // Page 25: "/fx/1 ,s *" -> "/fx/1~~~,s~~mdl=NONE,fxmix=100,~" (32 bytes).
    let bytes = encode(&osc::node_dump("/fx/1")).unwrap();
    assert_eq!(bytes.len(), 16);

    let wire = "2f66782f310000002c7300006d646c3d4e4f4e452c66786d69783d3130302c00";
    let reply_bytes: Vec<u8> = (0..wire.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(reply_bytes.len(), 32);

    let reply = decode(&reply_bytes).unwrap();
    let pairs = parse_node_dump(&reply).unwrap();
    assert_eq!(
        pairs,
        vec![
            ("mdl".to_string(), "NONE".to_string()),
            ("fxmix".to_string(), "100".to_string()),
        ]
    );
}

#[test]
fn golden_reply_port_prefix() {
    // Page 21: "->W, 20 B: /%10027/ch/1/mute~~~"
    let bytes = encode(&with_reply_port(10027, osc::get_param("/ch/1/mute"))).unwrap();
    assert_eq!(bytes.len(), 20);
    assert_eq!(hex(&bytes), "2f2531303032372f63682f312f6d757465000000");
}

// ---------------------------------------------------------------------------
// Node ack parsing
// ---------------------------------------------------------------------------

fn ack_message(addr: &str, payload: &str) -> OscMessage {
    OscMessage::new(addr, vec![OscArg::Str(payload.to_string())])
}

#[test]
fn parses_root_ack_ok() {
    assert!(parse_node_ack(&ack_message("/*", "OK")).is_ok());
}

#[test]
fn parses_node_local_ack_address() {
    assert!(parse_node_ack(&ack_message("/ch/1*", "OK")).is_ok());
}

#[test]
fn parses_every_documented_node_error() {
    let cases = [
        ("NODE NOT FOUND", OscNodeError::NodeNotFound),
        ("VALUE ERROR", OscNodeError::ValueError),
        ("BUFFER OVERFLOW", OscNodeError::BufferOverflow),
        ("NODE IS NOT PAR", OscNodeError::NodeIsNotPar),
        ("INCOMPLETE DATA", OscNodeError::IncompleteData),
        ("STACK EMPTY", OscNodeError::StackEmpty),
    ];
    for (wire, expected) in cases {
        match parse_node_ack(&ack_message("/*", wire)) {
            Err(OscError::Node(got)) => assert_eq!(got, expected, "for {wire:?}"),
            other => panic!("expected Node({expected:?}) for {wire:?}, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// WingOscClient: loopback round-trip
// ---------------------------------------------------------------------------

#[test]
fn client_request_round_trips_over_loopback() {
    // Bind a "console" socket that echoes back a canned /ch/1/fdr reply whenever it
    // receives anything, then drive it through `WingOscClient::request`. Uses
    // `connect_addr` rather than `connect` since the test can't bind the real
    // well-known OSC port (2223).
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let (n, from) = console_sock.recv_from(&mut buf).unwrap();
        let request = decode(&buf[..n]).unwrap();
        assert_eq!(request.addr, "/ch/1/fdr");

        let reply = OscMessage::new(
            "/ch/1/fdr",
            vec![
                OscArg::Str("-1.0".to_string()),
                OscArg::Float(0.725),
                OscArg::Float(-1.0),
            ],
        );
        let bytes = encode(&reply).unwrap();
        console_sock.send_to(&bytes, from).unwrap();
    });

    let reply = client
        .request(&osc::get_param("/ch/1/fdr"), Duration::from_secs(2))
        .unwrap();
    let parsed = parse_param_reply(&reply).unwrap();
    match parsed.facets {
        ParamFacets::Float { value, .. } => assert_eq!(value, -1.0),
        other => panic!("expected Float facets, got {other:?}"),
    }

    responder.join().unwrap();
}

#[test]
fn client_request_times_out_without_a_reply() {
    let console_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let console_addr = console_sock.local_addr().unwrap();
    let client = WingOscClient::connect_addr(console_addr).unwrap();

    let err = client
        .request(&osc::get_param("/ch/1/fdr"), Duration::from_millis(200))
        .unwrap_err();
    assert!(matches!(err, OscError::Timeout));
}

use libwing::native::{encode_responses, BoundedResponseEncoder, NativeResponse, NativeValue};
use libwing::{FloatEnumItem, NodeType, NodeUnit, StringEnumItem, WingNodeDef};

fn deframe(wire: &[u8]) -> Vec<u8> {
    assert_eq!(&wire[..2], &[0xdf, 0xd1]);
    let mut payload = Vec::new();
    let mut i = 2;
    while i < wire.len() {
        let byte = wire[i];
        i += 1;
        if byte == 0xdf {
            assert_eq!(wire.get(i), Some(&0xde));
            i += 1;
        }
        payload.push(byte);
    }
    payload
}

fn integer_def() -> WingNodeDef {
    WingNodeDef {
        id: 0x0000_00df,
        parent_id: 4,
        index: 2,
        name: "gain".to_owned(),
        long_name: "Gain".to_owned(),
        node_type: NodeType::Integer,
        unit: NodeUnit::Db,
        read_only: false,
        min_float: None,
        max_float: None,
        steps: None,
        min_int: Some(-100),
        max_int: Some(10),
        max_string_len: None,
        string_enum: None,
        float_enum: None,
        raw: Vec::new(),
    }
}

#[test]
fn encodes_literal_node_values_and_completion() {
    let responses = [
        NativeResponse::NodeData {
            id: 0xdf,
            value: NativeValue::Integer(-8448),
        },
        NativeResponse::NodeData {
            id: 2,
            value: NativeValue::Float(f32::from_bits(0xdf00_0001)),
        },
        NativeResponse::NodeData {
            id: 3,
            value: NativeValue::String("".to_owned()),
        },
        NativeResponse::RequestEnd,
    ];

    let wire = encode_responses(&responses).unwrap();
    let mut expected = vec![
        0xd7, 0, 0, 0, 0xdf, 0xd3, 0xdf, 0, // integer and escaped-value boundaries
        0xd7, 0, 0, 0, 2, 0xd5, 0xdf, 0, 0, 1, // float
        0xd7, 0, 0, 0, 3, 0xd0, // empty string
        0xde,
    ];
    assert_eq!(deframe(&wire), expected);
    expected.clear();
}

#[test]
fn bounded_encoder_rejects_the_response_that_crosses_the_wire_limit() {
    let first = NativeResponse::NodeData {
        id: 0xdf,
        value: NativeValue::Integer(1),
    };
    let first_wire = encode_responses(std::slice::from_ref(&first)).unwrap();
    let mut encoder = BoundedResponseEncoder::new(first_wire.len());

    encoder.push(&first).unwrap();
    assert!(encoder.push(&NativeResponse::RequestEnd).is_err());
    assert_eq!(encoder.finish().unwrap(), first_wire);
}

#[test]
fn serializes_node_definition_from_metadata_and_round_trips() {
    let def = integer_def();
    let body = def.to_wire_bytes().unwrap();
    assert_eq!(
        body,
        [
            0, 0, 0, 4, 0, 0, 0, 0xdf, 0, 2, 4, b'g', b'a', b'i', b'n', 4, b'G', b'a', b'i', b'n',
            0, 0x41, 0xff, 0xff, 0xff, 0x9c, 0, 0, 0, 10,
        ]
    );

    let parsed = WingNodeDef::try_from_bytes(&body).unwrap();
    assert_eq!(parsed.id, def.id);
    assert_eq!(parsed.node_type, NodeType::Integer);
    assert_eq!(parsed.unit, NodeUnit::Db);
    assert_eq!(parsed.min_int, Some(-100));
    assert_eq!(parsed.max_int, Some(10));

    let wire = encode_responses(&[NativeResponse::NodeDef(def)]).unwrap();
    let payload = deframe(&wire);
    assert_eq!(payload[0], 0xdf);
    assert_eq!(
        u16::from_be_bytes([payload[1], payload[2]]) as usize,
        body.len()
    );
    assert_eq!(&payload[3..], body);
}

#[test]
fn round_trips_string_and_float_enum_families() {
    let mut def = integer_def();
    def.node_type = NodeType::StringEnum;
    def.min_int = None;
    def.max_int = None;
    def.string_enum = Some(vec![StringEnumItem {
        item: "ON".to_owned(),
        long_item: "Enabled".to_owned(),
    }]);
    let parsed = WingNodeDef::try_from_bytes(&def.to_wire_bytes().unwrap()).unwrap();
    assert_eq!(parsed.string_enum.unwrap()[0].long_item, "Enabled");

    def.node_type = NodeType::FloatEnum;
    def.string_enum = None;
    def.float_enum = Some(vec![FloatEnumItem {
        item: 0.5,
        long_item: "Half".to_owned(),
    }]);
    let parsed = WingNodeDef::try_from_bytes(&def.to_wire_bytes().unwrap()).unwrap();
    assert_eq!(parsed.float_enum.unwrap()[0].item, 0.5);
}

#[test]
fn rejects_incomplete_metadata_instead_of_guessing() {
    let mut def = integer_def();
    def.max_int = None;
    assert!(matches!(
        def.to_wire_bytes(),
        Err(libwing::Error::InvalidInput)
    ));
}

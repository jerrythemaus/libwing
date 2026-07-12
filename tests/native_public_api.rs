use libwing::native::{ChannelDecoder, ChannelEvent, NativeRequestDecoder};

#[test]
fn direction_neutral_codec_is_public_and_propmap_independent() {
    let mut channels = ChannelDecoder::default();
    assert_eq!(
        channels.push(&[0xdf, 0xd1, 0xdf, 0xde]).unwrap(),
        vec![ChannelEvent::Selected(1), ChannelEvent::Data(1, 0xdf)]
    );
    channels.finish().unwrap();

    let _: NativeRequestDecoder = Default::default();
}

#[cfg(feature = "propmap")]
#[test]
fn public_propmap_iterator_exposes_generator_input() {
    let entries: Vec<_> = libwing::WingConsole::propmap_iter().take(2).collect();
    assert!(!entries.is_empty());
    assert!(entries
        .iter()
        .all(|(name, def)| !name.is_empty() && def.id != 0));
}

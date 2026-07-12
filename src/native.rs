//! Direction-neutral primitives for the WING Native TCP protocol.
//!
//! This module owns only byte framing, bounded request decoding, and response
//! encoding. Console state, request ordering, networking, clocks, and server
//! lifecycle deliberately belong to the caller.

use crate::{Error, Meter, NodeType, Result, WingNodeDef};

const ESCAPE: u8 = 0xdf;
const ESCAPED_ESCAPE: u8 = 0xde;
const CHANNEL_BASE: u8 = 0xd0;
const CHANNEL_COUNT: u8 = 14;

/// A de-framed Native stream event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelEvent {
    /// The stream selected channel `0..=13`.
    Selected(u8),
    /// One logical payload byte on the selected channel.
    Data(u8, u8),
}

/// Incremental WING channel selector and escape decoder.
#[derive(Clone, Debug, Default)]
pub struct ChannelDecoder {
    escaped: bool,
    channel: Option<u8>,
}

impl ChannelDecoder {
    /// Start with an already-selected channel, useful when decoding a captured
    /// channel payload rather than a complete TCP session.
    pub fn with_channel(channel: u8) -> Result<Self> {
        if channel >= CHANNEL_COUNT {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            escaped: false,
            channel: Some(channel),
        })
    }

    /// Consume an arbitrary fragment and return every complete logical event.
    pub fn push(&mut self, input: &[u8]) -> Result<Vec<ChannelEvent>> {
        let mut events = Vec::with_capacity(input.len());
        for &byte in input {
            if !self.escaped {
                if byte == ESCAPE {
                    self.escaped = true;
                } else {
                    let channel = self.channel.ok_or(Error::InvalidData)?;
                    events.push(ChannelEvent::Data(channel, byte));
                }
                continue;
            }

            self.escaped = false;
            match byte {
                ESCAPED_ESCAPE | ESCAPE => {
                    let channel = self.channel.ok_or(Error::InvalidData)?;
                    events.push(ChannelEvent::Data(channel, ESCAPE));
                }
                CHANNEL_BASE..=0xdd => {
                    let channel = byte - CHANNEL_BASE;
                    self.channel = Some(channel);
                    events.push(ChannelEvent::Selected(channel));
                }
                // A raw protocol token 0xdf followed by a non-channel byte is
                // legal. Preserve both bytes rather than silently discarding one.
                other if self.channel.is_some() => {
                    let channel = self.channel.expect("checked above");
                    events.push(ChannelEvent::Data(channel, ESCAPE));
                    events.push(ChannelEvent::Data(channel, other));
                }
                _ => return Err(Error::InvalidData),
            }
        }
        Ok(events)
    }

    /// Reject a stream ending halfway through an escape/channel sequence.
    pub fn finish(&self) -> Result<()> {
        if self.escaped {
            Err(Error::InvalidData)
        } else {
            Ok(())
        }
    }

    /// Discard all framing state after a rejected or disconnected stream.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Encode one complete logical payload on `channel`.
pub fn encode_channel(channel: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if channel >= CHANNEL_COUNT {
        return Err(Error::InvalidInput);
    }
    let mut wire = Vec::with_capacity(payload.len().saturating_mul(2).saturating_add(2));
    wire.extend_from_slice(&[ESCAPE, CHANNEL_BASE + channel]);
    append_escaped(&mut wire, payload);
    Ok(wire)
}

fn append_escaped(out: &mut Vec<u8>, payload: &[u8]) {
    for &byte in payload {
        out.push(byte);
        if byte == ESCAPE {
            out.push(ESCAPED_ESCAPE);
        }
    }
}

/// Resource ceilings applied before a request is returned to a server.
#[derive(Clone, Copy, Debug)]
pub struct NativeLimits {
    pub max_buffered_bytes: usize,
    pub max_string_bytes: usize,
    pub max_path_elements: usize,
    pub max_path_bytes: usize,
    pub max_definition_bytes: usize,
    pub max_batch_requests: usize,
    pub max_meter_entries: usize,
}

impl Default for NativeLimits {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 64 * 1024,
            max_string_bytes: 256,
            max_path_elements: 256,
            max_path_bytes: 4096,
            max_definition_bytes: 1024 * 1024,
            max_batch_requests: 4096,
            max_meter_entries: 512,
        }
    }
}

/// A typed Native value, shared by request decoding and response encoding.
#[derive(Clone, Debug, PartialEq)]
pub enum NativeValue {
    Integer(i32),
    Float(f32),
    RawFloat(f32),
    String(String),
}

/// One navigation component used by subtree/bulk requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathElement {
    Name(String),
    Index(u32),
}

/// A decoded client-to-console Native operation.
///
/// `Unknown` makes the model forward-compatible: consumers must not use an
/// exhaustive match to assume today's opcode set is permanent.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum NativeRequest {
    KeepAlive {
        channel: u8,
    },
    Get {
        id: i32,
    },
    Definition {
        id: i32,
    },
    Set {
        id: i32,
        value: NativeValue,
    },
    Toggle {
        id: i32,
    },
    Step {
        id: i32,
        amount: i8,
    },
    BulkData {
        path: Vec<PathElement>,
    },
    BulkDefinition {
        path: Vec<PathElement>,
    },
    MeterPort {
        port: u16,
    },
    MeterSubscribe {
        port: u16,
        report_id: u32,
        meters: Vec<Meter>,
    },
    MeterRenew {
        report_id: u32,
    },
    Unknown {
        channel: u8,
        opcode: u8,
    },
}

/// Incremental, bounded decoder for client-to-console Native requests.
pub struct NativeRequestDecoder {
    channels: ChannelDecoder,
    limits: NativeLimits,
    audio: Vec<u8>,
    meter: Vec<u8>,
    selected_id: Option<i32>,
    path: Vec<PathElement>,
    path_bytes: usize,
    meter_port: Option<u16>,
}

impl Default for NativeRequestDecoder {
    fn default() -> Self {
        Self::new(NativeLimits::default())
    }
}

impl NativeRequestDecoder {
    pub fn new(limits: NativeLimits) -> Self {
        Self {
            channels: ChannelDecoder::default(),
            limits,
            audio: Vec::new(),
            meter: Vec::new(),
            selected_id: None,
            path: Vec::new(),
            path_bytes: 0,
            meter_port: None,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<NativeRequest>> {
        let events = match self.channels.push(input) {
            Ok(events) => events,
            Err(err) => {
                self.reset();
                return Err(err);
            }
        };
        let mut requests = Vec::new();
        for event in events {
            match event {
                ChannelEvent::Selected(channel) => {
                    requests.extend(self.flush_meter_renewal()?);
                    requests.push(NativeRequest::KeepAlive { channel });
                }
                ChannelEvent::Data(1, byte) => {
                    self.audio.push(byte);
                    self.check_buffer_limit()?;
                    while let Some(request) = self.parse_audio()? {
                        requests.push(request);
                    }
                }
                ChannelEvent::Data(3, byte) => {
                    self.meter.push(byte);
                    self.check_buffer_limit()?;
                    while let Some(request) = self.parse_meter()? {
                        requests.push(request);
                    }
                }
                ChannelEvent::Data(channel, opcode) => {
                    requests.push(NativeRequest::Unknown { channel, opcode });
                }
            }
            if requests.len() > self.limits.max_batch_requests {
                self.reset();
                return Err(Error::InvalidData);
            }
        }
        Ok(requests)
    }

    /// Resolve a standalone meter-renew command at a boundary known by the
    /// caller (for example, an idle/read boundary). Do not call this merely
    /// because one TCP read ended: the next fragment may begin a collection.
    pub fn flush(&mut self) -> Result<Vec<NativeRequest>> {
        self.flush_meter_renewal()
    }

    pub fn finish(&self) -> Result<()> {
        self.channels.finish()?;
        if self.audio.is_empty() && self.meter.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidData)
        }
    }

    pub fn reset(&mut self) {
        let limits = self.limits;
        *self = Self::new(limits);
    }

    fn check_buffer_limit(&mut self) -> Result<()> {
        if self.audio.len().saturating_add(self.meter.len()) > self.limits.max_buffered_bytes {
            self.reset();
            Err(Error::InvalidData)
        } else {
            Ok(())
        }
    }

    fn parse_audio(&mut self) -> Result<Option<NativeRequest>> {
        let Some(&opcode) = self.audio.first() else {
            return Ok(None);
        };

        if opcode == 0xd7 {
            let Some(bytes) = self.audio.get(1..5) else {
                return Ok(None);
            };
            self.selected_id = Some(i32::from_be_bytes(bytes.try_into().expect("four bytes")));
            self.audio.drain(..5);
            return self.parse_audio();
        }

        let request = match opcode {
            0x00..=0x3f => self.set_value(1, NativeValue::Integer(opcode as i32))?,
            0x40..=0x7f => {
                self.push_path_index((opcode - 0x3f) as u32)?;
                self.audio.drain(..1);
                return self.parse_audio();
            }
            0x80..=0xbf => {
                let len = (opcode - 0x7f) as usize;
                if self.audio.len() < len + 1 {
                    return Ok(None);
                }
                self.parse_string_token(len, 1)?
            }
            0xc0..=0xcf => {
                let len = (opcode - 0xbf) as usize;
                if self.audio.len() < len + 1 {
                    return Ok(None);
                }
                self.check_path_room(len)?;
                let value = String::from_utf8(self.audio[1..=len].to_vec())
                    .map_err(|_| Error::InvalidData)?;
                self.path_bytes += len;
                self.path.push(PathElement::Name(value));
                self.audio.drain(..=len);
                return self.parse_audio();
            }
            0xd0 => self.set_value(1, NativeValue::String(String::new()))?,
            0xd1 => {
                let Some(&encoded_len) = self.audio.get(1) else {
                    return Ok(None);
                };
                let len = encoded_len as usize + 1;
                if self.audio.len() < len + 2 {
                    return Ok(None);
                }
                self.parse_string_token(len, 2)?
            }
            0xd2 => {
                let Some(bytes) = self.audio.get(1..3) else {
                    return Ok(None);
                };
                self.push_path_index(
                    u16::from_be_bytes(bytes.try_into().expect("two bytes")) as u32 + 1,
                )?;
                self.audio.drain(..3);
                return self.parse_audio();
            }
            0xd3 => {
                let Some(bytes) = self.audio.get(1..3) else {
                    return Ok(None);
                };
                self.set_value(
                    3,
                    NativeValue::Integer(
                        i16::from_be_bytes(bytes.try_into().expect("two bytes")) as i32
                    ),
                )?
            }
            0xd4 => {
                let Some(bytes) = self.audio.get(1..5) else {
                    return Ok(None);
                };
                self.set_value(
                    5,
                    NativeValue::Integer(i32::from_be_bytes(bytes.try_into().expect("four bytes"))),
                )?
            }
            0xd5 | 0xd6 => {
                let Some(bytes) = self.audio.get(1..5) else {
                    return Ok(None);
                };
                let value = f32::from_be_bytes(bytes.try_into().expect("four bytes"));
                self.set_value(
                    5,
                    if opcode == 0xd5 {
                        NativeValue::Float(value)
                    } else {
                        NativeValue::RawFloat(value)
                    },
                )?
            }
            0xd8 => {
                let id = self.selected_id.ok_or(Error::InvalidData)?;
                self.audio.drain(..1);
                NativeRequest::Toggle { id }
            }
            0xd9 => {
                let Some(&amount) = self.audio.get(1) else {
                    return Ok(None);
                };
                let id = self.selected_id.ok_or(Error::InvalidData)?;
                self.audio.drain(..2);
                NativeRequest::Step {
                    id,
                    amount: amount as i8,
                }
            }
            0xda => {
                self.selected_id = None;
                self.path.clear();
                self.path_bytes = 0;
                self.audio.drain(..1);
                return self.parse_audio();
            }
            0xdb => {
                self.selected_id = None;
                if let Some(PathElement::Name(name)) = self.path.pop() {
                    self.path_bytes -= name.len();
                }
                self.audio.drain(..1);
                return self.parse_audio();
            }
            0xdc | 0xdd => {
                self.audio.drain(..1);
                if let Some(id) = self.selected_id {
                    if opcode == 0xdc {
                        NativeRequest::Get { id }
                    } else {
                        NativeRequest::Definition { id }
                    }
                } else if opcode == 0xdc {
                    NativeRequest::BulkData {
                        path: self.path.clone(),
                    }
                } else {
                    NativeRequest::BulkDefinition {
                        path: self.path.clone(),
                    }
                }
            }
            unknown => {
                self.audio.drain(..1);
                NativeRequest::Unknown {
                    channel: 1,
                    opcode: unknown,
                }
            }
        };
        Ok(Some(request))
    }

    fn push_path_index(&mut self, index: u32) -> Result<()> {
        self.check_path_room(0)?;
        self.path.push(PathElement::Index(index));
        Ok(())
    }

    fn check_path_room(&mut self, name_bytes: usize) -> Result<()> {
        let within_elements = self.path.len() < self.limits.max_path_elements;
        let within_bytes = self
            .path_bytes
            .checked_add(name_bytes)
            .is_some_and(|bytes| bytes <= self.limits.max_path_bytes);
        if within_elements && within_bytes {
            Ok(())
        } else {
            self.reset();
            Err(Error::InvalidData)
        }
    }

    fn parse_string_token(&mut self, len: usize, header: usize) -> Result<NativeRequest> {
        if len > self.limits.max_string_bytes {
            self.reset();
            return Err(Error::InvalidData);
        }
        let value = String::from_utf8(self.audio[header..header + len].to_vec())
            .map_err(|_| Error::InvalidData)?;
        self.set_value(header + len, NativeValue::String(value))
    }

    fn set_value(&mut self, used: usize, value: NativeValue) -> Result<NativeRequest> {
        let id = self.selected_id.ok_or(Error::InvalidData)?;
        self.audio.drain(..used);
        Ok(NativeRequest::Set { id, value })
    }

    fn parse_meter(&mut self) -> Result<Option<NativeRequest>> {
        let Some(&opcode) = self.meter.first() else {
            return Ok(None);
        };
        match opcode {
            0xd3 => {
                let Some(bytes) = self.meter.get(1..3) else {
                    return Ok(None);
                };
                let port = u16::from_be_bytes(bytes.try_into().expect("two bytes"));
                self.meter_port = Some(port);
                self.meter.drain(..3);
                Ok(Some(NativeRequest::MeterPort { port }))
            }
            0xd4 => {
                let Some(bytes) = self.meter.get(1..5) else {
                    return Ok(None);
                };
                let report_id = u32::from_be_bytes(bytes.try_into().expect("four bytes"));
                let Some(&next) = self.meter.get(5) else {
                    return Ok(None);
                };
                if next != 0xdc {
                    self.meter.drain(..5);
                    return Ok(Some(NativeRequest::MeterRenew { report_id }));
                }
                let Some(end) = self.meter[6..].iter().position(|&byte| byte == 0xde) else {
                    return Ok(None);
                };
                let end = end + 6;
                let meters =
                    decode_meter_entries(&self.meter[6..end], self.limits.max_meter_entries)?;
                let port = self.meter_port.ok_or(Error::InvalidData)?;
                self.meter.drain(..=end);
                Ok(Some(NativeRequest::MeterSubscribe {
                    port,
                    report_id,
                    meters,
                }))
            }
            unknown => {
                self.meter.drain(..1);
                Ok(Some(NativeRequest::Unknown {
                    channel: 3,
                    opcode: unknown,
                }))
            }
        }
    }

    fn flush_meter_renewal(&mut self) -> Result<Vec<NativeRequest>> {
        if self.meter.is_empty() {
            return Ok(Vec::new());
        }
        if self.meter.len() == 5 && self.meter[0] == 0xd4 {
            let report_id =
                u32::from_be_bytes(self.meter[1..5].try_into().expect("four report-id bytes"));
            self.meter.clear();
            return Ok(vec![NativeRequest::MeterRenew { report_id }]);
        }
        Err(Error::InvalidData)
    }
}

fn decode_meter_entries(raw: &[u8], limit: usize) -> Result<Vec<Meter>> {
    let mut meters = Vec::new();
    let mut family = None;
    for &byte in raw {
        if (0xa0..=0xaf).contains(&byte) {
            family = Some(byte);
            if matches!(byte, 0xa9 | 0xaa) {
                meters.push(if byte == 0xa9 {
                    Meter::Monitor
                } else {
                    Meter::Rta
                });
            }
        } else if byte <= 0x7f {
            let n = byte.checked_add(1).ok_or(Error::InvalidData)?;
            meters.push(match family.ok_or(Error::InvalidData)? {
                0xa0 => Meter::Channel(n),
                0xa1 => Meter::Aux(n),
                0xa2 => Meter::Bus(n),
                0xa3 => Meter::Main(n),
                0xa4 => Meter::Matrix(n),
                0xa5 => Meter::Dca(n),
                0xa6 => Meter::Fx(n),
                0xa7 => Meter::Source(n),
                0xa8 => Meter::Output(n),
                0xab => Meter::Channel2(n),
                0xac => Meter::Aux2(n),
                0xad => Meter::Bus2(n),
                0xae => Meter::Main2(n),
                0xaf => Meter::Matrix2(n),
                _ => return Err(Error::InvalidData),
            });
        } else {
            return Err(Error::InvalidData);
        }
        if meters.len() > limit {
            return Err(Error::InvalidData);
        }
    }
    Ok(meters)
}

/// A console-to-client response. This deliberately does not replace the
/// client-facing [`crate::WingResponse`] enum.
#[non_exhaustive]
#[derive(Clone)]
pub enum NativeResponse {
    RequestEnd,
    NodeDef(WingNodeDef),
    NodeData { id: i32, value: NativeValue },
    AuthoritativeEvent { id: i32, value: NativeValue },
}

/// Encode an indivisible response batch on the Audio Engine channel.
pub fn encode_responses(responses: &[NativeResponse]) -> Result<Vec<u8>> {
    encode_responses_bounded(responses.iter().cloned(), usize::MAX)
}

/// Encode an indivisible response batch while enforcing its final wire-size ceiling.
///
/// Responses are consumed incrementally so a server can stream a large state iterator into a
/// bounded batch without first materializing the complete response list. If the batch would
/// exceed `max_wire_bytes`, encoding stops and returns [`Error::InvalidInput`].
pub fn encode_responses_bounded(
    responses: impl IntoIterator<Item = NativeResponse>,
    max_wire_bytes: usize,
) -> Result<Vec<u8>> {
    let mut encoder = BoundedResponseEncoder::new(max_wire_bytes);
    for response in responses {
        encoder.push(&response)?;
    }
    encoder.finish()
}

/// Incremental form of [`encode_responses_bounded`] for state visitors and generators.
pub struct BoundedResponseEncoder {
    payload: Vec<u8>,
    max_wire_bytes: usize,
}

impl BoundedResponseEncoder {
    pub fn new(max_wire_bytes: usize) -> Self {
        Self {
            payload: Vec::new(),
            max_wire_bytes,
        }
    }

    pub fn push(&mut self, response: &NativeResponse) -> Result<()> {
        let mut encoded = Vec::new();
        match response {
            NativeResponse::RequestEnd => encoded.push(0xde),
            NativeResponse::NodeData { id, value }
            | NativeResponse::AuthoritativeEvent { id, value } => {
                encoded.push(0xd7);
                encoded.extend_from_slice(&id.to_be_bytes());
                encode_value(&mut encoded, value)?;
            }
            NativeResponse::NodeDef(def) => {
                let body = def.to_wire_bytes()?;
                if body.len() > NativeLimits::default().max_definition_bytes {
                    return Err(Error::InvalidInput);
                }
                encoded.push(0xdf);
                if let Ok(len) = u16::try_from(body.len()) {
                    encoded.extend_from_slice(&len.to_be_bytes());
                } else {
                    encoded.extend_from_slice(&0u16.to_be_bytes());
                    encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
                }
                encoded.extend_from_slice(&body);
            }
        }
        let next_wire_len =
            encoded_channel_len(&self.payload).saturating_add(escaped_len(&encoded));
        if next_wire_len > self.max_wire_bytes {
            return Err(Error::InvalidInput);
        }
        self.payload.extend_from_slice(&encoded);
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        let wire_len = encoded_channel_len(&self.payload);
        if wire_len > self.max_wire_bytes {
            return Err(Error::InvalidInput);
        }
        let mut wire = Vec::with_capacity(wire_len);
        wire.extend_from_slice(&[ESCAPE, CHANNEL_BASE + 1]);
        append_escaped(&mut wire, &self.payload);
        Ok(wire)
    }
}

fn encoded_channel_len(payload: &[u8]) -> usize {
    2usize.saturating_add(escaped_len(payload))
}

fn escaped_len(payload: &[u8]) -> usize {
    payload
        .iter()
        .map(|byte| if *byte == ESCAPE { 2 } else { 1 })
        .sum()
}

fn encode_value(payload: &mut Vec<u8>, value: &NativeValue) -> Result<()> {
    match value {
        NativeValue::Integer(value) if (0..=0x3f).contains(value) => payload.push(*value as u8),
        NativeValue::Integer(value) if i16::try_from(*value).is_ok() => {
            payload.push(0xd3);
            payload.extend_from_slice(&(*value as i16).to_be_bytes());
        }
        NativeValue::Integer(value) => {
            payload.push(0xd4);
            payload.extend_from_slice(&value.to_be_bytes());
        }
        NativeValue::Float(value) => {
            payload.push(0xd5);
            payload.extend_from_slice(&value.to_be_bytes());
        }
        NativeValue::RawFloat(value) => {
            payload.push(0xd6);
            payload.extend_from_slice(&value.to_be_bytes());
        }
        NativeValue::String(value) if value.is_empty() => payload.push(0xd0),
        NativeValue::String(value) if value.len() <= 64 => {
            payload.push(0x7f + value.len() as u8);
            payload.extend_from_slice(value.as_bytes());
        }
        NativeValue::String(value) if value.len() <= 256 => {
            payload.extend_from_slice(&[0xd1, (value.len() - 1) as u8]);
            payload.extend_from_slice(value.as_bytes());
        }
        NativeValue::String(_) => return Err(Error::InvalidInput),
    }
    Ok(())
}

/// Map a public node type to its 4-bit wire discriminant.
pub(crate) fn node_type_nibble(node_type: NodeType) -> u8 {
    match node_type {
        NodeType::Node => 0,
        NodeType::LinearFloat => 1,
        NodeType::LogarithmicFloat => 2,
        NodeType::FaderLevel => 3,
        NodeType::Integer => 4,
        NodeType::StringEnum => 5,
        NodeType::FloatEnum => 6,
        NodeType::String => 7,
        NodeType::Unknown(value) => value & 0x0f,
    }
}

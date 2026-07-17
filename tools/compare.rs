use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use libwing::native::{NativeRequest, NativeRequestDecoder};
use libwing::{Error, Transport, WingConsole, WingNodeData, WingResponse};

pub struct FidelityReport {
    pub text: String,
    pub deviations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Integer(i32),
    Float(u32),
    String(String),
}

impl Value {
    fn from_node(data: &WingNodeData) -> Self {
        if data.has_string() {
            Self::String(data.get_string())
        } else if data.has_float() {
            Self::Float(data.get_float().to_bits())
        } else {
            Self::Integer(data.get_int())
        }
    }

    fn format(&self) -> String {
        match self {
            Self::Integer(value) => value.to_string(),
            Self::Float(bits) => f32::from_bits(*bits).to_string(),
            Self::String(value) => format!("{value:?}"),
        }
    }
}

#[derive(Default)]
struct Control {
    values: BTreeMap<i32, Vec<Value>>,
    definitions: BTreeSet<i32>,
    request_ends: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MeterShape {
    report_token: bool,
    payload_bytes: usize,
}

struct MeterEvidence {
    shapes: Vec<MeterShape>,
    cardinality: MeterCardinality,
}

impl MeterShape {
    fn words(self) -> Option<usize> {
        self.payload_bytes
            .is_multiple_of(2)
            .then_some(self.payload_bytes / 2)
    }

    fn format(self) -> String {
        let token = if self.report_token {
            "present"
        } else {
            "missing"
        };
        match self.words() {
            Some(words) => format!("token={token} words={words}"),
            None => format!("token={token} payload_bytes={} (odd)", self.payload_bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeterCardinality {
    Replaces,
    Concurrent,
    Ambiguous,
}

impl MeterCardinality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replaces => "replaces",
            Self::Concurrent => "concurrent",
            Self::Ambiguous => "ambiguous",
        }
    }
}

pub fn compare_fidelity(
    hardware: &[(String, Vec<u8>)],
    emulator: &[(String, Vec<u8>)],
) -> FidelityReport {
    let hardware_control = decode_control(hardware);
    let emulator_control = decode_control(emulator);
    let hardware_requests = decode_requests(hardware, "N>");
    let emulator_requests = decode_requests(emulator, "N>");
    let hardware_meter_requests = decode_requests(hardware, "M>");
    let emulator_meter_requests = decode_requests(emulator, "M>");

    let hardware_meter = meter_evidence(
        hardware,
        requests(&hardware_requests, &hardware_meter_requests),
    );
    let emulator_meter = meter_evidence(
        emulator,
        requests(&emulator_requests, &emulator_meter_requests),
    );
    let mut deviations = Vec::new();

    match (&hardware_control, &emulator_control) {
        (Ok(hardware), Ok(emulator)) => compare_control(hardware, emulator, &mut deviations),
        (Err(hardware), Err(emulator)) if hardware == emulator => {
            deviations.push(format!("control decode failed on both sides: {hardware}"));
        }
        (Err(error), _) => deviations.push(format!("hardware control decode failed: {error}")),
        (_, Err(error)) => deviations.push(format!("emulator control decode failed: {error}")),
    }
    report_decode_failures(
        "N> request",
        &hardware_requests,
        &emulator_requests,
        &mut deviations,
    );
    report_decode_failures(
        "M> request",
        &hardware_meter_requests,
        &emulator_meter_requests,
        &mut deviations,
    );
    compare_meters(
        &hardware_meter.shapes,
        &emulator_meter.shapes,
        &mut deviations,
    );
    if hardware_meter.cardinality != emulator_meter.cardinality {
        deviations.push(format!(
            "meter cardinality hw={} emu={}",
            hardware_meter.cardinality.as_str(),
            emulator_meter.cardinality.as_str()
        ));
    }

    let mut text = format!(
        "# WING fidelity comparison\n# hardware: {} events\n# emulator: {} events\n# deviations: {}\n# meter cardinality: hw={} emu={}\n",
        hardware.len(),
        emulator.len(),
        deviations.len(),
        hardware_meter.cardinality.as_str(),
        emulator_meter.cardinality.as_str()
    );
    for deviation in &deviations {
        text.push_str(deviation);
        text.push('\n');
    }
    FidelityReport {
        text,
        deviations: deviations.len(),
    }
}

fn compare_control(hardware: &Control, emulator: &Control, deviations: &mut Vec<String>) {
    let hardware_ids = observed_ids(hardware);
    let emulator_ids = observed_ids(emulator);
    for id in hardware_ids.difference(&emulator_ids) {
        deviations.push(format!(
            "missing {} hw=present emu=missing",
            describe_id(*id)
        ));
    }
    for id in emulator_ids.difference(&hardware_ids) {
        deviations.push(format!(
            "missing {} hw=missing emu=present",
            describe_id(*id)
        ));
    }
    for id in hardware_ids.intersection(&emulator_ids) {
        match (hardware.values.get(id), emulator.values.get(id)) {
            (Some(hardware), Some(emulator)) if hardware != emulator => deviations.push(format!(
                "value {} hw={} emu={}",
                describe_id(*id),
                format_values(hardware),
                format_values(emulator)
            )),
            (Some(_), None) => {
                deviations.push(format!("data {} hw=present emu=missing", describe_id(*id)))
            }
            (None, Some(_)) => {
                deviations.push(format!("data {} hw=missing emu=present", describe_id(*id)))
            }
            _ => {}
        }
    }
    for id in hardware_ids.intersection(&emulator_ids) {
        match (
            hardware.definitions.contains(id),
            emulator.definitions.contains(id),
        ) {
            (true, false) => deviations.push(format!(
                "definition {} hw=present emu=missing",
                describe_id(*id)
            )),
            (false, true) => deviations.push(format!(
                "definition {} hw=missing emu=present",
                describe_id(*id)
            )),
            _ => {}
        }
    }
    if hardware.request_ends != emulator.request_ends {
        deviations.push(format!(
            "request-end count hw={} emu={}",
            hardware.request_ends, emulator.request_ends
        ));
    }
}

fn observed_ids(control: &Control) -> BTreeSet<i32> {
    control
        .values
        .keys()
        .chain(control.definitions.iter())
        .copied()
        .collect()
}

/// Names an id for the report. A unique id resolves to its single path. A SHARED id (WING ids are
/// structural hashes reused across every model variant at a slot -- e.g. one id for
/// `/ch/30/eq/{STD,E88,F110,...}/<leaf>`) is labeled by the common slot plus a variant count, so a
/// deviation on it reads as "this model-dependent slot differs" rather than mislabeling it with an
/// arbitrary first-sorted model name.
fn describe_id(id: i32) -> String {
    match WingConsole::id_to_defs(id) {
        Some(defs) if defs.len() == 1 => format!("path={} id={id}", defs[0].0),
        Some(defs) if !defs.is_empty() => {
            let mut paths: Vec<String> = defs.into_iter().map(|(path, _)| path).collect();
            paths.sort();
            format!(
                "slot={}/* id={id} ({} model variants, e.g. {})",
                common_slot(&paths),
                paths.len(),
                paths[0]
            )
        }
        _ => format!("id={id}"),
    }
}

/// The longest common leading `/`-segment prefix of `paths` (e.g. `/ch/30/eq` for the EQ-model
/// aliases). Assumes a non-empty slice.
fn common_slot(paths: &[String]) -> String {
    let first: Vec<&str> = paths[0].split('/').collect();
    let mut shared = first.len();
    for path in &paths[1..] {
        let segs: Vec<&str> = path.split('/').collect();
        let common = first.iter().zip(&segs).take_while(|(a, b)| a == b).count();
        shared = shared.min(common);
    }
    first[..shared].join("/")
}

fn format_values(values: &[Value]) -> String {
    if let [value] = values {
        value.format()
    } else {
        format!(
            "[{}]",
            values
                .iter()
                .map(Value::format)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn report_decode_failures(
    stream: &str,
    hardware: &Result<Vec<NativeRequest>, String>,
    emulator: &Result<Vec<NativeRequest>, String>,
    deviations: &mut Vec<String>,
) {
    match (hardware, emulator) {
        (Err(hardware), Err(emulator)) if hardware == emulator => {
            deviations.push(format!("{stream} decode failed on both sides: {hardware}"));
        }
        (Err(error), _) => deviations.push(format!("hardware {stream} decode failed: {error}")),
        (_, Err(error)) => deviations.push(format!("emulator {stream} decode failed: {error}")),
        _ => {}
    }
}

fn compare_meters(hardware: &[MeterShape], emulator: &[MeterShape], deviations: &mut Vec<String>) {
    if hardware.len() != emulator.len() {
        deviations.push(format!(
            "meter frame count hw={} emu={}",
            hardware.len(),
            emulator.len()
        ));
    }
    for (index, (hardware, emulator)) in hardware.iter().zip(emulator).enumerate() {
        if hardware != emulator {
            deviations.push(format!(
                "meter frame={} shape hw={} emu={}",
                index + 1,
                hardware.format(),
                emulator.format()
            ));
        }
    }
}

fn meter_evidence<'a>(
    events: &[(String, Vec<u8>)],
    requests: impl Iterator<Item = &'a NativeRequest>,
) -> MeterEvidence {
    let subscribed = requests
        .filter_map(|request| match request {
            NativeRequest::MeterSubscribe { report_id, .. } => Some(report_id & 0xffff_0000),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut tokens = BTreeSet::new();
    let shapes = events
        .iter()
        .filter(|(channel, _)| channel == "M<")
        .map(|(_, bytes)| {
            let report_token = bytes.len() >= 4;
            if let Some(token) = bytes
                .get(..4)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_be_bytes)
            {
                tokens.insert(token);
            }
            MeterShape {
                report_token,
                payload_bytes: bytes.len().saturating_sub(usize::from(report_token) * 4),
            }
        })
        .collect();
    let distinct_subscriptions = subscribed.iter().copied().collect::<BTreeSet<_>>();
    let cardinality = if distinct_subscriptions.len() < 2 {
        MeterCardinality::Ambiguous
    } else if tokens.intersection(&distinct_subscriptions).count() >= 2 {
        MeterCardinality::Concurrent
    } else if subscribed
        .last()
        .is_some_and(|latest| tokens.len() == 1 && tokens.contains(latest))
    {
        MeterCardinality::Replaces
    } else {
        MeterCardinality::Ambiguous
    };
    MeterEvidence {
        shapes,
        cardinality,
    }
}

fn requests<'a>(
    native: &'a Result<Vec<NativeRequest>, String>,
    meter: &'a Result<Vec<NativeRequest>, String>,
) -> impl Iterator<Item = &'a NativeRequest> {
    native
        .as_ref()
        .ok()
        .into_iter()
        .flatten()
        .chain(meter.as_ref().ok().into_iter().flatten())
}

fn decode_requests(
    events: &[(String, Vec<u8>)],
    channel: &str,
) -> Result<Vec<NativeRequest>, String> {
    let mut decoder = NativeRequestDecoder::default();
    let mut requests = Vec::new();
    for (_, bytes) in events
        .iter()
        .filter(|(event_channel, _)| event_channel == channel)
    {
        requests.extend(decoder.push(bytes).map_err(|error| format!("{error}"))?);
    }
    requests.extend(decoder.flush().map_err(|error| format!("{error}"))?);
    decoder.finish().map_err(|error| format!("{error}"))?;
    requests.retain(|request| !matches!(request, NativeRequest::KeepAlive { .. }));
    Ok(requests)
}

fn decode_control(events: &[(String, Vec<u8>)]) -> Result<Control, String> {
    let bytes = events
        .iter()
        .filter(|(channel, _)| channel == "N<")
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect::<Vec<_>>();
    let reader = MemoryTransport::new(bytes);
    let writer = MemoryTransport::default();
    let mut console = WingConsole::from_transports(reader, writer, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut control = Control::default();
    loop {
        match console.read_timeout(Duration::from_millis(1)) {
            Ok(WingResponse::NodeData(id, data)) => control
                .values
                .entry(id)
                .or_default()
                .push(Value::from_node(&data)),
            Ok(WingResponse::NodeDef(definition)) => {
                control.definitions.insert(definition.id);
            }
            Ok(WingResponse::RequestEnd) => control.request_ends += 1,
            Err(Error::Timeout) => return Ok(control),
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[derive(Default)]
struct MemoryTransport {
    bytes: VecDeque<u8>,
}

impl MemoryTransport {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl Read for MemoryTransport {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "capture exhausted",
            ));
        }
        let count = buffer.len().min(self.bytes.len()).max(1);
        for byte in buffer.iter_mut().take(count) {
            *byte = self.bytes.pop_front().expect("count is bounded by length");
        }
        Ok(count)
    }
}

impl Write for MemoryTransport {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Transport for MemoryTransport {
    fn set_read_timeout(&mut self, _duration: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libwing::native::{encode_responses, NativeResponse, NativeValue};

    fn node_data(path: &str, value: i32) -> Vec<(String, Vec<u8>)> {
        let id = WingConsole::name_to_id(path).expect("known property-map path");
        let bytes = encode_responses(&[NativeResponse::NodeData {
            id,
            value: NativeValue::Integer(value),
        }])
        .expect("encodable response");
        vec![("N<".to_string(), bytes)]
    }

    #[test]
    fn identical_inputs_have_no_deviations() {
        let events = node_data("/ch/1/fdr", 1);
        let report = compare_fidelity(&events, &events);

        assert_eq!(report.deviations, 0);
        assert!(report.text.contains("# deviations: 0\n"));
    }

    #[test]
    fn differing_node_data_is_one_named_deviation() {
        let hardware = node_data("/ch/1/fdr", 1);
        let emulator = node_data("/ch/1/fdr", 2);
        let report = compare_fidelity(&hardware, &emulator);

        assert_eq!(report.deviations, 1);
        assert!(report.text.contains("path=/ch/1/fdr"), "{}", report.text);
        assert!(report.text.contains("hw=1 emu=2"), "{}", report.text);
    }
}

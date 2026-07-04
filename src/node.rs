#[repr(C)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum NodeType {
    Node = 0,
    LinearFloat = 1,
    LogarithmicFloat = 2,
    FaderLevel = 3,
    Integer = 4,
    StringEnum = 5,
    FloatEnum = 6,
    String = 7,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum NodeUnit {
    None = 0,
    Db = 1,
    Percent = 2,
    Milliseconds = 3,
    Hertz = 4,
    Meters = 5,
    Seconds = 6,
    Octaves = 7,
}

#[derive(Clone)]
pub struct StringEnumItem {
    pub item: String,
    pub long_item: String,
}

#[derive(Clone)]
pub struct FloatEnumItem {
    pub item: f32,
    pub long_item: String,
}

#[derive(Clone)]
pub struct WingNodeDef {
    pub id: i32,
    pub parent_id: i32,
    pub index: u16,
    pub name: String,
    pub long_name: String,
    pub node_type: NodeType,
    pub unit: NodeUnit,
    pub read_only: bool,
    pub min_float: Option<f32>,
    pub max_float: Option<f32>,
    pub steps: Option<i32>,
    pub min_int: Option<i32>,
    pub max_int: Option<i32>,
    pub max_string_len: Option<u16>,
    pub string_enum: Option<Vec<StringEnumItem>>,
    pub float_enum: Option<Vec<FloatEnumItem>>,
    pub raw: Vec<u8>,
}

impl WingNodeDef {
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut i = 0;

        let parent_id = read_i32(raw, &mut i)?;
        let id = read_i32(raw, &mut i)?;
        let index = read_u16(raw, &mut i)?;
        let name_len = read_u8(raw, &mut i)?;
        let name = read_string(raw, &mut i, name_len as usize)?;
        let long_name_len = read_u8(raw, &mut i)?;
        let long_name = read_string(raw, &mut i, long_name_len as usize)?;
        let flags = read_u16(raw, &mut i)?;

        let node_type = match (flags >> 4) & 0x0F {
            0 => NodeType::Node,
            1 => NodeType::LinearFloat,
            2 => NodeType::LogarithmicFloat,
            3 => NodeType::FaderLevel,
            4 => NodeType::Integer,
            5 => NodeType::StringEnum,
            6 => NodeType::FloatEnum,
            7 => NodeType::String,
            _ => NodeType::Node,
        };

        let unit = match flags & 0x0F {
            0 => NodeUnit::None,
            1 => NodeUnit::Db,
            2 => NodeUnit::Percent,
            3 => NodeUnit::Milliseconds,
            4 => NodeUnit::Hertz,
            5 => NodeUnit::Meters,
            6 => NodeUnit::Seconds,
            7 => NodeUnit::Octaves,
            _ => NodeUnit::None,
        };

        let read_only = ((flags >> 9) & 0x01) != 0;

        let mut min_float      = Option::None;
        let mut max_float      = Option::None;
        let mut steps          = Option::None;
        let mut min_int        = Option::None;
        let mut max_int        = Option::None;
        let mut max_string_len = Option::None;
        let mut string_enum    = Option::None;
        let mut float_enum     = Option::None;

        match node_type {
            NodeType::Node | NodeType::FaderLevel => { }
            NodeType::String => {
                max_string_len = Some(read_u16(raw, &mut i)?);
            }
            NodeType::LinearFloat | 
                NodeType::LogarithmicFloat => {
                    min_float = Some(read_f32(raw, &mut i)?);
                    max_float = Some(read_f32(raw, &mut i)?);
                    steps = Some(read_i32(raw, &mut i)?);
                }
            NodeType::Integer => {
                min_int = Some(read_i32(raw, &mut i)?);
                max_int = Some(read_i32(raw, &mut i)?);
            }
            NodeType::StringEnum => {
                let num = read_u16(raw, &mut i)?;
                for _ in 0..num {
                    let item_len = read_u8(raw, &mut i)? as usize;
                    let item = read_string(raw, &mut i, item_len)?;
                    let long_item_len = read_u8(raw, &mut i)? as usize;
                    let long_item = read_string(raw, &mut i, long_item_len)?;
                    string_enum.get_or_insert_with(Vec::new).push(StringEnumItem {
                        item,
                        long_item,
                    });
                }
            }
            NodeType::FloatEnum => {
                let num = read_u16(raw, &mut i)?;
                for _ in 0..num {
                    let item = read_f32(raw, &mut i)?;
                    let long_item_len = read_u8(raw, &mut i)? as usize;
                    let long_item = read_string(raw, &mut i, long_item_len)?;
                    float_enum.get_or_insert_with(Vec::new).push(FloatEnumItem {
                        item,
                        long_item,
                    });
                }
            }
        }

        Ok(WingNodeDef {
            id,
            parent_id,
            index,
            name,
            long_name,
            node_type,
            unit,
            read_only,
            min_float,
            max_float,
            steps,
            min_int,
            max_int,
            max_string_len,
            string_enum,
            float_enum,
            raw: raw.to_vec(),
        })
    }
}

fn take<'a>(raw: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8]> {
    if raw.len().saturating_sub(*i) < len {
        return Err(Error::InvalidData);
    }
    let start = *i;
    *i += len;
    Ok(&raw[start..start + len])
}

fn read_u8(raw: &[u8], i: &mut usize) -> Result<u8> {
    Ok(take(raw, i, 1)?[0])
}

fn read_u16(raw: &[u8], i: &mut usize) -> Result<u16> {
    let bytes = take(raw, i, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_i32(raw: &[u8], i: &mut usize) -> Result<i32> {
    let bytes = take(raw, i, 4)?;
    Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_f32(raw: &[u8], i: &mut usize) -> Result<f32> {
    let bytes = take(raw, i, 4)?;
    Ok(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_string(raw: &[u8], i: &mut usize, len: usize) -> Result<String> {
    String::from_utf8(take(raw, i, len)?.to_vec()).map_err(|_| Error::InvalidData)
}

pub struct WingNodeData {
    string_value: Option<String>,
    float_value: Option<f32>,
    int_value: Option<i32>,
}

impl Default for WingNodeData {
    fn default() -> Self {
        Self::new()
    }
}

impl WingNodeData {
    pub fn new() -> Self {
        Self {
            string_value: None,
            float_value: None,
            int_value: None,
        }
    }

    pub fn with_string(s: String) -> Self {
        Self {
            string_value: Some(s),
            float_value: None,
            int_value: None,
        }
    }

    pub fn with_float(f: f32) -> Self {
        Self {
            string_value: None,
            float_value: Some(f),
            int_value: None,
        }
    }

    pub fn with_i32(i: i32) -> Self {
        Self {
            string_value: None,
            float_value: None,
            int_value: Some(i),
        }
    }
    pub fn with_i16(i: i16) -> Self {
        Self {
            string_value: None,
            float_value: None,
            int_value: Some(i as i32),
        }
    }

    pub fn with_i8(i: i8) -> Self {
        Self {
            string_value: None,
            float_value: None,
            int_value: Some(i as i32),
        }
    }

    pub fn get_string(&self) -> String {
        if let Some(value) = &self.string_value {
            value.clone()
        } else if let Some(value) = self.float_value {
            value.to_string()
        } else if let Some(value) = self.int_value {
            value.to_string()
        } else {
            String::new()
        }
    }

    pub fn get_float(&self) -> f32 {
        self.float_value.unwrap_or(0.0)
    }

    pub fn get_int(&self) -> i32 {
        self.int_value.unwrap_or(0)
    }

    pub fn has_string(&self) -> bool {
        self.string_value.is_some()
    }

    pub fn has_float(&self) -> bool {
        self.float_value.is_some()
    }

    pub fn has_int(&self) -> bool {
        self.int_value.is_some()
    }
}

impl WingNodeDef {
    pub fn get_type(&self) -> NodeType {
        self.node_type
    }

    pub fn get_unit(&self) -> NodeUnit {
        self.unit
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn to_description(&self) -> String {
        let mut r = String::with_capacity(1000);
        // if let Some(data) = WingConsole::id_to_data(self.id) {
        // }
        //
        //
        // if let Some(fullname) = fullname {
        //     r.push_str(fullname);
        // } else {
        //     let pname = WingConsole::id_to_name(self.parent_id);
        //     if let Some(pname) = pname {
        //         r.push_str(pname);
        //     } else {
        //         r.push_str(&format!("<Unknown:{}>", self.parent_id));
        //     }
        //     r.push_str(&format!("/<Unknown:{}>", self.id));
        // }
        //
        r.push_str(&format!(  "Id:        {}", self.id));
        r.push_str(&format!("\nRead-only: {}", if self.read_only { "yes" } else { "no" }));
        if self.index != 0 {
        r.push_str(&format!("\nIndex:     {}", self.index));
        }
        if !self.name.is_empty() {
        r.push_str(&format!("\nName:      {}", self.name));
        }
        if !self.long_name.is_empty() {
        r.push_str(&format!("\nLong Name: {}", self.long_name));
        }

        r.push_str(&format!("\nType:      {}",
            match self.node_type {
                NodeType::Node             => "node",
                NodeType::LinearFloat      => "linear float",
                NodeType::LogarithmicFloat => "log float",
                NodeType::Integer          => "integer",
                NodeType::String           => "string",
                NodeType::FaderLevel       => "fader level (float)",
                NodeType::StringEnum       => "string enum",
                NodeType::FloatEnum        => "float enum",
            }));
        if self.unit != NodeUnit::None {
            r.push_str(&format!("\nUnit:      {}",
                match self.unit {
                    NodeUnit::Db           => "dB",
                    NodeUnit::Percent      => "%",
                    NodeUnit::Milliseconds => "ms",
                    NodeUnit::Hertz        => "Hz",
                    NodeUnit::Meters       => "meters",
                    NodeUnit::Seconds      => "seconds",
                    NodeUnit::Octaves      => "octaves",
                    _ => "UNKNOWN"
                }));
        }

        match self.node_type {
            NodeType::LinearFloat | 
            NodeType::LogarithmicFloat |
            NodeType::FaderLevel => {
                if let Some(min_float) = self.min_float { r.push_str(&format!("\nMinimum:   {}", min_float)); }
                if let Some(max_float) = self.max_float { r.push_str(&format!("\nMaximum:   {}", max_float)); }
                if let Some(steps)     = self.steps     { r.push_str(&format!("\nSteps:     {}", steps)); }
            }
            NodeType::Integer => {
                if let Some(min_int) = self.min_int { r.push_str(&format!("\nMinimum:   {}", min_int)); }
                if let Some(max_int) = self.max_int { r.push_str(&format!("\nMaximum:   {}", max_int)); }
            }
            NodeType::String => {
                if let Some(max_string_len) = self.max_string_len { r.push_str(&format!("\nMaxLength: {}", max_string_len)); }
            }
            NodeType::StringEnum  => {
                if let Some(string_enum) = &self.string_enum {
                    r.push_str("\nItems:");
                    let mut first = true;
                    for item in string_enum {
                        if first {
                            r.push_str(&format!("     {}", item.item));
                            first = false;
                        } else {
                            r.push_str(&format!("           {}", item.item));
                        }

                        if !item.long_item.is_empty() {
                            r.push_str(&format!(" ({})", item.long_item));
                        }
                        r.push('\n');
                    }
                }
            }
            NodeType::FloatEnum => {
                if let Some(float_enum) = &self.float_enum {
                    r.push_str("\nItems:");
                    let mut first = true;
                    for item in float_enum {
                        if first {
                            r.push_str(&format!("     {}", item.item));
                            first = false;
                        } else {
                            r.push_str(&format!("           {}", item.item));
                        }
                        if !item.long_item.is_empty() {
                            r.push_str(&format!(" ({})", item.long_item));
                        }
                        r.push('\n');
                    }
                }
            }
            _ => {}
        }
        r
    }

    pub fn to_json(&self) -> jzon::JsonValue {
        let mut json = jzon::object!{
            id: self.id,
        };

        // if let Some(fullname) = WingConsole::id_to_name(self.id) {
        //     json.insert("fullname", fullname).unwrap();
        // }

        if self.index != 0 { 
            json.insert("index", self.index).unwrap();
        }
        if !self.name.is_empty() {
            json.insert("name", self.name.clone()).unwrap();
        }
        if !self.long_name.is_empty() {
            json.insert("longname", self.long_name.clone()).unwrap();
        }

        match self.node_type {
            NodeType::Node             => { json.insert("type", "node").unwrap(); }
            NodeType::LinearFloat      => { json.insert("type", "linear float").unwrap(); }
            NodeType::LogarithmicFloat => { json.insert("type", "log float").unwrap(); }
            NodeType::Integer          => { json.insert("type", "integer").unwrap(); }
            NodeType::String           => { json.insert("type", "string").unwrap(); }
            NodeType::FaderLevel       => { json.insert("type", "fader level").unwrap(); }
            NodeType::StringEnum       => { json.insert("type", "string enum").unwrap(); }
            NodeType::FloatEnum        => { json.insert("type", "float enum").unwrap(); }
        }
        match self.unit {
            NodeUnit::None         => { }
            NodeUnit::Db           => { json.insert("unit", "dB").unwrap(); }
            NodeUnit::Percent      => { json.insert("unit", "%").unwrap(); }
            NodeUnit::Milliseconds => { json.insert("unit", "ms").unwrap(); }
            NodeUnit::Hertz        => { json.insert("unit", "Hz").unwrap(); }
            NodeUnit::Meters       => { json.insert("unit", "meters").unwrap(); }
            NodeUnit::Seconds      => { json.insert("unit", "seconds").unwrap(); }
            NodeUnit::Octaves      => { json.insert("unit", "octaves").unwrap(); }
        }

        if self.read_only {
            json.insert("read_only", true).unwrap();
        }

        match self.node_type {
            NodeType::LinearFloat | 
            NodeType::LogarithmicFloat |
            NodeType::FaderLevel => {
                if let Some(min_float) = self.min_float { json.insert("minfloat", min_float).unwrap(); }
                if let Some(max_float) = self.max_float { json.insert("maxfloat", max_float).unwrap(); }
                if let Some(steps) = self.steps { json.insert("steps", steps).unwrap(); }
            }
            NodeType::Integer => {
                if let Some(min_int) = self.min_int { json.insert("minint", min_int).unwrap(); }
                if let Some(max_int) = self.max_int { json.insert("maxint", max_int).unwrap(); }
            }
            NodeType::String => {
                if let Some(max_string_len) = self.max_string_len { json.insert("maxstringlen", max_string_len).unwrap(); }
            }
            NodeType::StringEnum  => {
                if let Some(string_enum) = &self.string_enum {
                    json.insert("items", string_enum.iter().map(|item| {
                        let mut j = jzon::object!{ "item": item.item.clone() };
                        if !item.long_item.is_empty() {
                            j.insert("longitem", item.long_item.clone()).unwrap();
                        }
                        j
                    }).collect::<Vec<_>>()).unwrap();
                }
            }
            NodeType::FloatEnum => {
                if let Some(float_enum) = &self.float_enum {
                    json.insert("items", float_enum.iter().map(|item| {
                        let mut j = jzon::object!{ "item": item.item };
                        if !item.long_item.is_empty() {
                            j.insert("longitem", item.long_item.clone()).unwrap();
                        }
                        j
                    }).collect::<Vec<_>>()).unwrap();
                }
            }
            _ => {}
        }
        json
    }
}
use crate::{Error, Result};

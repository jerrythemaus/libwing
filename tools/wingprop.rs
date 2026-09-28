mod utils;
use utils::Args;

use std::result::Result;

use libwing::{NodeType, WingConsole, WingNodeData, WingNodeDef, WingResponse};

#[derive(Debug)]
enum SetValue {
    String(String),
    Integer(i32),
    Float(f32),
}

fn parse_set_value(node_type: NodeType, value: &str) -> Result<SetValue, String> {
    match node_type {
        NodeType::StringEnum | NodeType::String => Ok(SetValue::String(value.to_string())),
        NodeType::Integer => value
            .parse()
            .map(SetValue::Integer)
            .map_err(|_| format!("expected an integer, got {value}")),
        NodeType::FloatEnum
        | NodeType::FaderLevel
        | NodeType::LogarithmicFloat
        | NodeType::LinearFloat => value
            .parse()
            .map(SetValue::Float)
            .map_err(|_| format!("expected a floating point number, got {value}")),
        NodeType::Node => Err("nodes cannot be set".to_string()),
        _ => Err("node type is unknown to this libwing version".to_string()),
    }
}

/// One property lookup line: `name = value`, or with `-j` a bare JSON value -- a string for
/// String/StringEnum properties, a number for numeric ones.
fn format_lookup(propname: &str, proptype: NodeType, data: &WingNodeData, json: bool) -> String {
    let value = data.get_string();
    if !json {
        return format!("{propname} = {value}");
    }
    match proptype {
        NodeType::StringEnum | NodeType::String => jzon::stringify(jzon::JsonValue::String(value)),
        _ if data.has_float() => jzon::stringify(data.get_float()),
        _ if data.has_int() => jzon::stringify(data.get_int()),
        _ => jzon::stringify(jzon::JsonValue::String(value)),
    }
}

fn main() -> Result<(), libwing::Error> {
    let mut args = Args::new(
        r#"
Usage: wingprop [-h host] [-j] property[=value|?]

   -h host : IP address or hostname of Wing mixer. Default is to discover and connect to the first mixer found.
   -j      : Prints JSON of the value or definition.

   examples:
       wingprop /main/1/mute=1 # set a property
       wingprop /main/1/mute   # get a property's value
       wingprop /main/1/mute?  # get a property's definition

"#,
    );
    let mut host = None;
    let mut jsonoutput = false;

    let mut arg = args.next();
    if arg == "-h" {
        host = Some(args.next());
        arg = args.next();
    }
    if arg == "-j" {
        jsonoutput = true;
        arg = args.next();
    }

    #[derive(Debug)]
    enum Action {
        Lookup,
        Set(SetValue),
        Definition,
    }

    let propname;
    let propid;
    let proptype;
    let propparentid;

    fn parse_id(name: &str) -> (i32, i32, String, NodeType) {
        let propid;
        let propparentid;
        let propname;
        let proptype;

        if let Ok(id) = name.parse::<i32>() {
            propid = id;
            if let Some(defs) = WingConsole::id_to_defs(id) {
                if defs.len() == 1 {
                    proptype = defs[0].1.node_type;
                    propparentid = defs[0].1.parent_id;
                    propname = defs[0].0.clone();
                } else {
                    eprintln!("property id {} maps to multiple names, which may have different types. Use a full name please:", id);
                    eprintln!();
                    for (i, (name, _)) in defs.iter().enumerate() {
                        eprintln!("{}. {}", i + 1, name);
                    }
                    eprintln!();
                    std::process::exit(1);
                }
            } else {
                eprintln!("invalid property id: {}", id);
                std::process::exit(1);
            }
        } else {
            propname = name.to_string();
            if let Some(def) = WingConsole::name_to_def(name) {
                propid = def.id;
                proptype = def.node_type;
                propparentid = def.parent_id;
            } else {
                eprintln!("invalid property name: {}", name);
                std::process::exit(1);
            }
        }
        (propid, propparentid, propname, proptype)
    }

    let action = if arg.ends_with("?") {
        let name = arg.trim_end_matches("?");
        (propid, propparentid, propname, proptype) = parse_id(name);
        Action::Definition
    } else {
        let parts: Vec<&str> = arg.split("=").collect();
        if parts.len() == 2 {
            (propid, propparentid, propname, proptype) = parse_id(parts[0]);
            let value = parse_set_value(proptype, parts[1]).unwrap_or_else(|error| {
                eprintln!("Invalid value for {propname}: {error}");
                std::process::exit(1);
            });
            Action::Set(value)
        } else if parts.len() == 1 {
            (propid, propparentid, propname, proptype) = parse_id(parts[0]);
            Action::Lookup
        } else {
            eprintln!("invalid argument. only 1 equals allowed.");
            std::process::exit(1);
        }
    };

    let mut wing = WingConsole::connect(host.as_deref())?;

    match action {
        Action::Lookup => {
            if proptype == NodeType::Node {
                wing.request_node_definition(propid)?;
            } else {
                wing.request_node_data(propid)?;
            }
        }
        Action::Set(val) => {
            match val {
                SetValue::String(v) => wing.set_string(propid, &v)?,
                SetValue::Integer(v) => wing.set_int(propid, v)?,
                SetValue::Float(v) => wing.set_float(propid, v)?,
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::process::exit(0);
        }
        Action::Definition => {
            if proptype == NodeType::Node {
                wing.request_node_definition(propparentid)?;
            } else {
                wing.request_node_definition(propid)?;
            }
        }
    }

    let mut children = Vec::<WingNodeDef>::new();

    loop {
        match wing.read()? {
            WingResponse::RequestEnd => {
                if !children.is_empty() {
                    if jsonoutput {
                        let mut ret = jzon::array![];
                        for child in children {
                            ret.push(child.to_json()).unwrap();
                        }
                        println!("{}", ret);
                    } else {
                        for child in children {
                            println!("{}", child.to_description());
                            println!();
                        }
                    }
                }
                std::process::exit(0);
            }
            WingResponse::NodeData(id, data) => {
                if id == propid {
                    match proptype {
                        NodeType::Node => {
                            eprintln!("printing node for {}", propname);
                            std::process::exit(1);
                        }
                        NodeType::StringEnum
                        | NodeType::Integer
                        | NodeType::FloatEnum
                        | NodeType::LinearFloat
                        | NodeType::LogarithmicFloat
                        | NodeType::FaderLevel
                        | NodeType::String => {
                            println!("{}", format_lookup(&propname, proptype, &data, jsonoutput));
                        }
                        // NodeType is non_exhaustive (R21): print the raw value for a
                        // node type this build of libwing doesn't know about.
                        _ => {
                            println!("{} = {}", propname, data.get_string());
                        }
                    }
                }
            }
            WingResponse::NodeDef(d) => {
                if d.id == propid && matches!(action, Action::Definition) {
                    if jsonoutput {
                        let mut json = d.to_json();
                        json.insert("fullname", propname.clone()).unwrap();
                        println!("{}", json);
                    } else {
                        println!("Property:  {}", propname);
                        println!("{}", d.to_description());
                        println!();
                    }
                }
                if proptype == NodeType::Node
                    && matches!(action, Action::Lookup)
                    && d.parent_id == propid
                {
                    children.push(d);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_lookup_is_escaped_and_parseable() {
        let data = WingNodeData::with_string("line \"one\"\nline two".to_string());
        let output = format_lookup("/ch/1/name", NodeType::String, &data, true);
        let parsed = jzon::parse(&output).expect("-j must emit valid JSON");
        assert_eq!(parsed.as_str(), Some("line \"one\"\nline two"));
    }

    #[test]
    fn json_string_enum_lookup_is_a_json_string() {
        let data = WingNodeData::with_string("HALL".to_string());
        let output = format_lookup("/fx/1/mdl", NodeType::StringEnum, &data, true);
        assert_eq!(output, "\"HALL\"");
    }

    #[test]
    fn json_numeric_lookups_stay_json_numbers() {
        let float = format_lookup(
            "/ch/1/fdr",
            NodeType::FaderLevel,
            &WingNodeData::with_float(-6.5),
            true,
        );
        assert_eq!(jzon::parse(&float).unwrap().as_f32(), Some(-6.5));
        let int = format_lookup(
            "/cfg/amix/x",
            NodeType::Integer,
            &WingNodeData::with_i32(3),
            true,
        );
        assert_eq!(jzon::parse(&int).unwrap().as_i32(), Some(3));
    }

    #[test]
    fn plain_lookup_keeps_the_name_equals_value_form() {
        let data = WingNodeData::with_string("HALL".to_string());
        assert_eq!(
            format_lookup("/fx/1/mdl", NodeType::StringEnum, &data, false),
            "/fx/1/mdl = HALL"
        );
    }

    #[test]
    fn invalid_integer_set_is_rejected_before_connecting() {
        assert!(parse_set_value(NodeType::Integer, "not-an-integer").is_err());
    }

    #[test]
    fn invalid_float_set_is_rejected_before_connecting() {
        assert!(parse_set_value(NodeType::LinearFloat, "not-a-float").is_err());
    }
}

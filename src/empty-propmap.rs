use crate::node::WingNodeDef;
use std::collections::HashMap;

lazy_static::lazy_static! {
    pub static ref NAME_TO_DEF: HashMap<String, WingNodeDef> = HashMap::new();
}

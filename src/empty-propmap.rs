use crate::node::{PropMap, WingNodeDef};

lazy_static::lazy_static! {
    pub(crate) static ref NAME_TO_DEF: PropMap<&'static str, WingNodeDef> = PropMap::default();
}

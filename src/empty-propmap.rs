use std::sync::LazyLock;

use crate::propindex::PropIndex;

pub(crate) static NAME_TO_DEF: LazyLock<PropIndex> = LazyLock::new(PropIndex::empty);

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_float};
use std::ptr;
use crate::{WingConsole, NodeType, NodeUnit, WingResponse, console::Meter};

// Opaque type wrappers
#[repr(C)]
pub struct WingDiscoveryInfoHandle {
    info: Vec<crate::DiscoveryInfo>
}

// WingConsole is already Clone and internally synchronized (its rsock/wsock/main/mtrs
// fields are each Arc<Mutex<..>>), so it is Send+Sync and safe to share across the FFI
// boundary directly. Wrapping it in an *outer* Mutex would serialize every C call — a
// blocking wing_console_read() would then starve concurrent setters/requesters. Instead,
// each entry point clones this handle (a cheap Arc bump) and lets the internal
// per-resource locks provide the concurrency the split-lock design was built for.
#[repr(C)]
pub struct WingConsoleHandle {
    pub console: WingConsole,
}

#[repr(C)]
pub struct ResponseHandle {
    pub response: WingResponse
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub enum ResponseType {
    End = 0,
    NodeDefinition = 1,
    NodeData = 2,
}

fn string_to_c(value: &str) -> *mut c_char {
    CString::new(value).map_or(ptr::null_mut(), CString::into_raw)
}

unsafe fn cstr_to_str<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    CStr::from_ptr(value).to_str().ok()
}

unsafe fn discovery_ref<'a>(handle: *const WingDiscoveryInfoHandle) -> Option<&'a WingDiscoveryInfoHandle> {
    handle.as_ref()
}

unsafe fn response_ref<'a>(handle: *const ResponseHandle) -> Option<&'a ResponseHandle> {
    handle.as_ref()
}

#[no_mangle]
pub extern "C" fn wing_string_destroy(handle: *mut c_char) {
    unsafe {
        if handle.is_null() { return; }
        drop(CString::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn wing_discover_scan(stop_on_first: c_int) -> *mut WingDiscoveryInfoHandle {
    let results = WingConsole::scan(stop_on_first != 0);
    if let Ok(results) = results {
        Box::into_raw(Box::new(WingDiscoveryInfoHandle { info: results }))
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_discover_destroy(handle: *mut WingDiscoveryInfoHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn wing_discover_count(handle: *const WingDiscoveryInfoHandle) -> c_int {
    unsafe { discovery_ref(handle).map_or(-1, |handle| handle.info.len() as c_int) }
}

#[no_mangle]
pub extern "C" fn wing_discover_get_ip(handle: *const WingDiscoveryInfoHandle, index: c_int) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| usize::try_from(index).ok().and_then(|index| handle.info.get(index)))
        .map_or(ptr::null_mut(), |info| string_to_c(&info.ip))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_name(handle: *const WingDiscoveryInfoHandle, index: c_int) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| usize::try_from(index).ok().and_then(|index| handle.info.get(index)))
        .map_or(ptr::null_mut(), |info| string_to_c(&info.name))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_model(handle: *const WingDiscoveryInfoHandle, index: c_int) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| usize::try_from(index).ok().and_then(|index| handle.info.get(index)))
        .map_or(ptr::null_mut(), |info| string_to_c(&info.model))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_serial(handle: *const WingDiscoveryInfoHandle, index: c_int) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| usize::try_from(index).ok().and_then(|index| handle.info.get(index)))
        .map_or(ptr::null_mut(), |info| string_to_c(&info.serial))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_firmware(handle: *const WingDiscoveryInfoHandle, index: c_int) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| usize::try_from(index).ok().and_then(|index| handle.info.get(index)))
        .map_or(ptr::null_mut(), |info| string_to_c(&info.firmware))
}

#[no_mangle]
pub extern "C" fn wing_console_connect(ip: *const c_char) -> *mut WingConsoleHandle {
    if ip.is_null() {
        match WingConsole::connect(None) {
            Ok(console) => Box::into_raw(Box::new(WingConsoleHandle { console })),
            Err(_) => ptr::null_mut()
        }
    } else if let Some(ip) = unsafe { cstr_to_str(ip) } {
        match WingConsole::connect(Some(ip)) {
            Ok(console) => Box::into_raw(Box::new(WingConsoleHandle { console })),
            Err(_) => ptr::null_mut()
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_console_destroy(handle: *mut WingConsoleHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn wing_console_read(handle: *mut WingConsoleHandle) -> *mut ResponseHandle {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };
    let mut console = handle.console.clone();
    if let Ok(response) = console.read() {
        Box::into_raw(Box::new(ResponseHandle { response }))
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_response_destroy(handle: *mut ResponseHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}


#[no_mangle]
pub extern "C" fn wing_console_set_string(handle: *mut WingConsoleHandle, id: i32, value: *const c_char) -> c_int {
    let Some(value) = (unsafe { cstr_to_str(value) }) else {
        return -1;
    };
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let mut console = handle.console.clone();
    if console.set_string(id, value).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn wing_console_set_float(handle: *mut WingConsoleHandle, id: i32, value: c_float) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let mut console = handle.console.clone();
    if console.set_float(id, value).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn wing_console_set_int(handle: *mut WingConsoleHandle, id: i32, value: c_int) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let mut console = handle.console.clone();
    if console.set_int(id, value).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_node_definition(handle: *mut WingConsoleHandle, id: i32) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let mut console = handle.console.clone();
    if console.request_node_definition(id).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_node_data(handle: *mut WingConsoleHandle, id: i32) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let mut console = handle.console.clone();
    if console.request_node_data(id).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn wing_response_get_type(handle: *const ResponseHandle) -> ResponseType {
    match unsafe { response_ref(handle).map(|handle| &handle.response) } {
        Some(WingResponse::RequestEnd) => ResponseType::End,
        Some(WingResponse::NodeDef(_)) => ResponseType::NodeDefinition,
        Some(WingResponse::NodeData(_, _)) => ResponseType::NodeData,
        None => ResponseType::End,
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_id(handle: *const ResponseHandle) -> i32 {
    if let Some(WingResponse::NodeData(id, _)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        *id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_string(handle: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        string_to_c(&data.get_string())
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_float(handle: *const ResponseHandle) -> c_float {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        data.get_float()
    } else {
        0.0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_int(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        data.get_int()
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_string(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        if data.has_string() { 1 } else { 0 }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_float(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        if data.has_float() { 1 } else { 0 }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_int(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) = unsafe { response_ref(handle).map(|handle| &handle.response) } {
        if data.has_int() { 1 } else { 0 }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_name_to_id(name: *const c_char, out_id: *mut i32) -> c_int {
    if out_id.is_null() {
        return 0;
    }
    let Some(name_str) = (unsafe { cstr_to_str(name) }) else {
        return 0;
    };
    if let Some(id) = WingConsole::name_to_id(name_str) {
        unsafe { *out_id = id; }
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_id(def: *const ResponseHandle) -> i32 {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_parent_id(def: *const ResponseHandle) -> i32 {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.parent_id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_index(def: *const ResponseHandle) -> u16 {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.index
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_type(def: *const ResponseHandle) -> NodeType {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.node_type
    } else {
        NodeType::Node
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_unit(def: *const ResponseHandle) -> NodeUnit {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.unit
    } else {
        NodeUnit::None
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_name(def: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        string_to_c(&def.name)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_long_name(def: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        string_to_c(&def.long_name)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_is_read_only(def: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if def.read_only { 1 } else { 0 }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_min_float(def: *const ResponseHandle, ret: *mut c_float) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(min_float) = def.min_float {
            unsafe { *ret = min_float; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_float(def: *const ResponseHandle, ret: *mut c_float) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(max_float) = def.max_float {
            unsafe { *ret = max_float; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_steps(def: *const ResponseHandle, ret: *mut c_int) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(steps) = def.steps {
            unsafe { *ret = steps; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_min_int(def: *const ResponseHandle, ret: *mut c_int) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(min_int) = def.min_int {
            unsafe { *ret = min_int; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_int(def: *const ResponseHandle, ret: *mut c_int) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(max_int) = def.max_int {
            unsafe { *ret = max_int; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_string_len(def: *const ResponseHandle, ret: *mut c_int) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(max_string_len) = def.max_string_len {
            unsafe { *ret = max_string_len as i32; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_string_enum_count(def: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.string_enum.as_ref().map_or(0, |string_enum| string_enum.len() as c_int)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_count(def: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        def.float_enum.as_ref().map_or(0, |float_enum| float_enum.len() as c_int)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_item(def: *const ResponseHandle, index: c_int, ret: *mut c_float) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(item) = def.float_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe { *ret = item.item; }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_long_item(def: *const ResponseHandle, index: c_int, ret: *mut *mut c_char) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(item) = def.float_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe { *ret = string_to_c(&item.long_item); }
            if unsafe { (*ret).is_null() } { 0 } else { 1 }
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_string_enum_item(def: *const ResponseHandle, index: c_int, ret: *mut *mut c_char) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(item) = def.string_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe { *ret = string_to_c(&item.item); }
            if unsafe { (*ret).is_null() } { 0 } else { 1 }
        } else {
            0
        }
    } else {
        0
    }
}
#[no_mangle]
pub extern "C" fn wing_node_definition_get_string_enum_long_item(def: *const ResponseHandle, index: c_int, ret: *mut *mut c_char) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) = unsafe { response_ref(def).map(|handle| &handle.response) } {
        if let Some(item) = def.string_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe { *ret = string_to_c(&item.long_item); }
            if unsafe { (*ret).is_null() } { 0 } else { 1 }
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_meter(handle: *mut WingConsoleHandle, meters: *const u16, meters_count: usize) -> u16 {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return 0;
    };
    if meters_count > 0 && meters.is_null() {
        return 0;
    }

    let meter_ids = if meters_count == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(meters, meters_count) }
    };

    let Some(meters) = meter_ids.iter().map(|m|
        match m & 0xff00 {
            0xa000 => Some(Meter::Channel((m & 0xff) as u8)),
            0xa100 => Some(Meter::Aux((m & 0xff) as u8)),
            0xa200 => Some(Meter::Bus((m & 0xff) as u8)),
            0xa300 => Some(Meter::Main((m & 0xff) as u8)),
            0xa400 => Some(Meter::Matrix((m & 0xff) as u8)),
            0xa500 => Some(Meter::Dca((m & 0xff) as u8)),
            0xa600 => Some(Meter::Fx((m & 0xff) as u8)),
            0xa700 => Some(Meter::Source((m & 0xff) as u8)),
            0xa800 => Some(Meter::Output((m & 0xff) as u8)),
            0xa900 => Some(Meter::Monitor),
            0xaa00 => Some(Meter::Rta),
            0xab00 => Some(Meter::Channel2((m & 0xff) as u8)),
            0xac00 => Some(Meter::Aux2((m & 0xff) as u8)),
            0xad00 => Some(Meter::Bus2((m & 0xff) as u8)),
            0xae00 => Some(Meter::Main2((m & 0xff) as u8)),
            0xaf00 => Some(Meter::Matrix2((m & 0xff) as u8)),
            _ => None,
        }
    ).collect::<Option<Vec<_>>>() else {
        return 0;
    };

    let mut console = handle.console.clone();
    console.request_meter(&meters).unwrap_or_default()
}

#[no_mangle]
pub extern "C" fn wing_console_read_meter(handle: *mut WingConsoleHandle, ret_id: *mut u16, ret_data: *mut i16, ret_data_capacity: usize) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    if ret_id.is_null() || (ret_data_capacity > 0 && ret_data.is_null()) {
        return -1;
    }
    let mut console = handle.console.clone();
    if let Ok((id, data)) = console.read_meters() {
        unsafe { *ret_id = id; }
        if data.len() > ret_data_capacity {
            return -2;
        }
        if !data.is_empty() {
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), ret_data, data.len()); }
        }
        data.len() as c_int
    } else {
        -1
    }
}

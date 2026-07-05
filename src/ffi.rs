use crate::{console::Meter, Error, NodeType, NodeUnit, WingConsole, WingResponse};
use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_float, c_int};
use std::ptr;

/// FFI-usage error code (bad arguments detected at the FFI boundary -- null pointers,
/// out-of-range indices, invalid UTF-8 -- as opposed to a [`crate::Error`] surfaced by
/// the console/protocol layer). Returned by [`wing_last_error_code`].
const WING_ERROR_FFI_USAGE: c_int = -1;

thread_local! {
    // Structured last-error slot (R25): one message + one code per thread. Overwritten
    // on every failing FFI call; untouched on success, so a prior failure's message
    // remains readable until the next failure on the same thread.
    static LAST_ERROR_MESSAGE: RefCell<Option<CString>> = const { RefCell::new(None) };
    static LAST_ERROR_CODE: Cell<c_int> = const { Cell::new(0) };
}

fn set_last_error(message: impl Into<String>, code: c_int) {
    LAST_ERROR_MESSAGE.with(|slot| {
        // `CString::new` rejects embedded NULs; strip them rather than dropping the
        // message entirely -- this is a diagnostic string, not wire data.
        let sanitized = message.into().replace('\0', "");
        *slot.borrow_mut() = CString::new(sanitized).ok();
    });
    LAST_ERROR_CODE.with(|slot| slot.set(code));
}

/// Maps [`Error`] variants to stable, small positive codes for [`wing_last_error_code`].
/// `Error` is `#[non_exhaustive]` (R21): the match ends in a wildcard so a future
/// variant this build doesn't recognize still gets a valid (if generic) code. The
/// wildcard is unreachable *today* (this match already covers every variant that
/// exists in this build) -- `#[non_exhaustive]` only forces the wildcard on
/// downstream crates, not within libwing itself -- so it is kept deliberately and the
/// lint is silenced rather than removed, since removing it would make this the one
/// `Error` match in the crate that silently stops compiling when a variant is added.
#[allow(unreachable_patterns)]
fn error_to_code(err: &Error) -> c_int {
    match err {
        Error::Io(_) => 1,
        Error::InvalidData => 2,
        Error::InvalidInput => 3,
        Error::ConnectionError => 4,
        Error::DiscoveryError => 5,
        Error::MeterNotInitialized => 6,
        Error::Timeout => 7,
        Error::MeterFrameLength { .. } => 8,
        _ => 99,
    }
}

fn record_error(err: &Error) {
    set_last_error(err.to_string(), error_to_code(err));
}

fn record_ffi_usage_error(message: &str) {
    set_last_error(message, WING_ERROR_FFI_USAGE);
}

/// Returns the message for the most recent failing call made from the current thread,
/// or NULL if none has failed yet on this thread. The returned pointer is owned by the
/// library's thread-local slot: valid until the next failing FFI call on the same
/// thread (or thread exit), and must NOT be freed by the caller (do not pass it to
/// [`wing_string_destroy`]). It is never shared across threads.
#[no_mangle]
pub extern "C" fn wing_last_error_message() -> *const c_char {
    LAST_ERROR_MESSAGE.with(|slot| slot.borrow().as_ref().map_or(ptr::null(), |s| s.as_ptr()))
}

/// Returns the code for the most recent failing call made from the current thread, or
/// `0` if none has failed yet. `-1` means the failure was an FFI-usage error (bad
/// argument) rather than a [`crate::Error`]; `1..=8` mirror specific `Error` variants;
/// `99` is a future/unrecognized `Error` variant. See [`wing_last_error_message`] for
/// the paired human-readable message.
#[no_mangle]
pub extern "C" fn wing_last_error_code() -> c_int {
    LAST_ERROR_CODE.with(|slot| slot.get())
}

// Opaque type wrappers
#[repr(C)]
pub struct WingDiscoveryInfoHandle {
    info: Vec<crate::DiscoveryInfo>,
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
    pub response: WingResponse,
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

fn is_c_string_compatible(value: &str) -> bool {
    !value.as_bytes().contains(&0)
}

unsafe fn cstr_to_str<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    CStr::from_ptr(value).to_str().ok()
}

unsafe fn discovery_ref<'a>(
    handle: *const WingDiscoveryInfoHandle,
) -> Option<&'a WingDiscoveryInfoHandle> {
    handle.as_ref()
}

unsafe fn response_ref<'a>(handle: *const ResponseHandle) -> Option<&'a ResponseHandle> {
    handle.as_ref()
}

#[no_mangle]
pub extern "C" fn wing_string_destroy(handle: *mut c_char) {
    unsafe {
        if handle.is_null() {
            return;
        }
        drop(CString::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn wing_discover_scan(stop_on_first: c_int) -> *mut WingDiscoveryInfoHandle {
    match WingConsole::scan(stop_on_first != 0) {
        Ok(results) => Box::into_raw(Box::new(WingDiscoveryInfoHandle { info: results })),
        Err(err) => {
            record_error(&err);
            ptr::null_mut()
        }
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
pub extern "C" fn wing_discover_get_ip(
    handle: *const WingDiscoveryInfoHandle,
    index: c_int,
) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| {
            usize::try_from(index)
                .ok()
                .and_then(|index| handle.info.get(index))
        })
        .map_or(ptr::null_mut(), |info| string_to_c(&info.ip))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_name(
    handle: *const WingDiscoveryInfoHandle,
    index: c_int,
) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| {
            usize::try_from(index)
                .ok()
                .and_then(|index| handle.info.get(index))
        })
        .map_or(ptr::null_mut(), |info| string_to_c(&info.name))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_model(
    handle: *const WingDiscoveryInfoHandle,
    index: c_int,
) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| {
            usize::try_from(index)
                .ok()
                .and_then(|index| handle.info.get(index))
        })
        .map_or(ptr::null_mut(), |info| string_to_c(&info.model))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_serial(
    handle: *const WingDiscoveryInfoHandle,
    index: c_int,
) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| {
            usize::try_from(index)
                .ok()
                .and_then(|index| handle.info.get(index))
        })
        .map_or(ptr::null_mut(), |info| string_to_c(&info.serial))
}

#[no_mangle]
pub extern "C" fn wing_discover_get_firmware(
    handle: *const WingDiscoveryInfoHandle,
    index: c_int,
) -> *mut c_char {
    unsafe { discovery_ref(handle) }
        .and_then(|handle| {
            usize::try_from(index)
                .ok()
                .and_then(|index| handle.info.get(index))
        })
        .map_or(ptr::null_mut(), |info| string_to_c(&info.firmware))
}

#[no_mangle]
pub extern "C" fn wing_console_connect(ip: *const c_char) -> *mut WingConsoleHandle {
    if ip.is_null() {
        match WingConsole::connect(None) {
            Ok(console) => Box::into_raw(Box::new(WingConsoleHandle { console })),
            Err(err) => {
                record_error(&err);
                ptr::null_mut()
            }
        }
    } else if let Some(ip) = unsafe { cstr_to_str(ip) } {
        match WingConsole::connect(Some(ip)) {
            Ok(console) => Box::into_raw(Box::new(WingConsoleHandle { console })),
            Err(err) => {
                record_error(&err);
                ptr::null_mut()
            }
        }
    } else {
        record_ffi_usage_error("wing_console_connect: invalid or non-UTF-8 ip");
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
        record_ffi_usage_error("wing_console_read: null console handle");
        return ptr::null_mut();
    };
    let mut console = handle.console.clone();
    match console.read() {
        Ok(response) => Box::into_raw(Box::new(ResponseHandle { response })),
        Err(err) => {
            record_error(&err);
            ptr::null_mut()
        }
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
pub extern "C" fn wing_console_set_string(
    handle: *mut WingConsoleHandle,
    id: i32,
    value: *const c_char,
) -> c_int {
    let Some(value) = (unsafe { cstr_to_str(value) }) else {
        record_ffi_usage_error("wing_console_set_string: invalid or non-UTF-8 value");
        return -1;
    };
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_set_string: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.set_string(id, value) {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_console_set_float(
    handle: *mut WingConsoleHandle,
    id: i32,
    value: c_float,
) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_set_float: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.set_float(id, value) {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_console_set_int(
    handle: *mut WingConsoleHandle,
    id: i32,
    value: c_int,
) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_set_int: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.set_int(id, value) {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_node_definition(
    handle: *mut WingConsoleHandle,
    id: i32,
) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_request_node_definition: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.request_node_definition(id) {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_node_data(handle: *mut WingConsoleHandle, id: i32) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_request_node_data: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.request_node_data(id) {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
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
    if let Some(WingResponse::NodeData(id, _)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        *id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_string(handle: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        string_to_c(&data.get_string())
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_float(handle: *const ResponseHandle) -> c_float {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        data.get_float()
    } else {
        0.0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_get_int(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        data.get_int()
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_string(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        if data.has_string() && is_c_string_compatible(&data.get_string()) {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_float(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        if data.has_float() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_data_has_int(handle: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeData(_, data)) =
        unsafe { response_ref(handle).map(|handle| &handle.response) }
    {
        if data.has_int() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_name_to_id(name: *const c_char, out_id: *mut i32) -> c_int {
    if out_id.is_null() {
        record_ffi_usage_error("wing_name_to_id: null out_id");
        return 0;
    }
    let Some(name_str) = (unsafe { cstr_to_str(name) }) else {
        record_ffi_usage_error("wing_name_to_id: invalid or non-UTF-8 name");
        return 0;
    };
    if let Some(id) = WingConsole::name_to_id(name_str) {
        unsafe {
            *out_id = id;
        }
        1
    } else {
        record_ffi_usage_error("wing_name_to_id: name not found in property map");
        0
    }
}

/// Reverse lookup: the node definition for a full property-map name (e.g.
/// `/ch/1/fdr`), as a [`ResponseHandle`] wrapping a `NodeDef` response -- the SAME
/// handle type and accessor family (`wing_node_definition_get_*`) used for definitions
/// read live off the console. Returns NULL if `name` is null/non-UTF-8 or not present
/// in the embedded property map (see [`wing_last_error_message`]).
///
/// Return value must be freed with [`wing_response_destroy`].
#[no_mangle]
pub extern "C" fn wing_name_to_def(name: *const c_char) -> *mut ResponseHandle {
    let Some(name_str) = (unsafe { cstr_to_str(name) }) else {
        record_ffi_usage_error("wing_name_to_def: null or non-UTF-8 name");
        return ptr::null_mut();
    };
    match WingConsole::name_to_def(name_str) {
        Some(def) => Box::into_raw(Box::new(ResponseHandle {
            response: WingResponse::NodeDef(def.clone()),
        })),
        None => {
            record_ffi_usage_error("wing_name_to_def: name not found in property map");
            ptr::null_mut()
        }
    }
}

/// Number of candidate node definitions sharing wire `id` (an id can map to more than
/// one full name -- e.g. every `/fx/N/HALL/...` slot aliases the same ids across `N`,
/// see [`WingConsole::id_to_defs`]). Returns 0 if `id` has no known candidates; this is
/// not distinguished from "no error" since an absent id is a normal, non-exceptional
/// query result (no last-error is recorded).
#[no_mangle]
pub extern "C" fn wing_id_to_defs_count(id: i32) -> usize {
    WingConsole::id_to_defs(id).map_or(0, |defs| defs.len())
}

/// Full name of the `index`-th candidate for `id` (see [`wing_id_to_defs_count`]),
/// written into the caller-provided `name_out` buffer.
///
/// Out-param buffer convention (R28), deliberately distinct from
/// [`wing_console_read_meter_bounded`]'s fixed `-2` sentinel (that convention suits a
/// fixed-shape numeric buffer; this is a variable-length C string, so it uses the more
/// common "tell me how big" idiom instead):
/// - On success (`name_cap` large enough), copies the NUL-terminated name into
///   `name_out` and returns the number of bytes written *including* the NUL
///   terminator.
/// - If `name_cap` is too small (or `name_out` is NULL), nothing is written and the
///   required size (including the NUL terminator) is returned anyway, so the caller
///   can grow its buffer and retry -- pass `name_out = NULL, name_cap = 0` to query the
///   size up front.
/// - Returns -1 if `id`/`index` do not name a known candidate, or if the name contains
///   an embedded NUL (unrepresentable as a C string; see [`wing_last_error_message`]).
#[no_mangle]
pub extern "C" fn wing_id_to_defs_get_name(
    id: i32,
    index: usize,
    name_out: *mut c_char,
    name_cap: usize,
) -> c_int {
    let Some(defs) = WingConsole::id_to_defs(id) else {
        record_ffi_usage_error("wing_id_to_defs_get_name: unknown id");
        return -1;
    };
    let Some((name, _)) = defs.get(index) else {
        record_ffi_usage_error("wing_id_to_defs_get_name: index out of range");
        return -1;
    };
    if !is_c_string_compatible(name) {
        record_ffi_usage_error("wing_id_to_defs_get_name: name contains embedded NUL");
        return -1;
    }
    let needed = name.len() + 1;
    if name_out.is_null() || name_cap < needed {
        return needed as c_int;
    }
    unsafe {
        ptr::copy_nonoverlapping(name.as_ptr().cast::<c_char>(), name_out, name.len());
        *name_out.add(name.len()) = 0;
    }
    needed as c_int
}

/// Node definition of the `index`-th candidate for `id` (see
/// [`wing_id_to_defs_count`]), as a [`ResponseHandle`] -- same handle type and
/// `wing_node_definition_get_*` accessor family as [`wing_name_to_def`]. Returns NULL
/// if `id`/`index` do not name a known candidate (see [`wing_last_error_message`]).
///
/// Return value must be freed with [`wing_response_destroy`].
#[no_mangle]
pub extern "C" fn wing_id_to_defs_get_def(id: i32, index: usize) -> *mut ResponseHandle {
    let Some(defs) = WingConsole::id_to_defs(id) else {
        record_ffi_usage_error("wing_id_to_defs_get_def: unknown id");
        return ptr::null_mut();
    };
    match defs.get(index) {
        Some((_, def)) => Box::into_raw(Box::new(ResponseHandle {
            response: WingResponse::NodeDef(def.clone()),
        })),
        None => {
            record_ffi_usage_error("wing_id_to_defs_get_def: index out of range");
            ptr::null_mut()
        }
    }
}

/// Sends a keepalive for the main (get/set) connection if the console's internal
/// keepalive timer has elapsed. [`crate::WingConsole::read`] already does this as
/// needed; call this yourself only if you have a loop that doesn't call `read()`
/// (e.g. a pure setter loop) but still wants to hold the connection open. Returns 0 on
/// success, -1 on failure (null handle, or see [`wing_last_error_message`]).
#[no_mangle]
pub extern "C" fn wing_console_keep_alive(handle: *mut WingConsoleHandle) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_keep_alive: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.keep_alive() {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

/// Sends a keepalive for the metering connection if its internal keepalive timer has
/// elapsed. [`crate::WingConsole::read_meters`] already does this as needed; call this
/// yourself only if you have a loop that doesn't call `read_meters()` but still wants
/// metering to keep flowing. Returns 0 on success, -1 on failure (null handle, meters
/// not initialized, or see [`wing_last_error_message`]).
#[no_mangle]
pub extern "C" fn wing_console_keep_alive_meters(handle: *mut WingConsoleHandle) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_keep_alive_meters: null console handle");
        return -1;
    };
    let mut console = handle.console.clone();
    match console.keep_alive_meters() {
        Ok(()) => 0,
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_id(def: *const ResponseHandle) -> i32 {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_parent_id(def: *const ResponseHandle) -> i32 {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.parent_id
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_index(def: *const ResponseHandle) -> u16 {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.index
    } else {
        0
    }
}

/// C ABI mirror of [`NodeType`]. `NodeType` itself is not `#[repr(C)]` (it carries a
/// raw discriminant in `Unknown(u8)`, R20), so this fieldless copy is what actually
/// crosses the FFI boundary; the existing 0-7 values match `libwing.h`'s
/// `WingNodeType` exactly, and `Unknown` is an additive sentinel (R21) for
/// discriminants no known variant covers.
#[repr(C)]
#[derive(Copy, Clone)]
pub enum FfiNodeType {
    Node = 0,
    LinearFloat = 1,
    LogarithmicFloat = 2,
    FaderLevel = 3,
    Integer = 4,
    StringEnum = 5,
    FloatEnum = 6,
    String = 7,
    Unknown = 8,
}

impl From<NodeType> for FfiNodeType {
    fn from(t: NodeType) -> Self {
        match t {
            NodeType::Node => FfiNodeType::Node,
            NodeType::LinearFloat => FfiNodeType::LinearFloat,
            NodeType::LogarithmicFloat => FfiNodeType::LogarithmicFloat,
            NodeType::FaderLevel => FfiNodeType::FaderLevel,
            NodeType::Integer => FfiNodeType::Integer,
            NodeType::StringEnum => FfiNodeType::StringEnum,
            NodeType::FloatEnum => FfiNodeType::FloatEnum,
            NodeType::String => FfiNodeType::String,
            NodeType::Unknown(_) => FfiNodeType::Unknown,
        }
    }
}

/// C ABI mirror of [`NodeUnit`]; see [`FfiNodeType`] for why a separate type is
/// needed.
#[repr(C)]
#[derive(Copy, Clone)]
pub enum FfiNodeUnit {
    None = 0,
    Db = 1,
    Percent = 2,
    Milliseconds = 3,
    Hertz = 4,
    Meters = 5,
    Seconds = 6,
    Octaves = 7,
    Unknown = 8,
}

impl From<NodeUnit> for FfiNodeUnit {
    fn from(u: NodeUnit) -> Self {
        match u {
            NodeUnit::None => FfiNodeUnit::None,
            NodeUnit::Db => FfiNodeUnit::Db,
            NodeUnit::Percent => FfiNodeUnit::Percent,
            NodeUnit::Milliseconds => FfiNodeUnit::Milliseconds,
            NodeUnit::Hertz => FfiNodeUnit::Hertz,
            NodeUnit::Meters => FfiNodeUnit::Meters,
            NodeUnit::Seconds => FfiNodeUnit::Seconds,
            NodeUnit::Octaves => FfiNodeUnit::Octaves,
            NodeUnit::Unknown(_) => FfiNodeUnit::Unknown,
        }
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_type(def: *const ResponseHandle) -> FfiNodeType {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.node_type.into()
    } else {
        FfiNodeType::Node
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_unit(def: *const ResponseHandle) -> FfiNodeUnit {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.unit.into()
    } else {
        FfiNodeUnit::None
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_name(def: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        string_to_c(&def.name)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_long_name(def: *const ResponseHandle) -> *mut c_char {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        string_to_c(&def.long_name)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_is_read_only(def: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if def.read_only {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_min_float(
    def: *const ResponseHandle,
    ret: *mut c_float,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(min_float) = def.min_float {
            unsafe {
                *ret = min_float;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_float(
    def: *const ResponseHandle,
    ret: *mut c_float,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(max_float) = def.max_float {
            unsafe {
                *ret = max_float;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_steps(
    def: *const ResponseHandle,
    ret: *mut c_int,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(steps) = def.steps {
            unsafe {
                *ret = steps;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_min_int(
    def: *const ResponseHandle,
    ret: *mut c_int,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(min_int) = def.min_int {
            unsafe {
                *ret = min_int;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_int(
    def: *const ResponseHandle,
    ret: *mut c_int,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(max_int) = def.max_int {
            unsafe {
                *ret = max_int;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_max_string_len(
    def: *const ResponseHandle,
    ret: *mut c_int,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(max_string_len) = def.max_string_len {
            unsafe {
                *ret = max_string_len as i32;
            }
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
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.string_enum
            .as_ref()
            .map_or(0, |string_enum| string_enum.len() as c_int)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_count(def: *const ResponseHandle) -> c_int {
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        def.float_enum
            .as_ref()
            .map_or(0, |float_enum| float_enum.len() as c_int)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_item(
    def: *const ResponseHandle,
    index: c_int,
    ret: *mut c_float,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(item) = def.float_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe {
                *ret = item.item;
            }
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_float_enum_long_item(
    def: *const ResponseHandle,
    index: c_int,
    ret: *mut *mut c_char,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(item) = def.float_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe {
                *ret = string_to_c(&item.long_item);
            }
            if unsafe { (*ret).is_null() } {
                0
            } else {
                1
            }
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_node_definition_get_string_enum_item(
    def: *const ResponseHandle,
    index: c_int,
    ret: *mut *mut c_char,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(item) = def.string_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe {
                *ret = string_to_c(&item.item);
            }
            if unsafe { (*ret).is_null() } {
                0
            } else {
                1
            }
        } else {
            0
        }
    } else {
        0
    }
}
#[no_mangle]
pub extern "C" fn wing_node_definition_get_string_enum_long_item(
    def: *const ResponseHandle,
    index: c_int,
    ret: *mut *mut c_char,
) -> c_int {
    if ret.is_null() {
        return 0;
    }
    let Some(index) = usize::try_from(index).ok() else {
        return 0;
    };
    if let Some(WingResponse::NodeDef(def)) =
        unsafe { response_ref(def).map(|handle| &handle.response) }
    {
        if let Some(item) = def.string_enum.as_ref().and_then(|items| items.get(index)) {
            unsafe {
                *ret = string_to_c(&item.long_item);
            }
            if unsafe { (*ret).is_null() } {
                0
            } else {
                1
            }
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn wing_console_request_meter(
    handle: *mut WingConsoleHandle,
    meters: *const u16,
    meters_count: usize,
) -> u16 {
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

    let Some(meters) = meter_ids
        .iter()
        .map(|m| match m & 0xff00 {
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
        })
        .collect::<Option<Vec<_>>>()
    else {
        return 0;
    };

    let mut console = handle.console.clone();
    console.request_meter(&meters).unwrap_or_default()
}

#[no_mangle]
pub extern "C" fn wing_console_read_meter(
    handle: *mut WingConsoleHandle,
    ret_id: *mut u16,
    ret_data: *mut i16,
    ret_data_capacity: usize,
) -> c_int {
    wing_console_read_meter_into(handle, ret_id, ret_data, ret_data_capacity, true)
}

#[no_mangle]
pub extern "C" fn wing_console_read_meter_bounded(
    handle: *mut WingConsoleHandle,
    ret_id: *mut u16,
    ret_data: *mut i16,
    ret_data_capacity: usize,
) -> c_int {
    wing_console_read_meter_into(handle, ret_id, ret_data, ret_data_capacity, false)
}

fn wing_console_read_meter_into(
    handle: *mut WingConsoleHandle,
    ret_id: *mut u16,
    ret_data: *mut i16,
    ret_data_capacity: usize,
    write_id_on_capacity_failure: bool,
) -> c_int {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        record_ffi_usage_error("wing_console_read_meter: null console handle");
        return -1;
    };
    if ret_id.is_null() || (ret_data_capacity > 0 && ret_data.is_null()) {
        record_ffi_usage_error("wing_console_read_meter: null out-param for requested capacity");
        return -1;
    }
    let mut console = handle.console.clone();
    match console.read_meters() {
        Ok((id, data)) => {
            if data.len() > ret_data_capacity {
                if write_id_on_capacity_failure {
                    unsafe {
                        *ret_id = id;
                    }
                }
                return -2;
            }
            unsafe {
                *ret_id = id;
            }
            if !data.is_empty() {
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr(), ret_data, data.len());
                }
            }
            data.len() as c_int
        }
        Err(err) => {
            record_error(&err);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WingNodeData;
    use std::net::{SocketAddr, UdpSocket};

    fn meter_handle() -> (UdpSocket, SocketAddr, WingConsoleHandle) {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_ip = sender.local_addr().unwrap().ip();
        let console = WingConsole::test_with_meter_socket(peer_ip, receiver);
        (sender, receiver_addr, WingConsoleHandle { console })
    }

    #[test]
    fn string_presence_matches_c_getter_for_embedded_nul() {
        let response = ResponseHandle {
            response: WingResponse::NodeData(1, WingNodeData::with_string("a\0b".to_string())),
        };

        assert_eq!(wing_node_data_has_string(&response), 0);
        assert!(wing_node_data_get_string(&response).is_null());
    }

    #[test]
    fn string_getter_out_params_reject_null_and_bad_index() {
        assert_eq!(
            wing_node_definition_get_string_enum_item(ptr::null(), 0, ptr::null_mut()),
            0
        );

        let response = ResponseHandle {
            response: WingResponse::NodeDef(crate::WingNodeDef {
                id: 1,
                parent_id: 0,
                index: 0,
                name: String::new(),
                long_name: String::new(),
                node_type: NodeType::StringEnum,
                unit: NodeUnit::None,
                read_only: false,
                min_float: None,
                max_float: None,
                steps: None,
                min_int: None,
                max_int: None,
                max_string_len: None,
                string_enum: Some(vec![crate::node::StringEnumItem {
                    item: "short".to_string(),
                    long_item: "Long".to_string(),
                }]),
                float_enum: None,
                raw: Vec::new(),
            }),
        };
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(
            wing_node_definition_get_string_enum_item(&response, -1, &mut out),
            0
        );
        assert!(out.is_null());
        assert_eq!(
            wing_node_definition_get_string_enum_item(&response, 0, &mut out),
            1
        );
        assert!(!out.is_null());
        wing_string_destroy(out);
    }

    #[test]
    fn bounded_meter_read_reports_capacity_failure_without_copying() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender
            .send_to(&[0x12, 0x34, 0, 0, 0, 1, 0, 2], receiver_addr)
            .unwrap();

        let mut id = 0xbeef;
        let mut data = [123_i16; 1];
        assert_eq!(
            wing_console_read_meter_bounded(&mut handle, &mut id, data.as_mut_ptr(), data.len()),
            -2
        );
        assert_eq!(id, 0xbeef);
        assert_eq!(data, [123]);
    }

    #[test]
    fn legacy_meter_read_keeps_id_on_capacity_failure() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender
            .send_to(&[0x12, 0x34, 0, 0, 0, 1, 0, 2], receiver_addr)
            .unwrap();

        let mut id = 0xbeef;
        let mut data = [123_i16; 1];
        assert_eq!(
            wing_console_read_meter(&mut handle, &mut id, data.as_mut_ptr(), data.len()),
            -2
        );
        assert_eq!(id, 0x1234);
        assert_eq!(data, [123]);
    }

    #[test]
    fn meter_read_rejects_null_outputs() {
        let (_, _, mut handle) = meter_handle();
        let mut id = 0;
        let mut data = [0_i16; 1];

        assert_eq!(
            wing_console_read_meter_bounded(
                &mut handle,
                ptr::null_mut(),
                data.as_mut_ptr(),
                data.len()
            ),
            -1
        );
        assert_eq!(
            wing_console_read_meter_bounded(&mut handle, &mut id, ptr::null_mut(), data.len()),
            -1
        );
    }

    #[test]
    fn bounded_meter_read_allows_null_data_for_zero_capacity() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender
            .send_to(&[0x12, 0x34, 0, 0, 0, 1, 0, 2], receiver_addr)
            .unwrap();

        let mut id = 0xbeef;
        assert_eq!(
            wing_console_read_meter_bounded(&mut handle, &mut id, ptr::null_mut(), 0),
            -2
        );
        assert_eq!(id, 0xbeef);
    }

    #[test]
    fn bounded_meter_read_allows_null_data_for_empty_packet() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender.send_to(&[0x12, 0x34, 0, 0], receiver_addr).unwrap();

        let mut id = 0;
        assert_eq!(
            wing_console_read_meter_bounded(&mut handle, &mut id, ptr::null_mut(), 0),
            0
        );
        assert_eq!(id, 0x1234);
    }

    #[test]
    fn meter_read_copies_samples_on_success() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender
            .send_to(&[0x12, 0x34, 0, 0, 0, 1, 0, 2], receiver_addr)
            .unwrap();

        let mut id = 0;
        let mut data = [0_i16; 2];
        assert_eq!(
            wing_console_read_meter(&mut handle, &mut id, data.as_mut_ptr(), data.len()),
            2
        );
        assert_eq!(id, 0x1234);
        assert_eq!(data, [1, 2]);
    }

    #[test]
    fn bounded_meter_read_copies_samples_on_success() {
        let (sender, receiver_addr, mut handle) = meter_handle();

        sender
            .send_to(&[0x12, 0x34, 0, 0, 0, 1, 0, 2], receiver_addr)
            .unwrap();

        let mut id = 0;
        let mut data = [0_i16; 2];
        assert_eq!(
            wing_console_read_meter_bounded(&mut handle, &mut id, data.as_mut_ptr(), data.len()),
            2
        );
        assert_eq!(id, 0x1234);
        assert_eq!(data, [1, 2]);
    }

    // Needs a populated embedded map; under --no-default-features NAME_TO_DEF is empty.
    #[cfg(feature = "propmap")]
    #[test]
    fn name_to_def_matches_rust_lookup_for_known_name() {
        let name = CString::new("/ch/1/fdr").unwrap();
        let rust_def = WingConsole::name_to_def("/ch/1/fdr").expect("known propmap entry");

        let handle = wing_name_to_def(name.as_ptr());
        assert!(!handle.is_null());
        assert_eq!(wing_node_definition_get_id(handle), rust_def.id);
        assert_eq!(
            wing_node_definition_get_parent_id(handle),
            rust_def.parent_id
        );
        assert_eq!(wing_node_definition_get_index(handle), rust_def.index);
        let c_name = wing_node_definition_get_name(handle);
        assert_eq!(
            unsafe { CStr::from_ptr(c_name) }.to_str().unwrap(),
            rust_def.name
        );
        wing_string_destroy(c_name);
        wing_response_destroy(handle);
    }

    #[test]
    fn name_to_def_reports_unknown_name_via_last_error() {
        let name = CString::new("/no/such/node").unwrap();
        assert!(wing_name_to_def(name.as_ptr()).is_null());
        assert_eq!(wing_last_error_code(), WING_ERROR_FFI_USAGE);
        let message = wing_last_error_message();
        assert!(!message.is_null());
        assert!(unsafe { CStr::from_ptr(message) }
            .to_str()
            .unwrap()
            .contains("not found"));
    }

    #[cfg(feature = "propmap")]
    #[test]
    fn id_to_defs_enumerates_same_candidate_as_name_to_def() {
        let rust_def = WingConsole::name_to_def("/ch/1/fdr").expect("known propmap entry");
        let id = rust_def.id;

        let count = wing_id_to_defs_count(id);
        assert!(count >= 1);

        let found = (0..count).any(|index| {
            let needed = wing_id_to_defs_get_name(id, index, ptr::null_mut(), 0);
            assert!(needed > 0);
            let mut buf = vec![0_u8; needed as usize];
            let written =
                wing_id_to_defs_get_name(id, index, buf.as_mut_ptr().cast::<c_char>(), buf.len());
            assert_eq!(written, needed);
            let name = unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
                .to_str()
                .unwrap();
            name == "/ch/1/fdr"
        });
        assert!(found, "expected /ch/1/fdr among id_to_defs candidates");

        let def_handle = wing_id_to_defs_get_def(id, 0);
        assert!(!def_handle.is_null());
        assert_eq!(wing_node_definition_get_id(def_handle), id);
        wing_response_destroy(def_handle);
    }

    #[cfg(feature = "propmap")]
    #[test]
    fn id_to_defs_get_name_reports_short_buffer_without_writing() {
        let rust_def = WingConsole::name_to_def("/ch/1/fdr").expect("known propmap entry");
        let mut buf = [0xffu8; 1];
        let needed =
            wing_id_to_defs_get_name(rust_def.id, 0, buf.as_mut_ptr().cast::<c_char>(), buf.len());
        assert!(needed > buf.len() as c_int);
        assert_eq!(buf, [0xff]);
    }

    #[test]
    fn id_to_defs_rejects_unknown_id() {
        assert_eq!(wing_id_to_defs_count(0), 0);
        assert!(wing_id_to_defs_get_def(0, 0).is_null());
        assert_eq!(wing_last_error_code(), WING_ERROR_FFI_USAGE);
    }

    #[test]
    fn last_error_retrievable_after_forced_null_pointer_failure() {
        assert!(wing_console_read(ptr::null_mut()).is_null());
        assert_eq!(wing_last_error_code(), WING_ERROR_FFI_USAGE);
        let message = wing_last_error_message();
        assert!(!message.is_null());
        assert!(unsafe { CStr::from_ptr(message) }
            .to_str()
            .unwrap()
            .contains("null"));
    }

    #[test]
    fn keep_alive_functions_succeed_on_a_fresh_console() {
        let (_sender, _receiver_addr, mut handle) = meter_handle();

        assert_eq!(wing_console_keep_alive(&mut handle), 0);
        assert_eq!(wing_console_keep_alive_meters(&mut handle), 0);
    }

    #[test]
    fn keep_alive_functions_reject_null_handle() {
        assert_eq!(wing_console_keep_alive(ptr::null_mut()), -1);
        assert_eq!(wing_last_error_code(), WING_ERROR_FFI_USAGE);
        assert_eq!(wing_console_keep_alive_meters(ptr::null_mut()), -1);
        assert_eq!(wing_last_error_code(), WING_ERROR_FFI_USAGE);
    }
}

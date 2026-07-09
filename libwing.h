#ifndef LIBWING_H
#define LIBWING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WingDiscoveryInfo WingDiscoveryInfo;
typedef struct WingConsole WingConsole;
typedef struct Response Response;

// Enums
typedef enum {
    WING_RESPONSE_END = 0,
    WING_RESPONSE_NODE_DEFINITION = 1,
    WING_RESPONSE_NODE_DATA = 2
} WingResponseType;

typedef enum {
    WING_NODE_TYPE_NODE = 0,
    WING_NODE_TYPE_LINEAR_FLOAT = 1,
    WING_NODE_TYPE_LOGARITHMIC_FLOAT = 2,
    WING_NODE_TYPE_FADER_LEVEL = 3,
    WING_NODE_TYPE_INTEGER = 4,
    WING_NODE_TYPE_STRING_ENUM = 5,
    WING_NODE_TYPE_FLOAT_ENUM = 6,
    WING_NODE_TYPE_STRING = 7,
    // A type nibble not recognized by this version of libwing (additive sentinel;
    // values 0-7 above are unchanged).
    WING_NODE_TYPE_UNKNOWN = 8
} WingNodeType;

typedef enum {
    WING_NODE_UNIT_NONE = 0,
    WING_NODE_UNIT_DB = 1,
    WING_NODE_UNIT_PERCENT = 2,
    WING_NODE_UNIT_MILLISECONDS = 3,
    WING_NODE_UNIT_HERTZ = 4,
    WING_NODE_UNIT_METERS = 5,
    WING_NODE_UNIT_SECONDS = 6,
    WING_NODE_UNIT_OCTAVES = 7,
    // A unit nibble not recognized by this version of libwing (additive sentinel;
    // values 0-7 above are unchanged).
    WING_NODE_UNIT_UNKNOWN = 8
} WingNodeUnit;

typedef enum {
    CHANNEL = 0xA0,
    AUX = 0xA1,
    BUS = 0xA2,
    MAIN = 0xA3,
    MATRIX = 0xA4,
    DCA = 0xA5,
    FX = 0xA6,
    SOURCE = 0xA7,
    OUTPUT = 0xA8,
    MONITOR = 0xA9,
    RTA = 0xAA,
    CHANNEL2 = 0xAB,
    AUX2 = 0xAC,
    BUS2 = 0xAD,
    MAIN2 = 0xAE,
    MATRIX2 = 0xAF
} MeterType;
#define METER_ID(type, index) (((type << 8) | (index & 0xFF)) & 0xFFFF)

WingDiscoveryInfo* wing_discover_scan                             (int stop_on_first); // Return value must be freed by wing_discover_destroy()
int                wing_discover_count                            (const WingDiscoveryInfo* handle);
char*              wing_discover_get_ip                           (const WingDiscoveryInfo* handle, int index); // Return value must be freed by wing_string_destroy()
char*              wing_discover_get_name                         (const WingDiscoveryInfo* handle, int index); // Return value must be freed by wing_string_destroy()
char*              wing_discover_get_model                        (const WingDiscoveryInfo* handle, int index); // Return value must be freed by wing_string_destroy()
char*              wing_discover_get_serial                       (const WingDiscoveryInfo* handle, int index); // Return value must be freed by wing_string_destroy()
char*              wing_discover_get_firmware                     (const WingDiscoveryInfo* handle, int index); // Return value must be freed by wing_string_destroy()
void               wing_discover_destroy                          (WingDiscoveryInfo* handle);

WingConsole*       wing_console_connect                           (const char* ip); // Return value must be freed by wing_console_destroy()
Response*          wing_console_read                              (WingConsole* handle); // Return value must be freed by wing_response_destroy()
int                wing_console_set_string                        (WingConsole* handle, int32_t id, const char* value);
int                wing_console_set_float                         (WingConsole* handle, int32_t id, float value);
int                wing_console_set_int                           (WingConsole* handle, int32_t id, int value);
int                wing_console_toggle                            (WingConsole* handle, int32_t id); // flip a 0/1 parameter in one write
// Capture the raw hash-addressed native byte stream for the subtree at `id` into out_buf (up to out_capacity).
// Returns bytes written, -2 if out_capacity is too small (nothing copied), or -1 on error. Round-trips through wing_console_set_binary_node().
int                wing_console_get_binary_node                   (WingConsole* handle, int32_t id, int timeout_ms, uint8_t* out_buf, size_t out_capacity);
// Replay a buffer captured by wing_console_get_binary_node(). Returns bytes written to the wire (>= len when escaped), or -1 on error.
int                wing_console_set_binary_node                   (WingConsole* handle, const uint8_t* data, size_t len);
int                wing_console_request_node_definition           (WingConsole* handle, int32_t id);
int                wing_console_request_node_data                 (WingConsole* handle, int32_t id);
uint16_t           wing_console_request_meter                     (WingConsole* handle, uint16_t *meter_ids, size_t len); // see above about meter ids
int                wing_console_read_meter                        (WingConsole* handle, uint16_t *out_id, int16_t *out_data, size_t out_data_capacity);
int                wing_console_read_meter_bounded                (WingConsole* handle, uint16_t *out_id, int16_t *out_data, size_t out_data_capacity);
// read()/read_meters() already send keepalives as needed; call these yourself only if
// you have a loop that doesn't call read()/read_meters() but still wants the
// connection held open. Returns 0 on success, -1 on failure (see wing_last_error_message()).
int                wing_console_keep_alive                        (WingConsole* handle);
int                wing_console_keep_alive_meters                 (WingConsole* handle);
void               wing_console_destroy                           (WingConsole* handle);

WingResponseType   wing_response_get_type                         (const Response* handle);
void               wing_response_destroy                          (Response* handle);

int32_t            wing_node_data_get_id                          (const Response* handle); // id of the changed node (0 if response is not node-data)
char*              wing_node_data_get_string                      (const Response* handle); // Return value must be freed by wing_string_destroy()
float              wing_node_data_get_float                       (const Response* handle);
int                wing_node_data_get_int                         (const Response* handle);
int                wing_node_data_has_string                      (const Response* handle);
int                wing_node_data_has_float                       (const Response* handle);
int                wing_node_data_has_int                         (const Response* handle);

int32_t            wing_node_definition_get_parent_id             (const Response* handle);
int32_t            wing_node_definition_get_id                    (const Response* handle);
uint16_t           wing_node_definition_get_index                 (const Response* handle);
WingNodeType       wing_node_definition_get_type                  (const Response* handle);
WingNodeUnit       wing_node_definition_get_unit                  (const Response* handle);
char*              wing_node_definition_get_name                  (const Response* handle); // Return value must be freed by wing_string_destroy()
char*              wing_node_definition_get_long_name             (const Response* handle); // Return value must be freed by wing_string_destroy()
int                wing_node_definition_is_read_only              (const Response* handle);
int                wing_node_definition_get_min_float             (const Response* handle, float* ret);
int                wing_node_definition_get_max_float             (const Response* handle, float* ret);
int                wing_node_definition_get_steps                 (const Response* handle, int* ret);
int                wing_node_definition_get_min_int               (const Response* handle, int* ret);
int                wing_node_definition_get_max_int               (const Response* handle, int* ret);
int                wing_node_definition_get_max_string_len        (const Response* handle, int* ret);
int                wing_node_definition_get_string_enum_count     (const Response* handle);
int                wing_node_definition_get_float_enum_count      (const Response* handle);
int                wing_node_definition_get_float_enum_item       (const Response* handle, int index, float* ret);
int                wing_node_definition_get_float_enum_long_item  (const Response* handle, int index, char** ret); // On success (returns 1), *ret must be freed by wing_string_destroy()
int                wing_node_definition_get_string_enum_item      (const Response* handle, int index, char** ret); // On success (returns 1), *ret must be freed by wing_string_destroy()
int                wing_node_definition_get_string_enum_long_item (const Response* handle, int index, char** ret); // On success (returns 1), *ret must be freed by wing_string_destroy()

int                wing_name_to_id                                (const char* name, int32_t* out_id);
// Reverse lookup: node definition for a full property-map name (e.g. "/ch/1/fdr"),
// exposed through the SAME accessor family (wing_node_definition_get_*) used for
// definitions read live off the console. NULL if not found (see
// wing_last_error_message()). Return value must be freed by wing_response_destroy().
Response*          wing_name_to_def                               (const char* name);

// A wire id can map to more than one full name (e.g. every "/fx/N/HALL/..." slot
// aliases the same ids across N). These enumerate the candidate names/definitions for
// a given id; 0 candidates is a normal ("not found") result, not an error.
size_t             wing_id_to_defs_count                          (int32_t id);
// Writes the index-th candidate's full name into name_out (NUL-terminated).
// - On success, returns bytes written including the NUL terminator.
// - If name_cap is too small (or name_out is NULL), nothing is written and the
//   required size (including the NUL terminator) is returned anyway -- pass
//   name_out=NULL, name_cap=0 to query the size first. This differs deliberately from
//   wing_console_read_meter_bounded()'s fixed -2 sentinel, which suits a fixed-shape
//   numeric buffer rather than a variable-length C string.
// - Returns -1 if id/index name no known candidate (see wing_last_error_message()).
int                wing_id_to_defs_get_name                       (int32_t id, size_t index, char* name_out, size_t name_cap);
// Node definition for the index-th candidate, through the same accessor family as
// wing_name_to_def(). NULL if id/index name no known candidate. Return value must be
// freed by wing_response_destroy().
Response*          wing_id_to_defs_get_def                        (int32_t id, size_t index);

// Structured last-error (R25): message + code for the most recent failing call made
// from the CURRENT thread (each thread has its own slot). wing_last_error_message()
// returns NULL if nothing has failed yet on this thread; otherwise the pointer is
// owned by the library and valid until the next failing call on the same thread --
// do not free it, and do not pass it to wing_string_destroy(). wing_last_error_code()
// returns 0 if nothing has failed yet, -1 for an FFI-usage error (bad argument
// detected at the FFI boundary, e.g. a null pointer), 1-8 for a specific underlying
// error, or 99 for a future/unrecognized error variant.
const char*        wing_last_error_message                        (void);
int                wing_last_error_code                            (void);

// you must call this to free the memory of any string returned by the library
void               wing_string_destroy                            (char* handle);

#ifdef __cplusplus
}
#endif

#endif /* LIBWING_H */

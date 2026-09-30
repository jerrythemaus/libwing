#include "libwing.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define ABI_ASSERT static_assert
#else
#define ABI_ASSERT _Static_assert
#endif
ABI_ASSERT(sizeof(WingResponseType) == sizeof(int), "response enum ABI");
ABI_ASSERT(sizeof(WingNodeType) == sizeof(int), "node type enum ABI");
ABI_ASSERT(sizeof(WingNodeUnit) == sizeof(int), "node unit enum ABI");
ABI_ASSERT(sizeof(MeterType) == sizeof(int), "meter enum ABI");
ABI_ASSERT(WING_RESPONSE_NODE_DEFINITION == 1, "definition response tag");
ABI_ASSERT(WING_NODE_TYPE_UNKNOWN == 8, "unknown node type tag");
ABI_ASSERT(WING_NODE_UNIT_UNKNOWN == 8, "unknown node unit tag");
ABI_ASSERT(METER_ID(CHANNEL, 1) == 0xA001, "meter ID layout");

int main(void) {
#include "abi_symbols.inc"
    int32_t id = 0;
    assert(wing_last_error_code() == 0);
    assert(wing_last_error_message() == NULL);
    assert(wing_name_to_id("/ch/1/fdr", &id) == 1);
    Response *definition = wing_name_to_def("/ch/1/fdr");
    assert(definition != NULL);
    assert(wing_response_get_type(definition) == WING_RESPONSE_NODE_DEFINITION);
    assert(wing_node_definition_get_id(definition) == id);
    char *name = wing_node_definition_get_name(definition);
    assert(name != NULL && strcmp(name, "fdr") == 0);
    wing_string_destroy(name);
    assert(wing_id_to_defs_count(id) > 0);
    int required = wing_id_to_defs_get_name(id, 0, NULL, 0);
    assert(required > 0);
    char *full_name = (char *)malloc((size_t)required);
    assert(full_name != NULL);
    assert(wing_id_to_defs_get_name(id, 0, full_name, (size_t)required) == required);
    assert(strcmp(full_name, "/ch/1/fdr") == 0);
    free(full_name);
    wing_response_destroy(definition);
    wing_string_destroy(NULL);
    wing_response_destroy(NULL);
    assert(wing_name_to_def("/not/a/console/path") == NULL);
    assert(wing_last_error_code() != 0);
    assert(wing_last_error_message() != NULL);
    return 0;
}

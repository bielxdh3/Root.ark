// Deliberately unrelated N-API addon for a same-environment regression.
// This addon uses Node's single instance-data slot for its own zeroed object.
// A correctly isolated root lab must not consume or free this object.
#include <node_api.h>
#include <stdlib.h>

static void release_other(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  free(data);
}

static napi_value install(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  if (napi_get_cb_info(env, info, &argc, NULL, NULL, NULL) != napi_ok || argc != 0) {
    napi_throw_error(env, NULL, "COMPETITOR_INVALID_ARGUMENT");
    return NULL;
  }
  void *previous = NULL;
  if (napi_get_instance_data(env, &previous) != napi_ok) {
    napi_throw_error(env, NULL, "COMPETITOR_QUERY_FAILED");
    return NULL;
  }
  void *owned = calloc(1, 1024);
  if (!owned) {
    napi_throw_error(env, NULL, "COMPETITOR_ALLOCATION_FAILED");
    return NULL;
  }
  if (napi_set_instance_data(env, owned, release_other, NULL) != napi_ok) {
    free(owned);
    napi_throw_error(env, NULL, "COMPETITOR_SLOT_FAILED");
    return NULL;
  }
  napi_value outcome;
  const char *category = previous == NULL ? "COMPETITOR_SLOT_EMPTY" : "COMPETITOR_SLOT_OCCUPIED";
  if (napi_create_string_utf8(env, category, NAPI_AUTO_LENGTH, &outcome) != napi_ok) return NULL;
  return outcome;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor property = {
    "install", NULL, install, NULL, NULL, NULL, napi_default, NULL,
  };
  if (napi_define_properties(env, exports, 1, &property) != napi_ok) return NULL;
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

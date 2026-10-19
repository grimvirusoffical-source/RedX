/*
 * RedX C ABI: a shared library built from the Go SDK (sdk/go/cabi) for C, C++ and game engines (Unreal, native
 * plugins). Build: go build -buildmode=c-shared -o libredx.so ./cabi   (libredx.dylib on macOS, redx.dll on Windows)
 * On macOS, set an rpath install name afterwards: install_name_tool -id @rpath/libredx.dylib libredx.dylib
 *
 * Every function that returns char* returns a NUL-terminated JSON document that the caller frees with redx_free:
 *   success: {"ok":true,"status":200,"body":<JSON value | string for Box text>,"body_base64":"<binary bodies>"}
 *   failure: {"ok":false,"status":<HTTP status, 0 = not sent/no answer>,"code":"<host code | confirm_required>","error":"<message>"}
 * Error messages never contain the API key. Handles are opaque positive integers; all functions are thread-safe.
 * Operations whose danger is REDX_DANGER_DANGEROUS are refused unless args contain "confirm": true.
 */
#ifndef REDX_H
#define REDX_H

#include <stdint.h>
#include "redx_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* config: {"url":"http://127.0.0.1:7777","key":"...","db":"game","pin":"<sha256 hex>","timeout_ms":30000}.
 * Returns a handle > 0, or 0 with *error_out set (a JSON document to free; error_out may be NULL). */
int64_t redx_client_new(const char *config_json, char **error_out);
void redx_client_free(int64_t client);

/* Any operation of api/redx-api.json by id (REDX_OP_* in redx_ops.h).
 * args: {"db":"...","params":{"pack":"p","file":"a/b.bin"},"query":{...},"body":<JSON>,"raw_base64":"...",
 *        "headers":{"Range":"bytes=0-9"},"confirm":true} (all optional) */
char *redx_call(int64_t client, const char *op_id, const char *args_json);

/* Shortcuts: value of a path decoded to JSON; write a JSON value (ttl_seconds 0 = no TTL); one BoxQL command. */
char *redx_get(int64_t client, const char *path);
char *redx_set(int64_t client, const char *path, const char *value_json, int32_t ttl_seconds);
char *redx_bx(int64_t client, const char *boxql, const char *params_json);

/* Streams (subscribe, bxWatch, rulesSubscribe). reconnect != 0 reconnects with backoff after an unexpected close.
 * redx_stream_next waits up to timeout_ms and returns {"ok":true,"event":{path,op,value,at,data}},
 * {"ok":true,"timeout":true} or {"ok":false,"closed":true,"error":"..."}. */
int64_t redx_stream_open(int64_t client, const char *op_id, const char *args_json, int32_t reconnect, char **error_out);
char *redx_stream_next(int64_t stream, int32_t timeout_ms);
void redx_stream_close(int64_t stream);

/* REDX_DANGER_* of an operation id (REDX_DANGER_DANGEROUS for an unknown id). */
int32_t redx_danger_level(const char *op_id);
/* Library version (static; do not free). */
const char *redx_version(void);
void redx_free(char *p);

#ifdef __cplusplus
}
#endif
#endif

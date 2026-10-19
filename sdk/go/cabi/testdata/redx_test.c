/* Exercises the C ABI against a real redxd. Env: REDX_URL, REDX_KEY (never printed). Exit 0 = all passed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "redx.h"

static int failures = 0;
static void check(int cond, const char *what, const char *detail) {
  if (cond) { printf("PASS  %s\n", what); return; }
  printf("FAIL  %s: %s\n", what, detail ? detail : "");
  failures++;
}
static int has(const char *s, const char *needle) { return s && strstr(s, needle) != NULL; }

int main(void) {
  const char *url = getenv("REDX_URL"), *key = getenv("REDX_KEY");
  if (!url || !key) { fprintf(stderr, "REDX_URL and REDX_KEY are needed\n"); return 2; }
  char cfg[512];
  snprintf(cfg, sizeof cfg, "{\"url\":\"%s\",\"key\":\"%s\"}", url, key);
  char *err = NULL;
  int64_t c = redx_client_new(cfg, &err);
  check(c > 0, "client_new", err);
  if (err) { redx_free(err); err = NULL; }

  int64_t bad = redx_client_new("{\"url\":\"ftp://x\"}", &err);
  check(bad == 0 && has(err, "\"ok\":false"), "client_new refuses a bad url", err);
  redx_free(err); err = NULL;

  check(redx_danger_level(REDX_OP_DELETE_DATABASE) == REDX_DANGER_DANGEROUS, "danger level of deleteDatabase", NULL);
  check(redx_danger_level(REDX_OP_GET_PATH) == REDX_DANGER_SAFE, "danger level of getPath", NULL);
  check(strlen(redx_version()) > 0, "version", NULL);

  char *r = redx_call(c, REDX_OP_CREATE_DATABASE, "{\"body\":{\"name\":\"sdkc\"}}");
  check(has(r, "\"ok\":true"), "createDatabase", r); redx_free(r);

  r = redx_call(c, REDX_OP_DELETE_DATABASE, "{\"db\":\"sdkc\"}");
  check(has(r, "confirm_required"), "dangerous call refused without confirm", r); redx_free(r);

  /* a second client on the new database */
  snprintf(cfg, sizeof cfg, "{\"url\":\"%s\",\"key\":\"%s\",\"db\":\"sdkc\"}", url, key);
  int64_t d = redx_client_new(cfg, NULL);
  r = redx_set(d, "p.red-xai.db:P[ID=1]", "{\"Name\":\"Ann\",\"Level\":5}", 0);
  check(has(r, "\"ok\":true"), "set", r); redx_free(r);
  r = redx_get(d, "p.red-xai.db:P[ID=1].Name");
  check(has(r, "\"body\":\"Ann\""), "get", r); redx_free(r);
  r = redx_bx(d, "{Get[]} = p:P[Level >= $min] -> Name", "{\"min\":3}");
  check(has(r, "\"count\":1"), "bx with params", r); redx_free(r);
  r = redx_get(d, "p.red-xai.db:P[ID=404]");
  check(has(r, "\"status\":404"), "missing path is 404", r);
  check(!has(r, "rx_live_"), "no key in errors", NULL); redx_free(r);

  r = redx_call(d, REDX_OP_PACK_PUT, "{\"params\":{\"pack\":\"assets\",\"file\":\"a/b.bin\"},\"raw_base64\":\"aGVsbG8gd29ybGQ=\"}");
  check(has(r, "\"ok\":true"), "pack upload", r); redx_free(r);
  r = redx_call(d, REDX_OP_PACK_GET, "{\"params\":{\"pack\":\"assets\",\"file\":\"a/b.bin\"},\"headers\":{\"Range\":\"bytes=0-4\"}}");
  check(has(r, "\"body_base64\":\"aGVsbG8=\""), "pack range download", r); redx_free(r);

  int64_t s = redx_stream_open(d, "subscribe", "{\"query\":{\"path\":\"w.red-xai.db:*\"}}", 1, &err);
  check(s > 0, "stream_open", err);
  if (err) { redx_free(err); err = NULL; }
  r = redx_stream_next(s, 200);
  check(has(r, "\"timeout\":true"), "stream timeout", r); redx_free(r);
  r = redx_set(d, "w.red-xai.db:W[ID=1]", "{\"A\":1}", 0); redx_free(r);
  r = redx_stream_next(s, 8000);
  check(has(r, "\"path\":\"w.red-xai.db:W[ID=1]\"") && has(r, "\"data\":{\"A\":1}"), "stream event", r); redx_free(r);
  redx_stream_close(s);

  r = redx_call(c, REDX_OP_DELETE_DATABASE, "{\"db\":\"sdkc\",\"confirm\":true}");
  check(has(r, "\"ok\":true"), "deleteDatabase confirmed", r); redx_free(r);
  redx_client_free(d);
  redx_client_free(c);
  r = redx_get(c, "x");
  check(has(r, "unknown client handle"), "freed handle", r); redx_free(r);
  printf(failures ? "C ABI: %d FAILED\n" : "C ABI: all passed\n", failures);
  return failures ? 1 : 0;
}

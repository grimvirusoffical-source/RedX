# Game engines

RedX is plain HTTP + JSON (and a WebSocket for streams), so any engine can use it. These recipes are **not tested in the engines themselves**; the libraries they build on (the C# SDK, the C ABI) are tested against a real `redxd`. The full route list is in [`api/openapi.json`](../api/openapi.json).

Rules that apply everywhere:

* Send the key as `Authorization: Bearer <key>`. Use a **scoped** key for a shipped game (a write key limited to a prefix such as `saves`, from [connect](connect.md) or `redx key create`), never an admin key.
* Paths go in the URL path, percent-encoded: `GET /v1/db/game/path/saves.red-xai.db%3AS%5BID%3D1%5D`. Values you `PUT` are JSON (`Content-Type: application/json`) or Box text.
* Streams: `GET /v1/db/<db>/subscribe?path=<pattern>` upgraded to a WebSocket, with the same `Authorization` header. Each message is JSON `{path, op, value, at}`. Missed events are not replayed after a reconnect.
* Keep the key out of logs and crash reports.

## Unity (C#)

Option 1: add the C# SDK (`sdk/csharp/RedX`, netstandard2.1, which Unity 2021.2+ supports) as source or a built DLL with its `System.Text.Json` and `System.Threading.Channels` dependencies, then `await new RedXClient(url, key, db: "game").SetAsync(...)`.

Option 2: `UnityWebRequest`, no dependencies:

```csharp
var path = UnityWebRequest.EscapeURL("saves.red-xai.db:S[ID=1]").Replace("+", "%20");
var req = new UnityWebRequest($"{url}/v1/db/game/path/{path}", "PUT");
req.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes("{\"Level\":3}"));
req.downloadHandler = new DownloadHandlerBuffer();
req.SetRequestHeader("Authorization", "Bearer " + key);
req.SetRequestHeader("Content-Type", "application/json");
yield return req.SendWebRequest();
if (req.result != UnityWebRequest.Result.Success) Debug.LogWarning($"RedX {req.responseCode}");
```

WebGL builds cannot set headers on browser WebSockets, so streams there need a different transport; use polling or an engine-side relay.

## Godot 4 (GDScript or C#)

GDScript with `HTTPRequest`:

```gdscript
var http := HTTPRequest.new()
add_child(http)
var path := "saves.red-xai.db:S[ID=1]".uri_encode()
http.request("%s/v1/db/game/path/%s" % [url, path], ["Authorization: Bearer " + key], HTTPClient.METHOD_GET)
var res = await http.request_completed   # [result, code, headers, body]
if res[1] == 200: print(res[3].get_string_from_utf8())   # Box text
```

Streams with `WebSocketPeer`:

```gdscript
var ws := WebSocketPeer.new()
ws.handshake_headers = PackedStringArray(["Authorization: Bearer " + key])
ws.connect_to_url(url.replace("http", "ws") + "/v1/db/game/subscribe?path=" + "saves.red-xai.db:*".uri_encode())
# in _process: ws.poll(); while ws.get_available_packet_count() > 0: JSON.parse_string(ws.get_packet().get_string_from_utf8())
```

Godot's .NET build can use the C# SDK directly (net8.0).

## Unreal Engine (C++)

Option 1: the C ABI. Build `libredx` with `go build -buildmode=c-shared -o libredx.so ./cabi` in `sdk/go` (`.dylib` on macOS, then `install_name_tool -id @rpath/libredx.dylib libredx.dylib`; `redx.dll` on Windows), add it and `include/redx.h` to a plugin as a third-party library, and call it off the game thread:

```cpp
char* err = nullptr;
int64_t h = redx_client_new("{\"url\":\"http://127.0.0.1:7777\",\"key\":\"...\",\"db\":\"game\"}", &err);
char* out = redx_set(h, "saves.red-xai.db:S[ID=1]", "{\"Level\":3}", 0);   // JSON result: {"ok":true,...}
redx_free(out);
int64_t s = redx_stream_open(h, "subscribe", "{\"query\":{\"path\":\"saves.red-xai.db:*\"}}", 1, &err);
char* ev = redx_stream_next(s, 1000);   // NULL on timeout
```

Every returned string is freed with `redx_free`. Building the library needs Go and a C toolchain for the target; console platforms are not supported by Go's c-shared mode.

Option 2: `FHttpModule`, no native library:

```cpp
auto Req = FHttpModule::Get().CreateRequest();
Req->SetURL(Url + TEXT("/v1/db/game/path/") + FGenericPlatformHttp::UrlEncode(TEXT("saves.red-xai.db:S[ID=1]")));
Req->SetVerb(TEXT("PUT"));
Req->SetHeader(TEXT("Authorization"), TEXT("Bearer ") + Key);
Req->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
Req->SetContentAsString(TEXT("{\"Level\":3}"));
Req->OnProcessRequestComplete().BindLambda([](FHttpRequestPtr, FHttpResponsePtr R, bool Ok) { /* R->GetResponseCode() */ });
Req->ProcessRequest();
```

Streams: Unreal's `WebSockets` module (`FWebSocketsModule::Get().CreateWebSocket(WsUrl, TEXT(""), {{TEXT("Authorization"), TEXT("Bearer ") + Key}})`).

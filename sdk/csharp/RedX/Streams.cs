#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace RedX
{
    /// <summary>One change from Subscribe or Watch. Value is Box text; Data its decoded form.</summary>
    public sealed class RedXEvent
    {
        public string Path = "", Op = "", Value = "", At = "";
        public object? Data;
        public JsonElement Raw;
    }

    /// <summary>
    /// Stream options. With Reconnect an unexpected close is followed by reconnects with exponential backoff
    /// (jittered). Events while disconnected are not replayed: re-read state in OnReconnect. A refusal
    /// (400/401/403/404) ends the stream.
    /// </summary>
    public sealed class StreamOptions
    {
        public bool Reconnect;
        public TimeSpan MinBackoff = TimeSpan.FromMilliseconds(250);
        public TimeSpan MaxBackoff = TimeSpan.FromSeconds(10);
        public Action? OnReconnect;
        public Action<Exception>? OnError;
    }

    /// <summary>An open stream. Read events with ReadAsync or ReadAllAsync; Dispose ends it.</summary>
    public sealed class RedXStream : IAsyncDisposable, IDisposable
    {
        readonly Channel<RedXEvent> ch = Channel.CreateBounded<RedXEvent>(256);
        readonly CancellationTokenSource cts = new CancellationTokenSource();
        Task? loop;
        public Exception? Error { get; private set; }
        internal RedXStream() { }

        /// <summary>The next event, or null when the stream ended.</summary>
        public async Task<RedXEvent?> ReadAsync(CancellationToken ct = default)
        {
            try { return await ch.Reader.ReadAsync(ct).ConfigureAwait(false); }
            catch (ChannelClosedException) { return null; }
        }

        public IAsyncEnumerable<RedXEvent> ReadAllAsync(CancellationToken ct = default) => ch.Reader.ReadAllAsync(ct);

        internal void Start(Func<CancellationToken, Task<ClientWebSocket>> dial, ClientWebSocket first, StreamOptions o) =>
            loop = Task.Run(() => Run(dial, first, o));

        async Task Run(Func<CancellationToken, Task<ClientWebSocket>> dial, ClientWebSocket ws, StreamOptions o)
        {
            var rnd = new Random();
            try
            {
                for (;;)
                {
                    await Pump(ws).ConfigureAwait(false);
                    ws.Dispose();
                    if (cts.IsCancellationRequested) return;
                    if (!o.Reconnect) { Error = new RedXException(0, "stream closed by the host"); o.OnError?.Invoke(Error); return; }
                    var delay = o.MinBackoff;
                    for (;;)
                    {
                        var ms = delay.TotalMilliseconds / 2 + rnd.NextDouble() * delay.TotalMilliseconds / 2;
                        try { await Task.Delay(TimeSpan.FromMilliseconds(ms), cts.Token).ConfigureAwait(false); }
                        catch (OperationCanceledException) { return; }
                        delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, o.MaxBackoff.TotalMilliseconds));
                        try { ws = await dial(cts.Token).ConfigureAwait(false); }
                        catch (RedXException e) when (e.Status == 400 || e.Status == 401 || e.Status == 403 || e.Status == 404)
                        { Error = e; o.OnError?.Invoke(e); return; }
                        catch (OperationCanceledException) { return; }
                        catch (Exception) { continue; }
                        o.OnReconnect?.Invoke();
                        break;
                    }
                }
            }
            finally { ch.Writer.TryComplete(); }
        }

        async Task Pump(ClientWebSocket ws)
        {
            var buf = new byte[64 * 1024];
            using var ms = new MemoryStream();
            try
            {
                while (ws.State == WebSocketState.Open)
                {
                    var r = await ws.ReceiveAsync(new ArraySegment<byte>(buf), cts.Token).ConfigureAwait(false);
                    if (r.MessageType == WebSocketMessageType.Close) break;
                    ms.Write(buf, 0, r.Count);
                    if (!r.EndOfMessage) continue;
                    var text = Encoding.UTF8.GetString(ms.ToArray());
                    ms.SetLength(0);
                    RedXEvent ev;
                    try
                    {
                        using var d = JsonDocument.Parse(text);
                        var e = d.RootElement;
                        string S(string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
                        ev = new RedXEvent { Path = S("path"), Op = S("op"), Value = S("value"), At = S("at"), Raw = e.Clone() };
                    }
                    catch (JsonException) { continue; }
                    if (ev.Op == "set" && ev.Value != "") { try { ev.Data = BoxText.Decode(ev.Value); } catch (BoxTextException) { } }
                    await ch.Writer.WriteAsync(ev, cts.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (WebSocketException) { }
            if (cts.IsCancellationRequested && ws.State == WebSocketState.Open)
            {
                using var t = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", t.Token).ConfigureAwait(false); } catch { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            if (loop != null) { try { await loop.ConfigureAwait(false); } catch { } }
        }

        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public partial class RedXClient
    {
        /// <summary>Changes matching a path pattern such as "players.red-xai.db:Player[ID=*]".</summary>
        public Task<RedXStream> SubscribeAsync(string pattern, StreamOptions? o = null, string? db = null, CancellationToken ct = default) =>
            StreamAsync("subscribe", new Dictionary<string, object?> { ["path"] = pattern }, o, db, ct);

        /// <summary>The changes a BoxQL {Watch[]} command matches.</summary>
        public Task<RedXStream> WatchAsync(string q, IDictionary<string, object?>? parameters = null, StreamOptions? o = null, string? db = null, CancellationToken ct = default)
        {
            var query = new Dictionary<string, object?> { ["q"] = q };
            if (parameters != null) query["params"] = JsonSerializer.Serialize(parameters);
            return StreamAsync("bxWatch", query, o, db, ct);
        }

        /// <summary>Open any WebSocket operation (subscribe, bxWatch, rulesSubscribe) by id.</summary>
        public async Task<RedXStream> StreamAsync(string opId, IDictionary<string, object?>? query = null, StreamOptions? o = null, string? db = null, CancellationToken ct = default)
        {
            if (!Operations.All.TryGetValue(opId, out var op) || op.Response != "websocket") throw new ArgumentException($"{opId} is not a stream operation");
            var url = "ws" + BaseUrl.Substring(4) + OpPath(op, db, null) + QueryString(query);
            Task<ClientWebSocket> Dial(CancellationToken t) => DialAsync(new Uri(url), t);
            var first = await Dial(ct).ConfigureAwait(false);
            var s = new RedXStream();
            s.Start(Dial, first, o ?? new StreamOptions());
            return s;
        }

        async Task<ClientWebSocket> DialAsync(Uri url, CancellationToken ct)
        {
            var ws = new ClientWebSocket();
            if (Key != "") ws.Options.SetRequestHeader("Authorization", "Bearer " + Key);
            if (Pin != null) ws.Options.RemoteCertificateValidationCallback = (_, cert, _, _) => PinMatches(cert, Pin);
            try
            {
                using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
                t.CancelAfter(TimeSpan.FromSeconds(15));
                await ws.ConnectAsync(url, t.Token).ConfigureAwait(false);
                return ws;
            }
            catch (WebSocketException e)
            {
                ws.Dispose();
                // the handshake status is not exposed on every runtime; ask the host what is wrong with a plain GET
                var status = await ProbeAsync(url, ct).ConfigureAwait(false);
                throw new RedXException(status.Item1, Scrub(status.Item2 ?? ("stream: " + e.Message)), status.Item3);
            }
        }

        async Task<(int, string?, string?)> ProbeAsync(Uri wsUrl, CancellationToken ct)
        {
            try
            {
                var u = "http" + wsUrl.ToString().Substring(2);
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, u);
                if (Key != "") req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Key);
                using var res = await http.SendAsync(req, ct).ConfigureAwait(false);
                // A plain GET that got past every host check (key, scope, path, database) is answered by the
                // WebSocket upgrader itself ("not a websocket handshake", with Sec-WebSocket-Version). That says
                // the stream WOULD be accepted, so the dial failure was transient (e.g. the host was still
                // starting when the handshake ran, and up by the time of the probe): never report it as a refusal.
                if (IsUpgradeOnlyRejection(res)) return (0, null, null);
                var body = await res.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var ex = ErrorFrom((int)res.StatusCode, null, body);
                return ((int)res.StatusCode >= 400 ? (int)res.StatusCode : 0, (int)res.StatusCode >= 400 ? ex.Message : null, ex.Code);
            }
            catch (Exception) { return (0, null, null); }
        }

        internal static bool IsUpgradeOnlyRejection(System.Net.Http.HttpResponseMessage res) =>
            (int)res.StatusCode < 500 && res.Headers.Contains("Sec-WebSocket-Version");
    }
}

#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace RedX
{
    /// <summary>A refused or failed call. Status 0: not answered, or refused by the client (Code "confirm_required").</summary>
    public sealed class RedXException : Exception
    {
        public int Status { get; }
        public string? Code { get; }
        public TimeSpan? RetryAfter { get; }
        public RedXException(int status, string message, string? code = null, TimeSpan? retryAfter = null) : base(message)
        {
            Status = status; Code = code; RetryAfter = retryAfter;
        }
    }

    /// <summary>A successful response.</summary>
    public sealed class RedXResult
    {
        public int Status { get; internal set; }
        public HttpResponseHeaders? Headers { get; internal set; }
        public byte[] Body { get; internal set; } = Array.Empty<byte>();
        public string Text() => Encoding.UTF8.GetString(Body);
        /// <summary>The JSON body (an empty object for an empty body).</summary>
        public JsonElement Json()
        {
            if (Body.Length == 0) return JsonDocument.Parse("{}").RootElement.Clone();
            using var d = JsonDocument.Parse(Body);
            return d.RootElement.Clone();
        }
    }

    /// <summary>TTL options of Set (seconds; null values are not sent).</summary>
    public sealed class WriteOptions
    {
        public int? Ttl; public bool? Sliding; public int? Checkpoint;
    }

    /// <summary>
    /// Client for one RedX host and key. Every operation of api/redx-api.json is a method (Operations.g.cs) and
    /// CallAsync runs any of them by id. Dangerous operations need confirm: true. The key never appears in
    /// ToString() or in exception messages.
    /// </summary>
    public partial class RedXClient : IDisposable
    {
        static readonly Regex DbName = new Regex("^[a-z0-9][a-z0-9_-]{0,62}$");
        static readonly Regex KeyShape = new Regex("rx_live_[A-Za-z0-9]+");
        static readonly Regex Param = new Regex(@"\{([a-z]+)\}");

        readonly string key;
        readonly HttpClient http;
        readonly bool ownsHttp;
        internal readonly string? Pin;
        public string BaseUrl { get; }
        public string? Db { get; }
        public TimeSpan Timeout { get; }

        /// <param name="url">http(s)://host[:port]</param>
        /// <param name="key">API key; may be empty for operations that need none</param>
        /// <param name="db">database (null: the host's default)</param>
        /// <param name="pin">SHA-256 (hex) of the host's certificate, for self-signed hosts</param>
        /// <param name="timeout">per-request timeout (default 30 s; streams are not affected)</param>
        public RedXClient(string url, string key, string? db = null, string? pin = null, TimeSpan? timeout = null)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https"))
                throw new ArgumentException("url must be http(s)://host[:port]");
            if (db != null && !DbName.IsMatch(db)) throw new ArgumentException("invalid db name");
            BaseUrl = u.GetLeftPart(UriPartial.Authority);
            this.key = key ?? "";
            Db = db;
            Timeout = timeout ?? TimeSpan.FromSeconds(30);
            if (pin != null)
            {
                Pin = pin.Replace(":", "").ToLowerInvariant();
                if (Pin.Length != 64) throw new ArgumentException("pin must be a SHA-256 in hex");
            }
            var handler = new HttpClientHandler { AllowAutoRedirect = false };
            if (Pin != null) handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => PinMatches(cert, Pin);
            http = new HttpClient(handler) { Timeout = Timeout };
            ownsHttp = true;
        }

        RedXClient(RedXClient o, string db)
        {
            BaseUrl = o.BaseUrl; key = o.key; Db = db; Timeout = o.Timeout; Pin = o.Pin; http = o.http; ownsHttp = false;
        }

        /// <summary>A client for another database sharing this one's key and connection pool.</summary>
        public RedXClient WithDb(string db)
        {
            if (!DbName.IsMatch(db)) throw new ArgumentException("invalid db name");
            return new RedXClient(this, db);
        }

        public override string ToString() => $"RedXClient({BaseUrl}, db={Db ?? "(default)"})";
        public void Dispose() { if (ownsHttp) http.Dispose(); }

        internal string Key => key;

        internal static bool PinMatches(X509Certificate? cert, string pin)
        {
            if (cert == null) return false;
            using var sha = SHA256.Create();
            var hex = BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-", "").ToLowerInvariant();
            return CryptographicEquals(hex, pin);
        }

        static bool CryptographicEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }

        internal static string Scrub(string s) => KeyShape.Replace(s, "rx_live_[redacted]");

        /// <summary>The danger of an operation id (Dangerous for an unknown id).</summary>
        public static DangerLevel DangerOf(string opId) =>
            Operations.All.TryGetValue(opId, out var op) ? op.Danger : DangerLevel.Dangerous;

        internal string OpPath(Operation op, string? db, IDictionary<string, string>? pathParams)
        {
            var p = op.Path;
            if (p.Contains("{db}"))
            {
                var d = db ?? Db;
                if (d != null && !DbName.IsMatch(d)) throw new ArgumentException("invalid db name");
                if (string.IsNullOrEmpty(d) && op.Shorthand != "") p = op.Shorthand;
                else p = p.Replace("{db}", string.IsNullOrEmpty(d) ? "default" : d);
            }
            return Param.Replace(p, m =>
            {
                var n = m.Groups[1].Value;
                string? v = null;
                if (pathParams != null) pathParams.TryGetValue(n, out v);
                if (string.IsNullOrEmpty(v))
                {
                    if (n == "folder") return "";
                    throw new ArgumentException($"{op.Id} needs {n}");
                }
                if (Operations.SegmentParams.Contains(n))
                    return string.Join("/", v!.Split('/').Select(Uri.EscapeDataString));
                return Uri.EscapeDataString(v!);
            });
        }

        internal static string QueryString(IDictionary<string, object?>? q)
        {
            if (q == null) return "";
            var parts = new List<string>();
            foreach (var kv in q.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                if (kv.Value == null) continue;
                string v = kv.Value switch
                {
                    bool b => b ? "1" : "0",
                    IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                    _ => kv.Value.ToString() ?? "",
                };
                parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(v));
            }
            return parts.Count == 0 ? "" : "?" + string.Join("&", parts);
        }

        /// <summary>Run any operation by id.</summary>
        public async Task<RedXResult> CallAsync(string opId, IDictionary<string, string>? pathParams = null, string? db = null,
            object? body = null, byte[]? raw = null, IDictionary<string, object?>? query = null, bool confirm = false,
            CancellationToken ct = default, IDictionary<string, string>? headers = null)
        {
            if (!Operations.All.TryGetValue(opId, out var op)) throw new ArgumentException($"unknown operation {opId}");
            if (op.Response == "websocket") throw new ArgumentException($"{opId} is a stream: use StreamAsync");
            if (op.Danger == DangerLevel.Dangerous && !confirm)
                throw new RedXException(0, $"{opId} is a dangerous operation ({op.Summary}) and needs confirm: true", "confirm_required");
            var q = query == null ? new Dictionary<string, object?>() : new Dictionary<string, object?>(query);
            if (op.HostConfirm != "")
            {
                string? v = null;
                if (op.HostConfirm == "db") v = db ?? Db ?? "default";
                else pathParams?.TryGetValue(op.HostConfirm, out v);
                q["confirm"] = v;
            }
            var url = BaseUrl + OpPath(op, db, pathParams) + QueryString(q);
            using var req = new HttpRequestMessage(new HttpMethod(op.Method), url);
            if (op.Auth != "none" && key != "") req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
            HttpContent? content = null;
            switch (op.Request)
            {
                case "json":
                    content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(body ?? new Dictionary<string, object>()));
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                    break;
                case "text":
                    content = new ByteArrayContent(raw ?? Array.Empty<byte>());
                    content.Headers.ContentType = new MediaTypeHeaderValue("text/x-redx-box");
                    break;
                case "binary":
                    if (raw == null) throw new ArgumentException($"{opId} needs raw bytes");
                    content = new ByteArrayContent(raw);
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                    if (headers == null || !headers.Keys.Any(k => k.Equals("X-Redx-SHA256", StringComparison.OrdinalIgnoreCase)))
                    {
                        using var sha = SHA256.Create();
                        req.Headers.TryAddWithoutValidation("X-Redx-SHA256", BitConverter.ToString(sha.ComputeHash(raw)).Replace("-", "").ToLowerInvariant());
                    }
                    break;
            }
            req.Content = content;
            if (op.Response == "text") req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/x-redx-box"));
            if (confirm) req.Headers.TryAddWithoutValidation("X-RedX-Confirm", opId);
            if (headers != null) foreach (var kv in headers) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            HttpResponseMessage res;
            try { res = await http.SendAsync(req, ct).ConfigureAwait(false); }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested) { throw new RedXException(0, $"request timed out after {Timeout}"); }
            catch (HttpRequestException e) { throw new RedXException(0, Scrub("request failed: " + e.Message)); }
            using (res)
            {
                var bytes = await res.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                if ((int)res.StatusCode >= 300) throw ErrorFrom((int)res.StatusCode, res.Headers.RetryAfter?.Delta, bytes);
                return new RedXResult { Status = (int)res.StatusCode, Headers = res.Headers, Body = bytes };
            }
        }

        internal static RedXException ErrorFrom(int status, TimeSpan? retryAfter, byte[] body)
        {
            string msg = "HTTP " + status;
            string? code = null;
            try
            {
                using var d = JsonDocument.Parse(body);
                if (d.RootElement.ValueKind == JsonValueKind.Object)
                {
                    if (d.RootElement.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String) msg = e.GetString()!;
                    if (d.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) code = c.GetString();
                }
            }
            catch (JsonException) { }
            return new RedXException(status, Scrub(msg), code, retryAfter);
        }

        // ---- convenience calls (same names in every RedX SDK) ----

        /// <summary>The value at path decoded from Box text (see BoxText.Decode).</summary>
        public async Task<object?> GetAsync(string path, CancellationToken ct = default)
        {
            var r = await GetPathAsync(path, ct: ct).ConfigureAwait(false);
            var j = r.Json();
            if (!j.TryGetProperty("value", out var v) || v.ValueKind != JsonValueKind.String)
                throw new RedXException(0, "unexpected response shape");
            return BoxText.Decode(v.GetString()!);
        }

        /// <summary>The value at path as raw Box text.</summary>
        public async Task<string> GetBoxAsync(string path, CancellationToken ct = default) =>
            (await GetPathBoxAsync(path, ct: ct).ConfigureAwait(false)).Text();

        /// <summary>Write a JSON-serializable value (objects become boxes, null becomes NELL).</summary>
        public Task<RedXResult> SetAsync(string path, object? value, WriteOptions? o = null, CancellationToken ct = default)
        {
            var b = new Dictionary<string, object?> { ["value"] = value };
            if (o?.Ttl != null) b["ttl_seconds"] = o.Ttl;
            if (o?.Sliding != null) b["sliding"] = o.Sliding;
            if (o?.Checkpoint != null) b["checkpoint_seconds"] = o.Checkpoint;
            return SetPathAsync(path, body: b, ct: ct);
        }

        public Task<RedXResult> DeleteAsync(string path, CancellationToken ct = default) => DeletePathAsync(path, ct: ct);

        /// <summary>One BoxQL command with $params; the host's result (kind, columns, rows, count, results...).</summary>
        public async Task<JsonElement> BxAsync(string q, IDictionary<string, object?>? parameters = null, string? db = null, CancellationToken ct = default) =>
            (await CallAsync("bx", null, db, new Dictionary<string, object?> { ["q"] = q, ["params"] = parameters ?? new Dictionary<string, object?>() }, ct: ct).ConfigureAwait(false)).Json();

        /// <summary>Several BoxQL commands, all-or-nothing.</summary>
        public Task<JsonElement> TxAsync(IEnumerable<string> commands, IDictionary<string, object?>? parameters = null, CancellationToken ct = default)
        {
            var list = commands.ToList();
            if (list.Count == 0) throw new ArgumentException("TxAsync needs at least one command");
            return BxAsync("{Tx[]} = [\n  " + string.Join(",\n  ", list) + "\n]", parameters, null, ct);
        }

        public Task<RedXResult> UploadFileAsync(string pack, string file, byte[] data, CancellationToken ct = default) =>
            PackPutAsync(pack, file, data, ct: ct);

        /// <summary>Download a pack file; start/end are inclusive byte offsets (end null: to the end).</summary>
        public async Task<byte[]> DownloadFileAsync(string pack, string file, long? start = null, long? end = null, CancellationToken ct = default) =>
            (await CallAsync("packGet", new Dictionary<string, string> { ["pack"] = pack, ["file"] = file }, ct: ct, headers: Range(start, end)).ConfigureAwait(false)).Body;

        public Task<RedXResult> UploadMediaAsync(string lib, string name, byte[] data, string? mediaType = null, CancellationToken ct = default) =>
            MediaPutAsync(lib, name, data, query: mediaType == null ? null : new Dictionary<string, object?> { ["type"] = mediaType }, ct: ct);

        public async Task<byte[]> DownloadMediaAsync(string lib, string name, long? start = null, long? end = null, CancellationToken ct = default) =>
            (await CallAsync("mediaGet", new Dictionary<string, string> { ["lib"] = lib, ["name"] = name }, ct: ct, headers: Range(start, end)).ConfigureAwait(false)).Body;

        static IDictionary<string, string>? Range(long? start, long? end) =>
            start == null && end == null ? null : new Dictionary<string, string> { ["Range"] = $"bytes={start ?? 0}-{(end == null ? "" : end.Value.ToString(CultureInfo.InvariantCulture))}" };
    }
}

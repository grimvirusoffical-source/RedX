#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace RedX
{
    /// <summary>The app side of the connect handshake (docs/connect.md).</summary>
    public static class Connect
    {
        public sealed class Request
        {
            public string State = "", Verifier = "", Challenge = "";
        }

        public sealed class Callback
        {
            public string Code = "", State = "", Host = "", Pin = "";
        }

        static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>A fresh state and PKCE S256 pair. Keep State and Verifier private until the exchange.</summary>
        public static Request NewRequest()
        {
            var v = new byte[32]; var st = new byte[24];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(v); rng.GetBytes(st); }
            var verifier = B64Url(v);
            using var sha = SHA256.Create();
            return new Request { State = B64Url(st), Verifier = verifier, Challenge = B64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier))) };
        }

        static readonly string[] Fields = { "app", "workspace", "scope", "prefix", "label", "callback", "host", "pin", "name" };

        /// <summary>The link the owner opens: redx://connect?... or consoleUrl/#/connect?...</summary>
        public static string Link(string provider, Request rq, IDictionary<string, string>? options = null, string? consoleUrl = null)
        {
            var q = new List<string> { "v=1", "provider=" + Uri.EscapeDataString(provider), "state=" + Uri.EscapeDataString(rq.State) };
            if (options != null)
                foreach (var f in Fields)
                    if (options.TryGetValue(f, out var v) && !string.IsNullOrEmpty(v)) q.Add(f + "=" + Uri.EscapeDataString(v));
            q.Add("pkce_challenge=" + rq.Challenge);
            q.Add("pkce_method=S256");
            var qs = string.Join("&", q);
            return consoleUrl == null ? "redx://connect?" + qs : new Uri(consoleUrl).GetLeftPart(UriPartial.Authority) + "/#/connect?" + qs;
        }

        /// <summary>Read the callback URL; throws RedXException (Code state_mismatch) unless the state matches.</summary>
        public static Callback ParseCallback(string url, string expectedState)
        {
            var q = new Uri(url).Query.TrimStart('?').Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Split(new[] { '=' }, 2))
                .GroupBy(p => Uri.UnescapeDataString(p[0]))
                .ToDictionary(g => g.Key, g => Uri.UnescapeDataString(g.First().Length > 1 ? g.First()[1].Replace('+', ' ') : ""));
            string G(string k) => q.TryGetValue(k, out var v) ? v : "";
            var cb = new Callback { Code = G("code"), State = G("state"), Host = G("host"), Pin = G("pin") };
            if (cb.Code == "") throw new RedXException(0, "callback carries no code", "bad_callback");
            int d = cb.State.Length ^ expectedState.Length;
            for (int i = 0; i < Math.Min(cb.State.Length, expectedState.Length); i++) d |= cb.State[i] ^ expectedState[i];
            if (d != 0) throw new RedXException(0, "callback state does not match", "state_mismatch");
            return cb;
        }
    }

    public partial class RedXClient
    {
        /// <summary>Trade the approved code plus the verifier for the app's key (returned once). The client may have an empty key.</summary>
        public async Task<JsonElement> ExchangeConnectCodeAsync(string code, Connect.Request rq, string? deviceLabel = null, CancellationToken ct = default)
        {
            var b = new Dictionary<string, object?> { ["code"] = code, ["pkce_verifier"] = rq.Verifier, ["state"] = rq.State };
            if (deviceLabel != null) b["device_label"] = deviceLabel;
            return (await ConnectExchangeAsync(body: b, ct: ct).ConfigureAwait(false)).Json();
        }
    }
}

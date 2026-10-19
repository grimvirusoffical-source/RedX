using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace RedX.Tests
{
    public class OfflineTests
    {
        [Fact]
        public void TableMatchesSpec()
        {
            using var d = JsonDocument.Parse(File.ReadAllText(Path.Combine(Host.RepoRoot, "api", "redx-api.json")));
            var ops = d.RootElement.GetProperty("operations").EnumerateArray().ToList();
            Assert.Equal(ops.Count, Operations.All.Count);
            foreach (var o in ops)
            {
                var id = o.GetProperty("id").GetString()!;
                Assert.Equal(o.GetProperty("danger").GetString(), Operations.All[id].Danger.ToString().ToLowerInvariant());
                Assert.Equal(o.GetProperty("path").GetString(), Operations.All[id].Path);
            }
            foreach (var id in new[] { "deleteDatabase", "createKey", "revokeKey", "promote", "repoint", "connectApprove", "createJoinToken" })
                Assert.Equal(DangerLevel.Dangerous, RedXClient.DangerOf(id));
            Assert.Equal(DangerLevel.Dangerous, RedXClient.DangerOf("no-such-op"));
            Assert.Equal(DangerLevel.Safe, RedXClient.DangerOf("getPath"));
        }

        [Fact]
        public void BoxTextDecodes()
        {
            Assert.Equal("a\"bé", BoxText.Decode("\"a\\\"b\\u00e9\""));
            Assert.Equal(-150.0, BoxText.Decode("-1.5e2"));
            Assert.Null(BoxText.Decode("NELL"));
            Assert.Equal(new List<object?> { "a", 2.0, true }, (List<object?>)BoxText.Decode(";[\"a\", 2, TRUE]:")!);
            var box = (Dictionary<string, object?>)BoxText.Decode("[ {A[]} = 1, {B[ID=7]} = [ {C[]} = ;[]: ] ]")!;
            Assert.Equal(1.0, box["A"]);
            Assert.Empty((List<object?>)((Dictionary<string, object?>)box["B[ID=7]"]!)["C"]!);
            Assert.Throws<BoxTextException>(() => BoxText.Decode("[ {A[]} = "));
        }

        [Fact]
        public async Task DangerousRefusedWithoutRequest()
        {
            using var c = new RedXClient("http://127.0.0.1:9", "rx_" + "live_" + new string('x', 43));
            foreach (var id in new[] { "deleteDatabase", "promote", "connectApprove", "createPairingCode" })
            {
                var e = await Assert.ThrowsAsync<RedXException>(() => c.CallAsync(id, db: "x"));
                Assert.Equal("confirm_required", e.Code);
                Assert.Equal(0, e.Status);
            }
            Assert.DoesNotContain("xxxx", c.ToString());
        }
    }

    public class StreamDialTests
    {
        // A fake host: every WebSocket handshake is dropped (as when redxd is still starting), every plain GET
        // gets `probe`. Reproduces the 0.4.4 Linux flake at ClientTests.cs:129 deterministically: the dial failed
        // while redxd restarted, the probe GET reached the restarted host, which answered the non-upgrade GET
        // with the upgrader's 400, and the SDK took that as a refusal and ended the stream for good.
        static async Task<RedXException> DialAgainst(string probe)
        {
            var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            l.Start();
            var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
            using var stop = new CancellationTokenSource();
            var srv = Task.Run(async () =>
            {
                try
                {
                    for (;;)
                    {
                        using var c = await l.AcceptTcpClientAsync(stop.Token);
                        var st = c.GetStream();
                        var buf = new byte[8192];
                        var sb = new StringBuilder();
                        while (!sb.ToString().Contains("\r\n\r\n"))
                        {
                            var n = await st.ReadAsync(buf, stop.Token);
                            if (n == 0) break;
                            sb.Append(Encoding.ASCII.GetString(buf, 0, n));
                        }
                        if (sb.ToString().IndexOf("upgrade: websocket", StringComparison.OrdinalIgnoreCase) >= 0) continue; // drop
                        var b = Encoding.ASCII.GetBytes(probe);
                        await st.WriteAsync(b, stop.Token);
                    }
                }
                catch (Exception) { }
            });
            try
            {
                using var c = new RedXClient($"http://127.0.0.1:{port}", "rx_" + "live_" + new string('C', 43), "x");
                return await Assert.ThrowsAsync<RedXException>(() => c.SubscribeAsync("x.red-xai.db:*"));
            }
            finally { stop.Cancel(); l.Stop(); try { await srv; } catch { } }
        }

        [Fact]
        public async Task UpgradeOnlyProbeIsTransientNotARefusal()
        {
            var e = await DialAgainst("HTTP/1.1 400 Bad Request\r\nSec-Websocket-Version: 13\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Request\n");
            Assert.Equal(0, e.Status); // 0 = transient: a Reconnect stream keeps retrying
        }

        [Fact]
        public async Task RealRefusalIsStillReported()
        {
            const string body = "{\"error\":\"invalid key\",\"code\":\"unauthorized\"}";
            var e = await DialAgainst($"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
            Assert.Equal(401, e.Status);
        }
    }

    public class LiveTests : IDisposable
    {
        readonly Host host = new Host();
        public void Dispose() => host.Dispose();

        static async Task<T> Within<T>(Task<T> t, int ms = 8000)
        {
            if (await Task.WhenAny(t, Task.Delay(ms)) != t) throw new TimeoutException("timed out waiting");
            return await t;
        }

        [Fact]
        public async Task EverythingAgainstARealHost()
        {
            using var admin = new RedXClient(host.Url, host.AdminKey);
            Assert.Equal("ok", (await admin.HealthAsync()).Json().GetProperty("status").GetString());
            await admin.CreateDatabaseAsync(body: new { name = "sdkcs" });
            Assert.Contains("sdkcs", (await admin.ListDatabasesAsync()).Text());
            var c = admin.WithDb("sdkcs");

            // data, TTL, BoxQL, Tx
            await c.SetAsync("p.red-xai.db:P[ID=1]", new { Name = "Ann", Level = 5 });
            var p = (Dictionary<string, object?>)(await c.GetAsync("p.red-xai.db:P[ID=1]"))!;
            Assert.Equal("Ann", p["Name"]);
            Assert.Equal(5.0, p["Level"]);
            Assert.Equal("\"Ann\"", await c.GetBoxAsync("p.red-xai.db:P[ID=1].Name"));
            await c.SetAsync("s.red-xai-db-qs:S[ID=1]", "short", new WriteOptions { Ttl = 1 });
            await Task.Delay(2500);
            Assert.Equal(404, (await Assert.ThrowsAsync<RedXException>(() => c.GetAsync("s.red-xai-db-qs:S[ID=1]"))).Status);
            Assert.Equal(1, (await c.BxAsync("{Get[]} = p:P[Level >= $min] -> Name", new Dictionary<string, object?> { ["min"] = 3 })).GetProperty("count").GetInt32());
            var tx = await c.TxAsync(new[] { "{Set[]} = p:P[ID=1].Level = $l", "{Add[]} = p:P[ID=3] = [ {Name[]} = \"Cy\" ]" }, new Dictionary<string, object?> { ["l"] = 9 });
            Assert.Equal(2, tx.GetProperty("results").GetArrayLength());
            Assert.Equal(409, (await Assert.ThrowsAsync<RedXException>(() => c.TxAsync(new[] { "{Require[]} = p:P[ID=1, Level > 100]", "{Delete[]} = p:P[ID=3]" }))).Status);
            await c.DeleteAsync("p.red-xai.db:P[ID=3]");
            Assert.Equal("confirm_required", (await Assert.ThrowsAsync<RedXException>(() => admin.DeleteDatabaseAsync("sdkcs"))).Code);

            // keys
            var k = (await admin.CreateKeyAsync(body: new { db = "sdkcs", scope = "read", label = "cs-ro" }, confirm: true)).Json();
            using (var ro = new RedXClient(host.Url, k.GetProperty("key").GetString()!, "sdkcs"))
            {
                Assert.Equal("Ann", await ro.GetAsync("p.red-xai.db:P[ID=1].Name"));
                Assert.Equal(403, (await Assert.ThrowsAsync<RedXException>(() => ro.SetAsync("p.red-xai.db:P[ID=9]", 1))).Status);
                await admin.RevokeKeyAsync(k.GetProperty("id").GetString()!, confirm: true);
                Assert.Equal(401, (await Assert.ThrowsAsync<RedXException>(() => ro.GetAsync("p.red-xai.db:P[ID=1]"))).Status);
            }

            // files and media
            var data = new byte[300000];
            RandomNumberGenerator.Fill(data);
            await c.UploadFileAsync("assets", "lvl/one.bin", data);
            Assert.Equal(data, await c.DownloadFileAsync("assets", "lvl/one.bin"));
            Assert.Equal(data.Skip(10).Take(10).ToArray(), await c.DownloadFileAsync("assets", "lvl/one.bin", 10, 19));
            var bad = await Assert.ThrowsAsync<RedXException>(() => c.CallAsync("packPut", new Dictionary<string, string> { ["pack"] = "assets", ["file"] = "bad.bin" },
                raw: new byte[] { 1 }, headers: new Dictionary<string, string> { ["X-Redx-SHA256"] = new string('0', 64) }));
            Assert.Equal(422, bad.Status);
            var png = new byte[] { 0x89, (byte)'P', (byte)'N', (byte)'G', 13, 10, 26, 10 }.Concat(data.Take(64)).ToArray();
            await c.UploadMediaAsync("art", "icon.png", png, "image/png");
            Assert.Equal(png, await c.DownloadMediaAsync("art", "icon.png"));

            // streams with reconnect
            int reconnects = 0;
            await using (var s = await c.SubscribeAsync("w.red-xai.db:*", new StreamOptions { Reconnect = true, MinBackoff = TimeSpan.FromMilliseconds(50), MaxBackoff = TimeSpan.FromMilliseconds(200), OnReconnect = () => Interlocked.Increment(ref reconnects) }))
            {
                await c.SetAsync("w.red-xai.db:W[ID=1]", new { A = 1 });
                var ev = await Within(s.ReadAsync());
                Assert.Equal(1.0, ((Dictionary<string, object?>)ev!.Data!)["A"]);
                host.Restart();
                for (int i = 0; i < 200 && Volatile.Read(ref reconnects) == 0; i++) await Task.Delay(50);
                Assert.Equal(1, Volatile.Read(ref reconnects));
                await c.SetAsync("w.red-xai.db:W[ID=2]", new { A = 2 });
                Assert.Equal("w.red-xai.db:W[ID=2]", (await Within(s.ReadAsync()))!.Path);
            }
            await using (var w = await c.WatchAsync("{Watch[]} = w:W[A > $min]", new Dictionary<string, object?> { ["min"] = 4 }))
            {
                await c.SetAsync("w.red-xai.db:W[ID=3]", new { A = 5 });
                Assert.NotNull(await Within(w.ReadAsync()));
            }
            Assert.Equal(401, (await Assert.ThrowsAsync<RedXException>(() => new RedXClient(host.Url, "rx_" + "live_" + new string('B', 43)).SubscribeAsync("x.red-xai.db:*"))).Status);

            // cluster
            Assert.True((await admin.ClusterStatusAsync()).Json().TryGetProperty("role", out _));
            await Assert.ThrowsAsync<RedXException>(() => admin.PromoteAsync(confirm: true));

            // connect, app side
            var rq = Connect.NewRequest();
            Assert.StartsWith("redx://connect?v=1&", Connect.Link("gendragoon", rq));
            var start = (await admin.ConnectStartAsync(body: new Dictionary<string, object> { ["v"] = 1, ["provider"] = "gendragoon", ["state"] = rq.State, ["pkce_challenge"] = rq.Challenge, ["callback"] = "gendragoon://redx-callback" })).Json();
            var ap = (await admin.ConnectApproveAsync(body: new { request_id = start.GetProperty("request_id").GetString() }, confirm: true)).Json();
            var cbUrl = ap.GetProperty("callback_template").GetString()!.Replace("{state}", rq.State);
            Assert.Equal("state_mismatch", Assert.Throws<RedXException>(() => Connect.ParseCallback(cbUrl, new string('x', rq.State.Length))).Code);
            var cb = Connect.ParseCallback(cbUrl, rq.State);
            using var anon = new RedXClient(host.Url, "");
            var wrong = new Connect.Request { State = rq.State, Verifier = new string('A', 43), Challenge = rq.Challenge };
            Assert.Equal("pkce_mismatch", (await Assert.ThrowsAsync<RedXException>(() => anon.ExchangeConnectCodeAsync(cb.Code, wrong))).Code);
            var ex = await anon.ExchangeConnectCodeAsync(cb.Code, rq, "cs test");
            using (var app = new RedXClient(host.Url, ex.GetProperty("key").GetString()!, ex.GetProperty("workspace").GetProperty("db").GetString()))
            {
                await app.SetAsync("save.red-xai.db:S[ID=1]", new { L = 2 });
                await app.ConnectRevokeAsync();
                Assert.Equal(401, (await Assert.ThrowsAsync<RedXException>(() => app.GetAsync("save.red-xai.db:S[ID=1]"))).Status);
            }

            // backup and delete
            Assert.True((await admin.BackupAsync()).Body.Length > 100);
            await admin.DeleteDatabaseAsync("sdkcs", confirm: true);
            Assert.DoesNotContain("sdkcs", (await admin.ListDatabasesAsync()).Text());
        }
    }
}

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace RedX.Tests
{
    /// <summary>A real redxd on a free port with a throwaway data dir (REDXD_BIN, or built from the repository).
    /// The bootstrap admin key is read from its output and never printed.</summary>
    public sealed class Host : IDisposable
    {
        public string Url { get; }
        public string AdminKey { get; private set; } = "";
        readonly string tmp, bin;
        readonly int port;
        Process? proc;

        static string Repo()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            while (d != null && !File.Exists(Path.Combine(d.FullName, "api", "redx-api.json"))) d = d.Parent;
            return d?.FullName ?? throw new InvalidOperationException("repository root not found");
        }

        public static string RepoRoot => Repo();

        public Host()
        {
            tmp = Path.Combine(Path.GetTempPath(), "redx-sdk-cs-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmp);
            bin = Environment.GetEnvironmentVariable("REDXD_BIN") ?? "";
            if (bin == "")
            {
                bin = Path.Combine(tmp, RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "redxd.exe" : "redxd");
                var b = Process.Start(new ProcessStartInfo("go", $"build -o \"{bin}\" ./cmd/redxd") { WorkingDirectory = Repo(), UseShellExecute = false })!;
                b.WaitForExit();
                if (b.ExitCode != 0) throw new InvalidOperationException("building redxd failed");
            }
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            Url = $"http://127.0.0.1:{port}";
            Spawn();
        }

        void Spawn()
        {
            var psi = new ProcessStartInfo(bin) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in new[] { "run", "--no-open", "--bootstrap", "console", "--data-dir", Path.Combine(tmp, "data"), "--listen", $"127.0.0.1:{port}" })
                psi.ArgumentList.Add(a);
            psi.Environment.Clear();
            psi.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH") ?? "";
            psi.Environment["HOME"] = tmp;
            psi.Environment["SYSTEMROOT"] = Environment.GetEnvironmentVariable("SYSTEMROOT") ?? "";
            var re = new Regex("rx_live_[A-Za-z0-9]{43}");
            proc = new Process { StartInfo = psi };
            proc.OutputDataReceived += (_, e) => { if (e.Data != null && AdminKey == "") { var m = re.Match(e.Data); if (m.Success) AdminKey = m.Value; } };
            proc.ErrorDataReceived += (_, _) => { };
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
            for (int i = 0; i < 400; i++)
            {
                if (proc.HasExited) throw new InvalidOperationException("redxd exited early");
                try { if (http.GetAsync(Url + "/healthz").Result.IsSuccessStatusCode && AdminKey != "") return; } catch { }
                Thread.Sleep(50);
            }
            throw new InvalidOperationException("redxd did not become ready");
        }

        void Kill()
        {
            if (proc != null && !proc.HasExited) { proc.Kill(true); proc.WaitForExit(); }
            proc?.Dispose();
        }

        /// <summary>Kill and start again on the same port and data (to test reconnects).</summary>
        public void Restart(int downMs = 300) { Kill(); Thread.Sleep(downMs); Spawn(); }

        public void Dispose()
        {
            Kill();
            try { Directory.Delete(tmp, true); } catch { }
        }
    }
}

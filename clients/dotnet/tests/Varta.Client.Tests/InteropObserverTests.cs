using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using Varta.Tests.Helpers;
using Xunit;
using Xunit.Abstractions;

namespace Varta.Tests;

/// <summary>
/// Live interop: .NET agent ↔ real <c>varta-watch</c> observer. Spawns
/// the release binary, drives 50 beats, scrapes /metrics with the
/// bearer token, asserts at least one <c>varta_*</c> counter is
/// non-zero.
/// </summary>
/// <remarks>
/// Skipped if no varta-watch binary is found. To run locally:
/// <code>
/// cargo build --release -p varta-watch --features prometheus-exporter
/// VARTA_WATCH_BIN=$(pwd)/target/release/varta-watch \
///   dotnet test clients/dotnet/tests/Varta.Client.Tests -c Release
/// </code>
/// </remarks>
public class InteropObserverTests
{
    private const string PromTokenHex =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private readonly ITestOutputHelper _output;
    public InteropObserverTests(ITestOutputHelper output) => _output = output;

    [SkipOnWindowsFact]
    public async Task DotnetAgentBeatsVisibleInMetrics()
    {
        string? binary = LocateWatchBinary();
        if (binary == null)
        {
            _output.WriteLine("varta-watch binary not found; skipping interop test.");
            return;
        }

        string udsPath = TmpUds.AllocatePath();
        string tokenPath = udsPath + ".token";
        await File.WriteAllTextAsync(tokenPath, PromTokenHex);
        File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        try
        {
            using var obs = await StartObserverAsync(binary, udsPath, tokenPath);

            // Wait for the UDS socket file to appear so the agent doesn't race the bind.
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (DateTimeOffset.UtcNow < deadline && !File.Exists(udsPath))
            {
                await Task.Delay(10);
            }
            Assert.True(File.Exists(udsPath), "observer never created the UDS socket");

            using var agent = global::Varta.Varta.Connect(udsPath);

            int sent = 0;
            for (int i = 0; i < 50; i++)
            {
                var outcome = agent.Beat(Status.Ok, payload: 0);
                if (outcome.IsSent)
                {
                    sent++;
                }
                else if (outcome.IsDropped && outcome.Reason == DropReason.KernelQueueFull)
                {
                    await Task.Delay(1);
                }
                else if (outcome.IsDropped)
                {
                    Assert.Fail($"unexpected drop reason: {outcome.Reason}");
                }
                else
                {
                    Assert.Fail($"unexpected outcome: {outcome}");
                }
            }
            Assert.True(sent >= 10, $"expected ≥10 sent beats, got {sent}");

            // Give the observer one poll-loop iteration to consume.
            await Task.Delay(500);

            string body = await ScrapeMetricsAsync(obs.PromUrl);
            _output.WriteLine($"/metrics size: {body.Length} bytes");
            Assert.Contains("varta_", body, StringComparison.Ordinal);

            bool anyNonZero = false;
            foreach (string line in body.Split('\n'))
            {
                if (line.Length == 0 || line[0] == '#' || !line.StartsWith("varta_", StringComparison.Ordinal))
                {
                    continue;
                }
                int space = line.LastIndexOf(' ');
                if (space < 0) continue;
                if (double.TryParse(line.AsSpan(space + 1), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out double v) && v > 0)
                {
                    anyNonZero = true;
                    _output.WriteLine($"first non-zero metric: {line}");
                    break;
                }
            }
            Assert.True(anyNonZero, "no varta_ metric reached a non-zero value");
        }
        finally
        {
            try { File.Delete(udsPath); } catch { /* best-effort */ }
            try { File.Delete(tokenPath); } catch { /* best-effort */ }
        }
    }

    private static string? LocateWatchBinary()
    {
        string? env = Environment.GetEnvironmentVariable("VARTA_WATCH_BIN");
        if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;

        string root = RepoRoot();
        foreach (string profile in new[] { "release", "debug" })
        {
            string candidate = Path.Combine(root, "target", profile, "varta-watch");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static string RepoRoot()
    {
        // tests/Varta.Client.Tests/bin/<cfg>/<tfm>/ -> walk up to repo root
        string dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir != null; i++)
        {
            if (File.Exists(Path.Combine(dir, "Cargo.toml")))
            {
                return dir;
            }
            dir = Path.GetDirectoryName(dir)!;
        }
        throw new InvalidOperationException("could not locate repo root from " + AppContext.BaseDirectory);
    }

    private sealed class ObserverHandle : IDisposable
    {
        public required Process Process { get; init; }
        public required string PromUrl { get; init; }

        public void Dispose()
        {
            try
            {
                if (!Process.HasExited)
                {
                    Process.Kill(entireProcessTree: true);
                    Process.WaitForExit(5000);
                }
            }
            catch { /* best-effort */ }
            Process.Dispose();
        }
    }

    private static async Task<ObserverHandle> StartObserverAsync(string binary, string udsPath, string tokenPath)
    {
        var psi = new ProcessStartInfo(binary)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("--socket"); psi.ArgumentList.Add(udsPath);
        psi.ArgumentList.Add("--threshold-ms"); psi.ArgumentList.Add("10000");
        psi.ArgumentList.Add("--prom-addr"); psi.ArgumentList.Add("127.0.0.1:0");
        psi.ArgumentList.Add("--prom-token-file"); psi.ArgumentList.Add(tokenPath);
        psi.ArgumentList.Add("--prom-rate-limit-burst"); psi.ArgumentList.Add("0");
        psi.ArgumentList.Add("--shutdown-after-secs"); psi.ArgumentList.Add("60");

        var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start varta-watch");

        // First stdout line is the bound prom address ("host:port").
        Task<string?> lineTask = proc.StandardOutput.ReadLineAsync();
        Task timeout = Task.Delay(10_000);
        if (await Task.WhenAny(lineTask, timeout) == timeout)
        {
            try { proc.Kill(); } catch { /* best-effort */ }
            throw new InvalidOperationException("varta-watch did not print bound prometheus address within 10 s");
        }
        string? line = await lineTask;
        if (string.IsNullOrWhiteSpace(line))
        {
            try { proc.Kill(); } catch { /* best-effort */ }
            throw new InvalidOperationException("empty first line from varta-watch stdout");
        }
        line = line.Trim().Trim('[', ']');
        string url = $"http://{line}/metrics";
        return new ObserverHandle { Process = proc, PromUrl = url };
    }

    private static async Task<string> ScrapeMetricsAsync(string url)
    {
        // varta-watch serves HTTP/1.0 with a hand-rolled parser that
        // wants the request line to start with literal "GET " and
        // expects Authorization on its own header line. We bypass
        // HttpClient and write the raw bytes so the format matches the
        // server's tested-by-fixture happy path exactly.
        const string Prefix = "http://";
        if (!url.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"unsupported URL scheme: {url}", nameof(url));
        }
        string hostPathPort = url[Prefix.Length..];
        int slash = hostPathPort.IndexOf('/', StringComparison.Ordinal);
        string authority = slash < 0 ? hostPathPort : hostPathPort[..slash];
        string path = slash < 0 ? "/" : hostPathPort[slash..];
        int colon = authority.LastIndexOf(':');
        string host = authority[..colon];
        int port = int.Parse(authority[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture);

        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var stream = client.GetStream();

        string request =
            $"GET {path} HTTP/1.0\r\n" +
            $"Host: {authority}\r\n" +
            $"Authorization: Bearer {PromTokenHex}\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        byte[] reqBytes = Encoding.ASCII.GetBytes(request);
        await stream.WriteAsync(reqBytes);

        using var ms = new MemoryStream();
        byte[] chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk)) > 0)
        {
            ms.Write(chunk, 0, read);
        }
        string raw = Encoding.UTF8.GetString(ms.ToArray());
        int headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0)
        {
            throw new InvalidOperationException("malformed HTTP response: no header terminator");
        }
        string statusLine = raw[..raw.IndexOf("\r\n", StringComparison.Ordinal)];
        if (!statusLine.Contains(" 200 ", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"/metrics returned: {statusLine}");
        }
        return raw[(headerEnd + 4)..];
    }
}

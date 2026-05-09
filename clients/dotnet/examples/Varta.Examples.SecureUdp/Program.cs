// Varta agent over ChaCha20-Poly1305 AEAD UDP. Mirror of
// clients/go/cmd/examples/secure_udp/main.go.

using System.Globalization;
using Varta;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: varta-example-secure-udp <key-file> [host] [port]");
    Environment.Exit(2);
}

string keyFile = args[0];
string host = args.Length > 1 ? args[1] : "127.0.0.1";
int port = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 9876;

string hex = (await File.ReadAllTextAsync(keyFile)).Trim();
byte[] key = Convert.FromHexString(hex);
if (key.Length != 32)
{
    Console.Error.WriteLine($"key file must contain a 64-char hex string (32 bytes); got {key.Length}");
    Environment.Exit(2);
}

using var agent = global::Varta.Varta.ConnectSecureUdp(host, port, key);
Console.WriteLine($"connected to secure UDP {host}:{port}; sending Status.Ok every 500 ms");

while (true)
{
    var outcome = agent.Beat(Status.Ok);
    if (outcome.IsFailed)
    {
        Console.Error.WriteLine($"beat failed: {outcome}");
    }
    await Task.Delay(500);
}

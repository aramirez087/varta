// Demonstrates Varta.Panic.SignalHandler: install a signal-driven
// emitter that publishes a Critical + NONCE_TERMINAL beat before the
// process exits. Optional --crash flag triggers SignalHandler.Run with
// an exception so the defer/recover path also fires.
//
// Mirror of clients/go/cmd/examples/with_signal_handler/main.go.

using Varta;
using Varta.Panic;

string socket = args.Length > 0 && !args[0].StartsWith("--", StringComparison.Ordinal)
    ? args[0]
    : "/run/varta/observer.sock";
bool crash = args.Contains("--crash", StringComparer.Ordinal);

using var sig = SignalHandler.InstallUds(socket);
using var agent = global::Varta.Varta.Connect(socket);

if (crash)
{
    Console.WriteLine($"installed handler on {socket}; about to throw inside SignalHandler.Run …");
    SignalHandler.Run(() => throw new InvalidOperationException("intentional crash"));
}

Console.WriteLine($"installed handler on {socket}; send SIGTERM/SIGINT/SIGQUIT/SIGHUP to fire");

while (true)
{
    agent.Beat(Status.Ok);
    await Task.Delay(500);
}

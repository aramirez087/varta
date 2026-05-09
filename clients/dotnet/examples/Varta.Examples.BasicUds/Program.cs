// Minimal Varta beat loop — connect once over UDS, emit Status.Ok
// every 500 ms. Mirror of clients/go/cmd/examples/basic_uds/main.go.

using Varta;

string socket = args.Length > 0 ? args[0] : "/run/varta/observer.sock";

using var agent = global::Varta.Varta.Connect(socket);

Console.WriteLine($"connected to {socket}; sending Status.Ok every 500 ms (Ctrl-C to stop)");

while (true)
{
    var outcome = agent.Beat(Status.Ok, payload: 0);
    if (outcome.IsFailed)
    {
        Console.Error.WriteLine($"beat failed: {outcome}");
    }
    else if (outcome.IsDropped)
    {
        Console.Error.WriteLine($"beat dropped: {outcome.Reason}");
    }
    await Task.Delay(500);
}

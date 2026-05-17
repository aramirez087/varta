// Pack queue depth (high 16 bits) and last error code (low 16 bits) into
// the 32-bit payload. Mirror of clients/go/cmd/examples/with_payload/main.go.

using Varta;

string socket = args.Length > 0 ? args[0] : "/run/varta/observer.sock";

using var agent = global::Varta.Varta.Connect(socket);

int tick = 0;
while (true)
{
    ushort queueDepth = (ushort)(tick * 3);
    ushort lastError = (ushort)(tick % 5 == 0 ? 42 : 0);
    uint payload = ((uint)queueDepth << 16) | lastError;

    var outcome = agent.Beat(Status.Ok, payload);
    if (outcome.IsFailed)
    {
        Console.Error.WriteLine($"beat failed: {outcome}");
    }

    tick++;
    await Task.Delay(500);
}

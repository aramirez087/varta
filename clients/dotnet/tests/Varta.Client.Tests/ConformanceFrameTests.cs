using Varta.Internal.Vlp;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class ConformanceFrameTests
{
    public static IEnumerable<object[]> AllVectors() => Vectors.AsTheoryData(Vectors.Frames());

    [Theory]
    [MemberData(nameof(AllVectors))]
    public void RoundTripOrDecodeError(string id, VectorRow row)
    {
        var v = row.Element;
        string? expectedError = v.GetProperty("expected_decode_error").GetString();

        if (expectedError != null)
        {
            byte[] wire = Vectors.Hex(v.GetProperty("wire_hex").GetString()!);
            var ex = Assert.Throws<DecodeError>(() => Frame.Decode(wire));
            Assert.Equal(expectedError, ex.Kind.ToString());
            return;
        }

        var inputs = v.GetProperty("inputs");
        Status status = inputs.GetProperty("status").GetString() switch
        {
            "ok" => Status.Ok,
            "degraded" => Status.Degraded,
            "critical" => Status.Critical,
            var x => throw new InvalidOperationException($"unknown status '{x}'"),
        };
        uint pid = inputs.GetProperty("pid").GetUInt32();
        ulong timestamp = inputs.GetProperty("timestamp").GetUInt64();
        ulong nonce = inputs.GetProperty("nonce").GetUInt64();
        uint payload = inputs.GetProperty("payload").GetUInt32();

        byte[] expectedWire = Vectors.Hex(v.GetProperty("expected_wire_hex").GetString()!);

        byte[] actual = new byte[Frame.Bytes];
        Codec.EncodeInto(actual, status, pid, timestamp, nonce, payload);
        Assert.Equal(expectedWire, actual);

        var frame = Frame.Decode(expectedWire);
        Assert.Equal(status, frame.Status);
        Assert.Equal(pid, frame.Pid);
        Assert.Equal(timestamp, frame.Timestamp);
        Assert.Equal(nonce, frame.Nonce);
        Assert.Equal(payload, frame.Payload);
    }
}

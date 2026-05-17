using Varta.Internal.Vlp;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class ConformanceCrc32CTests
{
    public static IEnumerable<object[]> AllVectors() => Vectors.AsTheoryData(Vectors.Crc32C());

    [Theory]
    [MemberData(nameof(AllVectors))]
    public void MatchesGoldenVector(string id, VectorRow row)
    {
        var v = row.Element;
        byte[] input = Vectors.Hex(v.GetProperty("input_hex").GetString()!);
        uint expected = Convert.ToUInt32(v.GetProperty("expected_crc_hex").GetString()!, 16);

        uint actual = Crc32C.Compute(input);
        Assert.Equal(expected, actual);
    }
}

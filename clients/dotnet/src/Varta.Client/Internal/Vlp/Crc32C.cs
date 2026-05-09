namespace Varta.Internal.Vlp;

/// <summary>
/// CRC-32C (Castagnoli, RFC 3720 §B.4). Reflected polynomial
/// <c>0x82F63B78</c>; init <c>0xFFFFFFFF</c>; final XOR <c>0xFFFFFFFF</c>.
/// Table-driven byte-at-a-time — matches the Rust
/// <c>crates/varta-vlp/src/crc32c.rs</c> and Go
/// <c>clients/go/internal/vlp/crc32c.go</c> reference implementations
/// byte-for-byte; verified by <c>tools/vlp-test-vectors.json</c>.
/// </summary>
internal static class Crc32C
{
    private const uint ReflectedPoly = 0x82F63B78u;
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? (c >> 1) ^ ReflectedPoly : c >> 1;
            }
            table[i] = c;
        }
        return table;
    }

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        foreach (byte b in data)
        {
            crc = Table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
        }
        return crc ^ 0xFFFF_FFFFu;
    }
}

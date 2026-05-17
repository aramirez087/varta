using System.Reflection;
using System.Text.Json;

namespace Varta.Tests.Helpers;

/// <summary>
/// Loads <c>tools/vlp-test-vectors.json</c> from the test assembly's
/// embedded resources and exposes per-category materialised lists.
/// </summary>
internal static class Vectors
{
    private static readonly JsonDocument Doc = LoadDoc();

    private static JsonDocument LoadDoc()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream("vectors.json")
            ?? throw new InvalidOperationException("Embedded resource 'vectors.json' not found.");
        return JsonDocument.Parse(stream);
    }

    public static IEnumerable<JsonElement> Crc32C()
    {
        foreach (var v in Doc.RootElement.GetProperty("crc32c_vectors").EnumerateArray()) yield return v;
    }

    public static IEnumerable<JsonElement> Frames()
    {
        foreach (var v in Doc.RootElement.GetProperty("frame_vectors").EnumerateArray()) yield return v;
    }

    public static IEnumerable<JsonElement> Secure()
    {
        foreach (var v in Doc.RootElement.GetProperty("secure_frame_vectors").EnumerateArray()) yield return v;
    }

    public static byte[] Hex(string hex) => hex.Length == 0 ? [] : Convert.FromHexString(hex);

    /// <summary>Materialise vectors as xUnit-friendly object[] rows: [id, raw element].</summary>
    public static IEnumerable<object[]> AsTheoryData(IEnumerable<JsonElement> src)
    {
        foreach (var v in src)
        {
            yield return [v.GetProperty("id").GetString()!, new VectorRow(v.Clone())];
        }
    }
}

/// <summary>
/// Wrapper that gives Xunit a name we control via <see cref="ToString"/>
/// for the [Theory] discovery output. Without this xUnit would print the
/// full JSON, making the test reporter unreadable.
/// </summary>
public sealed class VectorRow
{
    public JsonElement Element { get; }
    public VectorRow(JsonElement element) => Element = element;
    public override string ToString() => Element.GetProperty("id").GetString() ?? "<no-id>";
}

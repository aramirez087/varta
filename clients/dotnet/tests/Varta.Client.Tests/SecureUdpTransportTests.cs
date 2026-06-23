using Varta.Internal.Transport;
using Varta.Internal.VlpSecure;
using Xunit;

namespace Varta.Tests;

public class SecureUdpTransportTests
{
    [Fact]
    public void ShortSecureSend_DoesNotCommitNonceState()
    {
        byte[] key = new byte[Hkdf.KeyBytes];
        using var transport = new SecureUdpTransport(SecureUdpMode.Shared, "127.0.0.1", 9, key);
        transport.CounterForTest = 17;
        uint prefixBefore = transport.PrefixIndexForTest;
        byte[] ivBefore = transport.IvPrefixForTest;

        transport.SetSendResultOverrideForTest(expectedWireBytes => expectedWireBytes - 1);

        int sent = transport.Send(new byte[AeadCodec.PlaintextBytes]);

        Assert.Equal(0, sent);
        Assert.Equal(prefixBefore, transport.PrefixIndexForTest);
        Assert.Equal(17u, transport.CounterForTest);
        Assert.Equal(ivBefore, transport.IvPrefixForTest);
    }
}

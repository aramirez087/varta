using System.Net.Sockets;
using Varta.Internal.Errno;
using Xunit;

namespace Varta.Tests;

public class ErrnoClassifierTests
{
    [Theory]
    [InlineData(SocketError.WouldBlock, DropReason.KernelQueueFull)]
    [InlineData(SocketError.NoBufferSpaceAvailable, DropReason.KernelQueueFull)]
    [InlineData(SocketError.ConnectionRefused, DropReason.NoObserver)]
    [InlineData(SocketError.AddressNotAvailable, DropReason.NoObserver)]
    [InlineData(SocketError.HostUnreachable, DropReason.NoObserver)]
    [InlineData(SocketError.ConnectionReset, DropReason.PeerGone)]
    [InlineData(SocketError.NotConnected, DropReason.PeerGone)]
    [InlineData(SocketError.Shutdown, DropReason.PeerGone)]
    public void DroppedClassifications(SocketError code, DropReason expected)
    {
        var ex = new SocketException((int)code);
        var outcome = ErrnoClassifier.Classify(ex);
        Assert.True(outcome.IsDropped, $"{code} should classify as Dropped, got {outcome}");
        Assert.Equal(expected, outcome.Reason);
    }

    [Fact]
    public void UnrecognisedCodeSurfacesAsFailed()
    {
        // SocketError.SocketError (-1) is the generic "unknown" code — used
        // here as a stand-in for any errno not in the classification table.
        var ex = new SocketException((int)SocketError.SocketError);
        var outcome = ErrnoClassifier.Classify(ex);
        Assert.True(outcome.IsFailed);
    }
}

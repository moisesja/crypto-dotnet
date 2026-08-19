using FluentAssertions;
using NetCrypto;

namespace NetCrypto.ExternalStore.Tests;

/// <summary>
/// Regression tests for the adversarial finding that <c>Consume</c> invoked the reader while
/// holding the instance's private lock. Because #28 made the reader arbitrary out-of-assembly
/// code — and a real store's reader takes the store's own lock — holding the lock across that
/// call spliced the instance into the application's lock order, so an ordinary two-lock cycle
/// deadlocked and left the secret stranded un-wiped. The reader now runs with the lock released.
/// </summary>
/// <remarks>
/// Every wait here is bounded: a regression makes these <b>fail</b> (the bounded join returns
/// false, or the responsive call times out), never hang the suite.
/// </remarks>
public class ConsumeConcurrencyTests
{
    private static readonly DefaultKeyGenerator Generator = new();
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(15);

    [Fact]
    public void AReaderTakingItsOwnLock_DoesNotDeadlockAConcurrentDispose()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var storeLock = new object();
        var bHasStoreLock = new ManualResetEventSlim();
        var aInReader = new ManualResetEventSlim();

        // A (the store): holds the instance's lock inside Consume, and its reader wants storeLock.
        var a = new Thread(() => material.Consume((_, _, _) =>
        {
            aInReader.Set();
            lock (storeLock) { }
            return 0;
        }));

        // B (a caller cleanup path): holds storeLock, then disposes — which wants the instance's
        // lock. This is the exact A-holds-x-wants-y / B-holds-y-wants-x cycle.
        var b = new Thread(() =>
        {
            lock (storeLock)
            {
                bHasStoreLock.Set();
                aInReader.Wait(Bound);
                Thread.Sleep(100);
                material.Dispose();
            }
        });

        b.Start();
        bHasStoreLock.Wait(Bound);
        a.Start();

        b.Join(Bound).Should().BeTrue("Dispose must not wait on a lock the live reader depends on");
        a.Join(Bound).Should().BeTrue("the reader must complete once its own lock is free");
        material.IsConsumed.Should().BeTrue("the read still spends and wipes the material");
    }

    [Fact]
    public void IsConsumedAndDispose_StayResponsiveWhileAReaderIsRunning()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var readerParked = new ManualResetEventSlim();
        var releaseReader = new ManualResetEventSlim();

        var reader = new Thread(() => material.Consume((_, _, _) =>
        {
            readerParked.Set();
            releaseReader.Wait(Bound);
            return 0;
        }));
        reader.Start();
        readerParked.Wait(Bound).Should().BeTrue();

        // The docs call IsConsumed the member that keeps working; prove it is not blockable by an
        // untrusted reader parked mid-read. Dispose likewise must not hang (it defers).
        var probe = new Thread(() =>
        {
            _ = material.IsConsumed;
            material.Dispose();
        });
        probe.Start();
        probe.Join(Bound).Should().BeTrue("neither IsConsumed nor Dispose may block behind a live reader");

        releaseReader.Set();
        reader.Join(Bound).Should().BeTrue();
        material.IsConsumed.Should().BeTrue();
    }

    [Fact]
    public void CrossThreadReEntry_IsRefusedNotHung()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        Exception? fromWorker = null;

        var outer = new Thread(() => material.Consume((_, _, _) =>
        {
            // A worker that re-enters from a *different* thread and is joined: on the old
            // lock-across-callback design this Join blocked forever. It must now be refused.
            var worker = new Thread(() => fromWorker = Record.Exception(() => material.Consume((_, _, _) => 0)));
            worker.Start();
            worker.Join(Bound).Should().BeTrue("a concurrent second read must be refused, not deadlock");
            return 0;
        }));
        outer.Start();
        outer.Join(Bound).Should().BeTrue();
        fromWorker.Should().BeOfType<InvalidOperationException>(
            "a concurrent read while one is live is a second read of one-read material");
        material.IsConsumed.Should().BeTrue();
    }

    [Fact]
    public void ManyConcurrentConsumers_YieldExactlyOneSuccessfulRead()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var expected = pair.PrivateKey;
        var material = TransferableKeyMaterial.FromKeyPair(pair);

        var start = new ManualResetEventSlim();
        int successes = 0;
        var reads = new System.Collections.Concurrent.ConcurrentBag<byte[]>();

        var threads = Enumerable.Range(0, 16).Select(_ => new Thread(() =>
        {
            start.Wait(Bound);
            try
            {
                var got = material.Consume((_, _, priv) => priv.ToArray());
                Interlocked.Increment(ref successes);
                reads.Add(got);
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        })).ToList();

        foreach (var t in threads) t.Start();
        start.Set();
        foreach (var t in threads) t.Join(Bound).Should().BeTrue();

        successes.Should().Be(1, "one-read material is read exactly once even under a stampede");
        reads.Single().Should().Equal(expected, "the one read observed the true secret, never a wiped buffer");
    }
}

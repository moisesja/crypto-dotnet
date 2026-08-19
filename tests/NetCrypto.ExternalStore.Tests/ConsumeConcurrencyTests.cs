using System.Collections.Concurrent;
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
/// Regressions must FAIL, never hang the suite: every wait is bounded, every worker is a
/// <b>background</b> thread (a re-deadlocked foreground thread would keep the testhost process
/// alive after the failed assertion), and worker exceptions are captured and re-asserted on the
/// test thread rather than thrown raw on a worker.
/// </remarks>
public class ConsumeConcurrencyTests
{
    private static readonly DefaultKeyGenerator Generator = new();
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(15);

    private static Thread StartBackground(ConcurrentQueue<Exception> failures, Action body)
    {
        var thread = new Thread(() =>
        {
            try { body(); }
            catch (Exception ex) { failures.Enqueue(ex); }
        })
        { IsBackground = true };
        thread.Start();
        return thread;
    }

    [Fact]
    public void AReaderTakingItsOwnLock_DoesNotDeadlockAConcurrentDispose()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var storeLock = new object();
        var bHasStoreLock = new ManualResetEventSlim();
        var aInReader = new ManualResetEventSlim();
        var failures = new ConcurrentQueue<Exception>();

        // B (a caller cleanup path): holds storeLock, then disposes — which wants the instance's
        // lock. A (the store): holds the instance's lock inside Consume, and its reader wants
        // storeLock. The exact A-holds-x-wants-y / B-holds-y-wants-x cycle.
        var b = StartBackground(failures, () =>
        {
            lock (storeLock)
            {
                bHasStoreLock.Set();
                aInReader.Wait(Bound);
                Thread.Sleep(100);
                material.Dispose();
            }
        });
        bHasStoreLock.Wait(Bound).Should().BeTrue();

        var a = StartBackground(failures, () => material.Consume((_, _, _) =>
        {
            aInReader.Set();
            lock (storeLock) { }
            return 0;
        }));

        b.Join(Bound).Should().BeTrue("Dispose must not wait on a lock the live reader depends on");
        a.Join(Bound).Should().BeTrue("the reader must complete once its own lock is free");
        failures.Should().BeEmpty();
        material.IsConsumed.Should().BeTrue("the read still spends and wipes the material");
    }

    [Fact]
    public void DisposeDuringALiveRead_LatchesImmediately_AndDefersOnlyTheWipe()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var expectedPrivateKey = pair.PrivateKey;
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var readerParked = new ManualResetEventSlim();
        var releaseReader = new ManualResetEventSlim();
        var failures = new ConcurrentQueue<Exception>();
        byte[]? observed = null;

        var reader = StartBackground(failures, () => observed = material.Consume((_, _, priv) =>
        {
            readerParked.Set();
            releaseReader.Wait(Bound);
            return priv.ToArray();
        }));
        readerParked.Wait(Bound).Should().BeTrue();

        material.Dispose();

        // The review's exact probe: BEFORE the reader is released, the object must already be
        // in its documented disposed state — not a half-state that contradicts Dispose's docs.
        material.IsConsumed.Should().BeTrue("Dispose latches immediately, even against a live read");
        material.Invoking(m => m.KeyType).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.Consume((_, _, _) => 0)).Should().Throw<ObjectDisposedException>(
            "after disposal the documented refusal is ObjectDisposedException, not the busy signal");

        releaseReader.Set();
        reader.Join(Bound).Should().BeTrue();
        failures.Should().BeEmpty();
        observed.Should().Equal(expectedPrivateKey,
            "only the physical wipe defers — the live read must never observe zeroed buffers");
    }

    [Fact]
    public void IsConsumedAndDispose_StayResponsiveWhileAReaderIsRunning()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var readerParked = new ManualResetEventSlim();
        var releaseReader = new ManualResetEventSlim();
        var failures = new ConcurrentQueue<Exception>();

        var reader = StartBackground(failures, () => material.Consume((_, _, _) =>
        {
            readerParked.Set();
            releaseReader.Wait(Bound);
            return 0;
        }));
        readerParked.Wait(Bound).Should().BeTrue();

        // Neither member may block behind an untrusted reader parked mid-read.
        var probe = StartBackground(failures, () =>
        {
            _ = material.IsConsumed;
            material.Dispose();
        });
        probe.Join(Bound).Should().BeTrue("neither IsConsumed nor Dispose may block behind a live reader");

        releaseReader.Set();
        reader.Join(Bound).Should().BeTrue();
        failures.Should().BeEmpty();
        material.IsConsumed.Should().BeTrue();
    }

    [Fact]
    public void CrossThreadReEntry_IsRefusedNotHung()
    {
        using var pair = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var failures = new ConcurrentQueue<Exception>();
        Exception? fromWorker = null;
        bool workerJoined = false;

        var outer = StartBackground(failures, () => material.Consume((_, _, _) =>
        {
            // A worker that re-enters from a *different* thread and is joined: on the old
            // lock-across-callback design this Join blocked forever. It must now be refused.
            var worker = StartBackground(failures, () =>
                fromWorker = Record.Exception(() => material.Consume((_, _, _) => 0)));
            workerJoined = worker.Join(Bound);
            return 0;
        }));

        outer.Join(Bound).Should().BeTrue();
        failures.Should().BeEmpty();
        workerJoined.Should().BeTrue("a concurrent second read must be refused, not deadlock");
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
        var reads = new ConcurrentBag<byte[]>();
        var failures = new ConcurrentQueue<Exception>();

        var threads = Enumerable.Range(0, 16).Select(_ => StartBackground(failures, () =>
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

        start.Set();
        foreach (var t in threads) t.Join(Bound).Should().BeTrue();

        failures.Should().BeEmpty();
        successes.Should().Be(1, "one-read material is read exactly once even under a stampede");
        reads.Single().Should().Equal(expected, "the one read observed the true secret, never a wiped buffer");
    }
}

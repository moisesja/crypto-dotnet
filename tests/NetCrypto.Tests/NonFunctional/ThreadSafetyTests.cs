using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// NFR-4 — determinism and thread safety. One shared <see cref="DefaultCryptoProvider"/> and
/// one shared <see cref="DefaultKeyGenerator"/> are driven from 8 threads × 100 operations
/// via <see cref="Parallel.For(int, int, ParallelOptions, Action{int})"/>, mixing Ed25519,
/// P-256, and secp256k1 over pre-generated key pairs. Every Sign/Verify round-trip must
/// verify as valid and no operation may throw (PRD §4 NFR-4 acceptance criterion:
/// ≥ 8 threads × 100 ops on one shared provider instance, mixed key types).
/// </summary>
public class ThreadSafetyTests
{
    private const int ThreadCount = 8;
    private const int OpsPerThread = 100;

    [Fact]
    public void SharedProviderAndGenerator_ParallelMixedKeyTypeSignVerify_AllRoundTripsValid()
    {
        var provider = new DefaultCryptoProvider();
        var generator = new DefaultKeyGenerator();

        // Pre-generate one key pair per key type outside the parallel loop; the loop then only
        // exercises the shared provider/generator instances, never per-thread state.
        KeyType[] mixedKeyTypes = [KeyType.Ed25519, KeyType.P256, KeyType.Secp256k1];
        var keyPairs = mixedKeyTypes.ToDictionary(keyType => keyType, keyType => generator.Generate(keyType));

        var failures = new ConcurrentBag<string>();

        // Any exception thrown inside the body surfaces as an AggregateException and fails the
        // test, covering the "no exceptions" half of the NFR-4 acceptance criterion.
        Parallel.For(0, ThreadCount, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, thread =>
        {
            for (var op = 0; op < OpsPerThread; op++)
            {
                var keyType = mixedKeyTypes[(thread + op) % mixedKeyTypes.Length];
                var keyPair = keyPairs[keyType];

                // Distinct, deterministic payload per (thread, op) so a cross-thread state leak
                // inside the provider produces a verification failure rather than a silent pass.
                var data = new byte[32];
                BinaryPrimitives.WriteInt32LittleEndian(data, thread * OpsPerThread + op);
                BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4), (int)keyType);

                var signature = provider.Sign(keyType, keyPair.PrivateKey, data);

                if (!provider.Verify(keyType, keyPair.PublicKey, data, signature))
                    failures.Add($"thread {thread} op {op} ({keyType}): signature failed verification");

                // Exercise the shared generator concurrently too: restoring from the private key
                // must deterministically reproduce the original public key (NFR-4 determinism).
                if (op % 10 == 0)
                {
                    var restored = generator.FromPrivateKey(keyType, keyPair.PrivateKey);
                    if (!restored.PublicKey.AsSpan().SequenceEqual(keyPair.PublicKey))
                        failures.Add($"thread {thread} op {op} ({keyType}): restored public key differs from original");
                }
            }
        });

        failures.Should().BeEmpty("all parallel Sign/Verify round-trips on the shared provider must be valid (NFR-4)");
    }
}

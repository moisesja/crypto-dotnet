using System.Reflection;
using FluentAssertions;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// Issue #17 (FR-18) — deterministic on-disposal zeroization of asymmetric key material.
/// Covers the acceptance criteria: disposing a <see cref="KeyPair"/> zeroizes its backing store
/// and makes key-material access throw; the borrow API lends the secret without cloning;
/// <see cref="InMemoryKeyStore.DeleteAsync"/> destroys (not merely unlists) the evicted key;
/// <see cref="KeyPairSigner"/> ownership semantics; non-disposing callers are unaffected.
/// </summary>
public class ZeroizationTests
{
    private static readonly DefaultKeyGenerator KeyGenerator = new();
    private static readonly DefaultCryptoProvider CryptoProvider = new();

    private static byte[] BackingPrivateKey(KeyPair pair)
    {
        var field = typeof(KeyPair).GetField("_privateKey", BindingFlags.NonPublic | BindingFlags.Instance);
        field.Should().NotBeNull();
        return (byte[])field!.GetValue(pair)!;
    }

    // --- KeyPair.Dispose ---

    [Fact]
    public void KeyPair_Dispose_ZeroizesBackingPrivateKey()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var backing = BackingPrivateKey(pair);
        backing.Should().Contain(b => b != 0, "a real private key cannot be all zeros");

        pair.Dispose();

        backing.Should().OnlyContain(b => b == 0, "Dispose must zeroize the canonical private-key copy");
    }

    [Fact]
    public void KeyPair_Dispose_MakesKeyMaterialAccessThrow()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        _ = pair.PrivateKey; // reading before dispose is fine
        pair.Dispose();

        pair.Invoking(p => p.PrivateKey).Should().Throw<ObjectDisposedException>();
        pair.Invoking(p => p.PublicKey).Should().Throw<ObjectDisposedException>();
        pair.Invoking(p => p.MultibasePublicKey).Should().Throw<ObjectDisposedException>();
        pair.Invoking(p => p.ToPublicJwk()).Should().Throw<ObjectDisposedException>();
        pair.Invoking(p => p.ToPrivateJwk()).Should().Throw<ObjectDisposedException>();
        pair.Invoking(p => p.WithPrivateKey(_ => 0)).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void KeyPair_Dispose_IsIdempotent()
    {
        var pair = KeyGenerator.Generate(KeyType.P256);
        pair.Dispose();
        pair.Invoking(p => p.Dispose()).Should().NotThrow();
    }

    [Fact]
    public void KeyPair_KeyType_RemainsReadableAfterDispose()
    {
        var pair = KeyGenerator.Generate(KeyType.Secp256k1);
        pair.Dispose();
        pair.KeyType.Should().Be(KeyType.Secp256k1);
    }

    [Fact]
    public void KeyPair_NonDisposingCaller_KeepsExistingBehavior()
    {
        // Backward compatibility: without a Dispose call, the clone-per-read contract is unchanged.
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var first = pair.PrivateKey;
        var second = pair.PrivateKey;
        first.Should().NotBeSameAs(second, "each read returns a fresh defensive copy");
        first.Should().Equal(second);
        pair.PublicKey.Should().Equal(pair.PublicKey);
    }

    // --- KeyPair.WithPrivateKey (borrow API) ---

    [Fact]
    public void WithPrivateKey_LendsTheExactKeyBytes_WithoutCloning()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var expected = pair.PrivateKey;

        var observed = pair.WithPrivateKey(privateKey => privateKey.ToArray());
        observed.Should().Equal(expected);

        // The span must alias the pinned backing store (no copy) — prove it by reference identity.
        var backing = BackingPrivateKey(pair);
        pair.WithPrivateKey(privateKey =>
            System.Runtime.CompilerServices.Unsafe.AreSame(
                in System.Runtime.InteropServices.MemoryMarshal.GetReference(privateKey),
                in backing[0]))
            .Should().BeTrue("the borrow API must lend the canonical copy, not a clone");
    }

    [Fact]
    public void WithPrivateKey_ReturnsCallbackResult_AndSupportsSigning()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var data = "payload"u8.ToArray();

        var signature = pair.WithPrivateKey(privateKey => CryptoProvider.Sign(pair.KeyType, privateKey, data));

        CryptoProvider.Verify(pair.KeyType, pair.PublicKey, data, signature).Should().BeTrue();
    }

    [Fact]
    public void WithPrivateKey_NullCallback_Throws()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        pair.Invoking(p => p.WithPrivateKey<int>(null!))
            .Should().Throw<ArgumentNullException>().WithParameterName("use");
    }

    // --- Restored/derived pairs are also disposable ---

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void GeneratedAndRestoredPairs_DisposeToZero_ForEveryKeyType(KeyType keyType)
    {
        var generated = KeyGenerator.Generate(keyType);
        var restored = KeyGenerator.FromPrivateKey(keyType, generated.PrivateKey);
        restored.PublicKey.Should().Equal(generated.PublicKey);

        foreach (var pair in new[] { generated, restored })
        {
            var backing = BackingPrivateKey(pair);
            pair.Dispose();
            backing.Should().OnlyContain(b => b == 0, $"{keyType} backing store must be zeroed after Dispose");
        }
    }

    [Fact]
    public void DeriveX25519FromEd25519_OnDisposedPair_ThrowsObjectDisposed()
    {
        var ed = KeyGenerator.Generate(KeyType.Ed25519);
        ed.Dispose();
        KeyGenerator.Invoking(g => g.DeriveX25519FromEd25519(ed)).Should().Throw<ObjectDisposedException>();
    }

    // --- InMemoryKeyStore ---

    [Fact]
    public async Task InMemoryKeyStore_Delete_DestroysTheEvictedKey()
    {
        using var store = new InMemoryKeyStore(KeyGenerator, CryptoProvider);
        var imported = KeyGenerator.Generate(KeyType.Ed25519);
        var backing = BackingPrivateKey(imported);
        await store.ImportAsync("alias", imported);

        (await store.DeleteAsync("alias")).Should().BeTrue();

        backing.Should().OnlyContain(b => b == 0, "DeleteAsync must zeroize, not merely unlist, the key");
        imported.Invoking(p => p.PrivateKey).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task InMemoryKeyStore_Dispose_DestroysAllKeys_AndFurtherOpsThrow()
    {
        var store = new InMemoryKeyStore(KeyGenerator, CryptoProvider);
        var imported = KeyGenerator.Generate(KeyType.Ed25519);
        var backing = BackingPrivateKey(imported);
        await store.ImportAsync("a", imported);
        await store.GenerateAsync("b", KeyType.P256);

        store.Dispose();

        backing.Should().OnlyContain(b => b == 0);
        await store.Invoking(s => s.SignAsync("a", new byte[] { 1 })).Should().ThrowAsync<ObjectDisposedException>();
        await store.Invoking(s => s.GenerateAsync("c", KeyType.Ed25519)).Should().ThrowAsync<ObjectDisposedException>();
        await store.Invoking(s => s.ListAsync()).Should().ThrowAsync<ObjectDisposedException>();
        await store.Invoking(s => s.DeleteAsync("a")).Should().ThrowAsync<ObjectDisposedException>();
        store.Invoking(s => s.Dispose()).Should().NotThrow("Dispose is idempotent");
    }

    [Fact]
    public async Task InMemoryKeyStore_DuplicateGenerate_DisposesTheOrphanPair_AndKeepsOriginal()
    {
        using var store = new InMemoryKeyStore(KeyGenerator, CryptoProvider);
        await store.GenerateAsync("alias", KeyType.Ed25519);

        await store.Invoking(s => s.GenerateAsync("alias", KeyType.Ed25519))
            .Should().ThrowAsync<InvalidOperationException>();

        // The original key must still be fully usable.
        var data = "still works"u8.ToArray();
        var signature = await store.SignAsync("alias", data);
        var info = await store.GetInfoAsync("alias");
        CryptoProvider.Verify(info!.KeyType, info.PublicKey, data, signature).Should().BeTrue();
    }

    [Fact]
    public async Task InMemoryKeyStore_SignAndDerive_DoNotDisturbTheStoredKey()
    {
        using var store = new InMemoryKeyStore(KeyGenerator, CryptoProvider);
        await store.GenerateAsync("sig", KeyType.Ed25519);
        await store.GenerateAsync("ecdh", KeyType.X25519);
        var peer = KeyGenerator.Generate(KeyType.X25519);

        // Repeated borrows must keep producing valid results (the borrow must not wipe the key).
        var data = "data"u8.ToArray();
        var info = await store.GetInfoAsync("sig");
        for (var i = 0; i < 3; i++)
        {
            var signature = await store.SignAsync("sig", data);
            CryptoProvider.Verify(info!.KeyType, info.PublicKey, data, signature).Should().BeTrue();
        }

        var z1 = await store.DeriveSharedSecretAsync("ecdh", peer.PublicKey);
        var z2 = await store.DeriveSharedSecretAsync("ecdh", peer.PublicKey);
        z1.Should().Equal(z2);
    }

    // --- KeyPairSigner ownership ---

    [Fact]
    public async Task KeyPairSigner_OwnsKeyPairByDefault_DisposeZeroizesIt()
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var backing = BackingPrivateKey(pair);
        var signer = new KeyPairSigner(pair, CryptoProvider);

        var data = "signed"u8.ToArray();
        var signature = await signer.SignAsync(data);
        CryptoProvider.Verify(pair.KeyType, pair.PublicKey, data, signature).Should().BeTrue();

        signer.Dispose();

        backing.Should().OnlyContain(b => b == 0, "the owning signer must destroy the wrapped key pair");
        pair.Invoking(p => p.PrivateKey).Should().Throw<ObjectDisposedException>();
        await signer.Invoking(s => s.SignAsync(data)).Should().ThrowAsync<ObjectDisposedException>();
        signer.Invoking(s => s.PublicKey).Should().Throw<ObjectDisposedException>();
        signer.Invoking(s => s.MultibasePublicKey).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task KeyPairSigner_NonOwning_LeavesKeyPairAlive()
    {
        using var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(pair, CryptoProvider, ownsKeyPair: false);

        signer.Dispose();

        // The signer is dead, but the caller-owned pair is untouched.
        await signer.Invoking(s => s.SignAsync(new byte[] { 1 })).Should().ThrowAsync<ObjectDisposedException>();
        pair.PrivateKey.Should().NotBeEmpty();
        BackingPrivateKey(pair).Should().Contain(b => b != 0);
    }

    // --- JWK egress ---

    [Fact]
    public void ToPrivateJwk_StillProducesPrivateJwk_AndPairRemainsUsable()
    {
        using var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var jwk = pair.ToPrivateJwk();
        jwk.D.Should().NotBeNullOrEmpty();

        // The wipe inside ToPrivateJwk must only hit its own transient copy, never the pair.
        pair.PrivateKey.Should().Contain(b => b != 0);
        var again = pair.ToPrivateJwk();
        again.D.Should().Be(jwk.D);
    }

    // --- Concurrent borrow vs. dispose (F1 regression) ---

    [Fact]
    public async Task WithPrivateKey_ConcurrentDispose_NeverSignsOverAZeroedKey()
    {
        // A Dispose racing an in-flight borrow must never let the callback observe a half-wiped
        // secret and silently return a wrong signature. Each round must end in exactly one of:
        // a signature that verifies, or ObjectDisposedException — never a verify-false signature.
        var data = "concurrent"u8.ToArray();
        const int rounds = 2000;
        var wrongSignatures = 0;

        for (var i = 0; i < rounds; i++)
        {
            var pair = KeyGenerator.Generate(KeyType.Ed25519);
            var publicKey = pair.PublicKey;
            using var start = new ManualResetEventSlim(false);

            var signer = Task.Run(() =>
            {
                start.Wait();
                try
                {
                    var sig = pair.WithPrivateKey(pk => CryptoProvider.Sign(pair.KeyType, pk, data));
                    if (!CryptoProvider.Verify(pair.KeyType, publicKey, data, sig))
                        Interlocked.Increment(ref wrongSignatures);
                }
                catch (ObjectDisposedException) { /* acceptable loud failure */ }
            });

            var disposer = Task.Run(() =>
            {
                start.Wait();
                pair.Dispose();
            });

            start.Set(); // release both tasks as simultaneously as possible
            await Task.WhenAll(signer, disposer);
        }

        wrongSignatures.Should().Be(0,
            "a borrow must complete atomically against Dispose — never sign over a zeroed key");
    }

    // --- Pinned canonical copy ---

    [Fact]
    public void KeyPair_PrivateKeyBackingStore_SurvivesCompactingGcThenZeroesOnDispose()
    {
        // Pinned-object-heap membership is not observable from managed code (a `fixed` block would
        // pin any array and prove nothing), so this asserts the guarantee that actually matters:
        // the canonical secret is intact after a forced compacting GC and is wiped on dispose.
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var expected = pair.WithPrivateKey(pk => pk.ToArray());
        var backing = BackingPrivateKey(pair);

        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();

        pair.WithPrivateKey(pk => pk.ToArray()).Should().Equal(expected, "the key survives a compacting GC");
        pair.Dispose();
        backing.Should().OnlyContain(b => b == 0);
    }
}

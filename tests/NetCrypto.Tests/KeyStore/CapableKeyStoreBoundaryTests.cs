using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rules 6, 8, 9, 10 — cancellation, finite bounds, and the portable error taxonomy,
/// plus the NFR-6 return-path obligations every delegating type inherits: validate backend
/// output as strictly as backend input, and hold defensive copies in both directions.
/// </summary>
public class CapableKeyStoreBoundaryTests
{
    // ------------------------------------------------------------ rule 6: cancellation

    [Fact]
    public async Task CancellingBeforeAcceptance_CreatesNothing_AndLeavesNoReceipt()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var operationId = CapableStoreTestSupport.NewOperationId();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        (await store.ListAsync()).Should().BeEmpty("cancellation before acceptance means nothing happened");
        (await store.GetMutationOutcomeAsync(KeyMutationKind.Generate, operationId)).Should().BeNull();
    }

    [Fact]
    public async Task CancellingAnImportBeforeAcceptance_LeavesTheMaterialUsable()
    {
        using var store = CapableStoreTestSupport.NewStore();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        material.IsConsumed.Should().BeFalse();
        material.ReadCount.Should().Be(0);
        (await store.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task CancellingADeleteBeforeAcceptance_DestroysNothing()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.Ed25519);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => store.DeleteAsync(
            new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), alias, instanceId), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        (await store.GetInfoAsync(alias, instanceId)).Should().NotBeNull();
    }

    [Fact]
    public async Task ReplayIsAnsweredEvenWhenCancelled_BecauseNothingIsBeingMutated()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var operationId = CapableStoreTestSupport.NewOperationId();
        var created = await store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        // The retry path is exactly what a caller runs after an ambiguous call; reporting
        // cancellation there would hide the fact that the key already exists.
        var replay = await store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519), cts.Token);

        replay.Replayed.Should().BeTrue();
        replay.InstanceId.Should().Be(created.InstanceId);
    }

    // ------------------------------------------------------------ rule 9: finite bounds

    [Fact]
    public async Task OversizeSignInput_FailsBeforeTheProviderIsTouched()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.P256, KeyStoreOperation.Sign, KeyStoreAlgorithms.Es256P1363)!;
        var oversize = new byte[capability.MaxInputBytes + 1];

        var act = () => store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, oversize));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        crypto.SignCalls.Should().Be(0);
    }

    [Fact]
    public async Task ExactlyTheAdvertisedBound_IsAccepted()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);
        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.P256, KeyStoreOperation.Sign, KeyStoreAlgorithms.Es256P1363)!;

        var signature = await store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, new byte[capability.MaxInputBytes]));

        signature.Should().HaveCount(64, "the bound is inclusive");
    }

    [Fact]
    public async Task OversizePeerPublicKey_FailsBeforeTheProviderIsTouched()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.X25519, KeyStoreOperation.KeyAgreement, KeyStoreAlgorithms.EcdhX25519)!;

        var act = () => store.DeriveSharedSecretAsync(new KeyAgreementRequest(
            alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[capability.MaxInputBytes + 1]));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        crypto.AgreeCalls.Should().Be(0);
    }

    // ------------------------------------------------------------ rule 10 / NFR-6: the boundary

    /// <summary>
    /// A genuine <c>Nethermind.Crypto.Bls.BlsException</c>, raised the way the backend really
    /// raises it — a hand-rolled stand-in would prove nothing about the real type.
    /// </summary>
    private static Exception RealBackendException()
    {
        try
        {
            new Nethermind.Crypto.Bls.SecretKey().FromBendian(new byte[3]);
        }
        catch (Exception ex)
        {
            return ex;
        }

        throw new InvalidOperationException("expected the BLS backend to reject a 3-byte scalar");
    }

    // The forbidden-leak list from NFR-3, plus a real backend type.
    //
    // CryptographicException is deliberately absent: it is path-dependent. On a path that
    // forwards caller-supplied key material it means the caller's bytes were bad and must be a
    // parameter fault; on a path whose only caller input is opaque bytes it is a genuine backend
    // failure. Both are pinned separately below.
    public static TheoryData<Func<Exception>> BackendFailures() => new()
    {
        RealBackendException,
        () => new DllNotFoundException("libnative.so"),
        () => new IndexOutOfRangeException("off the end"),
        () => new NullReferenceException("null deref inside the provider"),
        () => new FormatException("bad format"),
        () => new OverflowException("overflow"),
        () => new InvalidOperationException("provider is confused"),
    };

    [Theory]
    [MemberData(nameof(BackendFailures))]
    public async Task NoBackendExceptionTypeEscapesSigning(Func<Exception> failure)
    {
        var crypto = new HostileCryptoProvider { SignThrows = failure };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));

        var thrown = (await act.Should().ThrowAsync<KeyStoreException>()).Which;
        thrown.Error.Should().Be(KeyStoreError.Unavailable);
        thrown.InnerException.Should().BeOfType(failure().GetType(), "diagnosis must not be lost");
    }

    [Theory]
    [MemberData(nameof(BackendFailures))]
    public async Task NoBackendExceptionTypeEscapesKeyAgreement(Func<Exception> failure)
    {
        var crypto = new HostileCryptoProvider { AgreeThrows = failure };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[32]));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task ACryptographicFailureWhileSigning_IsABackendCondition()
    {
        // The only caller input on this path is opaque bytes, which cannot be "invalid" — so a
        // crypto failure here really is the backend's.
        var crypto = new HostileCryptoProvider
        {
            SignThrows = () => new System.Security.Cryptography.CryptographicException("platform crypto failure"),
        };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task ACryptographicFailureDuringAgreement_IsACallerFault_NotARetryableOutage()
    {
        // The peer public key is caller-supplied key material, and an off-curve or low-order
        // point arrives as a CryptographicException. Reporting Unavailable would tell the caller
        // to retry bytes that can never work, and would read as a backend outage in monitoring.
        var crypto = new HostileCryptoProvider
        {
            AgreeThrows = () => new System.Security.Cryptography.CryptographicException("point is not on the curve"),
        };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[32]));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    public static TheoryData<KeyType, byte[]> UnusablePeerKeys() => new()
    {
        // Structurally valid, semantically wrong — NFR-3 family (c), where the defects hide.
        { KeyType.X25519, new byte[32] },                                        // low-order point
        { KeyType.X25519, [0x01, .. new byte[31]] },                             // order-4 point
        { KeyType.P256, [0x04, .. Enumerable.Repeat((byte)0x11, 64)] },          // off-curve, non-zero
        { KeyType.P256, [0x04, .. new byte[64]] },                               // encoded identity
    };

    [Theory]
    [MemberData(nameof(UnusablePeerKeys))]
    public async Task AnUnusablePeerPoint_IsAParameterFault_OnBothTheCapableAndLegacyPaths(KeyType keyType, byte[] peer)
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", keyType);
        var algorithm = keyType == KeyType.X25519 ? KeyStoreAlgorithms.EcdhX25519 : KeyStoreAlgorithms.EcdhP256;

        var capable = () => store.DeriveSharedSecretAsync(new KeyAgreementRequest(alias, instanceId, algorithm, peer));
        await capable.Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        var legacy = () => store.DeriveSharedSecretAsync(alias, peer);
        await legacy.Should().ThrowAsync<ArgumentException>().WithParameterName("peerPublicKey");
    }

    [Theory]
    [MemberData(nameof(UnusablePeerKeys))]
    public async Task TheOlderInMemoryKeyStore_AlsoReportsAnUnusablePeerPointAsAParameterFault(KeyType keyType, byte[] peer)
    {
        // NFR-3 is not waived by "migrate verbatim": that rule covers valid-input behavior, and
        // on invalid input a leaked platform CryptographicException is a contract violation
        // wherever it happens.
        using var store = new InMemoryKeyStore(CapableStoreTestSupport.KeyGenerator, CapableStoreTestSupport.CryptoProvider);
        await store.GenerateAsync("k", keyType);

        var act = () => store.DeriveSharedSecretAsync("k", peer);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("peerPublicKey");
    }

    [Fact]
    public async Task AProviderArgumentFault_IsReportedAgainstTheCallersParameter()
    {
        var crypto = new HostileCryptoProvider { AgreeThrows = () => new ArgumentException("bad point", "publicKey") };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[32]));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    public async Task AMalformedPeerKey_IsAParameterFault_NotABackendCondition()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[31]));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(65)]
    public async Task AWronglySizedProviderResult_IsRejectedRatherThanPassedThrough(int length)
    {
        var crypto = new HostileCryptoProvider { SignReturns = () => new byte[length] };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AWronglySizedSharedSecret_IsRejected()
    {
        var crypto = new HostileCryptoProvider { AgreeReturns = () => new byte[16] };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[32]));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AProviderRetainingItsResultBuffer_CannotMutateWhatTheCallerGot()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var signature = await store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));
        var snapshot = (byte[])signature.Clone();

        // The provider still holds the array it returned and scribbles on it afterwards.
        crypto.LastReturnedBuffer.Should().NotBeNull();
        Array.Fill(crypto.LastReturnedBuffer!, (byte)0xAA);

        signature.Should().Equal(snapshot, "only a private verified copy is handed to the caller");
    }

    [Fact]
    public async Task AProviderRetainingItsAgreementBuffer_CannotMutateWhatTheCallerGot()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);
        using var peer = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.X25519);

        var z = await store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, peer.PublicKey));
        var snapshot = (byte[])z.Clone();

        Array.Fill(crypto.LastReturnedBuffer!, (byte)0xAA);

        z.Should().Equal(snapshot);
    }

    [Fact]
    public async Task AFailingKeyGenerator_SurfacesAsUnavailable_NotAsALeakedBackendType()
    {
        using var backend = new InMemoryKeyStoreBackend();
        using var store = new CapableInMemoryKeyStore(
            backend, new KeyStoreNamespaceId("ns"), new ThrowingKeyGenerator(), CapableStoreTestSupport.CryptoProvider);

        var act = () => store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        var thrown = (await act.Should().ThrowAsync<KeyStoreException>()).Which;
        thrown.Error.Should().Be(KeyStoreError.Unavailable);
        thrown.InnerException.Should().BeOfType<DllNotFoundException>();
        (await store.ListAsync()).Should().BeEmpty("a failed generate leaves no partial state");
    }

    [Fact]
    public void RetryAfter_MustNotBeNegative()
    {
        var act = () => new KeyStoreException(KeyStoreError.Throttled, "slow down", TimeSpan.FromSeconds(-1), null);

        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("retryAfter");
    }

    [Fact]
    public void RetryAfter_IsCarriedThrough()
    {
        var exception = new KeyStoreException(KeyStoreError.Throttled, "slow down", TimeSpan.FromSeconds(3), null);

        exception.Error.Should().Be(KeyStoreError.Throttled);
        exception.RetryAfter.Should().Be(TimeSpan.FromSeconds(3));
        new KeyStoreException(KeyStoreError.Unsupported, "no").RetryAfter.Should().BeNull();
    }

    private sealed class ThrowingKeyGenerator : IKeyGenerator
    {
        public KeyPair Generate(KeyType keyType) => throw new DllNotFoundException("the HSM driver is missing");

        public KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey)
            => throw new DllNotFoundException("the HSM driver is missing");

        public PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey)
            => throw new DllNotFoundException("the HSM driver is missing");

        public KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair)
            => throw new DllNotFoundException("the HSM driver is missing");

        public PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey)
            => throw new DllNotFoundException("the HSM driver is missing");
    }
}

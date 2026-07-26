using System.Globalization;
using System.Numerics;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// FR-12b acceptance tests for <see cref="IRecoverableDigestSigner"/> /
/// <see cref="RecoverableSignature"/> — the abstraction over <see cref="Secp256k1Recoverable"/>
/// that lets HSM/key-store-held secp256k1 keys produce recoverable digest signatures (issue #21).
/// The FR-12 boundary is unchanged: raw recovery id only, no keccak, no EVM v-encoding.
/// </summary>
public class RecoverableDigestSignerTests
{
    // secp256k1 group order n, per SEC 2 §2.4.1 ("Recommended Parameters secp256k1").
    private static readonly BigInteger CurveOrderN = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber);

    private static readonly BigInteger HalfCurveOrder = CurveOrderN / 2;

    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    private InMemoryKeyStore NewStore() => new(_keyGen, _crypto);

    // --- Round-trip through the in-repo oracle: recovered key == signer's public key ---

    [Fact]
    public async Task KeyPairSigner_SignDigestAsync_RecoversToSignerPublicKey()
    {
        var rng = new Random(42);
        for (var i = 0; i < 20; i++)
        {
            using var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);
            var digest = new byte[32];
            rng.NextBytes(digest);

            var (signature64, recoveryId) = await signer.SignDigestAsync(digest);

            signature64.Should().HaveCount(64, "iteration {0}", i);
            recoveryId.Should().BeInRange(0, 3, "iteration {0}", i);
            Secp256k1Recoverable.RecoverPublicKey(digest, signature64, recoveryId, compressed: true)
                .Should().Equal(signer.PublicKey.ToArray(), "iteration {0}", i);
        }
    }

    [Fact]
    public async Task InMemoryKeyStore_SignDigestAsync_RecoversToStoredPublicKey()
    {
        using var store = NewStore();
        var info = await store.GenerateAsync("evm", KeyType.Secp256k1);
        var digest = new byte[32];
        new Random(7).NextBytes(digest);

        var result = await store.SignDigestAsync("evm", digest);

        Secp256k1Recoverable.RecoverPublicKey(digest, result.Signature64, result.RecoveryId, compressed: true)
            .Should().Equal(info.PublicKey);
    }

    [Fact]
    public async Task CreateSignerAsync_ReturnsSigner_PatternMatchableToRecoverableDigestSigner()
    {
        // The consumer contract from issue #21: CreateSignerAsync keeps returning ISigner and
        // consumers pattern-match. The returned KeyStoreSigner must implement the new interface
        // and delegate to the store without the private key leaving it.
        using var store = NewStore();
        var info = await store.GenerateAsync("evm", KeyType.Secp256k1);
        var signer = await store.CreateSignerAsync("evm");

        var recoverable = signer.Should().BeAssignableTo<IRecoverableDigestSigner>().Subject;
        recoverable.KeyType.Should().Be(KeyType.Secp256k1);
        recoverable.PublicKey.ToArray().Should().Equal(info.PublicKey);

        var digest = new byte[32];
        new Random(11).NextBytes(digest);
        var result = await recoverable.SignDigestAsync(digest);

        Secp256k1Recoverable.RecoverPublicKey(digest, result.Signature64, result.RecoveryId, compressed: true)
            .Should().Equal(info.PublicKey);
    }

    // --- Low-S and RFC 6979 determinism ---

    [Fact]
    public async Task SignDigestAsync_AlwaysProducesLowS()
    {
        var rng = new Random(2026);
        using var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);

        for (var i = 0; i < 50; i++)
        {
            var digest = new byte[32];
            rng.NextBytes(digest);

            var (signature64, _) = await signer.SignDigestAsync(digest);

            var s = new BigInteger(signature64.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
            s.Should().BeGreaterThan(BigInteger.Zero, "iteration {0}", i);
            (s <= HalfCurveOrder).Should().BeTrue("low-S normalization requires S <= n/2 (iteration {0})", i);
        }
    }

    [Fact]
    public async Task SignDigestAsync_IsDeterministic_SameDigestSameSignatureAndRecid()
    {
        using var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);
        var digest = new byte[32];
        new Random(1337).NextBytes(digest);

        var first = await signer.SignDigestAsync(digest);
        var second = await signer.SignDigestAsync(digest);

        second.Signature64.Should().Equal(first.Signature64, "RFC 6979 nonces make signing deterministic");
        second.RecoveryId.Should().Be(first.RecoveryId);
    }

    // --- External known-good vector (EIP-155 example) through the abstraction ---

    [Fact]
    public async Task SignDigestAsync_Eip155ExampleTransaction_MatchesPublishedVector()
    {
        // Known vector from EIP-155 "Example" (https://eips.ethereum.org/EIPS/eip-155): the
        // example transaction's signing hash, signed with private key 0x4646…46, yields
        // (v, r, s) = (37, 18515461264373351373200002665853028612451056578545711640558177340181847433846,
        // 46948507304638947509940763649030358759909902576025900602547168820602576006531);
        // v = 37 on chain id 1 ⇒ raw recid = v - 35 - 2·chainId = 0. The abstraction must return
        // the same bytes as the FR-12 primitive — pinned against the published values, not
        // writer/reader parity.
        var privateKey = Convert.FromHexString("4646464646464646464646464646464646464646464646464646464646464646");
        var signingHash = Convert.FromHexString("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
        var expectedR = ToBigEndian32(BigInteger.Parse(
            "18515461264373351373200002665853028612451056578545711640558177340181847433846"));
        var expectedS = ToBigEndian32(BigInteger.Parse(
            "46948507304638947509940763649030358759909902576025900602547168820602576006531"));

        // Once via the in-memory KeyPair path…
        using var signer = new KeyPairSigner(_keyGen.FromPrivateKey(KeyType.Secp256k1, privateKey), _crypto);
        var direct = await signer.SignDigestAsync(signingHash);

        direct.Signature64.AsSpan(0, 32).ToArray().Should().Equal(expectedR);
        direct.Signature64.AsSpan(32, 32).ToArray().Should().Equal(expectedS);
        direct.RecoveryId.Should().Be(0);

        // …and once via the key-store path (store → KeyStoreSigner → store.SignDigestAsync).
        using var store = NewStore();
        await store.ImportAsync("eip155", _keyGen.FromPrivateKey(KeyType.Secp256k1, privateKey));
        var storeSigner = (IRecoverableDigestSigner)await store.CreateSignerAsync("eip155");
        var delegated = await storeSigner.SignDigestAsync(signingHash);

        delegated.Signature64.Should().Equal(direct.Signature64);
        delegated.RecoveryId.Should().Be(0);
    }

    // --- Negative matrix: digest length (NFR-3 — parameter-named, before any crypto op) ---

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public async Task KeyPairSigner_SignDigestAsync_WrongDigestLength_ThrowsArgumentException(int length)
    {
        using var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);

        var act = () => signer.SignDigestAsync(new byte[length]);

        (await act.Should().ThrowAsync<ArgumentException>()).WithParameterName("digest32");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public async Task InMemoryKeyStore_SignDigestAsync_WrongDigestLength_ThrowsArgumentException(int length)
    {
        using var store = NewStore();
        await store.GenerateAsync("evm", KeyType.Secp256k1);

        var act = () => store.SignDigestAsync("evm", new byte[length]);

        (await act.Should().ThrowAsync<ArgumentException>()).WithParameterName("digest32");
    }

    [Fact]
    public async Task KeyStoreSigner_SignDigestAsync_WrongDigestLength_ThrowsBeforeTouchingStore()
    {
        // Backed by a DIM-default store: if KeyStoreSigner delegated before validating, the
        // store's NotSupportedException would surface instead of the ArgumentException.
        var signer = new KeyStoreSigner(new DimDefaultKeyStore(), "alias", KeyType.Secp256k1, new byte[33]);

        var act = () => signer.SignDigestAsync(new byte[31]);

        (await act.Should().ThrowAsync<ArgumentException>()).WithParameterName("digest32");
    }

    // --- Negative matrix: key type, disposal, alias, and the DIM opt-in default ---

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task KeyPairSigner_SignDigestAsync_NonSecp256k1_ThrowsNotSupported(KeyType keyType)
    {
        using var signer = new KeyPairSigner(_keyGen.Generate(keyType), _crypto);

        var act = () => signer.SignDigestAsync(new byte[32]);

        (await act.Should().ThrowAsync<NotSupportedException>())
            .WithMessage($"*{keyType}*", "the message must name the offending key type");
    }

    [Fact]
    public async Task KeyPairSigner_SignDigestAsync_Disposed_ThrowsObjectDisposed()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);
        signer.Dispose();

        var act = () => signer.SignDigestAsync(new byte[32]);

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task IKeyStore_SignDigestAsync_DefaultImplementation_ThrowsNotSupported()
    {
        // A store compiled against the pre-1.4.0 interface shape implements nothing new and
        // must (a) still compile — DimDefaultKeyStore proves source compatibility — and
        // (b) surface the explicit opt-in contract, not a MissingMethodException or similar.
        IKeyStore store = new DimDefaultKeyStore();

        var act = () => store.SignDigestAsync("any", new byte[32]);

        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task KeyStoreSigner_SignDigestAsync_OverDimDefaultStore_ThrowsNotSupported()
    {
        var signer = new KeyStoreSigner(new DimDefaultKeyStore(), "alias", KeyType.Secp256k1, new byte[33]);

        var act = () => signer.SignDigestAsync(new byte[32]);

        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task InMemoryKeyStore_SignDigestAsync_UnknownAlias_ThrowsKeyNotFound()
    {
        using var store = NewStore();

        var act = () => store.SignDigestAsync("missing", new byte[32]);

        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task InMemoryKeyStore_SignDigestAsync_NonSecp256k1Alias_ThrowsNotSupported()
    {
        using var store = NewStore();
        await store.GenerateAsync("ed", KeyType.Ed25519);

        var act = () => store.SignDigestAsync("ed", new byte[32]);

        (await act.Should().ThrowAsync<NotSupportedException>())
            .WithMessage($"*{KeyType.Ed25519}*");
    }

    [Fact]
    public async Task InMemoryKeyStore_SignDigestAsync_NullOrEmptyAlias_ThrowsArgumentException()
    {
        using var store = NewStore();

        await FluentActions.Awaiting(() => store.SignDigestAsync(null!, new byte[32]))
            .Should().ThrowAsync<ArgumentNullException>();
        await FluentActions.Awaiting(() => store.SignDigestAsync("", new byte[32]))
            .Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task InMemoryKeyStore_SignDigestAsync_Disposed_ThrowsObjectDisposed()
    {
        var store = NewStore();
        await store.GenerateAsync("evm", KeyType.Secp256k1);
        store.Dispose();

        var act = () => store.SignDigestAsync("evm", new byte[32]);

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    // --- Digest content is opaque: an all-zero digest is a valid ECDSA input ---

    [Fact]
    public async Task SignDigestAsync_AllZeroDigest_SignsAndRecovers()
    {
        using var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Secp256k1), _crypto);
        var digest = new byte[32];

        var (signature64, recoveryId) = await signer.SignDigestAsync(digest);

        Secp256k1Recoverable.RecoverPublicKey(digest, signature64, recoveryId, compressed: true)
            .Should().Equal(signer.PublicKey.ToArray());
    }

    /// <summary>Converts a non-negative BigInteger to exactly 32 big-endian bytes.</summary>
    private static byte[] ToBigEndian32(BigInteger value)
    {
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        raw.Length.Should().BeLessThanOrEqualTo(32);
        var padded = new byte[32];
        raw.CopyTo(padded, 32 - raw.Length);
        return padded;
    }

    /// <summary>
    /// An <see cref="IKeyStore"/> written against the pre-1.4.0 interface shape: it implements
    /// every original member and does NOT override <see cref="IKeyStore.SignDigestAsync"/>.
    /// Compiling at all is the source-compatibility proof for the DIM default (issue #21).
    /// </summary>
    private sealed class DimDefaultKeyStore : IKeyStore
    {
        public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
            => throw new NotImplementedException();
    }
}

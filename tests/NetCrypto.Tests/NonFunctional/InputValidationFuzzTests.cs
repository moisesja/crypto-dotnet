using System.Security.Cryptography;
using FluentAssertions;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// NFR-3 fuzz-lite — drives the Phase-A byte-oriented entry points
/// (<see cref="DefaultCryptoProvider"/> Sign/Verify/KeyAgreement/DeriveSharedSecret,
/// <see cref="DefaultKeyGenerator"/> FromPrivateKey/FromPublicKey,
/// <see cref="ConcatKdf.DeriveKey"/>, the <see cref="Hkdf"/> methods, and
/// <see cref="JwkConverter.ExtractPublicKey"/> with null) with empty, 1-byte, and oversized
/// (10 000-byte) inputs across all <see cref="KeyType"/> values, asserting any exception
/// thrown is ArgumentException/ArgumentNullException/CryptographicException/
/// NotSupportedException — never IndexOutOfRangeException, NullReferenceException, or
/// OverflowException (PRD §4 NFR-3 acceptance criterion).
/// </summary>
/// <remarks>
/// Every byte-oriented entry point now validates its raw key/scalar inputs up front (see
/// <see cref="RawKeyGuard"/>), so malformed input always surfaces as a contract exception. There
/// is intentionally NO "known deviations" allow-list: any non-contract exception (a leaked NSec
/// <c>FormatException</c>, Nethermind <c>BlsException</c>, platform crypto exception, etc.) is a
/// real NFR-3 defect that must be fixed in src — never pinned to keep this suite green.
/// </remarks>
public class InputValidationFuzzTests
{
    private static readonly DefaultCryptoProvider Provider = new();
    private static readonly DefaultKeyGenerator Generator = new();

    /// <summary>Empty, single-byte, and oversized fuzz input lengths.</summary>
    private static readonly int[] InputSizes = [0, 1, 10_000];

    /// <summary>One valid key pair per key type, generated once and shared read-only.</summary>
    private static readonly IReadOnlyDictionary<KeyType, KeyPair> ValidKeyPairs =
        Enum.GetValues<KeyType>().ToDictionary(keyType => keyType, keyType => Generator.Generate(keyType));

    /// <summary>All key types crossed with all fuzz input sizes.</summary>
    public static TheoryData<KeyType, int> KeyTypeAndSizeMatrix()
    {
        var data = new TheoryData<KeyType, int>();
        foreach (var keyType in Enum.GetValues<KeyType>())
            foreach (var size in InputSizes)
                data.Add(keyType, size);
        return data;
    }

    /// <summary>All fuzz input sizes (for entry points without a key-type parameter).</summary>
    public static TheoryData<int> SizeMatrix()
    {
        var data = new TheoryData<int>();
        foreach (var size in InputSizes)
            data.Add(size);
        return data;
    }

    /// <summary>SHA-256/384/512 crossed with all fuzz input sizes (for the Hkdf methods).</summary>
    public static TheoryData<string, int> HashAlgorithmAndSizeMatrix()
    {
        var data = new TheoryData<string, int>();
        foreach (var name in new[] { "SHA256", "SHA384", "SHA512" })
            foreach (var size in InputSizes)
                data.Add(name, size);
        return data;
    }

    // ── DefaultCryptoProvider ──

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void Sign_MalformedPrivateKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("Sign", keyType, $"{Shape(size)} private key",
            () => Provider.Sign(keyType, new byte[size], [1, 2, 3]));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void Verify_MalformedPublicKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("Verify", keyType, $"{Shape(size)} public key",
            () => Provider.Verify(keyType, new byte[size], [1, 2, 3], new byte[64]));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void Verify_Sec1PrefixedJunkPublicKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
    {
        // First byte set to a SEC1 marker so EC paths reach point decompression / validation
        // instead of bailing on the format check.
        foreach (var prefix in new byte[] { 0x02, 0x04 })
        {
            var junk = new byte[Math.Max(size, 1)];
            junk[0] = prefix;
            AssertValidationContract("Verify", keyType, $"{Shape(junk.Length)} 0x{prefix:x2}-prefixed public key",
                () => Provider.Verify(keyType, junk, [1, 2, 3], new byte[64]));
        }
    }

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void Verify_ValidPublicKeyMalformedSignature_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("Verify", keyType, $"valid public key with {Shape(size)} signature",
            () => Provider.Verify(keyType, ValidKeyPairs[keyType].PublicKey, [1, 2, 3], new byte[size]));

    [Theory]
    [MemberData(nameof(SizeMatrix))]
    public void KeyAgreement_MalformedPrivateKey_ThrowsOnlyContractExceptions(int size)
        => AssertValidationContract("KeyAgreement", KeyType.X25519, $"{Shape(size)} private key",
            () => Provider.KeyAgreement(new byte[size], ValidKeyPairs[KeyType.X25519].PublicKey));

    [Theory]
    [MemberData(nameof(SizeMatrix))]
    public void KeyAgreement_MalformedPublicKey_ThrowsOnlyContractExceptions(int size)
        => AssertValidationContract("KeyAgreement", KeyType.X25519, $"{Shape(size)} public key",
            () => Provider.KeyAgreement(ValidKeyPairs[KeyType.X25519].PrivateKey, new byte[size]));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void DeriveSharedSecret_MalformedPrivateKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("DeriveSharedSecret", keyType, $"{Shape(size)} private key",
            () => Provider.DeriveSharedSecret(keyType, new byte[size], ValidKeyPairs[keyType].PublicKey));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void DeriveSharedSecret_MalformedPublicKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("DeriveSharedSecret", keyType, $"{Shape(size)} public key",
            () => Provider.DeriveSharedSecret(keyType, ValidKeyPairs[keyType].PrivateKey, new byte[size]));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void DeriveSharedSecret_BothInputsMalformed_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("DeriveSharedSecret", keyType, $"{Shape(size)} private and public keys",
            () => Provider.DeriveSharedSecret(keyType, new byte[size], new byte[size]));

    // ── DefaultKeyGenerator ──

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void FromPrivateKey_MalformedPrivateKey_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("FromPrivateKey", keyType, $"{Shape(size)} private key",
            () => Generator.FromPrivateKey(keyType, new byte[size]));

    [Theory]
    [MemberData(nameof(KeyTypeAndSizeMatrix))]
    public void FromPublicKey_AnyInput_ThrowsOnlyContractExceptions(KeyType keyType, int size)
        => AssertValidationContract("FromPublicKey", keyType, $"{Shape(size)} public key",
            () => Generator.FromPublicKey(keyType, new byte[size]));

    // ── ConcatKdf ──

    [Theory]
    [MemberData(nameof(SizeMatrix))]
    public void ConcatKdf_DeriveKey_FuzzedSpans_ThrowsOnlyContractExceptions(int size)
    {
        var junk = new byte[size];
        AssertValidationContract("ConcatKdf.DeriveKey", KeyType.Ed25519, $"{Shape(size)} for every span parameter",
            () => ConcatKdf.DeriveKey(junk, junk, junk, junk, junk, junk, keyDataLen: 32));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ConcatKdf_DeriveKey_NonPositiveKeyDataLen_ThrowsWithParameterName(int keyDataLen)
    {
        var act = () => ConcatKdf.DeriveKey([1], [1], [1], [1], [1], [1], keyDataLen);

        // ArgumentOutOfRangeException is an ArgumentException, satisfying the NFR-3 contract.
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("keyDataLen");
    }

    // ── Hkdf ──

    [Theory]
    [MemberData(nameof(HashAlgorithmAndSizeMatrix))]
    public void Hkdf_Extract_FuzzedInputs_ThrowsOnlyContractExceptions(string hashName, int size)
    {
        var junk = new byte[size];
        AssertValidationContract($"Hkdf.Extract({hashName})", KeyType.Ed25519, $"{Shape(size)} ikm and salt",
            () => Hkdf.Extract(new HashAlgorithmName(hashName), junk, junk));
    }

    [Theory]
    [MemberData(nameof(HashAlgorithmAndSizeMatrix))]
    public void Hkdf_Expand_FuzzedInputs_ThrowsOnlyContractExceptions(string hashName, int size)
    {
        var junk = new byte[size];
        AssertValidationContract($"Hkdf.Expand({hashName})", KeyType.Ed25519, $"{Shape(size)} prk and info",
            () => Hkdf.Expand(new HashAlgorithmName(hashName), junk, outputLength: 32, junk));
    }

    [Theory]
    [MemberData(nameof(HashAlgorithmAndSizeMatrix))]
    public void Hkdf_DeriveKey_FuzzedInputs_ThrowsOnlyContractExceptions(string hashName, int size)
    {
        var junk = new byte[size];
        AssertValidationContract($"Hkdf.DeriveKey({hashName})", KeyType.Ed25519, $"{Shape(size)} ikm, salt, and info",
            () => Hkdf.DeriveKey(new HashAlgorithmName(hashName), junk, outputLength: 32, junk, junk));
    }

    [Fact]
    public void Hkdf_UnsupportedHashAlgorithm_ThrowsArgumentExceptionWithParameterName()
    {
        var act = () => Hkdf.Extract(HashAlgorithmName.MD5, [1, 2, 3]);

        act.Should().Throw<ArgumentException>().WithParameterName("hashAlgorithm");
    }

    // ── JwkConverter ──

    [Fact]
    public void ExtractPublicKey_NullJwk_ThrowsArgumentNullExceptionWithParameterName()
    {
        var act = () => JwkConverter.ExtractPublicKey(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("jwk");
    }

    // ── helpers ──

    private static string Shape(int size) => size switch
    {
        0 => "empty",
        1 => "1-byte",
        _ => $"oversized {size}-byte",
    };

    /// <summary>
    /// Invokes the entry point and asserts the NFR-3 exception contract: not throwing is fine
    /// (e.g. Verify returning false); throwing is fine only for
    /// ArgumentException (covers ArgumentNullException/ArgumentOutOfRangeException),
    /// CryptographicException (covers platform-specific subclasses), or NotSupportedException.
    /// Any other exception type is an NFR-3 defect and fails the test — there is no allow-list.
    /// </summary>
    private static void AssertValidationContract(string member, KeyType keyType, string inputShape, Action act)
    {
        try
        {
            act();
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or NotSupportedException)
        {
            // Within the NFR-3 contract.
        }
        catch (Exception ex)
        {
            Assert.Fail(
                $"{member} ({keyType}) with {inputShape} input threw {ex.GetType().FullName}: '{ex.Message}'. " +
                "Expected ArgumentException/ArgumentNullException/CryptographicException/NotSupportedException, " +
                "and never IndexOutOfRangeException/NullReferenceException/OverflowException (NFR-3).");
        }
    }
}

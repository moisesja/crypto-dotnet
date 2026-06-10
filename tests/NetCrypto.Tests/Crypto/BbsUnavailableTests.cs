using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Acceptance tests for the PRD FR-5 BBS-absent supported mode (netcrypto-prd.md §FR-5,
/// concept decision 8): with the native zkryptium-ffi library absent,
/// <see cref="IBbsCryptoProvider.IsAvailable"/> is <c>false</c> and every
/// <see cref="IBbsCryptoProvider"/> operation throws <see cref="BbsUnavailableException"/>
/// carrying the original native-load error as <see cref="Exception.InnerException"/>.
/// These tests run ONLY in the no-native CI leg (filtered by Category=BbsAbsent, FR-22),
/// where no native payload is copied next to the test assembly.
/// </summary>
[Trait("Category", "BbsAbsent")]
public class BbsUnavailableTests
{
    private readonly DefaultBbsCryptoProvider _bbs = new();

    // Minimal well-formed arguments — correct SK (32) / PK (96) / signature (80) sizes, a
    // non-empty message list, one revealed index — so the unavailability check, which runs
    // before any argument validation, is the only thing that can throw.
    private static readonly byte[] WellFormedSecretKey = new byte[32];
    private static readonly byte[] WellFormedPublicKey = new byte[96];
    private static readonly byte[] WellFormedSignature = new byte[80];
    private static readonly List<byte[]> OneMessage = new() { "m"u8.ToArray() };
    private static readonly List<int> RevealIndexZero = new() { 0 };
    private static readonly byte[] Nonce = "nonce"u8.ToArray();
    // BLS12-381-SHA-256 proof size with zero undisclosed messages: 3*48 + 32*(0+1) = 176.
    private static readonly byte[] WellFormedProof = new byte[176];

    [Fact]
    public void IsAvailable_WithoutNativeLibrary_ReturnsFalse()
    {
        _bbs.IsAvailable.Should().BeFalse("the no-native test leg ships no zkryptium-ffi payload");
    }

    [Fact]
    public void Sign_WithoutNativeLibrary_ThrowsBbsUnavailableExceptionWithInnerException()
    {
        var act = () => _bbs.Sign(WellFormedSecretKey, OneMessage);

        act.Should().Throw<BbsUnavailableException>()
            .Which.InnerException.Should().NotBeNull(
                "the original native-load error must be preserved as InnerException");
    }

    [Fact]
    public void Verify_WithoutNativeLibrary_ThrowsBbsUnavailableExceptionWithInnerException()
    {
        var act = () => _bbs.Verify(WellFormedPublicKey, WellFormedSignature, OneMessage);

        act.Should().Throw<BbsUnavailableException>()
            .Which.InnerException.Should().NotBeNull(
                "the original native-load error must be preserved as InnerException");
    }

    [Fact]
    public void DeriveProof_WithoutNativeLibrary_ThrowsBbsUnavailableExceptionWithInnerException()
    {
        var act = () => _bbs.DeriveProof(
            WellFormedPublicKey, WellFormedSignature, OneMessage, RevealIndexZero, Nonce);

        act.Should().Throw<BbsUnavailableException>()
            .Which.InnerException.Should().NotBeNull(
                "the original native-load error must be preserved as InnerException");
    }

    [Fact]
    public void VerifyProof_WithoutNativeLibrary_ThrowsBbsUnavailableExceptionWithInnerException()
    {
        var act = () => _bbs.VerifyProof(
            WellFormedPublicKey, WellFormedProof, OneMessage, RevealIndexZero, Nonce);

        act.Should().Throw<BbsUnavailableException>()
            .Which.InnerException.Should().NotBeNull(
                "the original native-load error must be preserved as InnerException");
    }
}

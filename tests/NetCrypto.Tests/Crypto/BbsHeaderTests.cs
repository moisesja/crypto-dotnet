using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;
using NetCrypto.Native;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Coverage for the BBS signature <c>header</c> parameter (issue #2): the header is bound by
/// <see cref="IBbsCryptoProvider.Sign"/> and committed by both <see cref="IBbsCryptoProvider.Verify"/>
/// and the derived proof. This is what lets a consumer (e.g. the W3C <c>bbs-2023</c> cryptosuite)
/// bind application data — such as the mandatory-disclosure group — that the holder cannot drop or
/// alter. The header is distinct from the presentation header (<c>ph</c>): the header is fixed by the
/// signer at sign time, the presentation header is chosen by the holder at derive time.
/// </summary>
[Trait("Category", "NativeFFI")]
public class BbsHeaderTests
{
    private readonly DefaultBbsCryptoProvider _bbs = new();

    private static (byte[] sk, byte[] pk) GenerateBbsKeyPair()
    {
        var ikm = new byte[32];
        RandomNumberGenerator.Fill(ikm);

        var sk = new byte[32];
        var pk = new byte[96];
        var rc = ZkryptiumNative.bbs_keygen(ikm, (nuint)ikm.Length, ReadOnlySpan<byte>.Empty, 0, sk, pk);
        if (rc != 0)
            throw new CryptographicException("BBS key generation failed in test setup.");
        return (sk, pk);
    }

    private static List<byte[]> Messages() => new()
    {
        "issuer: did:example:123"u8.ToArray(),
        "given-name: Alice"u8.ToArray(),
        "expiry: 2030-01-01"u8.ToArray(),
    };

    // ── AC1: Sign(header) + Verify(header) round-trips; Verify fails on a different header ──

    [Fact]
    public void SignVerify_WithHeader_RoundTrips()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();
        var header = "bbs-2023-mandatory-binding"u8.ToArray();

        var signature = _bbs.Sign(sk, messages, header);

        _bbs.Verify(pk, signature, messages, header)
            .Should().BeTrue("the same header that was bound at sign time is supplied at verify time");
    }

    [Fact]
    public void Verify_DifferentHeader_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();

        var signature = _bbs.Sign(sk, messages, "header-A"u8.ToArray());

        _bbs.Verify(pk, signature, messages, "header-B"u8.ToArray())
            .Should().BeFalse("a header different from the one signed must fail verification");
    }

    [Fact]
    public void Verify_HeaderSignature_WithDefaultEmptyHeader_ReturnsFalse()
    {
        // A signature bound to a non-empty header must NOT verify when the caller omits the header
        // (the default empty header) — proving the header is genuinely committed, not ignored.
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();

        var signature = _bbs.Sign(sk, messages, "non-empty-header"u8.ToArray());

        _bbs.Verify(pk, signature, messages)
            .Should().BeFalse("omitting the header (default empty) must not verify a header-bound signature");
    }

    // ── AC2: DeriveProof(header) + VerifyProof(header) round-trips; proof commits the header ──

    [Fact]
    public void DeriveProof_VerifyProof_WithHeader_RoundTrips()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();
        var header = "credential-header"u8.ToArray();
        var ph = "verifier-challenge"u8.ToArray();
        var revealed = new List<int> { 0, 2 };

        var signature = _bbs.Sign(sk, messages, header);
        var proof = _bbs.DeriveProof(pk, signature, messages, revealed, ph, header);

        var revealedMessages = new List<byte[]> { messages[0], messages[2] };
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, ph, header)
            .Should().BeTrue("the proof is verified with the same presentation header and header it was derived under");
    }

    [Fact]
    public void VerifyProof_DifferentHeader_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();
        var header = "header-bound-at-derive"u8.ToArray();
        var ph = "verifier-challenge"u8.ToArray();
        var revealed = new List<int> { 0, 2 };

        var signature = _bbs.Sign(sk, messages, header);
        var proof = _bbs.DeriveProof(pk, signature, messages, revealed, ph, header);

        var revealedMessages = new List<byte[]> { messages[0], messages[2] };
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, ph, "different-header"u8.ToArray())
            .Should().BeFalse("the header is committed by the proof; a different header must fail verification");
    }

    [Fact]
    public void Header_And_PresentationHeader_AreIndependent()
    {
        // Changing the presentation header alone breaks verification, and changing the header alone
        // breaks verification — proving the two values are distinct, separately-committed inputs.
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();
        var header = "the-header"u8.ToArray();
        var ph = "the-ph"u8.ToArray();
        var revealed = new List<int> { 0, 2 };

        var signature = _bbs.Sign(sk, messages, header);
        var proof = _bbs.DeriveProof(pk, signature, messages, revealed, ph, header);
        var revealedMessages = new List<byte[]> { messages[0], messages[2] };

        // Correct header, wrong ph → false.
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, "wrong-ph"u8.ToArray(), header)
            .Should().BeFalse("a wrong presentation header must fail even with the correct header");

        // Wrong header, correct ph → false.
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, ph, "wrong-header"u8.ToArray())
            .Should().BeFalse("a wrong header must fail even with the correct presentation header");

        // Both correct → true.
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, ph, header)
            .Should().BeTrue("both the correct header and presentation header verify");
    }

    // ── AC3: the existing empty-header default behavior is unchanged ──

    [Fact]
    public void SignVerify_DefaultHeader_MatchesExplicitEmptyHeader()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();

        // Signing without a header (default) and verifying without a header still round-trips,
        // and is equivalent to passing an explicit empty header.
        var signature = _bbs.Sign(sk, messages);

        _bbs.Verify(pk, signature, messages).Should().BeTrue("default-header round-trip is unchanged");
        _bbs.Verify(pk, signature, messages, ReadOnlySpan<byte>.Empty)
            .Should().BeTrue("an explicit empty header equals the default");
    }

    [Fact]
    public void DeriveProof_DefaultHeader_RoundTrips()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = Messages();
        var ph = "verifier-challenge"u8.ToArray();
        var revealed = new List<int> { 0, 2 };

        // Omitting the header entirely (default) preserves the pre-issue-#2 behavior where only the
        // presentation header is supplied positionally.
        var signature = _bbs.Sign(sk, messages);
        var proof = _bbs.DeriveProof(pk, signature, messages, revealed, ph);

        var revealedMessages = new List<byte[]> { messages[0], messages[2] };
        _bbs.VerifyProof(pk, proof, revealedMessages, revealed, ph)
            .Should().BeTrue("default-header derive/verify is unchanged");
    }
}

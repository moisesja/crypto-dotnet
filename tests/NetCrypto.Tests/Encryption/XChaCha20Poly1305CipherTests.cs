using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Encryption;

/// <summary>
/// FR-16 — <see cref="XChaCha20Poly1305Cipher"/> (JOSE <c>XC20P</c>,
/// draft-irtf-cfrg-xchacha-03) validated against the draft's Appendix A AEAD known-answer
/// vector (detailed form in Appendix A.1, hex-only form in Appendix A.3.1), tamper rejection
/// (single-bit flips in ciphertext, tag, and AAD), the input-validation contract, and a
/// seeded round-trip property over plaintext lengths 0–4096.
/// Vectors: https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt
/// </summary>
public class XChaCha20Poly1305CipherTests
{
    // ── draft-irtf-cfrg-xchacha-03 Appendix A.1 / A.3.1 — AEAD_XCHACHA20_POLY1305, verbatim ──

    // Appendix A.3.1: Plaintext ("Ladies and Gentlemen of the class of '99: If I could offer
    // you only one tip for the future, sunscreen would be it.", 114 octets).
    private static readonly byte[] Plaintext = DraftHex(@"
        4c616469657320616e642047656e746c656d656e206f662074686520636c6173
        73206f66202739393a204966204920636f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
        637265656e20776f756c642062652069742e");

    // Appendix A.3.1: AAD (12 octets).
    private static readonly byte[] Aad = DraftHex("50515253c0c1c2c3c4c5c6c7");

    // Appendix A.3.1: Key (32 octets).
    private static readonly byte[] Key = DraftHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

    // Appendix A.3.1: IV (the 24-octet XChaCha20 nonce).
    private static readonly byte[] Nonce = DraftHex("404142434445464748494a4b4c4d4e4f5051525354555657");

    // Appendix A.3.1: Ciphertext (114 octets).
    private static readonly byte[] ExpectedCiphertext = DraftHex(@"
        bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
        731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
        2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
        21f9664c97637da9768812f615c68b13b52e");

    // Appendix A.3.1: Tag (16 octets).
    private static readonly byte[] ExpectedTag = DraftHex("c0875924c1c7987947deafd8780acf49");

    [Fact]
    public void Encrypt_XChaChaDraftAppendixA31_MatchesExpectedCiphertextAndTag()
    {
        var (ciphertext, tag) = XChaCha20Poly1305Cipher.Encrypt(Key, Nonce, Plaintext, Aad);

        ciphertext.Should().Equal(ExpectedCiphertext,
            because: "draft-irtf-cfrg-xchacha-03 Appendix A.3.1 publishes the exact AEAD ciphertext");
        tag.Should().Equal(ExpectedTag,
            because: "draft-irtf-cfrg-xchacha-03 Appendix A.3.1 publishes the exact 16-byte Poly1305 tag");
    }

    [Fact]
    public void Decrypt_XChaChaDraftAppendixA31_RecoversPlaintext()
    {
        var recovered = XChaCha20Poly1305Cipher.Decrypt(Key, Nonce, ExpectedCiphertext, ExpectedTag, Aad);

        recovered.Should().Equal(Plaintext);
    }

    // ── Tamper tests (FR-16 AC 2, "as in FR-13"): any single-bit flip must throw ──

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(57, 0x10)]   // middle byte
    [InlineData(113, 0x80)]  // last byte, high bit
    public void Decrypt_TamperedCiphertext_Throws(int index, byte mask)
    {
        var tampered = (byte[])ExpectedCiphertext.Clone();
        tampered[index] ^= mask;

        var act = () => XChaCha20Poly1305Cipher.Decrypt(Key, Nonce, tampered, ExpectedTag, Aad);

        act.Should().Throw<CryptographicException>(
            because: "the Poly1305 tag must reject any single-bit flip in the ciphertext");
    }

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(7, 0x08)]    // middle byte
    [InlineData(15, 0x80)]   // last byte, high bit
    public void Decrypt_TamperedTag_Throws(int index, byte mask)
    {
        var tamperedTag = (byte[])ExpectedTag.Clone();
        tamperedTag[index] ^= mask;

        var act = () => XChaCha20Poly1305Cipher.Decrypt(Key, Nonce, ExpectedCiphertext, tamperedTag, Aad);

        act.Should().Throw<CryptographicException>();
    }

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(5, 0x40)]    // middle byte
    [InlineData(11, 0x80)]   // last byte, high bit
    public void Decrypt_TamperedAad_Throws(int index, byte mask)
    {
        var tamperedAad = (byte[])Aad.Clone();
        tamperedAad[index] ^= mask;

        var act = () => XChaCha20Poly1305Cipher.Decrypt(Key, Nonce, ExpectedCiphertext, ExpectedTag, tamperedAad);

        act.Should().Throw<CryptographicException>(
            because: "AAD is authenticated by Poly1305; mutating any bit invalidates the tag");
    }

    // ── Input validation (NFR-3 / FR-16 AC 3): wrong sizes → ArgumentException with parameter name ──

    [Theory]
    [InlineData(0)]
    [InlineData(16)]  // ChaCha20 only ever takes 256-bit keys
    [InlineData(64)]  // A256CBC-HS512 size, not XC20P's 32
    public void Encrypt_WrongKeyLength_ThrowsArgumentException(int keyLength)
    {
        var act = () => XChaCha20Poly1305Cipher.Encrypt(new byte[keyLength], new byte[24], []);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]  // the RFC 8439 ChaCha20-Poly1305 nonce size, not XChaCha20's extended 24
    [InlineData(25)]
    public void Encrypt_WrongNonceLength_ThrowsArgumentException(int nonceLength)
    {
        var act = () => XChaCha20Poly1305Cipher.Encrypt(new byte[32], new byte[nonceLength], []);

        act.Should().Throw<ArgumentException>().WithParameterName("nonce");
    }

    [Fact]
    public void Decrypt_WrongKeyLength_ThrowsArgumentException()
    {
        var act = () => XChaCha20Poly1305Cipher.Decrypt(new byte[16], new byte[24], new byte[16], new byte[16]);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    [Fact]
    public void Decrypt_WrongNonceLength_ThrowsArgumentException()
    {
        var act = () => XChaCha20Poly1305Cipher.Decrypt(new byte[32], new byte[12], new byte[16], new byte[16]);

        act.Should().Throw<ArgumentException>().WithParameterName("nonce");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(32)]  // A256CBC-HS512 tag size, not Poly1305's 16
    public void Decrypt_WrongTagLength_ThrowsArgumentException(int tagLength)
    {
        var act = () => XChaCha20Poly1305Cipher.Decrypt(new byte[32], new byte[24], new byte[16], new byte[tagLength]);

        act.Should().Throw<ArgumentException>().WithParameterName("tag");
    }

    // ── FR-16 AC 4 — round-trip property: random key/nonce/AAD, plaintext lengths 0–4096 ──

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void RoundTrip_SeededRandomInputs_IsIdentity(int plaintextLength)
    {
        var random = new Random(Seed: 0xC20F + plaintextLength);
        var key = new byte[32];
        var nonce = new byte[24];
        var aad = new byte[29];
        var plaintext = new byte[plaintextLength];
        random.NextBytes(key);
        random.NextBytes(nonce);
        random.NextBytes(aad);
        random.NextBytes(plaintext);

        var (ciphertext, tag) = XChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, aad);
        var recovered = XChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, aad);

        ciphertext.Should().HaveCount(plaintextLength, because: "XChaCha20 is a stream cipher; no padding");
        tag.Should().HaveCount(16);
        recovered.Should().Equal(plaintext);
    }

    /// <summary>
    /// Decodes hex transcribed verbatim from draft-irtf-cfrg-xchacha-03 Appendix A.3
    /// ("All values below are hex-encoded"), tolerating the line breaks as printed so the
    /// constants can be diffed against the draft text.
    /// </summary>
    private static byte[] DraftHex(string hex) =>
        Convert.FromHexString(string.Concat(hex.Where(c => !char.IsWhiteSpace(c))));
}

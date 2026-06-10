using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Encryption;

/// <summary>
/// FR-13 — <see cref="AesGcmCipher"/> (JOSE <c>A256GCM</c>, RFC 7518 §5.3) validated against
/// NIST CAVP known-answer vectors for AES-256-GCM (96-bit IV, 128-bit tag, with and without
/// AAD), tamper rejection (single-bit flips in ciphertext, tag, and AAD), and the
/// input-validation contract. Vectors: <c>gcmEncryptExtIV256.rsp</c> from
/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
/// </summary>
public class AesGcmCipherTests
{
    // ── NIST CAVP gcmEncryptExtIV256.rsp,
    //    [Keylen = 256][IVlen = 96][PTlen = 128][AADlen = 0][Taglen = 128], Count = 0
    //    (downloaded from the gcmtestvectors.zip URL cited in the class doc) ──

    private static readonly byte[] NoAadKey =
        Convert.FromHexString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22");

    private static readonly byte[] NoAadIv =
        Convert.FromHexString("0d18e06c7c725ac9e362e1ce");

    private static readonly byte[] NoAadPlaintext =
        Convert.FromHexString("2db5168e932556f8089a0622981d017d");

    private static readonly byte[] NoAadExpectedCiphertext =
        Convert.FromHexString("fa4362189661d163fcd6a56d8bf0405a");

    private static readonly byte[] NoAadExpectedTag =
        Convert.FromHexString("d636ac1bbedd5cc3ee727dc2ab4a9489");

    // ── NIST CAVP gcmEncryptExtIV256.rsp,
    //    [Keylen = 256][IVlen = 96][PTlen = 128][AADlen = 128][Taglen = 128], Count = 0
    //    (same source file as above) ──

    private static readonly byte[] AadKey =
        Convert.FromHexString("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");

    private static readonly byte[] AadIv =
        Convert.FromHexString("ac93a1a6145299bde902f21a");

    private static readonly byte[] AadPlaintext =
        Convert.FromHexString("2d71bcfa914e4ac045b2aa60955fad24");

    private static readonly byte[] Aad =
        Convert.FromHexString("1e0889016f67601c8ebea4943bc23ad6");

    private static readonly byte[] AadExpectedCiphertext =
        Convert.FromHexString("8995ae2e6df3dbf96fac7b7137bae67f");

    private static readonly byte[] AadExpectedTag =
        Convert.FromHexString("eca5aa77d51d4a0a14d9c51e1da474ab");

    // ── FR-13 AC 1 — NIST known-answer vectors (encrypt and decrypt round-trip) ──

    [Fact]
    public void Encrypt_NistCavpVectorWithoutAad_MatchesExpectedCiphertextAndTag()
    {
        var (ciphertext, tag) = AesGcmCipher.Encrypt(NoAadKey, NoAadIv, NoAadPlaintext);

        ciphertext.Should().Equal(NoAadExpectedCiphertext,
            because: "NIST CAVP gcmEncryptExtIV256.rsp [AADlen = 0] Count = 0 publishes the exact CT");
        tag.Should().Equal(NoAadExpectedTag,
            because: "NIST CAVP gcmEncryptExtIV256.rsp [AADlen = 0] Count = 0 publishes the exact Tag");
    }

    [Fact]
    public void Decrypt_NistCavpVectorWithoutAad_RecoversPlaintext()
    {
        var recovered = AesGcmCipher.Decrypt(NoAadKey, NoAadIv, NoAadExpectedCiphertext, NoAadExpectedTag);

        recovered.Should().Equal(NoAadPlaintext);
    }

    [Fact]
    public void Encrypt_NistCavpVectorWithAad_MatchesExpectedCiphertextAndTag()
    {
        var (ciphertext, tag) = AesGcmCipher.Encrypt(AadKey, AadIv, AadPlaintext, Aad);

        ciphertext.Should().Equal(AadExpectedCiphertext,
            because: "NIST CAVP gcmEncryptExtIV256.rsp [AADlen = 128] Count = 0 publishes the exact CT");
        tag.Should().Equal(AadExpectedTag,
            because: "NIST CAVP gcmEncryptExtIV256.rsp [AADlen = 128] Count = 0 publishes the exact Tag");
    }

    [Fact]
    public void Decrypt_NistCavpVectorWithAad_RecoversPlaintext()
    {
        var recovered = AesGcmCipher.Decrypt(AadKey, AadIv, AadExpectedCiphertext, AadExpectedTag, Aad);

        recovered.Should().Equal(AadPlaintext);
    }

    [Fact]
    public void RoundTrip_ArbitraryInputs_RecoversPlaintext()
    {
        var random = new Random(Seed: 5678);
        var key = new byte[32];
        var nonce = new byte[12];
        var aad = new byte[29];
        var plaintext = new byte[173];
        random.NextBytes(key);
        random.NextBytes(nonce);
        random.NextBytes(aad);
        random.NextBytes(plaintext);

        var (ciphertext, tag) = AesGcmCipher.Encrypt(key, nonce, plaintext, aad);
        var recovered = AesGcmCipher.Decrypt(key, nonce, ciphertext, tag, aad);

        recovered.Should().Equal(plaintext);
    }

    // ── FR-13 AC 2 — tamper tests: any single-bit flip must throw on decrypt ──

    [Theory]
    [InlineData(0, 0x01)]   // first byte, low bit
    [InlineData(7, 0x10)]   // middle byte
    [InlineData(15, 0x80)]  // last byte, high bit
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException(int index, byte mask)
    {
        var tampered = (byte[])AadExpectedCiphertext.Clone();
        tampered[index] ^= mask;

        var act = () => AesGcmCipher.Decrypt(AadKey, AadIv, tampered, AadExpectedTag, Aad);

        act.Should().Throw<CryptographicException>(
            because: "GCM must reject any single-bit flip in the ciphertext");
    }

    [Theory]
    [InlineData(0, 0x01)]   // first byte, low bit
    [InlineData(8, 0x08)]   // middle byte
    [InlineData(15, 0x80)]  // last byte, high bit
    public void Decrypt_TamperedTag_ThrowsCryptographicException(int index, byte mask)
    {
        var tamperedTag = (byte[])AadExpectedTag.Clone();
        tamperedTag[index] ^= mask;

        var act = () => AesGcmCipher.Decrypt(AadKey, AadIv, AadExpectedCiphertext, tamperedTag, Aad);

        act.Should().Throw<CryptographicException>(
            because: "GCM must reject any single-bit flip in the authentication tag");
    }

    [Theory]
    [InlineData(0, 0x01)]   // first byte, low bit
    [InlineData(6, 0x40)]   // middle byte
    [InlineData(15, 0x80)]  // last byte, high bit
    public void Decrypt_TamperedAad_ThrowsCryptographicException(int index, byte mask)
    {
        var tamperedAad = (byte[])Aad.Clone();
        tamperedAad[index] ^= mask;

        var act = () => AesGcmCipher.Decrypt(AadKey, AadIv, AadExpectedCiphertext, AadExpectedTag, tamperedAad);

        act.Should().Throw<CryptographicException>(
            because: "AAD is authenticated by the GCM tag; mutating any bit invalidates it");
    }

    // ── FR-13 AC 3 — input validation (NFR-3): wrong sizes → ArgumentException ──

    [Theory]
    [InlineData(0)]
    [InlineData(16)]  // AES-128 key size, not the required AES-256
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]  // A256CBC-HS512 composite key size, not GCM's 32
    public void Encrypt_WrongKeyLength_ThrowsArgumentException(int keyLength)
    {
        var act = () => AesGcmCipher.Encrypt(new byte[keyLength], new byte[12], []);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(16)]  // CBC IV size, not GCM's 96-bit nonce
    public void Encrypt_WrongNonceLength_ThrowsArgumentException(int nonceLength)
    {
        var act = () => AesGcmCipher.Encrypt(new byte[32], new byte[nonceLength], []);

        act.Should().Throw<ArgumentException>().WithParameterName("nonce");
    }

    [Fact]
    public void Decrypt_WrongKeyLength_ThrowsArgumentException()
    {
        var act = () => AesGcmCipher.Decrypt(new byte[16], new byte[12], new byte[16], new byte[16]);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    [Fact]
    public void Decrypt_WrongNonceLength_ThrowsArgumentException()
    {
        var act = () => AesGcmCipher.Decrypt(new byte[32], new byte[16], new byte[16], new byte[16]);

        act.Should().Throw<ArgumentException>().WithParameterName("nonce");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]
    [InlineData(15)]
    [InlineData(32)]  // A256CBC-HS512 tag size, not GCM's 16
    public void Decrypt_WrongTagLength_ThrowsArgumentException(int tagLength)
    {
        var act = () => AesGcmCipher.Decrypt(new byte[32], new byte[12], new byte[16], new byte[tagLength]);

        act.Should().Throw<ArgumentException>().WithParameterName("tag");
    }

    [Fact]
    public void RoundTrip_EmptyPlaintextWithAadOnly_ProducesEmptyCiphertextAndAuthenticates()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var aad = "header-only authenticated data"u8.ToArray();

        var (ciphertext, tag) = AesGcmCipher.Encrypt(key, nonce, [], aad);

        ciphertext.Should().BeEmpty(because: "GCM ciphertext has the same length as the plaintext");
        tag.Should().HaveCount(16);

        var recovered = AesGcmCipher.Decrypt(key, nonce, ciphertext, tag, aad);
        recovered.Should().BeEmpty();

        // The AAD-only tag must still bind the AAD: a different AAD fails authentication.
        var act = () => AesGcmCipher.Decrypt(key, nonce, ciphertext, tag, "other"u8.ToArray());
        act.Should().Throw<CryptographicException>();
    }
}

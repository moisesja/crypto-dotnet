using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Encryption;

/// <summary>
/// Issue #12 (G5) — each AEAD cipher type exposes its key/nonce/tag sizes as public constants,
/// so a JOSE builder allocating the CEK and IV/nonce before <c>Encrypt</c> validates against the
/// source of truth instead of a hard-coded table. These tests pin the documented values
/// (A256GCM = 32/12/16, A256CBC-HS512 = 64/16/32, XC20P = 32/24/16) and assert the constants
/// actually match the bytes the ciphers accept and produce.
/// </summary>
public class AeadSizeMetadataTests
{
    [Fact]
    public void AesGcm_Constants_HaveExpectedValues()
    {
        AesGcmCipher.KeySizeBytes.Should().Be(32);
        AesGcmCipher.NonceSizeBytes.Should().Be(12);
        AesGcmCipher.TagSizeBytes.Should().Be(16);
    }

    [Fact]
    public void AesCbcHmac_Constants_HaveExpectedValues()
    {
        AesCbcHmacCipher.KeySizeBytes.Should().Be(64);
        AesCbcHmacCipher.IvSizeBytes.Should().Be(16);
        AesCbcHmacCipher.TagSizeBytes.Should().Be(32);
    }

    [Fact]
    public void XChaCha20Poly1305_Constants_HaveExpectedValues()
    {
        XChaCha20Poly1305Cipher.KeySizeBytes.Should().Be(32);
        XChaCha20Poly1305Cipher.NonceSizeBytes.Should().Be(24);
        XChaCha20Poly1305Cipher.TagSizeBytes.Should().Be(16);
    }

    [Fact]
    public void AesGcm_ConstantsMatch_CipherBehavior()
    {
        var key = RandomNumberGenerator.GetBytes(AesGcmCipher.KeySizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(AesGcmCipher.NonceSizeBytes);

        var (ciphertext, tag) = AesGcmCipher.Encrypt(key, nonce, "msg"u8);

        tag.Length.Should().Be(AesGcmCipher.TagSizeBytes);
        AesGcmCipher.Decrypt(key, nonce, ciphertext, tag).Should().Equal("msg"u8.ToArray());
    }

    [Fact]
    public void AesCbcHmac_ConstantsMatch_CipherBehavior()
    {
        var key = RandomNumberGenerator.GetBytes(AesCbcHmacCipher.KeySizeBytes);
        var iv = RandomNumberGenerator.GetBytes(AesCbcHmacCipher.IvSizeBytes);

        var (ciphertext, tag) = AesCbcHmacCipher.Encrypt(key, iv, "msg"u8);

        tag.Length.Should().Be(AesCbcHmacCipher.TagSizeBytes);
        AesCbcHmacCipher.Decrypt(key, iv, ciphertext, tag).Should().Equal("msg"u8.ToArray());
    }

    [Fact]
    public void XChaCha20Poly1305_ConstantsMatch_CipherBehavior()
    {
        var key = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.KeySizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.NonceSizeBytes);

        var (ciphertext, tag) = XChaCha20Poly1305Cipher.Encrypt(key, nonce, "msg"u8);

        tag.Length.Should().Be(XChaCha20Poly1305Cipher.TagSizeBytes);
        XChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag).Should().Equal("msg"u8.ToArray());
    }

    [Fact]
    public void WrongKeyLength_DerivedFromConstant_Throws()
    {
        // A key one byte short of the published size must be rejected — proves the constant is the
        // exact contract, not a documentation-only hint.
        var shortKey = RandomNumberGenerator.GetBytes(AesGcmCipher.KeySizeBytes - 1);
        var nonce = RandomNumberGenerator.GetBytes(AesGcmCipher.NonceSizeBytes);

        var act = () => AesGcmCipher.Encrypt(shortKey, nonce, "msg"u8);
        act.Should().Throw<ArgumentException>();
    }
}

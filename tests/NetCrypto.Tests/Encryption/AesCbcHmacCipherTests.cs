using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Encryption;

/// <summary>
/// FR-14 — <see cref="AesCbcHmacCipher"/> (JOSE <c>A256CBC-HS512</c>, RFC 7518 §5.2.2)
/// validated against the RFC 7518 Appendix B.3 known-answer vector, tamper rejection
/// (single-bit flips in ciphertext, tag, and AAD), the input-validation contract, and a
/// code-level assertion that tag verification (<c>FixedTimeEquals</c>) precedes CBC
/// decryption. Vectors: https://www.rfc-editor.org/rfc/rfc7518.txt
/// </summary>
public class AesCbcHmacCipherTests
{
    // ── RFC 7518 Appendix B.3 — AES_256_CBC_HMAC_SHA_512 test case, verbatim ──

    // RFC 7518 Appendix B.3: K (64 octets; MAC_KEY = first 32, ENC_KEY = last 32).
    private static readonly byte[] Key = RfcHex(@"
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
        30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f");

    // RFC 7518 Appendix B.3: P ("A cipher system must not be required to be secret...").
    private static readonly byte[] Plaintext = RfcHex(@"
        41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
        6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
        69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
        74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
        65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
        6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
        20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
        75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");

    // RFC 7518 Appendix B.3: IV (16 octets).
    private static readonly byte[] Iv = RfcHex("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");

    // RFC 7518 Appendix B.3: A ("The second principle of Auguste Kerckhoffs", 42 octets;
    // AL = 0x0000000000000150 = 336 bits).
    private static readonly byte[] Aad = RfcHex(@"
        54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
        69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
        4b 65 72 63 6b 68 6f 66 66 73");

    // RFC 7518 Appendix B.3: E (the AES-256-CBC ciphertext, 144 octets).
    private static readonly byte[] ExpectedCiphertext = RfcHex(@"
        4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd
        3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd
        82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2
        e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b
        36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1
        1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3
        a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e
        31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b
        be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6");

    // RFC 7518 Appendix B.3: T (the first 32 octets of M, the HMAC-SHA-512 output).
    private static readonly byte[] ExpectedTag = RfcHex(@"
        4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
        2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5");

    [Fact]
    public void Encrypt_Rfc7518AppendixB3_MatchesExpectedCiphertextAndTag()
    {
        var (ciphertext, tag) = AesCbcHmacCipher.Encrypt(Key, Iv, Plaintext, Aad);

        ciphertext.Should().Equal(ExpectedCiphertext,
            because: "RFC 7518 Appendix B.3 publishes the exact ciphertext E for A256CBC-HS512");
        tag.Should().Equal(ExpectedTag,
            because: "RFC 7518 Appendix B.3 publishes the exact 32-byte truncated HMAC-SHA-512 tag T");
    }

    [Fact]
    public void Decrypt_Rfc7518AppendixB3_RecoversPlaintext()
    {
        var recovered = AesCbcHmacCipher.Decrypt(Key, Iv, ExpectedCiphertext, ExpectedTag, Aad);

        recovered.Should().Equal(Plaintext);
    }

    [Fact]
    public void RoundTrip_ArbitraryInputs_RecoversPlaintext()
    {
        var random = new Random(Seed: 1234);
        var key = new byte[64];
        var iv = new byte[16];
        var aad = new byte[37];
        var plaintext = new byte[200];
        random.NextBytes(key);
        random.NextBytes(iv);
        random.NextBytes(aad);
        random.NextBytes(plaintext);

        var (ciphertext, tag) = AesCbcHmacCipher.Encrypt(key, iv, plaintext, aad);
        var recovered = AesCbcHmacCipher.Decrypt(key, iv, ciphertext, tag, aad);

        recovered.Should().Equal(plaintext);
    }

    // ── Tamper tests (FR-14 AC 2, "as in FR-13"): any single-bit flip must throw ──

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(71, 0x10)]   // middle byte
    [InlineData(143, 0x80)]  // last byte, high bit
    public void Decrypt_TamperedCiphertext_Throws(int index, byte mask)
    {
        var tampered = (byte[])ExpectedCiphertext.Clone();
        tampered[index] ^= mask;

        var act = () => AesCbcHmacCipher.Decrypt(Key, Iv, tampered, ExpectedTag, Aad);

        act.Should().Throw<CryptographicException>(
            because: "encrypt-then-MAC must reject any single-bit flip in the ciphertext before decryption");
    }

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(15, 0x08)]   // middle byte
    [InlineData(31, 0x80)]   // last byte, high bit
    public void Decrypt_TamperedTag_Throws(int index, byte mask)
    {
        var tamperedTag = (byte[])ExpectedTag.Clone();
        tamperedTag[index] ^= mask;

        var act = () => AesCbcHmacCipher.Decrypt(Key, Iv, ExpectedCiphertext, tamperedTag, Aad);

        act.Should().Throw<CryptographicException>();
    }

    [Theory]
    [InlineData(0, 0x01)]    // first byte, low bit
    [InlineData(20, 0x40)]   // middle byte
    [InlineData(41, 0x80)]   // last byte, high bit
    public void Decrypt_TamperedAad_Throws(int index, byte mask)
    {
        var tamperedAad = (byte[])Aad.Clone();
        tamperedAad[index] ^= mask;

        var act = () => AesCbcHmacCipher.Decrypt(Key, Iv, ExpectedCiphertext, ExpectedTag, tamperedAad);

        act.Should().Throw<CryptographicException>(
            because: "AAD is part of the MAC input; mutating any bit invalidates the tag (RFC 7518 §5.2.2.1)");
    }

    // ── Input validation (NFR-3): wrong sizes → ArgumentException with parameter name ──

    [Theory]
    [InlineData(0)]
    [InlineData(32)]  // A256GCM size, not CBC-HMAC's required 64
    [InlineData(48)]
    public void Encrypt_WrongKeyLength_ThrowsArgumentException(int keyLength)
    {
        var act = () => AesCbcHmacCipher.Encrypt(new byte[keyLength], new byte[16], []);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]  // GCM nonce size, not the CBC block size
    [InlineData(17)]
    public void Encrypt_WrongIvLength_ThrowsArgumentException(int ivLength)
    {
        var act = () => AesCbcHmacCipher.Encrypt(new byte[64], new byte[ivLength], []);

        act.Should().Throw<ArgumentException>().WithParameterName("iv");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]  // GCM tag size, not the 32-byte truncated HMAC
    [InlineData(64)]  // full HMAC-SHA-512 output, not the truncated half
    public void Decrypt_WrongTagLength_ThrowsArgumentException(int tagLength)
    {
        var act = () => AesCbcHmacCipher.Decrypt(new byte[64], new byte[16], new byte[16], new byte[tagLength]);

        act.Should().Throw<ArgumentException>().WithParameterName("tag");
    }

    [Fact]
    public void Decrypt_WrongKeyLength_ThrowsArgumentException()
    {
        var act = () => AesCbcHmacCipher.Decrypt(new byte[32], new byte[16], new byte[16], new byte[32]);

        act.Should().Throw<ArgumentException>().WithParameterName("key");
    }

    // ── FR-14 AC 3 — code-level assertion: tag-before-decrypt ──

    /// <summary>
    /// FR-14 AC: "tag verification precedes decryption and uses FixedTimeEquals". A behavioral
    /// test cannot observe statement ordering inside <c>Decrypt</c>, so this test inspects the
    /// SOURCE of <c>src/NetCrypto/AesCbcHmacCipher.cs</c> and asserts that, within the
    /// <c>Decrypt</c> method body, the <c>CryptographicOperations.FixedTimeEquals</c> call
    /// appears BEFORE the <c>DecryptCbc</c> call. Reordering them would reintroduce a CBC
    /// padding-oracle path even though every behavioral test would still pass.
    /// </summary>
    [Fact]
    public void DecryptSource_VerifiesTagWithFixedTimeEquals_BeforeCbcDecryption()
    {
        var sourcePath = Path.Combine(FindRepositoryRoot(), "src", "NetCrypto", "AesCbcHmacCipher.cs");
        var source = File.ReadAllText(sourcePath);

        // (a) Constant-time comparison is used at all.
        source.Should().Contain("FixedTimeEquals",
            because: "FR-14 mandates CryptographicOperations.FixedTimeEquals for tag comparison");

        // (b) Within the Decrypt method body, tag verification precedes CBC decryption.
        // Slice from the Decrypt signature to the next private member so XML docs and the
        // Encrypt method (which precede the signature) cannot satisfy the search.
        var decryptStart = source.IndexOf("public static byte[] Decrypt(", StringComparison.Ordinal);
        decryptStart.Should().BeGreaterThan(-1, because: "the Decrypt method must exist in the source");
        var decryptEnd = source.IndexOf("private static", decryptStart, StringComparison.Ordinal);
        decryptEnd.Should().BeGreaterThan(decryptStart, because: "private helpers must follow the Decrypt method");
        var decryptBody = source[decryptStart..decryptEnd];

        var fixedTimeEqualsIndex = decryptBody.IndexOf("FixedTimeEquals", StringComparison.Ordinal);
        var cbcDecryptIndex = decryptBody.IndexOf("DecryptCbc", StringComparison.Ordinal);

        fixedTimeEqualsIndex.Should().BeGreaterThan(-1,
            because: "Decrypt must verify the tag with FixedTimeEquals");
        cbcDecryptIndex.Should().BeGreaterThan(-1,
            because: "Decrypt must perform CBC decryption via DecryptCbc");
        fixedTimeEqualsIndex.Should().BeLessThan(cbcDecryptIndex,
            because: "the tag MUST be verified before any CBC decryption runs (FR-14: no padding-oracle path)");
    }

    /// <summary>
    /// Locates the repository root at runtime by walking up from
    /// <see cref="AppContext.BaseDirectory"/> until a directory containing
    /// <c>NetCrypto.sln</c> is found, so the source-inspection test is independent of the
    /// test runner's working directory.
    /// </summary>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "NetCrypto.sln")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Could not locate the repository root (no directory containing 'NetCrypto.sln' above " +
            AppContext.BaseDirectory + ").");
    }

    /// <summary>
    /// Decodes hex transcribed verbatim from the RFC (space- and newline-separated octet
    /// groups, exactly as printed) so the constants can be diffed against the source text.
    /// </summary>
    private static byte[] RfcHex(string hex) =>
        Convert.FromHexString(string.Concat(hex.Where(c => !char.IsWhiteSpace(c))));
}

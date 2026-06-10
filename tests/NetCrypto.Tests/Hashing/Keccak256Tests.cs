using System.Text;
using FluentAssertions;
using NBitcoin.Secp256k1;
using NetCrypto;
using Org.BouncyCastle.Crypto.Digests;

namespace NetCrypto.Tests.Hashing;

/// <summary>
/// FR-11 — <see cref="Keccak256"/> (original Keccak, <c>0x01</c> padding) validated against
/// the Keccak team's SHA-3 competition KATs, a 1,000-input differential sweep versus
/// BouncyCastle's <see cref="KeccakDigest"/> (test-only reference), a negative control
/// proving the 0x01-vs-0x06 padding distinction from NIST SHA3-256, and the documented
/// Ethereum key-to-address example from "Mastering Ethereum" chapter 4.
/// </summary>
public class Keccak256Tests
{
    // ── FR-11 AC 1–2: known-answer tests ──

    [Theory]
    // Keccak team KAT archive (https://keccak.team/obsolete/KeccakKAT-3.zip,
    // ShortMsgKAT_256.txt, Len = 0) and PRD FR-11: Keccak-256("").
    [InlineData("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")]
    // PRD FR-11 / canonical Ethereum-ecosystem KAT: Keccak-256("abc").
    [InlineData("abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")]
    public void Hash_Utf8Input_MatchesKnownAnswer(string text, string expectedHex)
    {
        var digest = Keccak256.Hash(Encoding.UTF8.GetBytes(text));

        digest.Should().Equal(Convert.FromHexString(expectedHex));
    }

    [Fact]
    public void Hash_KeccakTeamShortMessageKat_MatchesKnownAnswer()
    {
        // Keccak team KAT archive (https://keccak.team/obsolete/KeccakKAT-3.zip,
        // ShortMsgKAT_256.txt): Len = 24, Msg = 1F877C.
        var digest = Keccak256.Hash(Convert.FromHexString("1f877c"));

        digest.Should().Equal(Convert.FromHexString(
            "627d7bc1491b2ab127282827b8de2d276b13d7d70fb4c5957fdf20655bc7ac30"));
    }

    // ── FR-11 AC 3: differential test against the test-only reference implementation ──

    [Fact]
    public void Hash_OneThousandRandomInputs_MatchBouncyCastleKeccakDigest()
    {
        // Recorded seed — reproduce any failure with: new Random(20260610).
        const int seed = 20260610;
        var rng = new Random(seed);

        // Deterministic boundary lengths first: every exact multiple of the 136-byte rate
        // within 0..1024 (0, 136, 272, …, 952) plus the ±1 off-by-ones around each, and
        // the upper bound 1024 itself.
        var lengths = new List<int>();
        for (var multiple = 0; multiple <= 1024; multiple += 136)
        {
            if (multiple > 0)
                lengths.Add(multiple - 1);
            lengths.Add(multiple);
            lengths.Add(multiple + 1);
        }
        lengths.Add(1024);

        // Fill the remainder of the 1,000 inputs with random lengths spanning 0..1024.
        while (lengths.Count < 1000)
            lengths.Add(rng.Next(0, 1025));

        foreach (var length in lengths)
        {
            var input = new byte[length];
            rng.NextBytes(input);

            var actual = Keccak256.Hash(input);

            actual.Should().Equal(
                BouncyCastleKeccak256(input),
                $"Keccak-256 of a random {length}-byte input (seed {seed}) must match BouncyCastle's KeccakDigest(256)");
        }
    }

    // ── FR-11 AC 4: negative control — original Keccak (0x01) is not SHA3-256 (0x06) ──

    [Fact]
    public void Hash_EmptyInput_DiffersFromNistSha3_256()
    {
        // SHA3-256("") per the XKCP test vectors (https://raw.githubusercontent.com/XKCP/
        // XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-256.txt, Len = 0). Original Keccak
        // pads with 0x01; FIPS 202 SHA3-256 pads with the 0x06 domain byte, so the digests
        // must differ.
        var sha3Empty = Convert.FromHexString(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

        // Sanity-check the SHA3-256 constant against BouncyCastle before relying on it.
        var bouncySha3 = new Sha3Digest(256);
        var sha3Check = new byte[32];
        bouncySha3.DoFinal(sha3Check, 0);
        sha3Check.Should().Equal(sha3Empty, "the cited XKCP SHA3-256 empty-string vector must be right");

        Keccak256.Hash(ReadOnlySpan<byte>.Empty).Should().NotEqual(
            sha3Empty,
            "original Keccak (0x01 padding) must not collide with NIST SHA3-256 (0x06 domain byte)");
    }

    // ── FR-11 AC 5: Ethereum key → address known-answer test ──

    [Fact]
    public void Hash_UncompressedSecp256k1PublicKey_YieldsDocumentedEthereumAddress()
    {
        // Andreas M. Antonopoulos & Gavin Wood, "Mastering Ethereum", chapter 4
        // (Keys, Addresses — https://github.com/ethereumbook/ethereumbook, chapter_4.md):
        //   k          = f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315
        //   K (uncomp) = 046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae0
        //                7b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0
        //   Keccak256(K without 0x04) =
        //                2a5bc342ed616b5ba5732269001d3f1ef827552ae1114027bd3ecf1f086ba0f9
        //   address    = 001d3f1ef827552ae1114027bd3ecf1f086ba0f9 (last 20 bytes)
        var privateKey = ECPrivKey.Create(Convert.FromHexString(
            "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"));

        var uncompressed = new byte[65];
        privateKey.CreatePubKey().WriteToSpan(compressed: false, uncompressed, out var written);
        written.Should().Be(65);
        uncompressed.Should().Equal(
            Convert.FromHexString(
                "046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae0" +
                "7b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0"),
            "the derived public key must match the one printed in Mastering Ethereum ch. 4");

        // Hash the 64-byte public key (0x04 prefix dropped); the address is the last 20 bytes.
        var digest = Keccak256.Hash(uncompressed.AsSpan(1));

        digest.Should().Equal(Convert.FromHexString(
            "2a5bc342ed616b5ba5732269001d3f1ef827552ae1114027bd3ecf1f086ba0f9"));
        digest[12..].Should().Equal(Convert.FromHexString(
            "001d3f1ef827552ae1114027bd3ecf1f086ba0f9"));
    }

    // ── TryHash span-overload contract ──

    [Fact]
    public void TryHash_DestinationTooSmall_ReturnsFalseAndWritesNothing()
    {
        var destination = new byte[31];

        var result = Keccak256.TryHash("abc"u8, destination, out var bytesWritten);

        result.Should().BeFalse();
        bytesWritten.Should().Be(0);
        destination.Should().OnlyContain(b => b == 0, "a failed TryHash must not touch the destination");
    }

    [Fact]
    public void TryHash_SufficientDestination_WritesSameDigestAsHash()
    {
        var expected = Keccak256.Hash("abc"u8);

        var exact = new byte[32];
        Keccak256.TryHash("abc"u8, exact, out var exactWritten).Should().BeTrue();
        exactWritten.Should().Be(32);
        exact.Should().Equal(expected);

        var oversized = new byte[64];
        oversized.AsSpan().Fill(0xAA);
        Keccak256.TryHash("abc"u8, oversized, out var oversizedWritten).Should().BeTrue();
        oversizedWritten.Should().Be(32);
        oversized[..32].Should().Equal(expected);
        oversized[32..].Should().OnlyContain(b => b == 0xAA, "TryHash must write only the first 32 bytes");
    }

    private static byte[] BouncyCastleKeccak256(byte[] input)
    {
        var digest = new KeccakDigest(256);
        digest.BlockUpdate(input, 0, input.Length);

        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}

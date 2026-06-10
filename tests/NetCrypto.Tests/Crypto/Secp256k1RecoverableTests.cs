using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using FluentAssertions;
using NBitcoin.Secp256k1;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// FR-12 acceptance tests for <see cref="Secp256k1Recoverable"/> — recoverable ECDSA
/// over secp256k1 with raw recovery ids (no EVM v-encoding anywhere in NetCrypto).
/// </summary>
public class Secp256k1RecoverableTests
{
    // secp256k1 group order n, per SEC 2: Recommended Elliptic Curve Domain Parameters,
    // version 2.0, §2.4.1 ("Recommended Parameters secp256k1"):
    // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    private static readonly BigInteger CurveOrderN = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber);

    private static readonly BigInteger HalfCurveOrder = CurveOrderN / 2;

    /// <summary>Derives the true public key for a raw 32-byte private scalar via NBitcoin directly.</summary>
    private static byte[] TruePublicKey(byte[] privateKey, bool compressed)
    {
        using var key = ECPrivKey.Create(privateKey);
        var output = new byte[compressed ? 33 : 65];
        key.CreatePubKey().WriteToSpan(compressed, output, out _);
        return output;
    }

    /// <summary>Generates a seeded-random 32-byte scalar that is a valid secp256k1 private key.</summary>
    private static byte[] NextPrivateKey(Random rng)
    {
        var sk = new byte[32];
        do
        {
            rng.NextBytes(sk);
        } while (!Context.Instance.TryCreateECPrivKey(sk, out _)); // reject 0 or >= n (astronomically rare)
        return sk;
    }

    // --- AC 1: 100-iteration round-trip, both public key encodings ---

    [Fact]
    public void SignThenRecover_RandomKeysAndDigests_RecoversTruePublicKey_BothEncodings()
    {
        var rng = new Random(42); // seeded for reproducibility

        for (var i = 0; i < 100; i++)
        {
            var privateKey = NextPrivateKey(rng);
            var digest = new byte[32];
            rng.NextBytes(digest);

            var (signature, recoveryId) = Secp256k1Recoverable.Sign(privateKey, digest);

            signature.Should().HaveCount(64);
            recoveryId.Should().BeInRange(0, 3);

            var recoveredUncompressed = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId);
            var recoveredCompressed = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId, compressed: true);

            recoveredUncompressed.Should().HaveCount(65, "iteration {0}", i);
            recoveredUncompressed[0].Should().Be(0x04, "iteration {0}", i);
            recoveredCompressed.Should().HaveCount(33, "iteration {0}", i);

            recoveredUncompressed.Should().Equal(TruePublicKey(privateKey, compressed: false), "iteration {0}", i);
            recoveredCompressed.Should().Equal(TruePublicKey(privateKey, compressed: true), "iteration {0}", i);
        }
    }

    // --- AC 2: recovered key verifies via the existing ICryptoProvider.Verify path ---

    [Fact]
    public void RecoveredKey_VerifiesViaDefaultCryptoProvider()
    {
        // DefaultCryptoProvider.Verify(KeyType.Secp256k1, publicKey, data, signature) hashes
        // `data` internally with SHA-256 before ECDSA verification. Secp256k1Recoverable signs
        // a caller-supplied digest with NO internal hashing. To make the two paths meet, we
        // sign SHA-256(message) here, then hand Verify the raw *message* (preimage) so its
        // internal SHA-256 reproduces the exact digest we signed.
        var rng = new Random(2026);
        var privateKey = NextPrivateKey(rng);
        var message = "FR-12: recoverable secp256k1 meets ICryptoProvider.Verify"u8.ToArray();
        var digest = System.Security.Cryptography.SHA256.HashData(message);

        var (signature, recoveryId) = Secp256k1Recoverable.Sign(privateKey, digest);
        var recoveredCompressed = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId, compressed: true);

        var provider = new DefaultCryptoProvider();
        provider.Verify(KeyType.Secp256k1, recoveredCompressed, message, signature).Should().BeTrue();
    }

    // --- AC 3: low-S normalization for every produced signature ---

    [Fact]
    public void Sign_AlwaysProducesLowS()
    {
        var rng = new Random(7);

        for (var i = 0; i < 100; i++)
        {
            var privateKey = NextPrivateKey(rng);
            var digest = new byte[32];
            rng.NextBytes(digest);

            var (signature, _) = Secp256k1Recoverable.Sign(privateKey, digest);

            // S is the big-endian last 32 bytes of the compact R‖S signature.
            var s = new BigInteger(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
            s.Should().BeGreaterThan(BigInteger.Zero, "iteration {0}", i);
            (s <= HalfCurveOrder).Should().BeTrue("low-S normalization requires S <= n/2 (iteration {0})", i);
        }
    }

    // --- AC 4: published known vector ---

    [Fact]
    public void Sign_Eip155ExampleTransaction_MatchesPublishedVector()
    {
        // Known vector from EIP-155 "Example" (https://eips.ethereum.org/EIPS/eip-155):
        // a transaction with nonce=9, gasprice=20*10^9, startgas=21000,
        // to=0x3535...35, value=10^18, data='' on chain id 1 has
        //   signing hash: 0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
        // and, signed with private key 0x4646...46, yields (v, r, s) =
        //   (37,
        //    18515461264373351373200002665853028612451056578545711640558177340181847433846,
        //    46948507304638947509940763649030358759909902576025900602547168820602576006531).
        // v = 37 on chain id 1 means recid = v - 35 - 2*chainId = 0. NetCrypto returns that
        // raw recovery id — the EIP-155 v-encoding itself is wallet-layer work, out of scope.
        var privateKey = Convert.FromHexString("4646464646464646464646464646464646464646464646464646464646464646");
        var signingHash = Convert.FromHexString("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");

        var expectedR = ToBigEndian32(BigInteger.Parse(
            "18515461264373351373200002665853028612451056578545711640558177340181847433846"));
        var expectedS = ToBigEndian32(BigInteger.Parse(
            "46948507304638947509940763649030358759909902576025900602547168820602576006531"));

        var (signature, recoveryId) = Secp256k1Recoverable.Sign(privateKey, signingHash);

        signature.AsSpan(0, 32).ToArray().Should().Equal(expectedR);
        signature.AsSpan(32, 32).ToArray().Should().Equal(expectedS);
        recoveryId.Should().Be(0);

        // The recovered key must equal the true public key of the vector's private key
        // (both encodings), derived independently via NBitcoin.
        var recovered = Secp256k1Recoverable.RecoverPublicKey(signingHash, signature, recoveryId);
        recovered.Should().Equal(TruePublicKey(privateKey, compressed: false));
        Secp256k1Recoverable.RecoverPublicKey(signingHash, signature, recoveryId, compressed: true)
            .Should().Equal(TruePublicKey(privateKey, compressed: true));

        // Address step: the Ethereum sender address is the last 20 bytes of Keccak-256 over
        // the 64-byte uncompressed public key (0x04 prefix stripped). EIP-155 does not print
        // the sender address, so the expected value below is derived from the EIP-155 example
        // private key 0x4646…46 and cross-checked in-test against BouncyCastle's reference
        // KeccakDigest (the FR-11 test-only reference implementation) to keep the two Keccak
        // implementations honest about each other.
        var senderAddress = NetCrypto.Keccak256.Hash(recovered.AsSpan(1))[12..];

        var bcKeccak = new Org.BouncyCastle.Crypto.Digests.KeccakDigest(256);
        var truePublicKey = TruePublicKey(privateKey, compressed: false);
        bcKeccak.BlockUpdate(truePublicKey, 1, 64);
        var bcHash = new byte[32];
        bcKeccak.DoFinal(bcHash, 0);

        senderAddress.Should().Equal(bcHash[12..]);
        Convert.ToHexString(senderAddress).ToLowerInvariant()
            .Should().Be("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    }

    // --- AC 5: wrong recovery id is never silently the right key ---

    [Fact]
    public void RecoverPublicKey_WrongRecoveryId_NeverSilentlyReturnsTrueKey()
    {
        var rng = new Random(1337);

        for (var i = 0; i < 20; i++)
        {
            var privateKey = NextPrivateKey(rng);
            var digest = new byte[32];
            rng.NextBytes(digest);

            var (signature, recoveryId) = Secp256k1Recoverable.Sign(privateKey, digest);
            var truePublicKey = TruePublicKey(privateKey, compressed: false);

            foreach (var wrongId in Enumerable.Range(0, 4).Where(id => id != recoveryId))
            {
                try
                {
                    var recovered = Secp256k1Recoverable.RecoverPublicKey(digest, signature, wrongId);
                    recovered.Should().NotEqual(truePublicKey,
                        "wrong recovery id {0} must not recover the true key (iteration {1})", wrongId, i);
                }
                catch (CryptographicException)
                {
                    // Also acceptable: recovery ids 2/3 only have a solution when r + n < p,
                    // so recovery legitimately fails for almost all signatures.
                }
            }
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    [InlineData(27)] // an EVM legacy v value — must be rejected: NetCrypto takes raw ids only
    [InlineData(int.MaxValue)]
    public void RecoverPublicKey_RecoveryIdOutOfRange_Throws(int recoveryId)
    {
        var digest = new byte[32];
        var signature = new byte[64];

        var act = () => Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId);

        // ArgumentOutOfRangeException derives from ArgumentException; FR-12 allows either.
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("recoveryId");
    }

    // --- Input validation (NFR-3): argument failures carry the parameter name, before any crypto work ---

    [Fact]
    public void Sign_InvalidInputLengths_ThrowArgumentException()
    {
        var validKey = new byte[32];
        validKey[31] = 1;
        var validDigest = new byte[32];

        FluentActions.Invoking(() => Secp256k1Recoverable.Sign(new byte[31], validDigest))
            .Should().Throw<ArgumentException>().WithParameterName("privateKey");
        FluentActions.Invoking(() => Secp256k1Recoverable.Sign(new byte[33], validDigest))
            .Should().Throw<ArgumentException>().WithParameterName("privateKey");
        FluentActions.Invoking(() => Secp256k1Recoverable.Sign(validKey, new byte[31]))
            .Should().Throw<ArgumentException>().WithParameterName("digest32");
        // A zero scalar is not a valid private key even at the correct length.
        FluentActions.Invoking(() => Secp256k1Recoverable.Sign(new byte[32], validDigest))
            .Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Fact]
    public void RecoverPublicKey_InvalidInputLengths_ThrowArgumentException()
    {
        var digest = new byte[32];
        var signature = new byte[64];

        FluentActions.Invoking(() => Secp256k1Recoverable.RecoverPublicKey(new byte[31], signature, 0))
            .Should().Throw<ArgumentException>().WithParameterName("digest32");
        FluentActions.Invoking(() => Secp256k1Recoverable.RecoverPublicKey(digest, new byte[63], 0))
            .Should().Throw<ArgumentException>().WithParameterName("signature64");
        // 64 bytes of zeros is structurally sized but R = S = 0 is non-canonical.
        FluentActions.Invoking(() => Secp256k1Recoverable.RecoverPublicKey(digest, new byte[64], 0))
            .Should().Throw<ArgumentException>().WithParameterName("signature64");
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
}

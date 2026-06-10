using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// FR-1 + FR-6 acceptance tests: golden parity with net-did for the key model
/// (multibase, JWK, Ed25519→X25519 derivation), multicodec round-trips, and
/// per-key-type generate → sign/verify (or key-agreement) round-trips.
///
/// Golden values: captured from net-did @ main on 2026-06-10 with deterministic
/// private keys (bytes 0x01..len) — recorded in tasks/todo20260610T0815.md.
/// </summary>
public class KeyModelParityTests
{
    private readonly DefaultKeyGenerator _generator = new();
    private readonly DefaultCryptoProvider _crypto = new();

    /// <summary>Deterministic private key: bytes 0x01, 0x02, ... length.</summary>
    private static byte[] DeterministicPrivateKey(int length)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
            bytes[i] = (byte)(i + 1);
        return bytes;
    }

    // --- (a) Multibase golden parity (FR-1 AC: MultibasePublicKey identical to net-did) ---

    // Golden parity values captured from net-did @ main, 2026-06-10
    // (tasks/todo20260610T0815.md, "Golden parity values" section).
    [Theory]
    [InlineData(KeyType.Ed25519, 32,
        "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664",
        "z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7")]
    [InlineData(KeyType.X25519, 32,
        "07A37CBC142093C8B755DC1B10E86CB426374AD16AA853ED0BDFC0B2B86D1C7C",
        "z6LScBzcCzjZuJXEbSu5TKFpVfF7meSuF3afjxpDDMzwDEyR")]
    [InlineData(KeyType.P256, 32,
        "02515C3D6EB9E396B904D3FECA7F54FDCD0CC1E997BF375DCA515AD0A6C3B4035F",
        "zDnaeVuZeVRqvscGkiEoR9PFFra2xZUMp97ZPuGFK1VLU7iYN")]
    [InlineData(KeyType.P384, 48,
        "03C76F2283DDA95CD49B0ED9E733D2904474E37216F124E13D2C9AB4CF01021C49AD9CABB3D0B97499AEF2F0AB313FA028",
        "z82Lm3E6hNMpCovkE3i4zDhcCkxkNZzkXfy5wS6gm66h42E8K3hPuDuJRfao8731HJ5hwBm")]
    [InlineData(KeyType.P521, 66,
        "02000366C8C3B22DFB87D0922163CD4B53CD43A24A29F79292FA4EF1288D69ED139A7FC0552120EA1BDB4F88CA0DA4EB91DE9B077018D5885DBFF0E91A66639A9B72A5",
        "z2J9gaYXHwALa9SCKdTU7hMJoW7K6oBrDtiRTC8XF8dia9XZ5fsEw3ZnZgEiBqzPY6gzGmVgPaJTh671xMZvu8gNnK77BVzU")]
    [InlineData(KeyType.Secp256k1, 32,
        "0284BF7562262BBD6940085748F3BE6AFA52AE317155181ECE31B66351CCFFA4B0",
        "zQ3shWLyu8mc4GLnyzrxvWj9kJPijwGbjdrr3pZ8hacUYxawh")]
    [InlineData(KeyType.Bls12381G1, 32,
        "96A20BB9485FF6D8950955A629E8043A43775968AC133EB7B19C5F0389A2253676ABDD6C86C7B68D38A1B7F6AF8650E7",
        "z3tEFRqdN18CK1YLvPtiJhLMx27hC2hAsby95eo5Lo2TP9DdiTAsmRxTXH9PKRTo1du57U")]
    [InlineData(KeyType.Bls12381G2, 32,
        "8107AAD1D722B74D1955F000F764B907AEBC9FD0003CDC0DB16CE57028E0417257ABC93CDBD29BBEAE81D85C29DF2C4200C75B6ACD7E2AD2ED48092947C7659D3FD7C5DAE9340F1ED804B73417AAAF06F6BF985C8FF49C103482B606BF57042F",
        "zUC71HWXKCaok2SPibjvT65oPv5wq1VRbLfnBUHEURqMPDcYWEs1xPKCAjRsJr5YdJ1S2vbRZKmmBJpE8v2sijqpoENLPUKgATAXtkohkpTxmcF4SW6vhiuQj7Ke9xP8yYKDbVp")]
    public void FromPrivateKey_DeterministicKey_MatchesNetDidGoldenValues(
        KeyType keyType, int privateKeyLength, string expectedPublicKeyHex, string expectedMultibase)
    {
        var privateKey = DeterministicPrivateKey(privateKeyLength);

        var keyPair = _generator.FromPrivateKey(keyType, privateKey);

        Convert.ToHexString(keyPair.PublicKey).Should().Be(expectedPublicKeyHex);
        keyPair.MultibasePublicKey.Should().Be(expectedMultibase);
    }

    [Fact]
    public void FromPublicKey_DeterministicEd25519_MultibaseMatchesNetDidGoldenValue()
    {
        // Golden value captured from net-did @ main, 2026-06-10 (tasks/todo20260610T0815.md):
        // PublicKeyReference.MultibasePublicKey must encode identically to KeyPair.MultibasePublicKey.
        var keyPair = _generator.FromPrivateKey(KeyType.Ed25519, DeterministicPrivateKey(32));
        var pubRef = _generator.FromPublicKey(KeyType.Ed25519, keyPair.PublicKey);

        pubRef.MultibasePublicKey.Should().Be("z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7");
    }

    [Fact]
    public void ToPublicJwk_DeterministicEd25519_MatchesNetDidGoldenValues()
    {
        // JWK golden captured from net-did @ main, 2026-06-10 (tasks/todo20260610T0815.md):
        // JWK-Ed25519|kty=OKP|crv=Ed25519|x=ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ
        var keyPair = _generator.FromPrivateKey(KeyType.Ed25519, DeterministicPrivateKey(32));

        var jwk = keyPair.ToPublicJwk();

        jwk.Kty.Should().Be("OKP");
        jwk.Crv.Should().Be("Ed25519");
        jwk.X.Should().Be("ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
        jwk.D.Should().BeNull();
    }

    [Fact]
    public void ToPrivateJwk_DeterministicEd25519_MatchesNetDidGoldenValues()
    {
        // JWK golden captured from net-did @ main, 2026-06-10 (tasks/todo20260610T0815.md):
        // JWK-Ed25519-priv|d=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
        var keyPair = _generator.FromPrivateKey(KeyType.Ed25519, DeterministicPrivateKey(32));

        var jwk = keyPair.ToPrivateJwk();

        jwk.Kty.Should().Be("OKP");
        jwk.Crv.Should().Be("Ed25519");
        jwk.X.Should().Be("ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
        jwk.D.Should().Be("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    }

    [Fact]
    public void DeriveX25519FromEd25519_DeterministicKey_MatchesNetDidGoldenValues()
    {
        // Derived-X25519 goldens captured from net-did @ main, 2026-06-10 (tasks/todo20260610T0815.md):
        // DerivedX25519|pub=4A38...2B38|pubOnly=4A38...2B38|multibase=z6LSgfttUXwS7v5MP2Y7nYEbdzrYiEZJdrv6Uiqg7BapsXPd
        const string expectedPubHex = "4A3807D064D077181CC070989E76891D20DCA5559548DC2C77C1A50273882B38";
        const string expectedMultibase = "z6LSgfttUXwS7v5MP2Y7nYEbdzrYiEZJdrv6Uiqg7BapsXPd";

        var ed25519 = _generator.FromPrivateKey(KeyType.Ed25519, DeterministicPrivateKey(32));

        // Path 1: derive from the full Ed25519 key pair.
        var derivedPair = _generator.DeriveX25519FromEd25519(ed25519);
        Convert.ToHexString(derivedPair.PublicKey).Should().Be(expectedPubHex);
        derivedPair.MultibasePublicKey.Should().Be(expectedMultibase);

        // Path 2: derive from the Ed25519 public key only (birational map).
        var derivedRef = _generator.DeriveX25519PublicKeyFromEd25519(ed25519.PublicKey);
        Convert.ToHexString(derivedRef.PublicKey).Should().Be(expectedPubHex);
        derivedRef.MultibasePublicKey.Should().Be(expectedMultibase);
    }

    // --- (b) Multicodec round-trip (FR-1 AC) ---

    [Fact]
    public void GetMulticodec_FromMulticodec_IsIdentityForAllEightKeyTypes()
    {
        var allKeyTypes = Enum.GetValues<KeyType>();
        allKeyTypes.Should().HaveCount(8);

        foreach (var keyType in allKeyTypes)
        {
            KeyTypeExtensions.FromMulticodec(keyType.GetMulticodec()).Should().Be(keyType);
        }
    }

    [Fact]
    public void FromMulticodec_UnknownCodec_ThrowsArgumentException()
    {
        var act = () => KeyTypeExtensions.FromMulticodec(0xFFFF);

        act.Should().Throw<ArgumentException>();
    }

    // --- (c) Generate → sign/verify round-trip per key type (FR-6 AC) ---
    // BLS12-381 G1/G2 use the BLS path of ICryptoProvider.Sign/Verify;
    // X25519 is not a signing type and is covered by the key-agreement test below
    // (mirrors net-did's KeyAgreement_X25519_ProducesSharedSecret).

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void Generate_SigningKeyType_SignVerifyRoundTripSucceeds(KeyType keyType)
    {
        var keyPair = _generator.Generate(keyType);
        var data = "NetCrypto FR-6 sign/verify round-trip"u8.ToArray();

        var signature = _crypto.Sign(keyType, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(keyType, keyPair.PublicKey, data, signature);

        signature.Should().NotBeEmpty();
        valid.Should().BeTrue();
    }

    [Fact]
    public void Generate_X25519_KeyAgreementWithAnotherPairSucceeds()
    {
        var alice = _generator.Generate(KeyType.X25519);
        var bob = _generator.Generate(KeyType.X25519);

        var aliceShared = _crypto.KeyAgreement(alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.KeyAgreement(bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().NotBeEmpty();
        bobShared.Should().NotBeEmpty();
        aliceShared.Should().Equal(bobShared);
    }

    // --- (d) Ed25519 → X25519 derivation (FR-6 AC) ---

    [Fact]
    public void DeriveX25519FromEd25519_BothDerivationPaths_ProduceSamePublicKey()
    {
        var ed25519 = _generator.Generate(KeyType.Ed25519);

        var derivedPair = _generator.DeriveX25519FromEd25519(ed25519);
        var derivedRef = _generator.DeriveX25519PublicKeyFromEd25519(ed25519.PublicKey);

        derivedRef.KeyType.Should().Be(KeyType.X25519);
        derivedRef.PublicKey.Should().Equal(derivedPair.PublicKey);
    }

    [Fact]
    public void DeriveX25519FromEd25519_DerivedPair_PerformsSuccessfulKeyAgreement()
    {
        var ed25519 = _generator.Generate(KeyType.Ed25519);
        var derived = _generator.DeriveX25519FromEd25519(ed25519);
        var other = _generator.Generate(KeyType.X25519);

        var derivedShared = _crypto.KeyAgreement(derived.PrivateKey, other.PublicKey);
        var otherShared = _crypto.KeyAgreement(other.PrivateKey, derived.PublicKey);

        derivedShared.Should().NotBeEmpty();
        derivedShared.Should().Equal(otherShared);
    }
}

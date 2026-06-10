using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Jwk;

/// <summary>
/// FR-8 acceptance tests (netcrypto-prd.md §FR-8 — JWK conversion):
/// - Round-trip per supported key type: raw key → JWK → ExtractPublicKey → identical bytes + KeyType.
/// - ToPrivateJwk includes d; ToPublicJwk output contains no private material (D == null).
/// Key material comes from the golden parity values captured from net-did @ main (2026-06-10)
/// with deterministic private keys 0x01..len — see tasks/todo20260610T0815.md,
/// "Golden parity values" section.
/// </summary>
public class JwkAcceptanceTests
{
    /// <summary>Every key type supported by <see cref="JwkConverter"/>.</summary>
    public static TheoryData<KeyType> SupportedKeyTypes => new()
    {
        KeyType.Ed25519,
        KeyType.X25519,
        KeyType.P256,
        KeyType.P384,
        KeyType.P521,
        KeyType.Secp256k1,
        KeyType.Bls12381G1,
        KeyType.Bls12381G2
    };

    // FR-8 AC: round-trip per supported key type — raw public key → ToPublicJwk →
    // ExtractPublicKey → identical bytes + KeyType.
    [Theory]
    [MemberData(nameof(SupportedKeyTypes))]
    public void ToPublicJwk_ThenExtractPublicKey_RoundTripsBytesAndKeyType(KeyType keyType)
    {
        var rawPublicKey = GoldenKeyPair(keyType).PublicKey;

        var jwk = JwkConverter.ToPublicJwk(keyType, rawPublicKey);
        var (extractedType, extractedKey) = JwkConverter.ExtractPublicKey(jwk);

        extractedType.Should().Be(keyType);
        extractedKey.Should().Equal(rawPublicKey);
    }

    // FR-8 AC: ToPrivateJwk includes the private 'd' parameter for every supported type.
    [Theory]
    [MemberData(nameof(SupportedKeyTypes))]
    public void ToPrivateJwk_EverySupportedKeyType_IncludesD(KeyType keyType)
    {
        var keyPair = GoldenKeyPair(keyType);

        var jwk = JwkConverter.ToPrivateJwk(keyPair);

        jwk.D.Should().NotBeNullOrEmpty();
    }

    // FR-8 AC: ToPublicJwk output contains no private material (assert D == null) for every
    // supported type.
    [Theory]
    [MemberData(nameof(SupportedKeyTypes))]
    public void ToPublicJwk_EverySupportedKeyType_OmitsD(KeyType keyType)
    {
        var keyPair = GoldenKeyPair(keyType);

        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.D.Should().BeNull();
    }

    [Fact]
    public void ToPublicJwk_Ed25519GoldenKey_MatchesNetDidParityValues()
    {
        // Golden parity vector: tasks/todo20260610T0815.md — JWK-Ed25519
        // (captured from net-did @ main, 2026-06-10, priv = 0x0102..20).
        var jwk = JwkConverter.ToPublicJwk(GoldenKeyPair(KeyType.Ed25519));

        jwk.Kty.Should().Be("OKP");
        jwk.Crv.Should().Be("Ed25519");
        jwk.X.Should().Be("ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
        jwk.D.Should().BeNull();
    }

    [Fact]
    public void ToPrivateJwk_Ed25519GoldenKey_MatchesNetDidParityD()
    {
        // Golden parity vector: tasks/todo20260610T0815.md — JWK-Ed25519-priv
        // (captured from net-did @ main, 2026-06-10, priv = 0x0102..20).
        var jwk = JwkConverter.ToPrivateJwk(GoldenKeyPair(KeyType.Ed25519));

        jwk.D.Should().Be("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    }

    /// <summary>
    /// Golden key pairs captured from net-did @ main (2026-06-10) with deterministic private
    /// keys 0x01..len. Source: tasks/todo20260610T0815.md, "Golden parity values" section.
    /// Constructed directly (no key generator) so these tests need no native dependencies.
    /// </summary>
    private static KeyPair GoldenKeyPair(KeyType keyType) => keyType switch
    {
        KeyType.Ed25519 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664"),
        KeyType.X25519 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "07A37CBC142093C8B755DC1B10E86CB426374AD16AA853ED0BDFC0B2B86D1C7C"),
        KeyType.P256 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "02515C3D6EB9E396B904D3FECA7F54FDCD0CC1E997BF375DCA515AD0A6C3B4035F"),
        KeyType.P384 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30",
            "03C76F2283DDA95CD49B0ED9E733D2904474E37216F124E13D2C9AB4CF01021C49AD9CABB3D0B97499AEF2F0AB313FA028"),
        KeyType.P521 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142",
            "02000366C8C3B22DFB87D0922163CD4B53CD43A24A29F79292FA4EF1288D69ED139A7FC0552120EA1BDB4F88CA0DA4EB91DE9B077018D5885DBFF0E91A66639A9B72A5"),
        KeyType.Secp256k1 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "0284BF7562262BBD6940085748F3BE6AFA52AE317155181ECE31B66351CCFFA4B0"),
        KeyType.Bls12381G1 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "96A20BB9485FF6D8950955A629E8043A43775968AC133EB7B19C5F0389A2253676ABDD6C86C7B68D38A1B7F6AF8650E7"),
        KeyType.Bls12381G2 => Make(keyType,
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "8107AAD1D722B74D1955F000F764B907AEBC9FD0003CDC0DB16CE57028E0417257ABC93CDBD29BBEAE81D85C29DF2C4200C75B6ACD7E2AD2ED48092947C7659D3FD7C5DAE9340F1ED804B73417AAAF06F6BF985C8FF49C103482B606BF57042F"),
        _ => throw new ArgumentOutOfRangeException(nameof(keyType), keyType, "No golden key pair captured for this key type.")
    };

    private static KeyPair Make(KeyType keyType, string privateKeyHex, string publicKeyHex) => new()
    {
        KeyType = keyType,
        PrivateKey = Convert.FromHexString(privateKeyHex),
        PublicKey = Convert.FromHexString(publicKeyHex)
    };
}

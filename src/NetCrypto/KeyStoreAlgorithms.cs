namespace NetCrypto;

/// <summary>
/// The algorithm identifiers NetCrypto mints and understands, one per concrete
/// (curve, hash, <em>observable encoding</em>) combination.
/// </summary>
/// <remarks>
/// <para>
/// A store advertises these through <see cref="KeyStoreCapability.Algorithm"/> and a caller
/// selects one through <see cref="KeySignRequest.Algorithm"/>,
/// <see cref="KeyAgreementRequest.Algorithm"/>, or
/// <see cref="KeyBbsSignRequest.Algorithm"/>. An identifier a store does not advertise is
/// refused with <see cref="KeyStoreError.Unsupported"/> before any backend work — never
/// silently downgraded to a different curve, hash, or encoding.
/// </para>
/// <para>
/// Encoding is part of the identifier, not a separate knob, which is what makes
/// <see cref="EcdsaSignatureFormat"/> reachable for a key that never leaves its store.
/// secp256k1 deliberately has no DER variant: its signatures are always fixed-width 64-byte
/// compact <c>R‖S</c>. Ed25519 and BLS wire formats are fixed by their algorithms.
/// </para>
/// <para>
/// This list is not exhaustive for third-party stores. A backend is free to advertise
/// identifiers of its own — <see cref="KeyStoreAlgorithmId"/> is a string precisely so that
/// it can — but must never reuse one of these identifiers for different observable bytes.
/// </para>
/// </remarks>
public static class KeyStoreAlgorithms
{
    /// <summary>Ed25519 (EdDSA, RFC 8032) — 64-byte signature. Key type: <see cref="KeyType.Ed25519"/>.</summary>
    public static KeyStoreAlgorithmId Ed25519 { get; } = new("ed25519");

    /// <summary>ECDSA P-256 with SHA-256, ASN.1/DER encoded. Key type: <see cref="KeyType.P256"/>.</summary>
    public static KeyStoreAlgorithmId Es256Der { get; } = new("es256-der");

    /// <summary>
    /// ECDSA P-256 with SHA-256, IEEE P1363 fixed-width 64-byte <c>R‖S</c> — the encoding
    /// JOSE/JWS (RFC 7515 §3.4), COSE, and WebAuthn mandate. Key type: <see cref="KeyType.P256"/>.
    /// </summary>
    public static KeyStoreAlgorithmId Es256P1363 { get; } = new("es256-p1363");

    /// <summary>ECDSA P-384 with SHA-384, ASN.1/DER encoded. Key type: <see cref="KeyType.P384"/>.</summary>
    public static KeyStoreAlgorithmId Es384Der { get; } = new("es384-der");

    /// <summary>ECDSA P-384 with SHA-384, IEEE P1363 fixed-width 96-byte <c>R‖S</c>. Key type: <see cref="KeyType.P384"/>.</summary>
    public static KeyStoreAlgorithmId Es384P1363 { get; } = new("es384-p1363");

    /// <summary>ECDSA P-521 with SHA-512, ASN.1/DER encoded. Key type: <see cref="KeyType.P521"/>.</summary>
    public static KeyStoreAlgorithmId Es512Der { get; } = new("es512-der");

    /// <summary>ECDSA P-521 with SHA-512, IEEE P1363 fixed-width 132-byte <c>R‖S</c>. Key type: <see cref="KeyType.P521"/>.</summary>
    public static KeyStoreAlgorithmId Es512P1363 { get; } = new("es512-p1363");

    /// <summary>
    /// ECDSA secp256k1 (RFC 8812 ES256K) — always fixed-width 64-byte compact <c>R‖S</c>, so
    /// there is no DER counterpart. Key type: <see cref="KeyType.Secp256k1"/>.
    /// </summary>
    public static KeyStoreAlgorithmId Es256K { get; } = new("es256k");

    /// <summary>BLS12-381 basic signature with the public key in G1. Key type: <see cref="KeyType.Bls12381G1"/>.</summary>
    public static KeyStoreAlgorithmId Bls12381G1Basic { get; } = new("bls12381g1-basic");

    /// <summary>
    /// BLS12-381 basic signature with the public key in G2. Key type:
    /// <see cref="KeyType.Bls12381G2"/>. This is <em>plain BLS signing</em>, never advertised
    /// or accepted as BBS — see <see cref="BbsBls12381Sha256"/>.
    /// </summary>
    public static KeyStoreAlgorithmId Bls12381G2Basic { get; } = new("bls12381g2-basic");

    /// <summary>Raw X25519 ECDH — returns the shared secret Z, no KDF. Key type: <see cref="KeyType.X25519"/>.</summary>
    public static KeyStoreAlgorithmId EcdhX25519 { get; } = new("ecdh-x25519");

    /// <summary>Raw P-256 ECDH — returns the 32-byte shared secret Z, no KDF. Key type: <see cref="KeyType.P256"/>.</summary>
    public static KeyStoreAlgorithmId EcdhP256 { get; } = new("ecdh-p256");

    /// <summary>Raw P-384 ECDH — returns the 48-byte shared secret Z, no KDF. Key type: <see cref="KeyType.P384"/>.</summary>
    public static KeyStoreAlgorithmId EcdhP384 { get; } = new("ecdh-p384");

    /// <summary>Raw P-521 ECDH — returns the 66-byte shared secret Z, no KDF. Key type: <see cref="KeyType.P521"/>.</summary>
    public static KeyStoreAlgorithmId EcdhP521 { get; } = new("ecdh-p521");

    /// <summary>
    /// BBS multi-message signature over BLS12-381-SHA-256
    /// (draft-irtf-cfrg-bbs-signatures-10) — 80-byte signature. Key type:
    /// <see cref="KeyType.Bls12381G2"/>, matching <see cref="BbsCiphersuite.Bls12381Sha256"/>.
    /// </summary>
    public static KeyStoreAlgorithmId BbsBls12381Sha256 { get; } = new("bbs-bls12381-sha256");
}

/// <summary>
/// Resolution of a <see cref="KeyStoreAlgorithmId"/> minted by <see cref="KeyStoreAlgorithms"/>
/// into the key type it binds, the operation it belongs to, and — for NIST-curve ECDSA — the
/// <see cref="EcdsaSignatureFormat"/> its identifier promises.
/// </summary>
internal readonly record struct KeyStoreAlgorithmSpec(
    KeyStoreAlgorithmId Algorithm,
    KeyType KeyType,
    KeyStoreOperation Operation,
    EcdsaSignatureFormat Format);

internal static class KeyStoreAlgorithmTable
{
    // The single source of truth for the id table: capability advertisement, request
    // validation, and the encoding actually handed to ICryptoProvider all read from here, so
    // an advertised id and the bytes it produces cannot drift apart.
    private static readonly KeyStoreAlgorithmSpec[] Specs =
    [
        new(KeyStoreAlgorithms.Ed25519, KeyType.Ed25519, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.Es256Der, KeyType.P256, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.Es256P1363, KeyType.P256, KeyStoreOperation.Sign, EcdsaSignatureFormat.IeeeP1363),
        new(KeyStoreAlgorithms.Es384Der, KeyType.P384, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.Es384P1363, KeyType.P384, KeyStoreOperation.Sign, EcdsaSignatureFormat.IeeeP1363),
        new(KeyStoreAlgorithms.Es512Der, KeyType.P521, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.Es512P1363, KeyType.P521, KeyStoreOperation.Sign, EcdsaSignatureFormat.IeeeP1363),
        // secp256k1 ignores the format flag in the provider and always emits compact R‖S,
        // which is what IeeeP1363 names; recording it here keeps the table honest.
        new(KeyStoreAlgorithms.Es256K, KeyType.Secp256k1, KeyStoreOperation.Sign, EcdsaSignatureFormat.IeeeP1363),
        new(KeyStoreAlgorithms.Bls12381G1Basic, KeyType.Bls12381G1, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.Bls12381G2Basic, KeyType.Bls12381G2, KeyStoreOperation.Sign, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.EcdhX25519, KeyType.X25519, KeyStoreOperation.KeyAgreement, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.EcdhP256, KeyType.P256, KeyStoreOperation.KeyAgreement, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.EcdhP384, KeyType.P384, KeyStoreOperation.KeyAgreement, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.EcdhP521, KeyType.P521, KeyStoreOperation.KeyAgreement, EcdsaSignatureFormat.Der),
        new(KeyStoreAlgorithms.BbsBls12381Sha256, KeyType.Bls12381G2, KeyStoreOperation.BbsSign, EcdsaSignatureFormat.Der),
    ];

    private static readonly Dictionary<string, KeyStoreAlgorithmSpec> ById =
        Specs.ToDictionary(s => s.Algorithm.Value, StringComparer.Ordinal);

    internal static IReadOnlyList<KeyStoreAlgorithmSpec> All => Specs;

    internal static bool TryResolve(string? id, out KeyStoreAlgorithmSpec spec)
    {
        if (id is not null)
            return ById.TryGetValue(id, out spec);

        spec = default;
        return false;
    }
}

namespace NetCrypto;

/// <summary>
/// Wire format of an ECDSA signature. Defaults to <see cref="Der"/> for back-compat with
/// X.509, CMS, and generic DID proof flows; switch to <see cref="IeeeP1363"/> for JOSE / JWS /
/// JWE / COSE / WebAuthn consumers, all of which mandate the fixed-width R‖S concatenation.
/// </summary>
/// <remarks>
/// Only meaningful for NIST-curve ECDSA (P-256, P-384, P-521). secp256k1 always returns
/// 64-byte compact (R‖S), which already matches <see cref="IeeeP1363"/>. EdDSA (Ed25519) and
/// BLS signatures ignore this enum entirely — their wire format is fixed by the algorithm.
/// </remarks>
public enum EcdsaSignatureFormat
{
    /// <summary>
    /// ASN.1 / DER SEQUENCE { r INTEGER, s INTEGER }. Used by X.509, CMS, and generic
    /// DID proofs. This is the default to avoid breaking existing consumers that
    /// parse signatures with `System.Security.Cryptography.ECDsa.VerifyData`.
    /// </summary>
    Der = 0,

    /// <summary>
    /// IEEE P1363 fixed-width R‖S concatenation, each value zero-padded to the curve's
    /// field byte length (32 for P-256, 48 for P-384, 66 for P-521). Required by JOSE / JWS
    /// (RFC 7515 §3.4), JWE, COSE, and WebAuthn.
    /// </summary>
    IeeeP1363 = 1,
}

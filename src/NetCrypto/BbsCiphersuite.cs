namespace NetCrypto;

/// <summary>
/// BBS ciphersuites supported by <see cref="IBbsCryptoProvider"/> implementations.
/// </summary>
public enum BbsCiphersuite
{
    /// <summary>
    /// The BLS12-381-SHA-256 ciphersuite of IETF draft-irtf-cfrg-bbs-signatures-10.
    /// The only value supported in v1.
    /// </summary>
    Bls12381Sha256 = 0,
}

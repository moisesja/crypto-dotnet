namespace NetCrypto;

/// <summary>
/// A recoverable ECDSA signature over a caller-supplied digest: the 64-byte compact
/// <c>R‖S</c> signature and the raw recovery id (0–3), as produced by
/// <see cref="IRecoverableDigestSigner.SignDigestAsync"/> and
/// <see cref="Secp256k1Recoverable.Sign"/>.
/// </summary>
/// <remarks>
/// <b>Boundary (PRD FR-12 ruling):</b> the recovery id is the <i>raw</i> id in
/// <c>{0, 1, 2, 3}</c>. EVM <c>v</c>-encoding — legacy <c>27 + recid</c> or EIP-155
/// <c>35 + recid + 2·chainId</c> — is the wallet layer's responsibility and is
/// deliberately absent from this library.
/// </remarks>
/// <param name="Signature64">The 64-byte compact signature (<c>R‖S</c>, each 32 bytes
/// big-endian), low-S normalized (<c>S ≤ n/2</c>).</param>
/// <param name="RecoveryId">The raw recovery id in <c>{0, 1, 2, 3}</c> — <b>not</b> an
/// EVM <c>v</c> value.</param>
public readonly record struct RecoverableSignature(byte[] Signature64, int RecoveryId);

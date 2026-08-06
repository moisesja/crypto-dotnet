namespace NetCrypto;

/// <summary>
/// A recoverable ECDSA signature over a caller-supplied digest: the 64-byte compact
/// <c>R‖S</c> signature and the raw recovery id (0–3), as produced by
/// <see cref="IRecoverableDigestSigner.SignDigestAsync"/> and
/// <see cref="Secp256k1Recoverable.Sign"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Boundary (PRD FR-12 ruling):</b> the recovery id is the <i>raw</i> id in
/// <c>{0, 1, 2, 3}</c>. EVM <c>v</c>-encoding — legacy <c>27 + recid</c> or EIP-155
/// <c>35 + recid + 2·chainId</c> — is the wallet layer's responsibility and is
/// deliberately absent from this library.
/// </para>
/// <para>
/// <b>Equality is reference-based on <see cref="Signature64"/>.</b> Because the compiler-generated
/// <c>Equals</c>/<c>==</c>/<c>GetHashCode</c> compare the <c>byte[]</c> by reference (not by
/// content), two structurally-identical signatures — including the byte-identical outputs RFC 6979
/// determinism produces for the same key and digest — are <i>not</i> equal and hash differently.
/// This matches the raw-tuple return of <see cref="Secp256k1Recoverable.Sign"/>. Callers that need
/// value comparison (deduplication, replay caches) must compare <see cref="Signature64"/> with
/// <see cref="System.MemoryExtensions.SequenceEqual{T}(System.ReadOnlySpan{T}, System.ReadOnlySpan{T})"/>
/// (and <see cref="RecoveryId"/>), or key on an encoded form of the bytes.
/// </para>
/// <para>
/// <b>Content comparison is still not a replay defense for signatures from elsewhere.</b>
/// <see cref="Secp256k1Recoverable.Sign"/> always emits low-S, so signatures this library
/// produces are canonical — but ECDSA admits two valid encodings of every signature
/// (<c>(R, S)</c> and <c>(R, n-S)</c>), and
/// <see cref="ICryptoProvider.Verify(KeyType, System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>
/// accepts both for every ECDSA key type. A replay cache keyed on inbound signature bytes is defeated by
/// re-submitting the twin encoding. Bind replay protection to the message — a nonce, <c>jti</c>,
/// or the digest — and enforce <c>S ≤ n/2</c> explicitly if you need canonicality.
/// </para>
/// </remarks>
/// <param name="Signature64">The 64-byte compact signature (<c>R‖S</c>, each 32 bytes
/// big-endian), low-S normalized (<c>S ≤ n/2</c>).</param>
/// <param name="RecoveryId">The raw recovery id in <c>{0, 1, 2, 3}</c> — <b>not</b> an
/// EVM <c>v</c> value.</param>
public readonly record struct RecoverableSignature(byte[] Signature64, int RecoveryId);

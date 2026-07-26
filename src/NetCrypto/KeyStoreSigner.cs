using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using NetCid;

namespace NetCrypto;

/// <summary>
/// Wraps a key store alias for HSM/vault-backed signing (secure path).
/// The private key never leaves the store.
/// </summary>
public sealed class KeyStoreSigner : ISigner, IRecoverableDigestSigner
{
    private static readonly BigInteger HalfCurveOrder = BigInteger.Parse(
        "07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        NumberStyles.HexNumber);

    private readonly IKeyStore _store;
    private readonly string _alias;
    private readonly byte[] _publicKey;

    /// <summary>Creates a signer that delegates signing for <paramref name="alias"/> to the given key store.</summary>
    public KeyStoreSigner(IKeyStore store, string alias, KeyType keyType, byte[] publicKey)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _alias = alias ?? throw new ArgumentNullException(nameof(alias));
        ArgumentNullException.ThrowIfNull(publicKey);
        KeyType = keyType;
        _publicKey = (byte[])publicKey.Clone();
    }

    /// <inheritdoc />
    public KeyType KeyType { get; }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> PublicKey => (byte[])_publicKey.Clone();

    /// <inheritdoc />
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), _publicKey), MultibaseEncoding.Base58Btc);

    /// <inheritdoc />
    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        => _store.SignAsync(_alias, data, ct);

    /// <inheritdoc />
    /// <remarks>
    /// The backing store may be an arbitrary external provider (HSM, cloud KMS), so its output is
    /// verified at this boundary before being returned: the signature must be structurally valid
    /// (64-byte <c>R‖S</c>, recovery id 0–3), low-S normalized, and recover to this signer's
    /// advertised <see cref="PublicKey"/>. The signer keeps a private snapshot of that identity;
    /// the caller's digest and public-key buffers are never shared with the store or retained
    /// internally. The store-owned signature buffer is defensively copied before validation, and
    /// only that verified copy is returned. These checks turn a malformed or mutable provider
    /// result — or an alias that was rebound to a different key under the same name (delete +
    /// recreate) — into a <see cref="CryptographicException"/> instead of a signature that
    /// silently changes after validation or speaks for the wrong key.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="digest32"/> is not 32 bytes.</exception>
    /// <exception cref="KeyNotFoundException">The store no longer holds a key under this signer's alias.</exception>
    /// <exception cref="NotSupportedException">This signer's key is not secp256k1, or the store
    /// does not support recoverable digest signing.</exception>
    /// <exception cref="CryptographicException">The store returned a signature that is malformed or
    /// does not recover to this signer's <see cref="PublicKey"/>.</exception>
    public Task<RecoverableSignature> SignDigestAsync(ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
    {
        // Validate synchronously — before any store round-trip — so every IRecoverableDigestSigner
        // front door enforces the same parameter-named contract, even over a store that forgets to.
        if (digest32.Length != 32)
            throw new ArgumentException($"Digest must be 32 bytes, got {digest32.Length}.", nameof(digest32));
        if (KeyType != KeyType.Secp256k1)
            throw new NotSupportedException(
                $"Recoverable digest signing requires a secp256k1 key; this signer holds {KeyType}.");

        // Preserve the caller's digest for verification. The separate provider copy below prevents
        // an arbitrary store from mutating either the caller's buffer or the bytes trusted here.
        return SignAndVerifyAsync(digest32.ToArray(), ct);
    }

    private async Task<RecoverableSignature> SignAndVerifyAsync(byte[] verificationDigest, CancellationToken ct)
    {
        var providerDigest = (byte[])verificationDigest.Clone();
        var storeSignature = await _store.SignDigestAsync(_alias, providerDigest, ct).ConfigureAwait(false);
        return CopyAndVerify(verificationDigest, storeSignature);
    }

    private RecoverableSignature CopyAndVerify(ReadOnlySpan<byte> digest32, RecoverableSignature storeSignature)
    {
        if (storeSignature.Signature64 is not { Length: 64 } || storeSignature.RecoveryId is < 0 or > 3)
            throw new CryptographicException(
                "The key store returned a malformed recoverable signature (expected a 64-byte R‖S and a recovery id in 0–3).");

        // The provider may retain its result buffer. Copy before validating so a later provider
        // mutation cannot alter the bytes that passed validation or the value returned to callers.
        var signature = new RecoverableSignature(
            (byte[])storeSignature.Signature64.Clone(),
            storeSignature.RecoveryId);

        var s = new BigInteger(signature.Signature64.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
        if (s > HalfCurveOrder)
            throw new CryptographicException(
                "The key store returned a non-canonical recoverable signature; expected low-S normalization (S ≤ n/2).");

        // Recover in whichever SEC1 form this signer advertises its public key (33 → compressed,
        // otherwise uncompressed) so the comparison is byte-exact against the private snapshot.
        var compressed = _publicKey.Length == 33;
        byte[] recovered;
        try
        {
            recovered = Secp256k1Recoverable.RecoverPublicKey(digest32, signature.Signature64, signature.RecoveryId, compressed);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            // Re-surface a store's non-canonical/non-recoverable output as a boundary integrity
            // failure — never as a caller-argument (paramName) error, which would misattribute a
            // store-side fault to the caller's digest.
            throw new CryptographicException("The key store returned a non-recoverable signature.", ex);
        }

        if (!recovered.AsSpan().SequenceEqual(_publicKey))
            throw new CryptographicException(
                "The key store returned a signature that does not recover to this signer's public key; " +
                "the alias may have been rebound to a different key.");

        return signature;
    }
}

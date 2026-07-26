using System.Security.Cryptography;
using NetCid;

namespace NetCrypto;

/// <summary>
/// Wraps a key store alias for HSM/vault-backed signing (secure path).
/// The private key never leaves the store.
/// </summary>
public sealed class KeyStoreSigner : ISigner, IRecoverableDigestSigner
{
    private readonly IKeyStore _store;
    private readonly string _alias;

    /// <summary>Creates a signer that delegates signing for <paramref name="alias"/> to the given key store.</summary>
    public KeyStoreSigner(IKeyStore store, string alias, KeyType keyType, byte[] publicKey)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _alias = alias ?? throw new ArgumentNullException(nameof(alias));
        KeyType = keyType;
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    /// <inheritdoc />
    public KeyType KeyType { get; }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <inheritdoc />
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey.Span), MultibaseEncoding.Base58Btc);

    /// <inheritdoc />
    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        => _store.SignAsync(_alias, data, ct);

    /// <inheritdoc />
    /// <remarks>
    /// The backing store may be an arbitrary external provider (HSM, cloud KMS), so its output is
    /// verified at this boundary before being returned: the signature must be structurally valid
    /// (64-byte <c>R‖S</c>, recovery id 0–3) <b>and</b> must recover to this signer's advertised
    /// <see cref="PublicKey"/>. That turns a malformed provider result — or an alias that was
    /// rebound to a different key under the same name (delete + recreate) — into a
    /// <see cref="CryptographicException"/> instead of a signature that silently speaks for the
    /// wrong key.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="digest32"/> is not 32 bytes.</exception>
    /// <exception cref="KeyNotFoundException">The store no longer holds a key under this signer's alias.</exception>
    /// <exception cref="NotSupportedException">The store does not support recoverable digest signing.</exception>
    /// <exception cref="CryptographicException">The store returned a signature that is malformed or
    /// does not recover to this signer's <see cref="PublicKey"/>.</exception>
    public Task<RecoverableSignature> SignDigestAsync(ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
    {
        // Validate synchronously — before any store round-trip — so every IRecoverableDigestSigner
        // front door enforces the same parameter-named contract, even over a store that forgets to.
        if (digest32.Length != 32)
            throw new ArgumentException($"Digest must be 32 bytes, got {digest32.Length}.", nameof(digest32));

        return SignAndVerifyAsync(digest32, ct);
    }

    private async Task<RecoverableSignature> SignAndVerifyAsync(ReadOnlyMemory<byte> digest32, CancellationToken ct)
    {
        var signature = await _store.SignDigestAsync(_alias, digest32, ct).ConfigureAwait(false);

        // secp256k1 is the only recoverable type; a non-secp256k1 store legitimately throws
        // NotSupportedException above and never reaches here. For the supported type, prove the
        // store's output recovers to the identity this signer advertises.
        if (KeyType == KeyType.Secp256k1)
            VerifyRecoversToPublicKey(digest32.Span, signature);

        return signature;
    }

    private void VerifyRecoversToPublicKey(ReadOnlySpan<byte> digest32, RecoverableSignature signature)
    {
        if (signature.Signature64 is not { Length: 64 } || signature.RecoveryId is < 0 or > 3)
            throw new CryptographicException(
                "The key store returned a malformed recoverable signature (expected a 64-byte R‖S and a recovery id in 0–3).");

        // Recover in whichever SEC1 form this signer advertises its public key (33 → compressed,
        // otherwise uncompressed) so the comparison is byte-exact against PublicKey.
        var compressed = PublicKey.Length == 33;
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

        if (!recovered.AsSpan().SequenceEqual(PublicKey.Span))
            throw new CryptographicException(
                "The key store returned a signature that does not recover to this signer's public key; " +
                "the alias may have been rebound to a different key.");
    }
}

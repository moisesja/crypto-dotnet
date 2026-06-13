using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// Low-level cryptographic operations. Application code should use <see cref="ISigner"/> instead.
/// </summary>
public interface ICryptoProvider
{
    /// <summary>
    /// Sign data with the algorithm bound to <paramref name="keyType"/>. NIST-curve ECDSA
    /// (P-256, P-384, P-521) signatures are returned in DER form for back-compat. Callers
    /// that need IEEE P1363 (JOSE / COSE / WebAuthn) should use the
    /// <see cref="Sign(KeyType, ReadOnlySpan{byte}, ReadOnlySpan{byte}, EcdsaSignatureFormat)"/>
    /// overload.
    /// </summary>
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);

    /// <summary>
    /// Verify a DER-encoded ECDSA signature (or the algorithm-native format for non-ECDSA
    /// key types). Use the <see cref="Verify(KeyType, ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte}, EcdsaSignatureFormat)"/>
    /// overload to verify IEEE P1363 signatures.
    /// </summary>
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>
    /// Sign data with an explicit NIST-curve ECDSA signature format. Non-ECDSA key types
    /// (Ed25519, secp256k1, BLS12-381) ignore <paramref name="format"/> and return their
    /// algorithm-native wire format — secp256k1 already returns 64-byte compact (R‖S),
    /// which matches <see cref="EcdsaSignatureFormat.IeeeP1363"/>.
    /// </summary>
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format);

    /// <summary>
    /// Verify a NIST-curve ECDSA signature in the specified format. A DER signature passed
    /// with <see cref="EcdsaSignatureFormat.IeeeP1363"/> (or vice versa) returns
    /// <c>false</c> — not an exception. Non-ECDSA key types ignore <paramref name="format"/>.
    /// </summary>
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format);

    /// <summary>
    /// Performs X25519 key agreement and returns an HKDF-SHA256-derived 32-byte key. Convenience wrapper
    /// for the common DIDComm/did:peer use case. Prefer <see cref="DeriveSharedSecret"/> when the caller
    /// needs to apply its own KDF (Concat KDF, HKDF with custom info, KMAC, etc.) or when working with
    /// the NIST P-curves.
    /// </summary>
    byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);

    /// <summary>
    /// Compute the raw ECDH shared secret "Z" between a local private key and a remote public key
    /// on the same curve. No KDF, no truncation, no normalization is applied. Callers are responsible
    /// for applying their own key-derivation function (Concat KDF, HKDF, KMAC, etc.) to the returned
    /// bytes before using them as keying material.
    /// </summary>
    /// <param name="keyType">
    /// One of: <see cref="KeyType.X25519"/>, <see cref="KeyType.P256"/>, <see cref="KeyType.P384"/>.
    /// (P-521 added in issue #61.) Other key types throw <see cref="ArgumentException"/>.
    /// </param>
    /// <param name="privateKey">Raw private key bytes for <paramref name="keyType"/>.</param>
    /// <param name="publicKey">Remote public key in the canonical encoding for <paramref name="keyType"/>:
    /// raw 32 bytes for X25519; SEC1 compressed (0x02/0x03 || X) or uncompressed (0x04 || X || Y) for NIST curves.</param>
    /// <returns>The raw ECDH shared secret "Z": 32 bytes for X25519 and P-256; 48 bytes for P-384 (X-coordinate of the shared point).</returns>
    /// <exception cref="ArgumentException">If <paramref name="keyType"/> is not an ECDH-capable curve.</exception>
    /// <exception cref="CryptographicException">If key agreement fails (e.g. invalid point, mismatched curve).</exception>
    /// <remarks>
    /// This is a low-level primitive. Apply a NIST SP 800-56A-conformant KDF (Concat KDF, HKDF, KMAC)
    /// before using the output as keying material. See RFC 7518 §4.6 for the JOSE ECDH-ES binding.
    /// </remarks>
    byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
}

/// <summary>
/// BBS signature operations (multi-message, selective disclosure, ZKPs).
/// Separated from <see cref="ICryptoProvider"/> because BBS operates over an ordered
/// set of messages rather than a single byte span.
/// </summary>
public interface IBbsCryptoProvider
{
    /// <summary>The BBS ciphersuite this provider instance operates with.</summary>
    BbsCiphersuite Ciphersuite { get; }

    /// <summary>
    /// Whether the BBS implementation is usable on the current platform. A capability
    /// probe — never throws. When <c>false</c> (the native library could not be loaded),
    /// the signature and proof operations throw <see cref="BbsUnavailableException"/>.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Sign an ordered set of messages using a BLS12-381 G2 private key.
    /// </summary>
    /// <param name="privateKey">32-byte BLS12-381 secret scalar.</param>
    /// <param name="messages">The ordered set of messages to sign.</param>
    /// <param name="header">
    /// Optional BBS signature <c>header</c> (draft-irtf-cfrg-bbs-signatures). Fixed by the
    /// signer at sign time and bound into the signature: <see cref="Verify"/> and any derived
    /// proof only succeed when the same <paramref name="header"/> is supplied. Application data
    /// committed here cannot be dropped or altered by the holder — e.g. the W3C <c>bbs-2023</c>
    /// cryptosuite binds its mandatory-disclosure group into the header. Distinct from the
    /// <c>presentationHeader</c> on <see cref="DeriveProof"/>/<see cref="VerifyProof"/>, which the
    /// holder chooses at derive time. Defaults to empty (no header bound).
    /// </param>
    byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages,
        ReadOnlySpan<byte> header = default);

    /// <summary>
    /// Verify a BBS signature against the full set of messages.
    /// </summary>
    /// <param name="publicKey">96-byte BLS12-381 G2 public key.</param>
    /// <param name="signature">The 80-byte BBS signature to verify.</param>
    /// <param name="messages">The full ordered set of messages that was signed.</param>
    /// <param name="header">
    /// The same BBS signature <c>header</c> that was supplied to <see cref="Sign"/>. Verification
    /// fails (returns <c>false</c>) if it differs from the header bound at sign time. Defaults to
    /// empty.
    /// </param>
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages,
        ReadOnlySpan<byte> header = default);

    /// <summary>
    /// Derive a zero-knowledge proof that selectively discloses only the messages
    /// at the specified indices, without revealing the original signature.
    /// </summary>
    /// <param name="publicKey">96-byte BLS12-381 G2 public key of the signer.</param>
    /// <param name="signature">The 80-byte BBS signature over <paramref name="messages"/>.</param>
    /// <param name="messages">The full ordered set of signed messages.</param>
    /// <param name="revealedIndices">Indices of the messages to disclose; must be distinct and in range.</param>
    /// <param name="presentationHeader">
    /// The BBS presentation header (<c>ph</c>) — chosen by the holder at derive time, typically the
    /// verifier's challenge/nonce so a captured proof cannot be replayed. Bound into the proof and
    /// must be supplied unchanged to <see cref="VerifyProof"/>. Distinct from
    /// <paramref name="header"/>.
    /// </param>
    /// <param name="header">
    /// The same BBS signature <c>header</c> that was bound at <see cref="Sign"/> time. It is
    /// committed by the derived proof, so <see cref="VerifyProof"/> fails unless the same value is
    /// supplied there. Defaults to empty.
    /// </param>
    byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> presentationHeader,
        ReadOnlySpan<byte> header = default);

    /// <summary>
    /// Verify a derived proof against the revealed messages.
    /// </summary>
    /// <param name="publicKey">96-byte BLS12-381 G2 public key of the signer.</param>
    /// <param name="proof">The proof bytes produced by <see cref="DeriveProof"/>.</param>
    /// <param name="revealedMessages">Only the disclosed messages, in the order of their indices.</param>
    /// <param name="revealedIndices">The indices the proof discloses, matching <paramref name="revealedMessages"/>.</param>
    /// <param name="presentationHeader">
    /// The BBS presentation header (<c>ph</c>) that was supplied to <see cref="DeriveProof"/>.
    /// Verification fails if it differs.
    /// </param>
    /// <param name="header">
    /// The BBS signature <c>header</c> bound at <see cref="Sign"/>/<see cref="DeriveProof"/> time.
    /// Verification fails if it differs from the header committed by the proof. Defaults to empty.
    /// </param>
    bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> presentationHeader,
        ReadOnlySpan<byte> header = default);
}

using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as defined in RFC 5869,
/// with SHA-256, SHA-384, or SHA-512.
/// </summary>
/// <remarks>
/// <para>
/// Thin wrapper over the BCL <see cref="HKDF"/> exposing a single consistent parameter
/// convention (hash algorithm first, required inputs next, optional inputs last) with
/// up-front input validation, so consumers don't bind to the BCL directly.
/// </para>
/// <para>
/// Per RFC 5869 §2.2, an absent <c>salt</c> is equivalent to a string of HashLen zero
/// bytes; per RFC 5869 §2.3, an absent <c>info</c> is equivalent to the empty string and
/// the output keying material is limited to <c>255 × HashLen</c> bytes.
/// </para>
/// </remarks>
public static class Hkdf
{
    /// <summary>
    /// HKDF-Extract per RFC 5869 §2.2: computes the pseudorandom key
    /// <c>PRK = HMAC-Hash(salt, IKM)</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The hash function: <see cref="HashAlgorithmName.SHA256"/>,
    /// <see cref="HashAlgorithmName.SHA384"/>, or <see cref="HashAlgorithmName.SHA512"/>.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="salt">Optional salt. Pass empty (the default) for absent — per RFC 5869
    /// §2.2 this is equivalent to a string of HashLen zero bytes.</param>
    /// <returns>The pseudorandom key, HashLen bytes long.</returns>
    /// <exception cref="ArgumentException">If <paramref name="hashAlgorithm"/> is not
    /// SHA-256, SHA-384, or SHA-512.</exception>
    public static byte[] Extract(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt = default)
    {
        var hashLen = GetHashLength(hashAlgorithm);

        var prk = new byte[hashLen];
        HKDF.Extract(hashAlgorithm, ikm, salt, prk);
        return prk;
    }

    /// <summary>
    /// HKDF-Expand per RFC 5869 §2.3: expands the pseudorandom key
    /// <paramref name="prk"/> into <paramref name="outputLength"/> bytes of output keying
    /// material.
    /// </summary>
    /// <param name="hashAlgorithm">The hash function: <see cref="HashAlgorithmName.SHA256"/>,
    /// <see cref="HashAlgorithmName.SHA384"/>, or <see cref="HashAlgorithmName.SHA512"/>.</param>
    /// <param name="prk">The pseudorandom key, at least HashLen bytes long (typically the
    /// output of <see cref="Extract"/>).</param>
    /// <param name="outputLength">Desired output length in bytes. Must be positive and at
    /// most <c>255 × HashLen</c> per RFC 5869 §2.3.</param>
    /// <param name="info">Optional context and application specific information. Pass empty
    /// (the default) for absent — per RFC 5869 §2.3 this is equivalent to the empty string.</param>
    /// <returns><paramref name="outputLength"/> bytes of output keying material.</returns>
    /// <exception cref="ArgumentException">If <paramref name="hashAlgorithm"/> is not
    /// SHA-256, SHA-384, or SHA-512; if <paramref name="outputLength"/> is non-positive or
    /// exceeds <c>255 × HashLen</c>; or if <paramref name="prk"/> is shorter than HashLen.</exception>
    public static byte[] Expand(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> prk, int outputLength, ReadOnlySpan<byte> info = default)
    {
        var hashLen = GetHashLength(hashAlgorithm);
        ValidateOutputLength(outputLength, hashLen);

        var okm = new byte[outputLength];
        HKDF.Expand(hashAlgorithm, prk, okm, info);
        return okm;
    }

    /// <summary>
    /// One-shot HKDF per RFC 5869: <c>Expand(Extract(salt, IKM), info, outputLength)</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The hash function: <see cref="HashAlgorithmName.SHA256"/>,
    /// <see cref="HashAlgorithmName.SHA384"/>, or <see cref="HashAlgorithmName.SHA512"/>.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="outputLength">Desired output length in bytes. Must be positive and at
    /// most <c>255 × HashLen</c> per RFC 5869 §2.3.</param>
    /// <param name="salt">Optional salt. Pass empty (the default) for absent — per RFC 5869
    /// §2.2 this is equivalent to a string of HashLen zero bytes.</param>
    /// <param name="info">Optional context and application specific information. Pass empty
    /// (the default) for absent — per RFC 5869 §2.3 this is equivalent to the empty string.</param>
    /// <returns><paramref name="outputLength"/> bytes of output keying material.</returns>
    /// <exception cref="ArgumentException">If <paramref name="hashAlgorithm"/> is not
    /// SHA-256, SHA-384, or SHA-512, or if <paramref name="outputLength"/> is non-positive
    /// or exceeds <c>255 × HashLen</c>.</exception>
    public static byte[] DeriveKey(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> ikm, int outputLength, ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default)
    {
        var hashLen = GetHashLength(hashAlgorithm);
        ValidateOutputLength(outputLength, hashLen);

        var okm = new byte[outputLength];
        HKDF.DeriveKey(hashAlgorithm, ikm, okm, salt, info);
        return okm;
    }

    private static int GetHashLength(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return 32;
        if (hashAlgorithm == HashAlgorithmName.SHA384)
            return 48;
        if (hashAlgorithm == HashAlgorithmName.SHA512)
            return 64;

        throw new ArgumentException(
            $"Unsupported hash algorithm '{hashAlgorithm.Name}'. Supported: SHA-256, SHA-384, SHA-512.",
            nameof(hashAlgorithm));
    }

    private static void ValidateOutputLength(int outputLength, int hashLen)
    {
        if (outputLength <= 0)
            throw new ArgumentException("Must be greater than zero.", nameof(outputLength));
        if (outputLength > 255 * hashLen)
            throw new ArgumentException(
                $"Must not exceed 255 × HashLen = {255 * hashLen} bytes (RFC 5869 §2.3).",
                nameof(outputLength));
    }
}

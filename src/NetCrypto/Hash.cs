using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// SHA-2 hashing helpers (FIPS 180-4): SHA-256, SHA-384, and SHA-512.
/// </summary>
/// <remarks>
/// <para>
/// Thin wrappers over the BCL one-shot statics (<see cref="SHA256.HashData(ReadOnlySpan{byte})"/>
/// and friends) so consumers depend on NetCrypto rather than binding to
/// <c>System.Security.Cryptography</c> directly. Driver: SD-JWT disclosure hashing in
/// <c>credentials-dotnet</c>, where each disclosure digest is the SHA-2 hash of the
/// base64url-encoded disclosure string.
/// </para>
/// <para>
/// Digest sizes: SHA-256 = 32 bytes, SHA-384 = 48 bytes, SHA-512 = 64 bytes.
/// All methods are stateless and thread-safe.
/// </para>
/// </remarks>
public static class Hash
{
    /// <summary>
    /// Computes the SHA-256 digest of <paramref name="data"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <returns>The 32-byte SHA-256 digest.</returns>
    public static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    /// <summary>
    /// Attempts to compute the SHA-256 digest of <paramref name="data"/> into
    /// <paramref name="destination"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <param name="destination">The buffer to receive the 32-byte digest.</param>
    /// <param name="bytesWritten">On success, the number of bytes written (32); otherwise 0.</param>
    /// <returns><c>true</c> if <paramref name="destination"/> is at least 32 bytes long and the
    /// digest was written; <c>false</c> if the buffer is too small (nothing is written).</returns>
    public static bool TrySha256(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) =>
        SHA256.TryHashData(data, destination, out bytesWritten);

    /// <summary>
    /// Computes the SHA-384 digest of <paramref name="data"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <returns>The 48-byte SHA-384 digest.</returns>
    public static byte[] Sha384(ReadOnlySpan<byte> data) => SHA384.HashData(data);

    /// <summary>
    /// Attempts to compute the SHA-384 digest of <paramref name="data"/> into
    /// <paramref name="destination"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <param name="destination">The buffer to receive the 48-byte digest.</param>
    /// <param name="bytesWritten">On success, the number of bytes written (48); otherwise 0.</param>
    /// <returns><c>true</c> if <paramref name="destination"/> is at least 48 bytes long and the
    /// digest was written; <c>false</c> if the buffer is too small (nothing is written).</returns>
    public static bool TrySha384(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) =>
        SHA384.TryHashData(data, destination, out bytesWritten);

    /// <summary>
    /// Computes the SHA-512 digest of <paramref name="data"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <returns>The 64-byte SHA-512 digest.</returns>
    public static byte[] Sha512(ReadOnlySpan<byte> data) => SHA512.HashData(data);

    /// <summary>
    /// Attempts to compute the SHA-512 digest of <paramref name="data"/> into
    /// <paramref name="destination"/> per FIPS 180-4.
    /// </summary>
    /// <param name="data">The data to hash. May be empty.</param>
    /// <param name="destination">The buffer to receive the 64-byte digest.</param>
    /// <param name="bytesWritten">On success, the number of bytes written (64); otherwise 0.</param>
    /// <returns><c>true</c> if <paramref name="destination"/> is at least 64 bytes long and the
    /// digest was written; <c>false</c> if the buffer is too small (nothing is written).</returns>
    public static bool TrySha512(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) =>
        SHA512.TryHashData(data, destination, out bytesWritten);
}

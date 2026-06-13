namespace NetCrypto;

/// <summary>
/// Up-front validation for raw key/scalar byte inputs, shared by <see cref="DefaultCryptoProvider"/>
/// and <see cref="DefaultKeyGenerator"/>. Converts a malformed caller input into a parameter-named
/// <see cref="System.ArgumentException"/> <em>before</em> it reaches a cryptographic backend that
/// would otherwise surface a non-contract exception — NSec's <c>FormatException</c>, Nethermind
/// BLS's <c>BlsException</c>, or a platform <c>CryptographicException</c> on EC key import (NFR-3:
/// bad input must produce <c>ArgumentException</c>, never a leaked backend type).
/// </summary>
internal static class RawKeyGuard
{
    /// <summary>
    /// Throw a parameter-named <see cref="System.ArgumentException"/> if <paramref name="value"/>
    /// is not exactly <paramref name="expected"/> bytes long.
    /// </summary>
    internal static void RequireLength(ReadOnlySpan<byte> value, int expected, string paramName, string label)
    {
        if (value.Length != expected)
            throw new ArgumentException(
                $"{label} must be {expected} bytes, but was {value.Length}.", paramName);
    }
}

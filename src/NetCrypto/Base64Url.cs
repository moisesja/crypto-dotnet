namespace NetCrypto;

/// <summary>
/// Base64url (RFC 4648 §5) without padding — the byte-to-text encoding used at every JOSE/JWK
/// boundary (protected headers, signatures, JWE <c>iv</c>/<c>ciphertext</c>/<c>tag</c>/<c>encrypted_key</c>,
/// JWK <c>x</c>/<c>y</c>/<c>d</c>, <c>apu</c>/<c>apv</c>). A single source of truth for the foundation's
/// consumers, so they do not each re-implement it and risk subtle padding/charset divergence.
/// </summary>
/// <remarks>
/// Thin wrapper over the BCL <see cref="System.Buffers.Text.Base64Url"/>. <see cref="Encode"/> never
/// emits <c>=</c> padding. <see cref="Decode"/> tolerates input with or without trailing <c>=</c> padding,
/// but is otherwise strict: it rejects any character outside the base64url alphabet — including ASCII
/// whitespace (space, tab, CR, LF), which the bare BCL decoder would silently strip. A canonical JOSE
/// primitive must not map several wire forms to the same bytes, so whitespace is treated as invalid input.
/// </remarks>
public static class Base64Url
{
    /// <summary>Encode bytes as base64url (RFC 4648 §5) with no trailing <c>=</c> padding.</summary>
    /// <param name="data">The bytes to encode. May be empty (returns an empty string).</param>
    /// <returns>The unpadded base64url text.</returns>
    public static string Encode(ReadOnlySpan<byte> data) =>
        System.Buffers.Text.Base64Url.EncodeToString(data);

    /// <summary>
    /// Decode base64url (RFC 4648 §5) text, tolerating input with or without trailing <c>=</c> padding.
    /// Whitespace and any other character outside the base64url alphabet are rejected (not stripped).
    /// </summary>
    /// <param name="text">The base64url text to decode. A <see cref="string"/> converts implicitly.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="System.FormatException">If <paramref name="text"/> contains a character outside the
    /// base64url alphabet (including whitespace) or is otherwise not valid base64url.</exception>
    public static byte[] Decode(ReadOnlySpan<char> text)
    {
        // The BCL decoder strips ASCII whitespace before decoding, so "QU JD", "\nQUJD\n", and "QUJD" all
        // decode to the same bytes. For a JOSE/JWK primitive that is a charset divergence — reject any
        // non-alphabet character up front so each byte string has exactly one accepted textual form
        // (modulo the documented optional padding, whose placement the BCL still validates).
        foreach (char c in text)
        {
            bool inAlphabet =
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_' || c == '=';
            if (!inAlphabet)
                throw new FormatException("Input contains a character outside the base64url alphabet.");
        }

        return System.Buffers.Text.Base64Url.DecodeFromChars(text);
    }
}

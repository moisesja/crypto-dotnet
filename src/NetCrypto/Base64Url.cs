namespace NetCrypto;

/// <summary>
/// Base64url (RFC 4648 §5) without padding — the byte-to-text encoding used at every JOSE/JWK
/// boundary (protected headers, signatures, JWE <c>iv</c>/<c>ciphertext</c>/<c>tag</c>/<c>encrypted_key</c>,
/// JWK <c>x</c>/<c>y</c>/<c>d</c>, <c>apu</c>/<c>apv</c>). A single source of truth for the foundation's
/// consumers, so they do not each re-implement it and risk subtle padding/charset divergence.
/// </summary>
/// <remarks>
/// Thin wrapper over the BCL <see cref="System.Buffers.Text.Base64Url"/>. <see cref="Encode"/> never
/// emits <c>=</c> padding; <see cref="Decode"/> accepts input with or without trailing padding.
/// </remarks>
public static class Base64Url
{
    /// <summary>Encode bytes as base64url (RFC 4648 §5) with no trailing <c>=</c> padding.</summary>
    /// <param name="data">The bytes to encode. May be empty (returns an empty string).</param>
    /// <returns>The unpadded base64url text.</returns>
    public static string Encode(ReadOnlySpan<byte> data) =>
        System.Buffers.Text.Base64Url.EncodeToString(data);

    /// <summary>Decode base64url (RFC 4648 §5) text, tolerating input with or without <c>=</c> padding.</summary>
    /// <param name="text">The base64url text to decode. A <see cref="string"/> converts implicitly.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="System.FormatException">If <paramref name="text"/> is not valid base64url.</exception>
    public static byte[] Decode(ReadOnlySpan<char> text) =>
        System.Buffers.Text.Base64Url.DecodeFromChars(text);
}

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetCrypto.Native;

/// <summary>
/// P/Invoke declarations for the zkryptium-ffi native library.
/// Provides BBS (BLS12-381-SHA-256) signature operations per IETF draft-irtf-cfrg-bbs-signatures-10.
/// </summary>
internal static partial class ZkryptiumNative
{
    private const string LibName = "zkryptium_ffi";

    /// <summary>
    /// Generate a BBS keypair from input keying material (>= 32 bytes) and an optional
    /// key_info octet string (pass empty for the spec default of an empty string).
    /// </summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_keygen(
        ReadOnlySpan<byte> ikm_ptr,
        nuint ikm_len,
        ReadOnlySpan<byte> key_info_ptr,
        nuint key_info_len,
        Span<byte> sk_out,
        Span<byte> pk_out);

    /// <summary>Derive a BBS public key (96 bytes) from a secret key (32 bytes).</summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_sk_to_pk(
        ReadOnlySpan<byte> sk_ptr,
        Span<byte> pk_out);

    /// <summary>Sign an ordered set of messages.</summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_sign(
        ReadOnlySpan<byte> sk_ptr,
        ReadOnlySpan<byte> pk_ptr,
        ReadOnlySpan<byte> header_ptr,
        nuint header_len,
        ReadOnlySpan<byte> messages_ptr,
        nuint messages_len,
        Span<byte> sig_out);

    /// <summary>Verify a BBS signature against the full set of messages.</summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_verify(
        ReadOnlySpan<byte> pk_ptr,
        ReadOnlySpan<byte> header_ptr,
        nuint header_len,
        ReadOnlySpan<byte> messages_ptr,
        nuint messages_len,
        ReadOnlySpan<byte> sig_ptr);

    /// <summary>Derive a selective-disclosure zero-knowledge proof.</summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_proof_gen(
        ReadOnlySpan<byte> pk_ptr,
        ReadOnlySpan<byte> sig_ptr,
        ReadOnlySpan<byte> header_ptr,
        nuint header_len,
        ReadOnlySpan<byte> ph_ptr,
        nuint ph_len,
        ReadOnlySpan<byte> messages_ptr,
        nuint messages_len,
        ReadOnlySpan<byte> indices_ptr,
        nuint indices_len,
        Span<byte> proof_out,
        nuint proof_out_cap,
        out nuint proof_out_len);

    /// <summary>Verify a selective-disclosure proof.</summary>
    [LibraryImport(LibName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int bbs_proof_verify(
        ReadOnlySpan<byte> pk_ptr,
        ReadOnlySpan<byte> proof_ptr,
        nuint proof_len,
        ReadOnlySpan<byte> header_ptr,
        nuint header_len,
        ReadOnlySpan<byte> ph_ptr,
        nuint ph_len,
        ReadOnlySpan<byte> disclosed_msgs_ptr,
        nuint disclosed_msgs_len,
        ReadOnlySpan<byte> indices_ptr,
        nuint indices_len);

    // --- Managed helpers for encoding/decoding ---

    /// <summary>
    /// Encode an ordered list of messages into the flat wire format expected by the FFI layer.
    /// Layout: [u32 count][u32 len_0][bytes_0][u32 len_1][bytes_1]...
    /// All u32 values are little-endian.
    /// </summary>
    internal static byte[] EncodeMessages(IReadOnlyList<byte[]> messages)
    {
        var totalSize = 4; // count
        for (var i = 0; i < messages.Count; i++)
        {
            var msg = messages[i];
            if (msg is null)
                throw new ArgumentException($"Message at index {i} is null.", nameof(messages));
            totalSize += 4 + msg.Length;
        }

        var buf = new byte[totalSize];
        var offset = 0;

        BitConverter.TryWriteBytes(buf.AsSpan(offset), (uint)messages.Count);
        offset += 4;

        foreach (var msg in messages)
        {
            BitConverter.TryWriteBytes(buf.AsSpan(offset), (uint)msg.Length);
            offset += 4;
            msg.CopyTo(buf, offset);
            offset += msg.Length;
        }

        return buf;
    }

    /// <summary>
    /// Encode a list of indices into the flat wire format expected by the FFI layer.
    /// Layout: [u32 count][u32 idx_0][u32 idx_1]...
    /// All u32 values are little-endian.
    /// </summary>
    internal static byte[] EncodeIndices(IReadOnlyList<int> indices)
    {
        var buf = new byte[4 + indices.Count * 4];
        var offset = 0;

        BitConverter.TryWriteBytes(buf.AsSpan(offset), (uint)indices.Count);
        offset += 4;

        foreach (var idx in indices)
        {
            BitConverter.TryWriteBytes(buf.AsSpan(offset), (uint)idx);
            offset += 4;
        }

        return buf;
    }
}

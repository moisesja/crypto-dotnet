using System.Security.Cryptography;
using NetCrypto.Native;

namespace NetCrypto;

/// <summary>
/// BBS signature operations using BLS12-381-SHA-256 (IETF draft-irtf-cfrg-bbs-signatures-10).
/// Delegates to the zkryptium-ffi native library via P/Invoke.
/// </summary>
public sealed class DefaultBbsCryptoProvider : IBbsCryptoProvider
{
    private const int SecretKeySize = 32;
    private const int PublicKeySize = 96;
    private const int SignatureSize = 80;

    // BLS12-381-SHA-256 proof size (IETF draft-10):
    //   proof_len = 3 * point_len + scalar_len * (undisclosed + 4)
    //   where point_len = 48, scalar_len = 32 (i.e. 272 + 32*undisclosed bytes).
    // We allocate the buffer generously off the total message count (always >= the
    // exact size for any reveal pattern) so the call is robust to draft/library drift;
    // the FFI writes the true length back via its out_len parameter.
    private const int ProofPointOverhead = 3 * 48;   // 144
    private const int ProofScalarSize = 32;
    private const int ProofScalarSlack = 8;          // covers the 4 fixed scalars + margin

    private static readonly bool NativeAvailable;
    private static readonly Exception? NativeLoadError;

    static DefaultBbsCryptoProvider()
    {
        try
        {
            // Probe for the native library by calling a trivial function.
            // bbs_sk_to_pk with empty input will return -1 (error) but that's fine —
            // we only care that the DLL loaded and the entry point resolved.
            ZkryptiumNative.bbs_sk_to_pk(ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
            NativeAvailable = true;
        }
        catch (Exception ex) when (
            ex is DllNotFoundException          // library not present for this RID
            or EntryPointNotFoundException      // wrong/older library: a symbol is missing
            or BadImageFormatException)         // architecture/format mismatch
        {
            // Treat a missing library OR an incompatible/partial one as unavailable so
            // operations surface BbsUnavailableException rather than a raw native error.
            NativeAvailable = false;
            NativeLoadError = ex;
        }
        catch
        {
            // Any other exception means the library loaded and the entry point resolved
            // but the call itself returned an error code, which is fine for a probe.
            NativeAvailable = true;
        }
    }

    /// <summary>
    /// Create a provider for the given BBS ciphersuite.
    /// </summary>
    /// <param name="ciphersuite">The BBS ciphersuite to operate with. Only
    /// <see cref="BbsCiphersuite.Bls12381Sha256"/> is supported in v1.</param>
    /// <exception cref="NotSupportedException">If <paramref name="ciphersuite"/> is not a
    /// supported suite.</exception>
    public DefaultBbsCryptoProvider(BbsCiphersuite ciphersuite = BbsCiphersuite.Bls12381Sha256)
    {
        if (ciphersuite != BbsCiphersuite.Bls12381Sha256)
            throw new NotSupportedException(
                $"BBS ciphersuite '{ciphersuite}' is not supported. " +
                $"Only '{BbsCiphersuite.Bls12381Sha256}' is available.");
        Ciphersuite = ciphersuite;
    }

    /// <inheritdoc />
    public BbsCiphersuite Ciphersuite { get; }

    /// <inheritdoc />
    public bool IsAvailable => NativeAvailable;

    private static void EnsureNativeAvailable()
    {
        if (!NativeAvailable)
            throw new BbsUnavailableException(
                "BBS native library (zkryptium_ffi) not found for this platform. " +
                "Pre-built binaries ship in the NetCrypto package for osx-arm64, osx-x64, " +
                "linux-x64, linux-arm64, and win-x64. " +
                "See the README for the supported BBS-absent mode.",
                NativeLoadError);
    }

    /// <inheritdoc />
    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        EnsureNativeAvailable();

        if (privateKey.Length != SecretKeySize)
            throw new ArgumentException($"BBS+ secret key must be {SecretKeySize} bytes.", nameof(privateKey));
        if (messages.Count == 0)
            throw new ArgumentException("At least one message is required.", nameof(messages));

        // Derive the public key from the secret key
        Span<byte> pk = stackalloc byte[PublicKeySize];
        var rc = ZkryptiumNative.bbs_sk_to_pk(privateKey, pk);
        if (rc != 0)
            throw new CryptographicException("Failed to derive BBS+ public key from secret key.");

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);
        Span<byte> signature = stackalloc byte[SignatureSize];

        rc = ZkryptiumNative.bbs_sign(
            privateKey, pk,
            ReadOnlySpan<byte>.Empty, 0,
            encodedMessages, (nuint)encodedMessages.Length,
            signature);

        if (rc != 0)
            throw new CryptographicException("BBS+ signing failed.");

        return signature.ToArray();
    }

    /// <inheritdoc />
    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        EnsureNativeAvailable();

        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));
        if (signature.Length != SignatureSize)
            return false;

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);

        var rc = ZkryptiumNative.bbs_verify(
            publicKey,
            ReadOnlySpan<byte>.Empty, 0,
            encodedMessages, (nuint)encodedMessages.Length,
            signature);

        return rc == 0;
    }

    /// <inheritdoc />
    public byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(revealedIndices);
        EnsureNativeAvailable();

        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));
        if (signature.Length != SignatureSize)
            throw new ArgumentException($"BBS+ signature must be {SignatureSize} bytes.", nameof(signature));
        if (revealedIndices.Count == 0)
            throw new ArgumentException("At least one revealed index is required.", nameof(revealedIndices));
        // Validate indices on the managed side so a bad index raises a clear argument exception
        // rather than being cast to a huge uint at the FFI boundary and surfacing as an opaque
        // CryptographicException (NFR-3); it also keeps invalid indices from depending on
        // third-party checks inside the native library. Draft-10 proof_gen requires the
        // disclosed indexes to be distinct, so duplicates are rejected rather than forwarded.
        var seen = new bool[messages.Count];
        foreach (var index in revealedIndices)
        {
            if (index < 0 || index >= messages.Count)
                throw new ArgumentOutOfRangeException(nameof(revealedIndices),
                    $"Revealed index {index} is out of range for {messages.Count} message(s).");
            if (seen[index])
                throw new ArgumentException($"Revealed index {index} is duplicated.", nameof(revealedIndices));
            seen[index] = true;
        }

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);
        var encodedIndices = ZkryptiumNative.EncodeIndices(revealedIndices);

        // Allocate off the total message count with slack: an upper bound for the proof
        // size under any reveal pattern (undisclosed <= messages.Count). The FFI writes
        // the actual length into proofLen.
        var proofBufSize = ProofPointOverhead + ProofScalarSize * (messages.Count + ProofScalarSlack);
        var proofBuf = new byte[proofBufSize];

        var rc = ZkryptiumNative.bbs_proof_gen(
            publicKey,
            signature,
            ReadOnlySpan<byte>.Empty, 0,
            nonce, (nuint)nonce.Length,
            encodedMessages, (nuint)encodedMessages.Length,
            encodedIndices, (nuint)encodedIndices.Length,
            proofBuf, (nuint)proofBuf.Length,
            out var proofLen);

        if (rc != 0)
            throw new CryptographicException("BBS+ proof generation failed.");

        return proofBuf.AsSpan(0, (int)proofLen).ToArray();
    }

    /// <inheritdoc />
    public bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(revealedMessages);
        ArgumentNullException.ThrowIfNull(revealedIndices);
        EnsureNativeAvailable();

        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));

        var encodedMessages = ZkryptiumNative.EncodeMessages(revealedMessages);
        var encodedIndices = ZkryptiumNative.EncodeIndices(revealedIndices);

        var rc = ZkryptiumNative.bbs_proof_verify(
            publicKey,
            proof, (nuint)proof.Length,
            ReadOnlySpan<byte>.Empty, 0,
            nonce, (nuint)nonce.Length,
            encodedMessages, (nuint)encodedMessages.Length,
            encodedIndices, (nuint)encodedIndices.Length);

        return rc == 0;
    }
}

namespace NetCrypto;

/// <summary>
/// The signing interface used by all DID method implementations.
/// Abstracts away whether the private key is in-memory or in a secure enclave.
/// </summary>
public interface ISigner
{
    KeyType KeyType { get; }

    /// <summary>The public key bytes (always available, even for HSM-backed signers).</summary>
    ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")</summary>
    string MultibasePublicKey { get; }

    /// <summary>
    /// Sign data. For HSM-backed signers, this delegates to the secure enclave
    /// without the private key ever leaving the device.
    /// </summary>
    Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
}

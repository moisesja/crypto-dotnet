using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using NetCid;

namespace NetCrypto;

/// <summary>A cryptographic key pair holding both public and private key material.</summary>
/// <remarks>
/// <para>
/// Disposing a key pair deterministically zeroizes its key material (via
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>) instead of leaving it on the managed heap
/// until garbage collection. The canonical private-key copy is held in a pinned allocation so the
/// GC cannot duplicate the secret while compacting the heap before the wipe runs. After
/// <see cref="Dispose"/>, any access to key material throws <see cref="ObjectDisposedException"/>.
/// Callers that never dispose keep the pre-1.2.0 behavior unchanged.
/// </para>
/// <para>
/// <b>Best-effort caveat.</b> Deterministic zeroization in managed memory shrinks the exposure
/// window; it cannot make it zero. JIT spills, copies handed to callers (see
/// <see cref="PrivateKey"/>), and strings (e.g. JWK <c>d</c> values from
/// <see cref="ToPrivateJwk"/>) are outside this type's control — the same caveat under which
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/> itself operates. Prefer
/// <see cref="WithPrivateKey{T}"/>, which exposes the secret as a span without creating a copy.
/// </para>
/// </remarks>
public sealed class KeyPair : IDisposable
{
    // Serializes every read of the backing key material against the Dispose-time wipe, so a
    // concurrent Dispose can never zero a buffer that a reader/borrow is mid-read: the reader
    // either completes first, or observes the disposed flag and throws — never sees a half-wiped
    // secret (which would silently produce a wrong signature). Held across the WithPrivateKey
    // callback so disposal deterministically waits for an in-flight borrow to finish.
    private readonly object _gate = new();
    private readonly byte[] _publicKey = [];
    private readonly byte[] _privateKey = [];
    private bool _disposed;

    /// <summary>Creates an empty key pair; initialize it via the required properties.</summary>
    public KeyPair()
    {
    }

    /// <summary>
    /// Internal copy-free-in construction path: copies the private key straight from a span into
    /// the pinned backing store, so generator code never mints an intermediate heap array that the
    /// public init accessor would clone and orphan unzeroed.
    /// </summary>
    [SetsRequiredMembers]
#pragma warning disable CS8618 // PublicKey/PrivateKey are satisfied via their backing fields, assigned below
    internal KeyPair(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
#pragma warning restore CS8618
    {
        KeyType = keyType;
        _publicKey = publicKey.ToArray();
        _privateKey = AllocatePinned(privateKey);
    }

    /// <summary>The type of the key pair.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// The raw public key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this key pair.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public required byte[] PublicKey
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return (byte[])_publicKey.Clone();
            }
        }
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _publicKey = (byte[])value.Clone();
        }
    }

    /// <summary>
    /// The raw private key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this key pair.
    /// </summary>
    /// <remarks>
    /// Each access returns a fresh copy of the secret, so every read leaves another unzeroed
    /// array on the managed heap until collected — the caller owns wiping it with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>. Prefer <see cref="WithPrivateKey{T}"/>,
    /// which lends the secret as a <see cref="ReadOnlySpan{T}"/> without creating a copy, and
    /// <see cref="Dispose"/> to destroy the key when it is no longer needed.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public required byte[] PrivateKey
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return (byte[])_privateKey.Clone();
            }
        }
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _privateKey = AllocatePinned(value);
        }
    }

    /// <summary>
    /// Lends the private key to <paramref name="use"/> as a <see cref="ReadOnlySpan{T}"/> over the
    /// canonical pinned copy — no heap copy is created, so there is nothing new to zeroize.
    /// </summary>
    /// <remarks>
    /// The span is only valid for the duration of the callback (the ref-struct rules prevent it
    /// from escaping). If the callback copies bytes out of the span, the callback owns wiping that
    /// copy. A concurrent <see cref="Dispose"/> cannot wipe the secret mid-borrow: disposal blocks
    /// until the callback returns, and a borrow that starts after disposal throws
    /// <see cref="ObjectDisposedException"/> instead of reading zeroed bytes. Keep the callback
    /// short — it runs under a per-instance lock, so borrows of the same key pair are serialized
    /// and a disposal waits behind them. For the same reason, avoid borrowing or disposing a
    /// <em>different</em> key pair from inside the callback: two threads nesting borrows of the
    /// same two pairs in opposite orders would deadlock.
    /// </remarks>
    /// <typeparam name="T">The callback's result type.</typeparam>
    /// <param name="use">Callback that receives the private key bytes.</param>
    /// <returns>The value returned by <paramref name="use"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="use"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public T WithPrivateKey<T>(Func<ReadOnlySpan<byte>, T> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return use(_privateKey);
        }
    }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")
    /// </summary>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public string MultibasePublicKey
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), _publicKey), MultibaseEncoding.Base58Btc);
            }
        }
    }

    /// <summary>JWK representation of the public key.</summary>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public JsonWebKey ToPublicJwk() => JwkConverter.ToPublicJwk(this);

    /// <summary>JWK representation of the key pair (includes private key material).</summary>
    /// <remarks>
    /// The returned JWK carries the private key as a base64url <em>string</em>, which managed code
    /// cannot wipe. Only take this egress when a serialized private JWK is genuinely required.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The key pair has been disposed.</exception>
    public JsonWebKey ToPrivateJwk() => JwkConverter.ToPrivateJwk(this);

    /// <summary>
    /// Deterministically zeroizes the key material (public and private) and marks the instance
    /// disposed. Idempotent; subsequent key-material access throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        // Under _gate so the wipe cannot interleave with a concurrent read/borrow: a reader either
        // finishes before this runs, or sees _disposed and throws — never reads a half-wiped buffer.
        lock (_gate)
        {
            if (_disposed)
                return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_privateKey);
            CryptographicOperations.ZeroMemory(_publicKey);
        }
    }

    // Pinned so the canonical secret cannot be relocated (and thereby duplicated) by a compacting
    // GC between construction and the Dispose-time wipe.
    private static byte[] AllocatePinned(ReadOnlySpan<byte> source)
    {
        var pinned = GC.AllocateArray<byte>(source.Length, pinned: true);
        source.CopyTo(pinned);
        return pinned;
    }
}

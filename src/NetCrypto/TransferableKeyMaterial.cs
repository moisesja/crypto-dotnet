using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// Reads key material out of a <see cref="TransferableKeyMaterial"/> exactly once, at the
/// moment a store accepts it. Internal by design: the whole point of the type is that no
/// caller-reachable read path exists.
/// </summary>
/// <typeparam name="T">The reader's result type.</typeparam>
/// <param name="keyType">The type of the transferred key.</param>
/// <param name="publicKey">The raw public key bytes.</param>
/// <param name="privateKey">The raw private key bytes, valid only for the duration of the call.</param>
/// <returns>Whatever the reader produces — in practice, the store's own key representation.</returns>
internal delegate T KeyMaterialReader<out T>(
    KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey);

/// <summary>
/// A one-way, single-use owner of private key material handed across a custody boundary
/// during import.
/// </summary>
/// <remarks>
/// <para>
/// Import is the one operation that moves a secret <em>into</em> a store, and it is the one
/// place where the store's defining property — private material is never extractable — can be
/// undermined by the caller's own object. Handing a <see cref="KeyPair"/> to a store leaves the
/// caller holding a live export surface: <see cref="KeyPair.PrivateKey"/> clones the secret to
/// the heap on every read, so the material remains readable after the store "owns" it. This
/// type closes that: it has <b>no getter, no formatting, and no export surface</b> for private
/// material at all.
/// </para>
/// <para>
/// The secret lives in a pinned buffer (the FR-18 zeroization infrastructure, so a compacting
/// GC cannot duplicate it before the wipe), is read exactly once through an internal accessor
/// at the instant the store accepts it, and is then zeroized while the instance latches
/// permanently unreadable. Every member except <see cref="IsConsumed"/> throws
/// <see cref="ObjectDisposedException"/> afterwards.
/// </para>
/// <para>
/// <b>Failure before acceptance leaves it usable.</b> A validation failure, an idempotency
/// conflict, a cancellation, or any definite failure that happens <em>before</em> the store
/// commits leaves the material intact so the caller can retry once. Only acceptance consumes
/// it — including acceptance whose acknowledgement was lost, which is why an
/// <see cref="KeyStoreError.OutcomeUnknown"/> import is reconciled through
/// <see cref="ICapableKeyStore.GetMutationOutcomeAsync"/> and never by resubmitting material.
/// </para>
/// <para>
/// Import support is optional. A store that does not advertise
/// <see cref="KeyStoreOperation.Import"/> refuses with <see cref="KeyStoreError.Unsupported"/>
/// and never sees the material.
/// </para>
/// <para>
/// <b>Best-effort caveat.</b> As with <see cref="KeyPair"/>, deterministic zeroization in
/// managed memory shrinks the exposure window but cannot make it zero; JIT spills and copies
/// made by whatever produced the source bytes are outside this type's control. There is
/// deliberately <em>no finalizer</em>, matching <see cref="KeyPair"/>: an instance that is
/// neither imported nor disposed is collected with its buffer intact, so wrap it in
/// <c>using</c> rather than relying on the GC.
/// </para>
/// </remarks>
public sealed class TransferableKeyMaterial : IDisposable
{
    // Serializes consumption against a concurrent Dispose, so the single-read guarantee holds
    // under races: a second thread either loses the CAS on _consumed and observes the disposed
    // state, or completes first — never reads a half-wiped secret.
    private readonly object _gate = new();
    private readonly byte[] _publicKey;
    private readonly byte[] _privateKey;
    private readonly KeyType _keyType;
    private bool _consumed;

    private TransferableKeyMaterial(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        _keyType = keyType;
        _publicKey = publicKey.ToArray();
        _privateKey = AllocatePinned(privateKey);
    }

    /// <summary>
    /// Copies the material out of a <see cref="KeyPair"/> into a transferable owner.
    /// </summary>
    /// <remarks>
    /// The copy is taken through <see cref="KeyPair.WithPrivateKey{T}"/>, so no intermediate
    /// unzeroed heap array is minted along the way. The source key pair is <em>not</em>
    /// disposed — it is the caller's object and disposing it here would be a surprising side
    /// effect — so dispose it yourself once the transfer object exists, to avoid leaving a
    /// second live copy of the secret behind.
    /// </remarks>
    /// <param name="keyPair">The key pair to transfer. Must not be disposed.</param>
    /// <returns>A fresh, unconsumed transfer object owning its own copy of the material.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keyPair"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="keyPair"/> has been disposed.</exception>
    public static TransferableKeyMaterial FromKeyPair(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var publicKey = keyPair.PublicKey;
        var keyType = keyPair.KeyType;
        return keyPair.WithPrivateKey(
            privateKey => new TransferableKeyMaterial(keyType, publicKey, privateKey));
    }

    /// <summary>
    /// Copies raw key material into a transferable owner.
    /// </summary>
    /// <remarks>
    /// The caller still owns wiping whatever buffer <paramref name="privateKey"/> points at;
    /// this type can only guarantee the copy it holds.
    /// </remarks>
    /// <remarks>
    /// Both lengths are checked against <paramref name="keyType"/> here, at the entry point. A
    /// wrong-length key that is only rejected later has already crossed the custody boundary:
    /// the store would hold it, publish its metadata as a real key, and hand out a signer for
    /// it, with the failure surfacing from a backend at first use — which is precisely the
    /// "first use is the probe" problem this contract exists to remove (NFR-3).
    /// </remarks>
    /// <param name="keyType">The type of the key being transferred.</param>
    /// <param name="publicKey">
    /// The raw public key bytes, in the canonical encoding for <paramref name="keyType"/>
    /// (compressed SEC1 point for the EC types).
    /// </param>
    /// <param name="privateKey">The raw private key bytes.</param>
    /// <returns>A fresh, unconsumed transfer object owning its own copy of the material.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="keyType"/> is not a defined <see cref="NetCrypto.KeyType"/>, or either key
    /// is not the length that key type requires.
    /// </exception>
    public static TransferableKeyMaterial FromRawKey(
        KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        if (!Enum.IsDefined(keyType))
            throw new ArgumentException($"Key type {(int)keyType} is not a defined {nameof(NetCrypto.KeyType)}.", nameof(keyType));
        if (!keyType.IsValidKeyLength(publicKey.Length))
            throw new ArgumentException(
                $"A {keyType} public key must be the canonical encoding for that key type; got {publicKey.Length} bytes.",
                nameof(publicKey));
        RawKeyGuard.RequireLength(
            privateKey, PrivateKeyLength(keyType), nameof(privateKey), $"A {keyType} private key");

        return new TransferableKeyMaterial(keyType, publicKey, privateKey);
    }

    // The raw scalar/seed size each key type stores, matching what IKeyGenerator produces.
    private static int PrivateKeyLength(KeyType keyType) => keyType switch
    {
        KeyType.P384 => 48,
        KeyType.P521 => 66,
        _ => 32, // Ed25519, X25519, P-256, secp256k1, and both BLS12-381 variants
    };

    /// <summary>
    /// The type of the key being transferred — public metadata a store reads to decide whether
    /// it advertises <see cref="KeyStoreOperation.Import"/> for this key at all.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The material has been consumed or disposed.</exception>
    public KeyType KeyType
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_consumed, this);
                return _keyType;
            }
        }
    }

    /// <summary>
    /// The raw public key bytes, defensively copied. Public material only — there is no
    /// counterpart for the private key, by design.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The material has been consumed or disposed.</exception>
    public byte[] PublicKey
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_consumed, this);
                return (byte[])_publicKey.Clone();
            }
        }
    }

    /// <summary>
    /// Whether the material has been consumed (by an accepted import) or disposed. The only
    /// member that keeps working afterwards, so a caller can tell "the store took it" from
    /// "the store refused it and I may retry" without provoking an exception.
    /// </summary>
    public bool IsConsumed
    {
        get
        {
            lock (_gate)
                return _consumed;
        }
    }

    /// <summary>
    /// Zeroizes the material without transferring it, and latches this instance unreadable.
    /// Idempotent, and safe to call on already-consumed material — so
    /// <c>using var material = …</c> is the correct way to guarantee the secret is destroyed
    /// whether or not the import succeeded.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_consumed)
                return;
            _consumed = true;
            CryptographicOperations.ZeroMemory(_privateKey);
            CryptographicOperations.ZeroMemory(_publicKey);
        }
    }

    /// <summary>
    /// How many times the private material has actually been read. The contract is that this
    /// never exceeds one, and that a replayed import leaves it at zero — a counting accessor,
    /// so "the store never re-reads material" is an assertion rather than a claim.
    /// </summary>
    internal int ReadCount { get; private set; }

    /// <summary>
    /// The store-side acceptance path: reads the material exactly once, then zeroizes it and
    /// latches this instance unreadable — atomically, so the "readable once" guarantee holds
    /// even if the reader throws.
    /// </summary>
    internal T Consume<T>(KeyMaterialReader<T> read)
    {
        ArgumentNullException.ThrowIfNull(read);

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_consumed, this);
            try
            {
                ReadCount++;
                return read(_keyType, _publicKey, _privateKey);
            }
            finally
            {
                // Latch inside the finally: material that has been exposed to a store is spent
                // whether or not the store's own ingestion completed. Anything else would let a
                // failing reader hand the caller a second read.
                _consumed = true;
                CryptographicOperations.ZeroMemory(_privateKey);
                CryptographicOperations.ZeroMemory(_publicKey);
            }
        }
    }

    /// <summary>
    /// Destroys the material without reading it — used when a store recognizes a replayed
    /// import and therefore must not read the secret at all, yet should not leave a live copy
    /// with the caller either. Distinct from <see cref="Consume{T}"/>: nothing is read.
    /// </summary>
    internal void Discard() => Dispose();

    // Pinned so the canonical secret cannot be relocated (and thereby duplicated) by a
    // compacting GC between construction and the wipe — same guarantee KeyPair makes.
    private static byte[] AllocatePinned(ReadOnlySpan<byte> source)
    {
        var pinned = GC.AllocateArray<byte>(source.Length, pinned: true);
        source.CopyTo(pinned);
        return pinned;
    }
}

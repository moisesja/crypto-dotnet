using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// Reads key material out of a <see cref="TransferableKeyMaterial"/> exactly once, at the
/// moment a store accepts it. This is the store-side acceptance path — the one sanctioned
/// read the type exists to gate. It is public so that key stores implemented outside this
/// assembly (an HSM, KMS, or Vault-backed <see cref="ICapableKeyStore"/>) can accept imports
/// at all (#28); the once-only latch and zeroization in
/// <see cref="TransferableKeyMaterial.Consume{T}"/> hold for every caller.
/// </summary>
/// <remarks>
/// <para>
/// Two duties belong to the reader, not to this type. It must not let
/// <paramref name="privateKey"/>, nor any pointer or reference into it, outlive the call. The
/// buffer is zeroized the moment the call returns, so a normal copy taken inside the call is the
/// only safe way to keep the value, and that copy is the reader's own to wipe. A retained
/// pointer is worse than useless: it reads zeros immediately, but the pinned buffer's address is
/// later reused for other materials' live secrets, so a stale pointer becomes a read into
/// somebody else's key. And the reader must not call back into the material it is reading: a
/// nested <see cref="TransferableKeyMaterial.Consume{T}"/> is refused with
/// <see cref="InvalidOperationException"/>.
/// </para>
/// </remarks>
/// <typeparam name="T">The reader's result type.</typeparam>
/// <param name="keyType">The type of the transferred key.</param>
/// <param name="publicKey">The raw public key bytes.</param>
/// <param name="privateKey">The raw private key bytes, valid only for the duration of the call.</param>
/// <returns>Whatever the reader produces — in practice, the store's own key representation.</returns>
public delegate T KeyMaterialReader<out T>(
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
/// GC cannot duplicate it before the wipe), is read exactly once through
/// <see cref="Consume{T}"/> at the instant the store accepts it, and is then zeroized while the
/// instance latches permanently unreadable. The data-access members <see cref="KeyType"/>,
/// <see cref="PublicKey"/>, and <see cref="Consume{T}"/> throw
/// <see cref="ObjectDisposedException"/> afterwards; <see cref="IsConsumed"/> remains readable,
/// and <see cref="Dispose"/> / <see cref="Discard"/> remain idempotent and non-throwing.
/// </para>
/// <para>
/// <b>A live instance is a bearer secret.</b> <see cref="Consume{T}"/> is public so that a store
/// written outside this assembly can accept an import at all (#28), which means the read is
/// available to <em>whoever holds the instance</em> — including anything a
/// <see cref="KeyImportRequest"/> is routed through on its way to the store, such as a DI
/// decorator or a logging wrapper. What the type guarantees is that the read happens at most
/// once and destroys the material; it cannot guarantee <em>who</em> performs it. Hand the
/// instance straight to the store you mean to trust, and construct it as late as possible.
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
    // True for the span of a reader callback. Set and cleared under _gate, but the reader runs
    // with _gate released, so this is how a concurrent Consume or Dispose on another thread
    // learns a read is live: Consume refuses, Dispose defers its wipe to the reader's finally.
    private bool _reading;

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
    /// Both key lengths are validated before a transfer owner is created, matching
    /// <see cref="FromRawKey"/>. In particular, a malformed private key is rejected while it is
    /// only borrowed from <paramref name="keyPair"/>, before it can cross the single-read custody
    /// boundary.
    /// </remarks>
    /// <param name="keyPair">The key pair to transfer. Must not be disposed.</param>
    /// <returns>A fresh, unconsumed transfer object owning its own copy of the material.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keyPair"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">
    /// The pair's key type is not defined, or either key is not the length that key type requires.
    /// <see cref="ArgumentException.ParamName"/> identifies the offending component as
    /// <c>keyType</c>, <c>publicKey</c>, or <c>privateKey</c>, respectively, rather than naming the
    /// containing <paramref name="keyPair"/> argument.
    /// </exception>
    /// <exception cref="ObjectDisposedException"><paramref name="keyPair"/> has been disposed.</exception>
    public static TransferableKeyMaterial FromKeyPair(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var publicKey = keyPair.PublicKey;
        var keyType = keyPair.KeyType;
        ValidateKeyTypeAndPublicKey(keyType, publicKey);

        return keyPair.WithPrivateKey(
            privateKey =>
            {
                ValidatePrivateKey(keyType, privateKey);
                return new TransferableKeyMaterial(keyType, publicKey, privateKey);
            });
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
        ValidateKeyTypeAndPublicKey(keyType, publicKey);
        ValidatePrivateKey(keyType, privateKey);

        return new TransferableKeyMaterial(keyType, publicKey, privateKey);
    }

    private static void ValidateKeyTypeAndPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey)
    {
        if (!Enum.IsDefined(keyType))
            throw new ArgumentException($"Key type {(int)keyType} is not a defined {nameof(NetCrypto.KeyType)}.", nameof(keyType));
        if (!keyType.IsValidKeyLength(publicKey.Length))
            throw new ArgumentException(
                $"A {keyType} public key must be the canonical encoding for that key type; got {publicKey.Length} bytes.",
                nameof(publicKey));
    }

    private static void ValidatePrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey)
    {
        RawKeyGuard.RequireLength(
            privateKey, PrivateKeyLength(keyType), nameof(privateKey), $"A {keyType} private key");
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
    /// <remarks>
    /// If a <see cref="Consume{T}"/> read is in flight on another thread, the latch is still
    /// immediate — <see cref="IsConsumed"/> reports <c>true</c> and the data-access members
    /// <see cref="KeyType"/>, <see cref="PublicKey"/>, and <see cref="Consume{T}"/> throw
    /// <see cref="ObjectDisposedException"/> from the moment this returns — but the physical wipe
    /// completes with that read: zeroing mid-read would blank the buffers the reader is borrowing
    /// and hand the accepting store an all-zero key. <see cref="Dispose"/> and
    /// <see cref="Discard"/> remain idempotent and non-throwing.
    /// </remarks>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_consumed)
                return;
            _consumed = true;
            // A read is live (this lock is free because Consume runs the reader with _gate
            // released — whether the caller is that reader, re-entering, or another thread).
            // The latch above still takes effect immediately: IsConsumed reports true and the
            // data-access members throw ObjectDisposedException from this point on, exactly as
            // the docs promise. Dispose and Discard remain idempotent. Only the PHYSICAL wipe
            // defers — zeroing now would blank the buffers the in-flight read is still borrowing
            // and hand the accepting store an all-zero key. Consume's finally performs the wipe
            // on the way out regardless.
            if (_reading)
                return;
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
    /// <remarks>
    /// <para>
    /// Public for out-of-assembly store implementations (#28). Every guarantee — once-only,
    /// zeroize, the <see cref="IsConsumed"/> latch — is enforced by this method body and so
    /// holds for every caller; see the type's remarks for what widening the accessibility does
    /// and does not change. A store that copies the spans owns its copy's zeroization.
    /// </para>
    /// <para>
    /// <b>The reader runs outside the instance's lock,</b> so a reader is free to take its own
    /// locks without splicing this type into its lock order — a store whose reader records the
    /// key under the store's mutex, while another thread disposes the material under that same
    /// mutex, does not deadlock.
    /// </para>
    /// <para>
    /// <b>The reader must not re-enter.</b> A nested <see cref="Consume{T}"/> on this instance —
    /// or a concurrent one from another thread while a read is live — is refused rather than
    /// served: it would be a second read of one-read material and would race the wipe against
    /// the buffers the live read is borrowing. Reading <see cref="KeyType"/> or
    /// <see cref="PublicKey"/> from inside a reader is fine, and a <see cref="Dispose"/> that
    /// arrives during a read latches the instance immediately while its physical wipe is
    /// performed by this call on the way out.
    /// </para>
    /// <para>
    /// An exception thrown by the reader propagates to the caller <b>unmodified</b> — the
    /// reader is the store's own code, so its failures are the store's to classify; this method
    /// adds no wrapping and no translation. The consumption latch and the wipe happen
    /// regardless.
    /// </para>
    /// </remarks>
    /// <typeparam name="T">The reader's result type — in practice the store's own key handle.</typeparam>
    /// <param name="read">The store's acceptance path. Invoked at most once — exactly once when this method does not throw before the read.</param>
    /// <returns>Whatever <paramref name="read"/> produced.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="read"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">The material has already been consumed or disposed.</exception>
    /// <exception cref="InvalidOperationException">
    /// Another read of this instance is already in progress — a re-entrant call from inside the
    /// reader, or a concurrent call from another thread. Note <see cref="ObjectDisposedException"/>
    /// derives from this type, and both refusals are terminal (the material is single-use), so a
    /// caller that needs to tell them apart must test for <see cref="ObjectDisposedException"/>
    /// first — neither is a "busy, retry later" signal.
    /// </exception>
    public T Consume<T>(KeyMaterialReader<T> read)
    {
        ArgumentNullException.ThrowIfNull(read);

        // Claim the single read under the lock, then run the reader OUTSIDE it. The reader is
        // now arbitrary out-of-assembly code (#28), and a store's reader will take the store's
        // own lock; holding _gate across that call would splice _gate into the application's
        // lock order and let an ordinary two-lock cycle deadlock — with the secret then stranded
        // un-wiped in the pinned buffer. So _gate guards only the state transitions and the
        // wipe, never a call into caller code.
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_consumed, this);
            // FR-7b rule 14: no reader may re-enter the read it is inside. Because the claim
            // above is exclusive, this same flag also turns away a concurrent Consume from
            // another thread — both would be a second read of the one-read material, and both
            // would race the wipe against the live borrow. Refused, not blocked: blocking here
            // would mean waiting on a lock the in-flight reader's own lock may depend on.
            if (_reading)
                throw new InvalidOperationException(
                    "A key material reader re-entered Consume while a read of this material was " +
                    "already in progress. The read-once guarantee and the buffers borrowed by " +
                    "that read both depend on the reader not calling back into the material.");

            _reading = true;
            ReadCount++;
        }

        try
        {
            return read(_keyType, _publicKey, _privateKey);
        }
        finally
        {
            lock (_gate)
            {
                _reading = false;
                // Latch here, not before the read: material that has been exposed to a store is
                // spent whether or not the store's own ingestion completed. Anything else would
                // let a failing reader hand the caller a second read. A Dispose that arrived
                // during the read deferred to exactly this wipe.
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
    /// Public alongside <see cref="Consume{T}"/> (#28) so external stores can honor the
    /// replay rule.
    /// </summary>
    /// <remarks>
    /// An alias for <see cref="Dispose"/>, and idempotent and non-throwing on the same terms:
    /// safe on already-consumed material, latching immediately even against an in-flight read
    /// (whose completion performs the physical wipe).
    /// </remarks>
    public void Discard() => Dispose();

    // Pinned so the canonical secret cannot be relocated (and thereby duplicated) by a
    // compacting GC between construction and the wipe — same guarantee KeyPair makes.
    private static byte[] AllocatePinned(ReadOnlySpan<byte> source)
    {
        var pinned = GC.AllocateArray<byte>(source.Length, pinned: true);
        source.CopyTo(pinned);
        return pinned;
    }
}

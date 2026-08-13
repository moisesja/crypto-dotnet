namespace NetCrypto;

/// <summary>
/// The kinds of state-changing operation a capable key store records under an idempotency key.
/// </summary>
/// <remarks>
/// Mutation identity is the triple
/// <c>(<see cref="KeyStoreNamespaceId"/>, <see cref="KeyMutationKind"/>, <see cref="KeyOperationId"/>)</c>,
/// so the same operation id may be used once per kind, and never collides across namespaces.
/// </remarks>
public enum KeyMutationKind
{
    /// <summary>Creation of a new key inside the store.</summary>
    Generate,

    /// <summary>Transfer of externally-generated key material into the store.</summary>
    Import,

    /// <summary>Destruction of a stored key.</summary>
    Delete,
}

/// <summary>The result of a generate or import: what now exists, and whether this call created it.</summary>
/// <param name="Info">Public metadata for the key. Never contains private key material.</param>
/// <param name="InstanceId">The immutable identity of the created key instance.</param>
/// <param name="Replayed">
/// <c>true</c> when this call matched an earlier mutation under the same
/// <see cref="KeyOperationId"/> and returned that original outcome instead of performing a new
/// one. The logical result is the same either way — which is the point — but a caller
/// reconciling an ambiguous retry learns which call actually did the work.
/// <para>
/// A replay reports what the original mutation <em>did</em>, not what exists now: if the key was
/// deleted in between, the replay still describes the key that was created, and
/// <see cref="ICapableKeyStore.GetInfoAsync(string, KeyInstanceId, CancellationToken)"/> is the
/// way to ask whether it is still there.
/// </para>
/// </param>
public sealed record KeyMutationResult(StoredKeyInfo Info, KeyInstanceId InstanceId, bool Replayed)
{
    private readonly StoredKeyInfo _info = Info ?? throw new ArgumentNullException(nameof(Info));

    /// <inheritdoc cref="KeyMutationResult" />
    /// <remarks>
    /// Null-checked on <c>init</c> rather than only in the constructor, because a <c>with</c>
    /// expression skips a property initializer.
    /// </remarks>
    public StoredKeyInfo Info
    {
        get => _info;
        init => _info = value ?? throw new ArgumentNullException(nameof(Info));
    }
}

/// <summary>The result of a delete.</summary>
/// <param name="Deleted">
/// <c>true</c> when a key was destroyed. <c>false</c> when nothing matched — no such alias, or
/// the alias holds a <em>different</em> key instance than the request named, which is not an
/// error but is emphatically not a deletion either.
/// </param>
/// <param name="Replayed">
/// <c>true</c> when this call matched an earlier delete under the same
/// <see cref="KeyOperationId"/> and returned that original outcome.
/// </param>
public sealed record KeyDeleteResult(bool Deleted, bool Replayed);

/// <summary>
/// A durable receipt for one mutation — the record that makes an ambiguous cloud call
/// recoverable.
/// </summary>
/// <remarks>
/// <para>
/// When a mutation returns <see cref="KeyStoreError.OutcomeUnknown"/>, the caller cannot tell
/// whether the backend applied it. The receipt answers that question after the fact, without
/// re-issuing the mutation — which matters most for import, where re-issuing means
/// re-transmitting private key material that may already have been accepted.
/// </para>
/// <para>
/// The taxonomy is closed: <see cref="KeyGeneratedOutcome"/>, <see cref="KeyImportedOutcome"/>,
/// and <see cref="KeyDeletionOutcome"/> are the only forms, one per
/// <see cref="KeyMutationKind"/>.
/// </para>
/// </remarks>
public abstract record KeyMutationOutcome
{
    private protected KeyMutationOutcome(KeyOperationId operationId, KeyMutationKind kind, DateTimeOffset recordedAt)
    {
        OperationId = operationId;
        Kind = kind;
        RecordedAt = recordedAt;
    }

    /// <summary>The idempotency key the mutation was recorded under.</summary>
    public KeyOperationId OperationId { get; }

    /// <summary>Which kind of mutation this receipt describes.</summary>
    public KeyMutationKind Kind { get; }

    /// <summary>
    /// When the store committed the mutation — the store's own clock at commit time, not the
    /// time the receipt was read.
    /// </summary>
    public DateTimeOffset RecordedAt { get; }
}

/// <summary>Receipt for a completed key generation.</summary>
public sealed record KeyGeneratedOutcome : KeyMutationOutcome
{
    /// <summary>Records a completed key generation.</summary>
    /// <param name="operationId">The idempotency key the generation was recorded under.</param>
    /// <param name="recordedAt">When the store committed the generation.</param>
    /// <param name="info">Public metadata for the created key.</param>
    /// <param name="instanceId">The immutable identity of the created key instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is <c>null</c>.</exception>
    public KeyGeneratedOutcome(
        KeyOperationId operationId, DateTimeOffset recordedAt, StoredKeyInfo info, KeyInstanceId instanceId)
        : base(operationId, KeyMutationKind.Generate, recordedAt)
    {
        Info = info ?? throw new ArgumentNullException(nameof(info));
        InstanceId = instanceId;
    }

    /// <summary>Public metadata for the created key. Never contains private key material.</summary>
    public StoredKeyInfo Info { get; }

    /// <summary>The immutable identity of the created key instance.</summary>
    public KeyInstanceId InstanceId { get; }
}

/// <summary>Receipt for a completed key import.</summary>
public sealed record KeyImportedOutcome : KeyMutationOutcome
{
    /// <summary>Records a completed key import.</summary>
    /// <param name="operationId">The idempotency key the import was recorded under.</param>
    /// <param name="recordedAt">When the store committed the import.</param>
    /// <param name="info">Public metadata for the imported key.</param>
    /// <param name="instanceId">The immutable identity of the imported key instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is <c>null</c>.</exception>
    public KeyImportedOutcome(
        KeyOperationId operationId, DateTimeOffset recordedAt, StoredKeyInfo info, KeyInstanceId instanceId)
        : base(operationId, KeyMutationKind.Import, recordedAt)
    {
        Info = info ?? throw new ArgumentNullException(nameof(info));
        InstanceId = instanceId;
    }

    /// <summary>Public metadata for the imported key. Never contains private key material.</summary>
    public StoredKeyInfo Info { get; }

    /// <summary>The immutable identity of the imported key instance.</summary>
    public KeyInstanceId InstanceId { get; }
}

/// <summary>Receipt for a completed delete.</summary>
public sealed record KeyDeletionOutcome : KeyMutationOutcome
{
    /// <summary>Records a completed delete.</summary>
    /// <param name="operationId">The idempotency key the delete was recorded under.</param>
    /// <param name="recordedAt">When the store committed the delete.</param>
    /// <param name="instanceId">The key instance the delete addressed.</param>
    /// <param name="deleted">Whether a key was actually destroyed.</param>
    public KeyDeletionOutcome(
        KeyOperationId operationId, DateTimeOffset recordedAt, KeyInstanceId instanceId, bool deleted)
        : base(operationId, KeyMutationKind.Delete, recordedAt)
    {
        InstanceId = instanceId;
        Deleted = deleted;
    }

    /// <summary>The key instance the delete addressed.</summary>
    public KeyInstanceId InstanceId { get; }

    /// <summary>
    /// Whether a key was actually destroyed, or nothing matched the alias and instance id.
    /// </summary>
    public bool Deleted { get; }
}

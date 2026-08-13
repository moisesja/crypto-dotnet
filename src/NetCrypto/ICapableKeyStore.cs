namespace NetCrypto;

/// <summary>
/// A key store that can describe itself, scope itself, identify its key instances, make its
/// mutations safely retryable, and name the algorithm and encoding of every operation — the
/// contract a production custody backend (cloud KMS, HSM, encrypted software keystore) needs
/// in order to sit behind <see cref="IKeyStore"/> without its consumer inventing a parallel
/// signer surface downstream.
/// </summary>
/// <remarks>
/// <para>
/// This is a purely additive <em>derived</em> interface. <see cref="IKeyStore"/> gains no
/// member, so every existing store implementation, <see cref="ISigner"/>,
/// <see cref="KeyStoreSigner"/>, and <see cref="InMemoryKeyStore"/> caller stays source- and
/// binary-compatible. A store opts in by implementing this interface; a caller opts in by
/// type-testing for it.
/// </para>
/// <para>
/// It also adds no export operation anywhere. Discovery, info, and mutation results expose
/// public material and metadata only — the defining property of a key store is preserved.
/// No KDF and no protocol semantics enter either:
/// <see cref="DeriveSharedSecretAsync(KeyAgreementRequest, CancellationToken)"/> still returns
/// raw Z, and BBS keeps its draft-pinned meaning.
/// </para>
/// <para><b>The contract, beyond the shape:</b></para>
/// <list type="number">
/// <item><description>
/// <b>Discovery honesty is bidirectional.</b> Every advertised
/// <see cref="KeyStoreCapability"/> genuinely works; every unadvertised combination fails with
/// <see cref="KeyStoreError.Unsupported"/> <em>before</em> key creation, signing, or agreement
/// — never a silent downgrade of algorithm, curve, hash, or encoding.
/// </description></item>
/// <item><description>
/// <b>Algorithm ids bind the observable encoding.</b> A request signs the exact supplied bytes
/// under exactly the requested advertised algorithm; a mismatch between the request's algorithm
/// and the addressed key fails before backend work.
/// </description></item>
/// <item><description>
/// <b>Instance identity is immutable and never reused.</b> Generate and import mint a fresh
/// <see cref="KeyInstanceId"/>; delete makes it permanently unusable; re-creating the alias
/// yields a different one, so a stale reference fails instead of silently signing under a
/// different key.
/// </description></item>
/// <item><description>
/// <b>Namespace scoping is least-privilege.</b> An instance sees only its
/// <see cref="NamespaceId"/> — including through the inherited <see cref="IKeyStore"/> members.
/// </description></item>
/// <item><description>
/// <b>Mutations are durably idempotent.</b> Identity is
/// <c>(<see cref="NamespaceId"/>, <see cref="KeyMutationKind"/>, <see cref="KeyOperationId"/>)</c>.
/// Same id and same request replays the original result; same id and a different request is
/// <see cref="KeyStoreError.IdempotencyConflict"/>.
/// </description></item>
/// <item><description>
/// <b>Cancellation never lies.</b> Before irreversible acceptance, cancellation has no effect
/// on state and surfaces as <see cref="OperationCanceledException"/>. After acceptance begins,
/// the call returns success, definite failure, or <see cref="KeyStoreError.OutcomeUnknown"/> —
/// never cancellation as an implied rollback.
/// </description></item>
/// <item><description>
/// <b>Import transfers ownership exactly once</b>, through
/// <see cref="TransferableKeyMaterial"/>, and only where advertised.
/// </description></item>
/// <item><description>
/// <b>Bounds are finite.</b> Every sign, BBS, and agreement capability carries a positive
/// finite <see cref="KeyStoreCapability.MaxInputBytes"/>; oversize input fails before backend
/// work.
/// </description></item>
/// <item><description>
/// <b>Errors are portable.</b> Routed operations surface <see cref="KeyStoreException"/>; no
/// vendor SDK exception type leaks. Argument faults remain parameter-named
/// <see cref="ArgumentException"/>s, and the inherited <see cref="IKeyStore"/> members keep
/// their documented BCL exceptions.
/// </description></item>
/// </list>
/// </remarks>
public interface ICapableKeyStore : IKeyStore, IKeyStoreCapabilityProvider
{
    /// <summary>
    /// The least-privilege scope this instance operates within. Every operation — including
    /// the inherited <see cref="IKeyStore"/> members — is confined to it, and it participates
    /// in mutation identity so the same <see cref="KeyOperationId"/> cannot collide across
    /// namespaces on one backend.
    /// </summary>
    KeyStoreNamespaceId NamespaceId { get; }

    /// <summary>Creates a new key inside the store, idempotently.</summary>
    /// <param name="request">The generation request, carrying its idempotency key.</param>
    /// <param name="ct">A token to cancel the operation before acceptance.</param>
    /// <returns>
    /// The created key's public metadata and instance id, with
    /// <see cref="KeyMutationResult.Replayed"/> indicating whether this call did the work or
    /// matched an earlier one.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">
    /// The request's operation id or alias is empty, over-long, or contains control characters,
    /// or its key type is not a defined <see cref="KeyType"/>.
    /// </exception>
    /// <exception cref="KeyStoreException">
    /// The store does not advertise generation for this key type
    /// (<see cref="KeyStoreError.Unsupported"/>), the operation id was used for a different
    /// request (<see cref="KeyStoreError.IdempotencyConflict"/>), or the backend failed.
    /// </exception>
    Task<KeyMutationResult> GenerateAsync(KeyGenerateRequest request, CancellationToken ct = default);

    /// <summary>
    /// Transfers externally-generated key material into the store, idempotently and one way.
    /// </summary>
    /// <remarks>
    /// The material is read exactly once, at acceptance, after which the caller's
    /// <see cref="TransferableKeyMaterial"/> is permanently unreadable. A failure before
    /// acceptance leaves it usable for one retry. A recognized replay never reads the secret at
    /// all.
    /// </remarks>
    /// <param name="request">The import request, carrying its idempotency key and the material.</param>
    /// <param name="ct">A token to cancel the operation before acceptance.</param>
    /// <returns>The imported key's public metadata and instance id.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="request"/> or its <see cref="KeyImportRequest.Material"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="ArgumentException">The request's operation id or alias is invalid.</exception>
    /// <exception cref="ObjectDisposedException">The material has already been consumed or disposed.</exception>
    /// <exception cref="KeyStoreException">
    /// The store does not advertise import for this key type
    /// (<see cref="KeyStoreError.Unsupported"/>), the operation id was used for a different
    /// request (<see cref="KeyStoreError.IdempotencyConflict"/>), or the backend failed.
    /// </exception>
    Task<KeyMutationResult> ImportAsync(KeyImportRequest request, CancellationToken ct = default);

    /// <summary>Destroys a specific key instance, idempotently.</summary>
    /// <param name="request">The delete request, carrying its idempotency key and the target instance.</param>
    /// <param name="ct">A token to cancel the operation before acceptance.</param>
    /// <returns>
    /// Whether a key was destroyed, and whether this call matched an earlier delete. Nothing
    /// matching the alias and instance id is <see cref="KeyDeleteResult.Deleted"/> <c>false</c>,
    /// not an exception.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">The request's operation id, alias, or instance id is invalid.</exception>
    /// <exception cref="KeyStoreException">
    /// The operation id was used for a different request
    /// (<see cref="KeyStoreError.IdempotencyConflict"/>), or the backend failed.
    /// </exception>
    Task<KeyDeleteResult> DeleteAsync(KeyDeleteRequest request, CancellationToken ct = default);

    /// <summary>
    /// Reads the durable receipt for a mutation — how an ambiguous call is reconciled without
    /// re-issuing it.
    /// </summary>
    /// <remarks>
    /// Side-effect-free. Receipts survive restart and are visible from every node serving the
    /// namespace, for at least 24 hours and never less than the configured retry horizon.
    /// </remarks>
    /// <param name="kind">Which kind of mutation to look up.</param>
    /// <param name="operationId">The idempotency key the mutation was issued under.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>
    /// The receipt, or <c>null</c> only when the backend can definitively prove no acceptance
    /// was retained. A <c>null</c> that merely means "I cannot tell" is a contract violation —
    /// that case is <see cref="KeyStoreError.Unavailable"/>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="operationId"/> is invalid, or <paramref name="kind"/> is not a defined
    /// <see cref="KeyMutationKind"/>.
    /// </exception>
    /// <exception cref="KeyStoreException">The backend failed.</exception>
    Task<KeyMutationOutcome?> GetMutationOutcomeAsync(
        KeyMutationKind kind, KeyOperationId operationId, CancellationToken ct = default);

    /// <summary>
    /// Gets public metadata for a specific key instance, so a caller can confirm the alias
    /// still holds the key it thinks it does.
    /// </summary>
    /// <remarks>
    /// Pass a <see cref="KeyInstanceId"/> value, not a bare <c>default</c> literal:
    /// <c>GetInfoAsync(alias, default)</c> is target-typed to the inherited
    /// <see cref="IKeyStore.GetInfoAsync(string, CancellationToken)"/> overload — which is the
    /// right reading of "no instance supplied", but is the alias-only lookup, without the
    /// instance check. Any expression actually typed as <see cref="KeyInstanceId"/> binds here
    /// and is validated.
    /// </remarks>
    /// <param name="alias">The alias to look up, within this instance's namespace.</param>
    /// <param name="instanceId">The key instance the caller expects the alias to hold.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>
    /// The metadata, or <c>null</c> when the alias does not exist <em>or</em> holds a different
    /// key instance. For a query, the nullable return is the failure channel; the operations
    /// that would otherwise sign under the wrong key throw instead.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="alias"/> or <paramref name="instanceId"/> is invalid.</exception>
    /// <exception cref="KeyStoreException">The backend failed.</exception>
    Task<StoredKeyInfo?> GetInfoAsync(string alias, KeyInstanceId instanceId, CancellationToken ct = default);

    /// <summary>
    /// Signs the exact supplied bytes with a stored key, under an explicitly named advertised
    /// algorithm and encoding.
    /// </summary>
    /// <param name="request">The signing request.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The signature, in the encoding the request's algorithm identifier names.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">
    /// The request's alias, instance id, or algorithm id is invalid, or
    /// <see cref="KeySignRequest.Data"/> exceeds the advertised
    /// <see cref="KeyStoreCapability.MaxInputBytes"/>.
    /// </exception>
    /// <exception cref="KeyNotFoundException">
    /// The alias holds no key in this namespace, or holds a different key instance than the
    /// request names.
    /// </exception>
    /// <exception cref="KeyStoreException">
    /// The algorithm is not advertised or does not match the key
    /// (<see cref="KeyStoreError.Unsupported"/>), or the backend failed.
    /// </exception>
    Task<byte[]> SignAsync(KeySignRequest request, CancellationToken ct = default);

    /// <summary>
    /// Produces a BBS multi-message signature with a stored BLS12-381 G2 key — the
    /// by-reference counterpart to <see cref="IBbsCryptoProvider.Sign"/>, which takes a raw
    /// private scalar and therefore excludes exactly the keys a custody store exists to hold.
    /// </summary>
    /// <param name="request">The BBS signing request.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The BBS signature.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="request"/> or its <see cref="KeyBbsSignRequest.Messages"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The request's alias, instance id, or algorithm id is invalid; the message set is empty or
    /// exceeds the store's message-count bound (its <c>Count</c> is untrusted, and a byte bound
    /// cannot limit a count of zero-byte messages); or the total message and header size exceeds
    /// the advertised <see cref="KeyStoreCapability.MaxInputBytes"/>.
    /// </exception>
    /// <exception cref="KeyNotFoundException">
    /// The alias holds no key in this namespace, or holds a different key instance.
    /// </exception>
    /// <exception cref="KeyStoreException">
    /// BBS is not advertised for this key (<see cref="KeyStoreError.Unsupported"/>) — including
    /// when the platform has no BBS implementation — or the backend failed.
    /// </exception>
    Task<byte[]> SignBbsAsync(KeyBbsSignRequest request, CancellationToken ct = default);

    /// <summary>
    /// Performs ECDH against a stored key-agreement key under an explicitly named advertised
    /// algorithm, returning the raw shared secret Z.
    /// </summary>
    /// <remarks>
    /// No KDF is applied — apply a NIST SP 800-56A-conformant one before using the result as
    /// keying material, exactly as with
    /// <see cref="IKeyStore.DeriveSharedSecretAsync(string, ReadOnlyMemory{byte}, CancellationToken)"/>.
    /// </remarks>
    /// <param name="request">The key-agreement request.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The raw shared secret Z.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">
    /// The request's alias, instance id, or algorithm id is invalid, the peer public key
    /// exceeds the advertised <see cref="KeyStoreCapability.MaxInputBytes"/>, or the peer public
    /// key is malformed for the curve.
    /// </exception>
    /// <exception cref="KeyNotFoundException">
    /// The alias holds no key in this namespace, or holds a different key instance.
    /// </exception>
    /// <exception cref="KeyStoreException">
    /// The algorithm is not advertised or does not match the key
    /// (<see cref="KeyStoreError.Unsupported"/>), or the backend failed.
    /// </exception>
    Task<byte[]> DeriveSharedSecretAsync(KeyAgreementRequest request, CancellationToken ct = default);
}

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// RS0026 (do not add multiple overloads with optional parameters) guards against an added
// overload silently changing how existing source resolves. It cannot apply here: every member
// below is on a type introduced in this release, so there is no existing source calling it, and
// the request-bearing overloads take types that did not exist before either. The legacy
// IKeyStore overloads they sit beside are inherited unchanged — IKeyStore itself gains no
// member, which is the whole point of shipping this as a derived interface.
#pragma warning disable RS0026

namespace NetCrypto;

/// <summary>
/// The reference <see cref="ICapableKeyStore"/>: a dictionary-backed store implementing the
/// whole custody contract end to end. For unit tests, development, and as executable
/// documentation for authors of real backends (Azure Key Vault, AWS KMS, PKCS#11). NOT for
/// production use.
/// </summary>
/// <remarks>
/// <para>
/// It is deliberately a sibling of <see cref="InMemoryKeyStore"/> rather than a change to it:
/// the older store keeps its exact behavior for existing consumers, and this one is free to be
/// strict. Both own the key material they hold — delete destroys the key rather than merely
/// unlisting it, and disposal zeroizes what remains.
/// </para>
/// <para>
/// What it demonstrates, in the order a backend author will need it: GUID-based
/// <see cref="KeyInstanceId"/>s that make alias rebinding detectable; namespace enforcement on
/// every member, including the inherited <see cref="IKeyStore"/> ones; a mutation ledger keyed
/// by <c>(namespace, kind, operation id)</c> holding a canonical request fingerprint next to
/// each receipt; <see cref="TransferableKeyMaterial"/> acceptance with pinned-buffer
/// zeroization; the ECDSA encoding identifiers wired through the format-bearing
/// <see cref="ICryptoProvider.Sign(KeyType, ReadOnlySpan{byte}, ReadOnlySpan{byte}, EcdsaSignatureFormat)"/>
/// overload; and BBS advertised only when the process can actually perform it.
/// </para>
/// <para>
/// <b>Threading.</b> Every operation takes the backend's single lock, so operations against one
/// backend are serialized — including the signature computation itself. That is the correct
/// trade for a reference implementation: the idempotency contract requires ledger read,
/// decision, and commit to be one indivisible step, and a finer-grained scheme is exactly where
/// that would break. A real backend gets its atomicity from its own transaction.
/// </para>
/// <para>
/// <b>Which errors it can raise.</b> Of the portable taxonomy, this store produces
/// <see cref="KeyStoreError.Unsupported"/>, <see cref="KeyStoreError.IdempotencyConflict"/>,
/// and <see cref="KeyStoreError.Unavailable"/> (for a provider failure, including a backend
/// result that fails the return-path shape check). It never produces
/// <see cref="KeyStoreError.AccessDenied"/>, <see cref="KeyStoreError.Throttled"/>, or
/// <see cref="KeyStoreError.OutcomeUnknown"/>: there is no remote call to be denied, throttled,
/// or lost, and its commit is a single locked write, so an accepted mutation is never
/// ambiguous. Callers must still handle all six — a real backend produces them all.
/// </para>
/// </remarks>
public sealed class CapableInMemoryKeyStore : ICapableKeyStore, IDisposable
{
    /// <summary>The namespace a store created without an explicit one operates in.</summary>
    internal const string DefaultNamespaceValue = "default";

    internal const int MaxAliasBytes = 512;
    internal const int MaxSignInputBytes = 1024 * 1024;
    internal const int MaxAgreementInputBytes = 256;
    internal const int MaxBbsInputBytes = 1024 * 1024;
    internal const int MaxBbsMessageCount = 4096;

    // Two snapshots, because the only thing that varies is whether this process can do BBS —
    // and IBbsCryptoProvider.IsAvailable is fixed for the process lifetime, which is what makes
    // a per-instance-stable Revision honest.
    private static readonly KeyStoreCapabilitySet CapabilitiesWithBbs = BuildCapabilities(bbsAvailable: true);
    private static readonly KeyStoreCapabilitySet CapabilitiesWithoutBbs = BuildCapabilities(bbsAvailable: false);

    private readonly InMemoryKeyStoreBackend _backend;
    private readonly bool _ownsBackend;
    private readonly KeyStoreNamespaceId _namespaceId;
    private readonly IKeyGenerator _keyGenerator;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IBbsCryptoProvider? _bbsProvider;
    private readonly TimeProvider _timeProvider;
    private readonly KeyStoreCapabilitySet _capabilities;
    private volatile bool _disposed;

    /// <summary>
    /// Creates a store with its own private backend in the default namespace — the shape most
    /// tests want.
    /// </summary>
    /// <param name="keyGenerator">Used to mint keys for <see cref="KeyStoreOperation.Generate"/>.</param>
    /// <param name="cryptoProvider">Used for signing and key agreement.</param>
    /// <param name="bbsProvider">
    /// Used for <see cref="KeyStoreOperation.BbsSign"/>. When <c>null</c>, or when its
    /// <see cref="IBbsCryptoProvider.IsAvailable"/> is <c>false</c>, BBS is simply not
    /// advertised and BBS requests are refused with <see cref="KeyStoreError.Unsupported"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">A required dependency is <c>null</c>.</exception>
    public CapableInMemoryKeyStore(
        IKeyGenerator keyGenerator, ICryptoProvider cryptoProvider, IBbsCryptoProvider? bbsProvider = null)
        : this(new InMemoryKeyStoreBackend(), new KeyStoreNamespaceId(DefaultNamespaceValue),
            keyGenerator, cryptoProvider, bbsProvider, timeProvider: null, ownsBackend: true)
    {
    }

    /// <summary>
    /// Creates a store over a shared backend in an explicit namespace — the shape that models a
    /// real multi-tenant backend, and the only way to observe namespace isolation or a receipt
    /// outliving the store instance that wrote it.
    /// </summary>
    /// <param name="backend">
    /// The shared state. Not disposed by this store: the backend outlives any one store over
    /// it, which is the point of sharing it.
    /// </param>
    /// <param name="namespaceId">The least-privilege scope this instance may touch.</param>
    /// <param name="keyGenerator">Used to mint keys for <see cref="KeyStoreOperation.Generate"/>.</param>
    /// <param name="cryptoProvider">Used for signing and key agreement.</param>
    /// <param name="bbsProvider">Used for <see cref="KeyStoreOperation.BbsSign"/>; may be <c>null</c>.</param>
    /// <param name="timeProvider">
    /// Supplies the commit timestamps on mutation receipts. Defaults to
    /// <see cref="TimeProvider.System"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">A required dependency is <c>null</c>.</exception>
    /// <exception cref="ArgumentException"><paramref name="namespaceId"/> is empty or malformed.</exception>
    public CapableInMemoryKeyStore(
        InMemoryKeyStoreBackend backend,
        KeyStoreNamespaceId namespaceId,
        IKeyGenerator keyGenerator,
        ICryptoProvider cryptoProvider,
        IBbsCryptoProvider? bbsProvider = null,
        TimeProvider? timeProvider = null)
        : this(backend, namespaceId, keyGenerator, cryptoProvider, bbsProvider, timeProvider, ownsBackend: false)
    {
    }

    private CapableInMemoryKeyStore(
        InMemoryKeyStoreBackend backend,
        KeyStoreNamespaceId namespaceId,
        IKeyGenerator keyGenerator,
        ICryptoProvider cryptoProvider,
        IBbsCryptoProvider? bbsProvider,
        TimeProvider? timeProvider,
        bool ownsBackend)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        KeyStoreIdentifier.Require(namespaceId.Value, nameof(namespaceId), "namespace id");
        _namespaceId = namespaceId;
        _bbsProvider = bbsProvider;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ownsBackend = ownsBackend;
        _capabilities = bbsProvider is { IsAvailable: true } ? CapabilitiesWithBbs : CapabilitiesWithoutBbs;
    }

    /// <inheritdoc />
    public KeyStoreNamespaceId NamespaceId => _namespaceId;

    // ---------------------------------------------------------------- discovery

    /// <inheritdoc />
    public Task<KeyStoreCapabilitySet> GetCapabilitiesAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(_capabilities);
    }

    // ---------------------------------------------------------------- mutations

    /// <inheritdoc />
    public Task<KeyMutationResult> GenerateAsync(KeyGenerateRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        KeyStoreIdentifier.Require(request.OperationId.Value, nameof(request), $"{nameof(KeyGenerateRequest)}.{nameof(KeyGenerateRequest.OperationId)}");
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeyGenerateRequest)}.{nameof(KeyGenerateRequest.Alias)}");
        RequireDefinedKeyType(request.KeyType, nameof(request));
        ObjectDisposedException.ThrowIf(_disposed, this);

        RequireCapability(request.KeyType, KeyStoreOperation.Generate, algorithm: null);

        var fingerprint = ComputeFingerprint(
            KeyMutationKind.Generate, Utf8(request.Alias), Utf8(request.KeyType.ToString()));

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);

            var ledgerKey = LedgerKey(KeyMutationKind.Generate, request.OperationId);
            if (_backend.Ledger.TryGetValue(ledgerKey, out var recorded))
            {
                RequireSameRequest(recorded, fingerprint, KeyMutationKind.Generate, request.OperationId);
                var previous = (KeyGeneratedOutcome)recorded.Outcome;
                return Task.FromResult(new KeyMutationResult(previous.Info, previous.InstanceId, Replayed: true));
            }

            // The last point at which nothing has happened yet. Past here the mutation is
            // irreversible, so cancellation is never consulted again — a cancelled token must
            // not be reported as a rollback that did not occur.
            ct.ThrowIfCancellationRequested();

            if (_backend.Keys.ContainsKey(KeyKey(request.Alias)))
                throw new InvalidOperationException($"Key alias '{request.Alias}' already exists.");

            KeyPair keyPair;
            try
            {
                keyPair = _keyGenerator.Generate(request.KeyType);
            }
            catch (Exception ex) when (IsBackendFailure(ex))
            {
                throw new KeyStoreException(
                    KeyStoreError.Unavailable, $"The key generator failed to create a {request.KeyType} key.", ex);
            }

            var instanceId = NewInstanceId();
            var info = NewInfo(request.Alias, keyPair, instanceId);
            var outcome = new KeyGeneratedOutcome(request.OperationId, _timeProvider.GetUtcNow(), info, instanceId);

            _backend.Keys[KeyKey(request.Alias)] = new InMemoryKeyStoreBackend.StoredEntry(keyPair, info, instanceId);
            _backend.Ledger[ledgerKey] = new InMemoryKeyStoreBackend.LedgerEntry(fingerprint, outcome, Deleted: false);

            return Task.FromResult(new KeyMutationResult(info, instanceId, Replayed: false));
        }
    }

    /// <inheritdoc />
    public Task<KeyMutationResult> ImportAsync(KeyImportRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Material, nameof(request));
        KeyStoreIdentifier.Require(request.OperationId.Value, nameof(request), $"{nameof(KeyImportRequest)}.{nameof(KeyImportRequest.OperationId)}");
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeyImportRequest)}.{nameof(KeyImportRequest.Alias)}");
        ObjectDisposedException.ThrowIf(_disposed, this);

        var material = request.Material;

        // Public metadata only, and read before any decision is taken: the replay check below
        // must be answerable without ever touching the secret.
        var keyType = material.KeyType;
        var publicKey = material.PublicKey;

        RequireCapability(keyType, KeyStoreOperation.Import, algorithm: null);

        var fingerprint = ComputeFingerprint(
            KeyMutationKind.Import, Utf8(request.Alias), Utf8(keyType.ToString()), publicKey);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);

            var ledgerKey = LedgerKey(KeyMutationKind.Import, request.OperationId);
            if (_backend.Ledger.TryGetValue(ledgerKey, out var recorded))
            {
                // A conflicting id leaves the material untouched — the caller's request was
                // never accepted, so they keep their one retry.
                RequireSameRequest(recorded, fingerprint, KeyMutationKind.Import, request.OperationId);

                // A genuine replay: the secret is already in the store, so this copy is
                // destroyed rather than read. Destroying is not reading — the store never sees
                // the material of a replayed import.
                material.Discard();
                var previous = (KeyImportedOutcome)recorded.Outcome;
                return Task.FromResult(new KeyMutationResult(previous.Info, previous.InstanceId, Replayed: true));
            }

            ct.ThrowIfCancellationRequested();

            if (_backend.Keys.ContainsKey(KeyKey(request.Alias)))
                throw new InvalidOperationException($"Key alias '{request.Alias}' already exists.");

            // Acceptance. From here the caller's material is spent, whatever happens next —
            // including the mismatch below, which is deliberate: the store has seen the secret,
            // so handing the caller a second chance with it would be the wrong trade.
            KeyPair keyPair;
            try
            {
                keyPair = ConsumeAndDerive(material, nameof(request));
            }
            catch (Exception ex) when (ex is not (ArgumentException or ObjectDisposedException or KeyStoreException))
            {
                // FromPrivateKey runs inside the reader, and only its ArgumentException is mapped
                // there. Anything else a key generator can throw — a missing HSM driver, a native
                // load failure — is a backend condition and must not escape as a backend type
                // (rule 10). The material is already spent; the receipt of that is IsConsumed.
                throw new KeyStoreException(
                    KeyStoreError.Unavailable, "The key generator failed while ingesting the imported material.", ex);
            }

            var instanceId = NewInstanceId();

            var info = NewInfo(request.Alias, keyPair, instanceId);
            var outcome = new KeyImportedOutcome(request.OperationId, _timeProvider.GetUtcNow(), info, instanceId);

            _backend.Keys[KeyKey(request.Alias)] = new InMemoryKeyStoreBackend.StoredEntry(keyPair, info, instanceId);
            _backend.Ledger[ledgerKey] = new InMemoryKeyStoreBackend.LedgerEntry(fingerprint, outcome, Deleted: false);

            return Task.FromResult(new KeyMutationResult(info, instanceId, Replayed: false));
        }
    }

    /// <inheritdoc />
    public Task<KeyDeleteResult> DeleteAsync(KeyDeleteRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        KeyStoreIdentifier.Require(request.OperationId.Value, nameof(request), $"{nameof(KeyDeleteRequest)}.{nameof(KeyDeleteRequest.OperationId)}");
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeyDeleteRequest)}.{nameof(KeyDeleteRequest.Alias)}");
        KeyStoreIdentifier.Require(request.InstanceId.Value, nameof(request), $"{nameof(KeyDeleteRequest)}.{nameof(KeyDeleteRequest.InstanceId)}");
        ObjectDisposedException.ThrowIf(_disposed, this);

        var fingerprint = ComputeFingerprint(
            KeyMutationKind.Delete, Utf8(request.Alias), Utf8(request.InstanceId.Value));

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);

            var ledgerKey = LedgerKey(KeyMutationKind.Delete, request.OperationId);
            if (_backend.Ledger.TryGetValue(ledgerKey, out var recorded))
            {
                RequireSameRequest(recorded, fingerprint, KeyMutationKind.Delete, request.OperationId);
                return Task.FromResult(new KeyDeleteResult(recorded.Deleted, Replayed: true));
            }

            ct.ThrowIfCancellationRequested();

            var deleted = false;
            if (_backend.Keys.TryGetValue(KeyKey(request.Alias), out var entry)
                && entry.InstanceId == request.InstanceId)
            {
                _backend.Keys.Remove(KeyKey(request.Alias));
                entry.KeyPair.Dispose(); // delete destroys the key material, not just the entry
                deleted = true;
            }

            var outcome = new KeyDeletionOutcome(
                request.OperationId, _timeProvider.GetUtcNow(), request.InstanceId, deleted);
            _backend.Ledger[ledgerKey] = new InMemoryKeyStoreBackend.LedgerEntry(fingerprint, outcome, deleted);

            return Task.FromResult(new KeyDeleteResult(deleted, Replayed: false));
        }
    }

    /// <inheritdoc />
    public Task<KeyMutationOutcome?> GetMutationOutcomeAsync(
        KeyMutationKind kind, KeyOperationId operationId, CancellationToken ct = default)
    {
        if (!Enum.IsDefined(kind))
            throw new ArgumentException($"Mutation kind {(int)kind} is not a defined {nameof(KeyMutationKind)}.", nameof(kind));
        KeyStoreIdentifier.Require(operationId.Value, nameof(operationId), "operation id");
        ObjectDisposedException.ThrowIf(_disposed, this);
        ct.ThrowIfCancellationRequested();

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            return Task.FromResult(
                _backend.Ledger.TryGetValue(LedgerKey(kind, operationId), out var recorded) ? recorded.Outcome : null);
        }
    }

    // ---------------------------------------------------------------- queries

    /// <inheritdoc />
    public Task<StoredKeyInfo?> GetInfoAsync(string alias, KeyInstanceId instanceId, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        KeyStoreIdentifier.Require(instanceId.Value, nameof(instanceId), "key instance id");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (_backend.Keys.TryGetValue(KeyKey(alias), out var entry) && entry.InstanceId == instanceId)
                return Task.FromResult<StoredKeyInfo?>(entry.Info);

            return Task.FromResult<StoredKeyInfo?>(null);
        }
    }

    // ---------------------------------------------------------------- operations

    /// <inheritdoc />
    public Task<byte[]> SignAsync(KeySignRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeySignRequest)}.{nameof(KeySignRequest.Alias)}");
        KeyStoreIdentifier.Require(request.InstanceId.Value, nameof(request), $"{nameof(KeySignRequest)}.{nameof(KeySignRequest.InstanceId)}");
        ObjectDisposedException.ThrowIf(_disposed, this);

        var spec = ResolveAlgorithm(request.Algorithm, KeyStoreOperation.Sign, nameof(request),
            $"{nameof(KeySignRequest)}.{nameof(KeySignRequest.Algorithm)}");
        var capability = RequireCapability(spec.KeyType, KeyStoreOperation.Sign, spec.Algorithm);
        RequireWithinBound(request.Data.Length, capability.MaxInputBytes, nameof(request), "signing input");

        // Snapshot once. A ReadOnlyMemory<byte> is a live window onto the caller's array, so
        // without this "signs the exact supplied bytes" is undefined under concurrent mutation —
        // and the output check below has to verify against the very bytes that were signed.
        var data = request.Data.ToArray();

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            var entry = RequireEntry(request.Alias, request.InstanceId);
            RequireKeyMatchesAlgorithm(entry, spec);

            // Borrow instead of reading KeyPair.PrivateKey: the clone-per-read getter would
            // leave one unzeroed private-key copy on the heap per signature.
            var signature = RouteToProvider(
                () => entry.KeyPair.WithPrivateKey(
                    privateKey => _cryptoProvider.Sign(spec.KeyType, privateKey, data, spec.Format)),
                nameof(request),
                "signing",
                ct);

            var checkedSignature = CheckedResult(signature, ExpectedSignatureLength(spec), "signature");
            RequireSpeaksForTheAdvertisedKey(entry, spec, data, checkedSignature);
            return Task.FromResult(checkedSignature);
        }
    }

    /// <inheritdoc />
    public Task<byte[]> SignBbsAsync(KeyBbsSignRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Messages, nameof(request));
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeyBbsSignRequest)}.{nameof(KeyBbsSignRequest.Alias)}");
        KeyStoreIdentifier.Require(request.InstanceId.Value, nameof(request), $"{nameof(KeyBbsSignRequest)}.{nameof(KeyBbsSignRequest.InstanceId)}");

        // Read Count exactly once, and check it here — before the capability lookup, so an
        // argument fault stays an argument fault rather than being masked by "unsupported" on a
        // platform that cannot do BBS at all (NFR-3: validate the caller's input first). The
        // count needs its own bound: Messages is a caller-supplied list whose Count is untrusted
        // (it may lie in either direction), the snapshot allocates from it, and MaxInputBytes
        // cannot help because a count of zero-byte messages stays "within" any byte bound — an
        // absurd Count must fail here, never as an OutOfMemoryException at the allocation.
        var count = request.Messages.Count;
        if (count <= 0)
            throw new ArgumentException("A BBS signature requires at least one message.", nameof(request));
        if (count > MaxBbsMessageCount)
            throw new ArgumentException(
                $"A BBS signature covers at most {MaxBbsMessageCount} messages in this store, got {count}.",
                nameof(request));
        ObjectDisposedException.ThrowIf(_disposed, this);

        var spec = ResolveAlgorithm(request.Algorithm, KeyStoreOperation.BbsSign, nameof(request),
            $"{nameof(KeyBbsSignRequest)}.{nameof(KeyBbsSignRequest.Algorithm)}");
        var capability = RequireCapability(spec.KeyType, KeyStoreOperation.BbsSign, spec.Algorithm);

        // Snapshot FIRST, then measure the snapshot. Messages is a caller-supplied
        // IReadOnlyList, so its enumerator and its indexer need not agree: bounding one read and
        // signing another lets a hostile list sign far past the advertised maximum. Reading each
        // element once means the bound covers exactly the bytes that get signed — and it pins
        // them against a caller mutating the buffers mid-operation.
        var messages = new byte[count][];
        for (var i = 0; i < count; i++)
            messages[i] = request.Messages[i].ToArray();
        var header = request.Header.ToArray();

        // Sum in a long: a handful of large messages would otherwise overflow int and slip past
        // the bound as a negative total.
        long total = header.Length;
        foreach (var message in messages)
            total += message.Length;
        RequireWithinBound(total, capability.MaxInputBytes, nameof(request), "BBS message and header input");

        var bbs = _bbsProvider
            ?? throw new KeyStoreException(KeyStoreError.Unsupported, "This store has no BBS provider configured.");

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            var entry = RequireEntry(request.Alias, request.InstanceId);
            RequireKeyMatchesAlgorithm(entry, spec);

            var signature = RouteToProvider(
                () => entry.KeyPair.WithPrivateKey(privateKey => bbs.Sign(privateKey, messages, header)),
                nameof(request),
                "BBS signing",
                ct);

            var checkedSignature = CheckedResult(signature, BbsSignatureLength, "BBS signature");

            // NFR-6.2 for the BBS path, with the same trust separation as the ECDSA path: a
            // provider that forged the signature will happily verify it too, so the check runs
            // through the in-repo DefaultBbsCryptoProvider whenever the native suite is
            // loadable. Only when it is not — a managed third-party BBS implementation on a
            // platform without the native library — does this fall back to asking the producing
            // provider, which still catches well-formed noise but not a provider lying in both
            // halves; that residual weakness is documented rather than implied away.
            var verifier = BbsVerificationProvider.IsAvailable ? BbsVerificationProvider : bbs;
            bool verified;
            try
            {
                verified = verifier.Verify(entry.Info.PublicKey, checkedSignature, messages, header);
            }
            catch (Exception ex)
            {
                throw new KeyStoreException(
                    KeyStoreError.Unavailable,
                    "The BBS provider returned a signature that could not be checked against the public " +
                    $"key this store advertises for alias '{entry.Info.Alias}'.", ex);
            }

            if (!verified)
                throw new KeyStoreException(
                    KeyStoreError.Unavailable,
                    "The BBS provider returned a signature that does not verify under the public key this " +
                    $"store advertises for alias '{entry.Info.Alias}'.");

            return Task.FromResult(checkedSignature);
        }
    }

    /// <inheritdoc />
    public Task<byte[]> DeriveSharedSecretAsync(KeyAgreementRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        KeyStoreIdentifier.RequireAlias(request.Alias, MaxAliasBytes, nameof(request), $"{nameof(KeyAgreementRequest)}.{nameof(KeyAgreementRequest.Alias)}");
        KeyStoreIdentifier.Require(request.InstanceId.Value, nameof(request), $"{nameof(KeyAgreementRequest)}.{nameof(KeyAgreementRequest.InstanceId)}");
        ObjectDisposedException.ThrowIf(_disposed, this);

        var spec = ResolveAlgorithm(request.Algorithm, KeyStoreOperation.KeyAgreement, nameof(request),
            $"{nameof(KeyAgreementRequest)}.{nameof(KeyAgreementRequest.Algorithm)}");
        var capability = RequireCapability(spec.KeyType, KeyStoreOperation.KeyAgreement, spec.Algorithm);
        RequireWithinBound(request.PeerPublicKey.Length, capability.MaxInputBytes, nameof(request), "peer public key");

        // Snapshot for the same reason SignAsync does: the peer key is a live window onto the
        // caller's array, and the provider must see exactly what was bounds-checked.
        var peerPublicKey = request.PeerPublicKey.ToArray();

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            var entry = RequireEntry(request.Alias, request.InstanceId);
            RequireKeyMatchesAlgorithm(entry, spec);

            // The stored private scalar is read here but never returned: only the raw shared
            // secret Z leaves the store, mirroring SignAsync.
            var z = RouteToProvider(
                () => entry.KeyPair.WithPrivateKey(
                    privateKey => _cryptoProvider.DeriveSharedSecret(spec.KeyType, privateKey, peerPublicKey)),
                nameof(request),
                "key agreement",
                ct,
                callerSuppliedKeyMaterial: true);

            return Task.FromResult(CheckedResult(z, ExpectedSharedSecretLength(spec), "shared secret"));
        }
    }

    // ---------------------------------------------------------------- IKeyStore (legacy surface)

    /// <inheritdoc />
    /// <remarks>
    /// Scoped to <see cref="NamespaceId"/> like every other member, and it still mints a
    /// <see cref="KeyInstanceId"/> so the returned info carries one. It is <b>not</b> idempotent
    /// — the legacy signature has nowhere to put an operation id — so use
    /// <see cref="GenerateAsync(KeyGenerateRequest, CancellationToken)"/> where a retry is
    /// possible.
    /// </remarks>
    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        RequireDefinedKeyType(keyType, nameof(keyType));
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Scope entered before the generator runs, matching the request-based path — a
        // reentrant key generator is refused on both.
        using var operation = OperationScope.Enter();
        var keyPair = _keyGenerator.Generate(keyType);
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (_backend.Keys.ContainsKey(KeyKey(alias)))
            {
                // The freshly generated pair never escaped — destroy it rather than orphan it.
                keyPair.Dispose();
                throw new InvalidOperationException($"Key alias '{alias}' already exists.");
            }

            var instanceId = NewInstanceId();
            var info = NewInfo(alias, keyPair, instanceId);
            _backend.Keys[KeyKey(alias)] = new InMemoryKeyStoreBackend.StoredEntry(keyPair, info, instanceId);
            return Task.FromResult(info);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The store owns the key pair from this point on: it is zeroized on delete or dispose. For
    /// a transfer that also revokes the caller's own access to the secret, use
    /// <see cref="ImportAsync(KeyImportRequest, CancellationToken)"/> with a
    /// <see cref="TransferableKeyMaterial"/>.
    /// </remarks>
    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ArgumentNullException.ThrowIfNull(keyPair);
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (_backend.Keys.ContainsKey(KeyKey(alias)))
                throw new InvalidOperationException($"Key alias '{alias}' already exists.");

            var instanceId = NewInstanceId();
            var info = NewInfo(alias, keyPair, instanceId);
            _backend.Keys[KeyKey(alias)] = new InMemoryKeyStoreBackend.StoredEntry(keyPair, info, instanceId);
            return Task.FromResult(info);
        }
    }

    /// <inheritdoc />
    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            return Task.FromResult(_backend.Keys.TryGetValue(KeyKey(alias), out var entry) ? entry.Info : null);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Signs with the algorithm bound to the key type and, for the NIST curves, the DER default
    /// — unchanged from <see cref="InMemoryKeyStore"/>, which also means <b>no return-path
    /// identity check</b>: this overload does not verify the produced signature against the
    /// advertised public key, and it carries no <see cref="KeyInstanceId"/> guard. Use
    /// <see cref="SignAsync(KeySignRequest, CancellationToken)"/> to choose the encoding and get
    /// both integrity checks.
    /// </remarks>
    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (!_backend.Keys.TryGetValue(KeyKey(alias), out var entry))
                throw new KeyNotFoundException($"Key alias '{alias}' not found.");

            var signature = entry.KeyPair.WithPrivateKey(
                privateKey => _cryptoProvider.Sign(entry.KeyPair.KeyType, privateKey, data.Span));
            return Task.FromResult(signature);
        }
    }

    /// <inheritdoc />
    public Task<RecoverableSignature> SignDigestAsync(string alias, ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (digest32.Length != 32)
            throw new ArgumentException($"Digest must be 32 bytes, got {digest32.Length}.", nameof(digest32));

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (!_backend.Keys.TryGetValue(KeyKey(alias), out var entry))
                throw new KeyNotFoundException($"Key alias '{alias}' not found.");
            if (entry.KeyPair.KeyType != KeyType.Secp256k1)
                throw new NotSupportedException(
                    $"Recoverable digest signing requires a secp256k1 key; alias '{alias}' holds {entry.KeyPair.KeyType}.");

            var (signature, recoveryId) = entry.KeyPair.WithPrivateKey(
                privateKey => Secp256k1Recoverable.Sign(privateKey, digest32.Span));
            return Task.FromResult(new RecoverableSignature(signature, recoveryId));
        }
    }

    /// <inheritdoc />
    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (!_backend.Keys.TryGetValue(KeyKey(alias), out var entry))
                throw new KeyNotFoundException($"Key alias '{alias}' not found.");

            ISigner signer = new KeyStoreSigner(this, alias, entry.Info.KeyType, entry.Info.PublicKey);
            return Task.FromResult(signer);
        }
    }

    /// <inheritdoc />
    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (!_backend.Keys.TryGetValue(KeyKey(alias), out var entry))
                throw new KeyNotFoundException($"Key alias '{alias}' not found.");

            byte[] z;
            try
            {
                z = entry.KeyPair.WithPrivateKey(
                    privateKey => _cryptoProvider.DeriveSharedSecret(entry.KeyPair.KeyType, privateKey, peerPublicKey.Span));
            }
            catch (ArgumentException ex) when (ex.ParamName == "publicKey")
            {
                // Re-surface the provider's parameter-named failure under THIS method's
                // parameter, exactly as InMemoryKeyStore does.
                throw new ArgumentException(
                    "The peer public key is invalid for the stored key's algorithm.", nameof(peerPublicKey), ex);
            }
            catch (CryptographicException ex)
            {
                // An off-curve, low-order, or otherwise unusable peer point reaches the backend
                // as a CryptographicException. NFR-3 forbids that type doubling as the catch-all
                // for malformed input, and this is new surface, so it does not inherit the
                // older store's leak. (Verbatim migration covers valid-input behavior; on
                // invalid input the NFR wins.)
                throw new ArgumentException(
                    "The peer public key is invalid for the stored key's algorithm.", nameof(peerPublicKey), ex);
            }

            return Task.FromResult(z);
        }
    }

    /// <inheritdoc />
    /// <remarks>Lists only the aliases in this instance's <see cref="NamespaceId"/>.</remarks>
    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            IReadOnlyList<string> aliases = _backend.Keys.Keys
                .Where(key => string.Equals(key.Namespace, _namespaceId.Value, StringComparison.Ordinal))
                .Select(key => key.Alias)
                .ToList();
            return Task.FromResult(aliases);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Destroys whatever instance the alias currently holds. Not idempotent, and it cannot
    /// express "delete only if this is still the key I mean" — use
    /// <see cref="DeleteAsync(KeyDeleteRequest, CancellationToken)"/> for either.
    /// </remarks>
    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        KeyStoreIdentifier.RequireAlias(alias, MaxAliasBytes, nameof(alias), "alias");
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var operation = OperationScope.Enter();
        lock (_backend.Gate)
        {
            ObjectDisposedException.ThrowIf(_backend.Disposed, this);
            if (!_backend.Keys.Remove(KeyKey(alias), out var entry))
                return Task.FromResult(false);

            entry.KeyPair.Dispose(); // delete destroys the key material, not just the entry
            return Task.FromResult(true);
        }
    }

    /// <summary>
    /// Marks this store disposed. A store that created its own backend also disposes it,
    /// zeroizing every key it held; a store over a shared backend leaves the backend alone, so
    /// other namespaces keep working. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        if (_ownsBackend)
            _backend.Dispose();
    }

    // ---------------------------------------------------------------- internals

    private const int BbsSignatureLength = 80;

    // Verification oracles for the NFR-6 return-path check. Deliberately NOT the injected
    // providers: a provider that produced a forged signature would happily verify it too.
    private static readonly DefaultCryptoProvider VerificationProvider = new();
    private static readonly DefaultBbsCryptoProvider BbsVerificationProvider = new();

    // Replacement fallback would encode every unpaired surrogate — and U+FFFD itself — to the
    // same three bytes, so two distinct requests could share a fingerprint and one caller's
    // mutation would silently replay another's. Identifiers and aliases are already screened for
    // ill-formed UTF-16 at the boundary; this makes a lossy encode impossible rather than merely
    // unreachable.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // Set for the duration of one store operation on the current thread. Monitor is reentrant,
    // so without this a provider that calls back into the store walks straight through the
    // backend lock — and a nested delete would zeroize the pinned buffer that the in-flight
    // KeyPair.WithPrivateKey borrow is still reading from.
    [ThreadStatic]
    private static bool _inOperation;

    private readonly struct OperationScope : IDisposable
    {
        internal static OperationScope Enter()
        {
            if (_inOperation)
                throw new InvalidOperationException(
                    "A key store operation re-entered the store on the same thread. A crypto provider, " +
                    "key generator, or time provider must not call back into the store that invoked it.");

            _inOperation = true;
            return default;
        }

        public void Dispose() => _inOperation = false;
    }

    /// <summary>
    /// The single read of transferred import material: derives the public key from the secret
    /// rather than believing the caller's copy — <see cref="StoredKeyInfo.PublicKey"/> is the
    /// identity downstream DID/VC code publishes and verifies against, and an unchecked import
    /// lets it be set to a key unrelated to the one that will actually sign.
    /// </summary>
    private KeyPair ConsumeAndDerive(TransferableKeyMaterial material, string paramName)
    {
        return material.Consume((type, publicBytes, privateBytes) =>
        {
            KeyPair derived;
            try
            {
                derived = _keyGenerator.FromPrivateKey(type, privateBytes);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException(
                    $"The transferred material is not a valid {type} private key.", paramName, ex);
            }

            if (derived.PublicKey.AsSpan().SequenceEqual(publicBytes))
                return derived;

            derived.Dispose();
            throw new ArgumentException(
                "The transferred public key does not belong to the transferred private key.", paramName);
        });
    }

    private (string Namespace, string Alias) KeyKey(string alias) => (_namespaceId.Value, alias);

    private (string Namespace, KeyMutationKind Kind, string OperationId) LedgerKey(
        KeyMutationKind kind, KeyOperationId operationId) => (_namespaceId.Value, kind, operationId.Value);

    private static KeyInstanceId NewInstanceId() => new(Guid.NewGuid().ToString("N"));

    private static StoredKeyInfo NewInfo(string alias, KeyPair keyPair, KeyInstanceId instanceId) => new()
    {
        Alias = alias,
        KeyType = keyPair.KeyType,
        PublicKey = keyPair.PublicKey,
        InstanceId = instanceId,
    };

    private static byte[] Utf8(string value) => StrictUtf8.GetBytes(value);

    private static void RequireDefinedKeyType(KeyType keyType, string paramName)
    {
        if (!Enum.IsDefined(keyType))
            throw new ArgumentException($"Key type {(int)keyType} is not a defined {nameof(NetCrypto.KeyType)}.", paramName);
    }

    private static void RequireWithinBound(long actual, int maxInputBytes, string paramName, string what)
    {
        if (actual > maxInputBytes)
            throw new ArgumentException(
                $"The {what} is {actual} bytes, exceeding this store's advertised maximum of {maxInputBytes}.",
                paramName);
    }

    private KeyStoreCapability RequireCapability(
        KeyType keyType, KeyStoreOperation operation, KeyStoreAlgorithmId? algorithm)
    {
        return _capabilities.Find(keyType, operation, algorithm)
            ?? throw new KeyStoreException(
                KeyStoreError.Unsupported,
                $"This store does not advertise {operation} for {keyType}" +
                $"{(algorithm is { } id ? $" with algorithm '{id.Value}'" : string.Empty)}.");
    }

    private static KeyStoreAlgorithmSpec ResolveAlgorithm(
        KeyStoreAlgorithmId algorithm, KeyStoreOperation operation, string paramName, string memberPath)
    {
        KeyStoreIdentifier.Require(algorithm.Value, paramName, memberPath);

        if (!KeyStoreAlgorithmTable.TryResolve(algorithm.Value, out var spec) || spec.Operation != operation)
            throw new KeyStoreException(
                KeyStoreError.Unsupported,
                $"Algorithm '{algorithm.Value}' is not an algorithm this store advertises for {operation}.");

        return spec;
    }

    private InMemoryKeyStoreBackend.StoredEntry RequireEntry(string alias, KeyInstanceId instanceId)
    {
        if (!_backend.Keys.TryGetValue(KeyKey(alias), out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        // The instance check is what generalizes the KeyStoreSigner alias-rebinding defense to
        // the whole surface: an alias that was deleted and re-created holds a different key, and
        // a stale reference must fail rather than silently speak for it.
        if (entry.InstanceId != instanceId)
            throw new KeyNotFoundException(
                $"Key alias '{alias}' no longer holds key instance '{instanceId.Value}'; " +
                "the alias may have been deleted and re-created.");

        return entry;
    }

    private static void RequireKeyMatchesAlgorithm(
        InMemoryKeyStoreBackend.StoredEntry entry, KeyStoreAlgorithmSpec spec)
    {
        if (entry.Info.KeyType != spec.KeyType)
            throw new KeyStoreException(
                KeyStoreError.Unsupported,
                $"Algorithm '{spec.Algorithm.Value}' requires a {spec.KeyType} key, but alias " +
                $"'{entry.Info.Alias}' holds {entry.Info.KeyType}.");
    }

    private static void RequireSameRequest(
        InMemoryKeyStoreBackend.LedgerEntry recorded, byte[] fingerprint, KeyMutationKind kind, KeyOperationId operationId)
    {
        if (!recorded.Fingerprint.AsSpan().SequenceEqual(fingerprint))
            throw new KeyStoreException(
                KeyStoreError.IdempotencyConflict,
                $"Operation id '{operationId.Value}' was already used in this namespace for a different " +
                $"{kind} request. Mint a new operation id, or replay the original request unchanged.");
    }

    private byte[] ComputeFingerprint(KeyMutationKind kind, params ReadOnlySpan<byte[]> parts)
    {
        // Length-prefixed so no two distinct field sequences can produce the same bytes: a
        // naive delimiter-joined encoding would let an alias containing the delimiter forge a
        // collision and silently replay somebody else's mutation.
        var buffer = new List<byte>();
        Append(buffer, Utf8(_namespaceId.Value));
        Append(buffer, Utf8(kind.ToString()));
        foreach (var part in parts)
            Append(buffer, part);

        return Hash.Sha256(CollectionsMarshal.AsSpan(buffer));

        static void Append(List<byte> target, ReadOnlySpan<byte> part)
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, part.Length);
            target.AddRange(length);
            target.AddRange(part);
        }
    }

    /// <summary>
    /// Runs a provider call and converts anything it can throw into this surface's contract.
    /// The injected <see cref="ICryptoProvider"/> / <see cref="IBbsCryptoProvider"/> is a trust
    /// boundary (the Posture-1 swap seam), so no backend or platform exception type is allowed
    /// through — the original is preserved as the inner exception for diagnosis.
    /// </summary>
    /// <param name="operation">The provider call.</param>
    /// <param name="paramName">The calling member's own parameter, for caller-attributable faults.</param>
    /// <param name="what">What was being attempted, for the message.</param>
    /// <param name="ct">The caller's token, so a cancellation claim can be checked against it.</param>
    /// <param name="callerSuppliedKeyMaterial">
    /// Whether the operation forwards caller-supplied <em>key</em> material (a peer public key).
    /// When it does, a <see cref="CryptographicException"/> from the provider means the caller's
    /// bytes were bad — an off-curve point, a low-order point — and must surface as a
    /// parameter-named <see cref="ArgumentException"/>, not as a retryable backend outage. When
    /// it does not, the only caller input is opaque bytes that cannot be "invalid", so the same
    /// exception really is a backend failure.
    /// </param>
    private byte[] RouteToProvider(
        Func<byte[]> operation, string paramName, string what, CancellationToken ct, bool callerSuppliedKeyMaterial = false)
    {
        try
        {
            return operation();
        }
        catch (KeyStoreException)
        {
            throw;
        }
        // Only honor a cancellation claim the caller actually made: a provider inventing one
        // would otherwise report a rollback that never happened ("cancellation never lies").
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (ObjectDisposedException) when (_disposed || _backend.Disposed)
        {
            throw;
        }
        catch (ArgumentException ex) when (ex.ParamName is "publicKey" or "data" or "privateKey")
        {
            // The provider named one of the inputs this store forwarded, so the fault is the
            // caller's — report it against the caller's own parameter. An argument fault naming
            // anything else is a provider-internal bug and falls through to Unavailable, rather
            // than pointing the operator at the wrong side of the boundary.
            throw new ArgumentException(
                $"The request is invalid for the stored key's algorithm ({what}).", paramName, ex);
        }
        catch (CryptographicException ex) when (callerSuppliedKeyMaterial)
        {
            // NFR-3: CryptographicException must not double as the catch-all for malformed
            // input. Here it is worse than a leak — Unavailable tells the caller to retry bytes
            // that will never work, and shows up as a backend outage in monitoring.
            throw new ArgumentException(
                $"The supplied key material is invalid for the stored key's algorithm ({what}).", paramName, ex);
        }
        catch (Exception ex)
        {
            throw new KeyStoreException(
                KeyStoreError.Unavailable, $"The cryptographic provider failed during {what}.", ex);
        }
    }

    /// <summary>
    /// NFR-6.2: assert that produced output really speaks for the identity this store advertises
    /// for the key, before the value reaches the caller.
    /// </summary>
    /// <remarks>
    /// Length is not identity. A provider is an arbitrary injected implementation, and a
    /// length-only check accepts a signature made under a completely different key — the exact
    /// failure <see cref="KeyStoreSigner"/> already defends against on the recoverable path,
    /// where a signature happens to encode its own signer. Verification runs through a private
    /// <see cref="DefaultCryptoProvider"/> rather than the injected one, so a provider cannot
    /// both forge the signature and bless it.
    /// </remarks>
    private static void RequireSpeaksForTheAdvertisedKey(
        InMemoryKeyStoreBackend.StoredEntry entry, KeyStoreAlgorithmSpec spec, byte[] data, byte[] signature)
    {
        bool verified;
        try
        {
            verified = VerificationProvider.Verify(
                spec.KeyType, entry.Info.PublicKey, data, signature, spec.Format);
        }
        catch (Exception ex)
        {
            throw new KeyStoreException(
                KeyStoreError.Unavailable,
                "The cryptographic provider returned a signature that could not be checked against " +
                $"the public key this store advertises for alias '{entry.Info.Alias}'.", ex);
        }

        if (!verified)
            throw new KeyStoreException(
                KeyStoreError.Unavailable,
                "The cryptographic provider returned a signature that does not verify under the public " +
                $"key this store advertises for alias '{entry.Info.Alias}'.");
    }

    /// <summary>
    /// Validates and defensively copies a provider result before it reaches the caller (NFR-6):
    /// a provider may return a wrongly-sized buffer and may retain and later mutate the array it
    /// returned. Only the verified private copy is handed out.
    /// </summary>
    private static byte[] CheckedResult(byte[] result, int? expectedLength, string what)
    {
        if (result is null || result.Length == 0)
            throw new KeyStoreException(
                KeyStoreError.Unavailable, $"The cryptographic provider returned an empty {what}.");

        if (expectedLength is { } expected && result.Length != expected)
            throw new KeyStoreException(
                KeyStoreError.Unavailable,
                $"The cryptographic provider returned a {result.Length}-byte {what}; " +
                $"the requested algorithm produces {expected} bytes.");

        return (byte[])result.Clone();
    }

    private static bool IsBackendFailure(Exception ex) =>
        ex is not (KeyStoreException or OperationCanceledException or ObjectDisposedException or ArgumentException);

    // Lengths the algorithm identifier fixes. DER is deliberately absent: its encoding is
    // variable-width, so there is nothing honest to assert beyond non-emptiness.
    private static int? ExpectedSignatureLength(KeyStoreAlgorithmSpec spec) => spec.Algorithm.Value switch
    {
        "ed25519" => 64,
        "es256-p1363" => 64,
        "es384-p1363" => 96,
        "es512-p1363" => 132,
        "es256k" => 64,
        // Signature and public key live in opposite groups: a G1 public key pairs with a
        // 96-byte G2 signature, and a G2 public key with a 48-byte G1 signature.
        "bls12381g1-basic" => 96,
        "bls12381g2-basic" => 48,
        _ => null,
    };

    private static int? ExpectedSharedSecretLength(KeyStoreAlgorithmSpec spec) => spec.Algorithm.Value switch
    {
        "ecdh-x25519" => 32,
        "ecdh-p256" => 32,
        "ecdh-p384" => 48,
        "ecdh-p521" => 66,
        _ => null,
    };

    private static KeyStoreCapabilitySet BuildCapabilities(bool bbsAvailable)
    {
        var capabilities = new List<KeyStoreCapability>();

        // Every key type the process can mint and hold can be generated and imported; neither
        // operation selects an algorithm, so the bound is on the alias.
        foreach (var keyType in Enum.GetValues<KeyType>())
        {
            capabilities.Add(new KeyStoreCapability(keyType, KeyStoreOperation.Generate, null, MaxAliasBytes));
            capabilities.Add(new KeyStoreCapability(keyType, KeyStoreOperation.Import, null, MaxAliasBytes));
        }

        foreach (var spec in KeyStoreAlgorithmTable.All)
        {
            // BBS is advertised exactly when the native implementation is loadable — the
            // generalization of IBbsCryptoProvider.IsAvailable this contract is built on.
            if (spec.Operation == KeyStoreOperation.BbsSign && !bbsAvailable)
                continue;

            var maxInputBytes = spec.Operation switch
            {
                KeyStoreOperation.Sign => MaxSignInputBytes,
                KeyStoreOperation.KeyAgreement => MaxAgreementInputBytes,
                KeyStoreOperation.BbsSign => MaxBbsInputBytes,
                _ => MaxAliasBytes,
            };

            capabilities.Add(new KeyStoreCapability(spec.KeyType, spec.Operation, spec.Algorithm, maxInputBytes));
        }

        return new KeyStoreCapabilitySet(ComputeRevision(capabilities), capabilities);
    }

    // Derived from the contents rather than minted at random, so the revision is stable for the
    // instance lifetime by construction, and two stores advertising the same capabilities agree
    // — which is the only honest meaning of "the snapshot did not change".
    private static string ComputeRevision(IEnumerable<KeyStoreCapability> capabilities)
    {
        var canonical = string.Join('\n', capabilities
            .Select(c => $"{c.KeyType}|{c.Operation}|{c.Algorithm?.Value ?? "-"}|{c.MaxInputBytes}")
            .OrderBy(line => line, StringComparer.Ordinal));

        return Base64Url.Encode(Hash.Sha256(Encoding.UTF8.GetBytes(canonical)));
    }
}

namespace NetCrypto;

/// <summary>
/// The shared state behind one or more <see cref="CapableInMemoryKeyStore"/> instances: the
/// keys, and the mutation ledger that makes their mutations idempotent. For tests and
/// development. NOT for production use.
/// </summary>
/// <remarks>
/// <para>
/// This exists because the two properties it backs are only meaningful across instances.
/// <b>Namespace isolation</b> is a claim about two stores over <em>one</em> backend refusing to
/// see each other's keys — over two separate dictionaries it would be vacuously true.
/// <b>Ledger durability</b> is a claim about a receipt outliving the store instance that wrote
/// it — a new <see cref="CapableInMemoryKeyStore"/> over the same backend is this library's
/// stand-in for a process restart.
/// </para>
/// <para>
/// The backend owns the key material it holds: disposing it zeroizes every stored key pair
/// across every namespace. A store that was handed a backend does not dispose it — the backend
/// outlives any one store, which is the whole point — so dispose it yourself. A store that
/// created its own backend disposes it along with itself.
/// </para>
/// <para>
/// Receipts are retained for the lifetime of the backend, which trivially satisfies the
/// contract's ≥ 24 hour retention floor for as long as the process lives, and just as trivially
/// fails to survive the process. A production store persists them.
/// </para>
/// </remarks>
public sealed class InMemoryKeyStoreBackend : IDisposable
{
    // One lock for the whole backend. A reference implementation optimizes for being obviously
    // correct: every mutation reads the ledger, decides, and commits key + receipt as one
    // indivisible step, which is exactly the atomicity the idempotency contract requires and
    // exactly what a finer-grained scheme would put at risk.
    internal readonly object Gate = new();

    internal readonly Dictionary<(string Namespace, string Alias), StoredEntry> Keys = new();
    internal readonly Dictionary<(string Namespace, KeyMutationKind Kind, string OperationId), LedgerEntry> Ledger = new();

    internal bool Disposed;

    /// <summary>Creates an empty backend.</summary>
    public InMemoryKeyStoreBackend()
    {
    }

    /// <summary>
    /// Zeroizes every stored key pair in every namespace and marks the backend disposed.
    /// Idempotent; subsequent operations on any store over it throw
    /// <see cref="ObjectDisposedException"/>. The mutation ledger holds only public metadata,
    /// so it needs no wiping.
    /// </summary>
    public void Dispose()
    {
        lock (Gate)
        {
            if (Disposed)
                return;
            Disposed = true;

            foreach (var entry in Keys.Values)
                entry.KeyPair.Dispose();
            Keys.Clear();
            Ledger.Clear();
        }
    }

    /// <summary>One stored key: the material, its public metadata, and its immutable identity.</summary>
    internal sealed record StoredEntry(KeyPair KeyPair, StoredKeyInfo Info, KeyInstanceId InstanceId);

    /// <summary>
    /// One mutation receipt, paired with the canonical fingerprint of the request that produced
    /// it — the fingerprint is what distinguishes an honest retry from a different request
    /// reusing the same idempotency key.
    /// </summary>
    internal sealed record LedgerEntry(byte[] Fingerprint, KeyMutationOutcome Outcome, bool Deleted);
}

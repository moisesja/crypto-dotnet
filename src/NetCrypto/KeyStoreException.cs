namespace NetCrypto;

/// <summary>
/// The portable failure taxonomy for a capable key store. Callers must react differently to
/// each of these, and must be able to do so without catching vendor SDK exception types.
/// </summary>
public enum KeyStoreError
{
    /// <summary>
    /// The requested (key type, operation, algorithm) combination is not advertised by this
    /// store, or the request's algorithm does not match the addressed key. Raised
    /// <em>before</em> any key creation, signing, or agreement — never as a silent downgrade.
    /// Not retryable; route the operation to a store that advertises it.
    /// </summary>
    Unsupported,

    /// <summary>
    /// The <see cref="KeyOperationId"/> was already used in this namespace for a
    /// <em>different</em> request. Not retryable under the same id; mint a new one (or correct
    /// the request to match the original).
    /// </summary>
    IdempotencyConflict,

    /// <summary>
    /// The backend refused the caller: missing or insufficient credentials, a policy denial, a
    /// namespace the instance may not touch. Not retryable without an operator change — page
    /// someone rather than looping.
    /// </summary>
    AccessDenied,

    /// <summary>
    /// The backend is rate-limiting. Retryable after a delay; honor
    /// <see cref="KeyStoreException.RetryAfter"/> when the backend supplied one.
    /// </summary>
    Throttled,

    /// <summary>
    /// The backend is temporarily unreachable or failed internally. Retryable; consider
    /// failover. A read operation is always safe to retry.
    /// </summary>
    Unavailable,

    /// <summary>
    /// The mutation may or may not have been applied — it was accepted and the acknowledgement
    /// was lost. Never assume either outcome. Reconcile through
    /// <see cref="ICapableKeyStore.GetMutationOutcomeAsync"/>; a generate or delete may
    /// alternatively be reconciled by replaying the exact same request under the same
    /// <see cref="KeyOperationId"/>. An <em>import</em> must be reconciled through the outcome
    /// reader only — private key material is never resubmitted.
    /// </summary>
    OutcomeUnknown,
}

/// <summary>
/// The single exception type routed <see cref="ICapableKeyStore"/> operations raise for
/// backend-attributable failures, carrying a portable <see cref="KeyStoreError"/> instead of a
/// vendor SDK exception type.
/// </summary>
/// <remarks>
/// <para>
/// This does <em>not</em> replace argument validation. Null, wrong-shape, and oversize inputs
/// still surface as parameter-named <see cref="ArgumentException"/> /
/// <see cref="ArgumentNullException"/> before any backend work (NFR-3): a caller's own mistake
/// is not a backend condition and must not be retried as one. Likewise, the legacy
/// <see cref="IKeyStore"/> members keep their documented BCL exceptions unchanged — adopting
/// <see cref="ICapableKeyStore"/> changes no existing behavior.
/// </para>
/// <para>
/// No backend exception type escapes a capable-store member. A failure originating inside a
/// provider is re-surfaced here with the original preserved as
/// <see cref="Exception.InnerException"/>, so diagnosis is not lost.
/// </para>
/// </remarks>
public sealed class KeyStoreException : Exception
{
    /// <summary>Creates a key-store exception with the given portable error and message.</summary>
    /// <param name="error">The portable error classification.</param>
    /// <param name="message">A message describing the failure.</param>
    public KeyStoreException(KeyStoreError error, string message)
        : this(error, message, retryAfter: null, innerException: null)
    {
    }

    /// <summary>Creates a key-store exception wrapping an underlying provider failure.</summary>
    /// <param name="error">The portable error classification.</param>
    /// <param name="message">A message describing the failure.</param>
    /// <param name="innerException">The original failure, preserved for diagnosis.</param>
    public KeyStoreException(KeyStoreError error, string message, Exception? innerException)
        : this(error, message, retryAfter: null, innerException)
    {
    }

    /// <summary>
    /// Creates a key-store exception carrying the backend's requested retry delay.
    /// </summary>
    /// <param name="error">The portable error classification.</param>
    /// <param name="message">A message describing the failure.</param>
    /// <param name="retryAfter">
    /// How long the backend asked the caller to wait, when it communicated one. Must not be
    /// negative.
    /// </param>
    /// <param name="innerException">The original failure, preserved for diagnosis.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="retryAfter"/> is negative.</exception>
    public KeyStoreException(KeyStoreError error, string message, TimeSpan? retryAfter, Exception? innerException)
        : base(message, innerException)
    {
        // An undefined classification is worse than no classification: every caller switches on
        // Error, and an unrecognized value silently falls to whatever the default arm does.
        if (!Enum.IsDefined(error))
            throw new ArgumentException(
                $"Error {(int)error} is not a defined {nameof(KeyStoreError)}.", nameof(error));
        if (retryAfter is { } delay && delay < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(retryAfter), delay, "A retry delay must not be negative.");

        Error = error;
        RetryAfter = retryAfter;
    }

    /// <summary>The portable error classification the caller should branch on.</summary>
    public KeyStoreError Error { get; }

    /// <summary>
    /// How long the backend asked the caller to wait before retrying, when it communicated a
    /// delay; otherwise <c>null</c>. Populated for <see cref="KeyStoreError.Throttled"/> and
    /// sometimes <see cref="KeyStoreError.Unavailable"/>. A <c>null</c> value means the backend
    /// said nothing, not that retrying is immediately safe.
    /// </summary>
    public TimeSpan? RetryAfter { get; }
}

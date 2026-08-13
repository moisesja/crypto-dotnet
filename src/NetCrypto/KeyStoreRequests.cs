namespace NetCrypto;

/// <summary>
/// A request to create a new key inside the store, tagged with a caller-minted idempotency key.
/// </summary>
/// <remarks>
/// Replaying this request under the same <see cref="OperationId"/> returns the original result
/// with <see cref="KeyMutationResult.Replayed"/> set, so a retry after a lost acknowledgement
/// cannot double-create (or double-bill).
/// </remarks>
/// <param name="OperationId">The caller-minted idempotency key for this logical operation.</param>
/// <param name="Alias">The alias to create the key under, within the store's namespace.</param>
/// <param name="KeyType">The type of key to create.</param>
public sealed record KeyGenerateRequest(KeyOperationId OperationId, string Alias, KeyType KeyType);

/// <summary>
/// A request to import externally-generated key material, tagged with a caller-minted
/// idempotency key.
/// </summary>
/// <remarks>
/// The material is transferred one way: at acceptance the store reads it once and the
/// caller's <see cref="TransferableKeyMaterial"/> latches permanently unreadable. A replay
/// under the same <see cref="OperationId"/> is recognized from public metadata alone and never
/// reads the secret.
/// </remarks>
/// <param name="OperationId">The caller-minted idempotency key for this logical operation.</param>
/// <param name="Alias">The alias to import the key under, within the store's namespace.</param>
/// <param name="Material">
/// The material to transfer. Consumed by an accepted import; still usable for one retry if the
/// import fails definitively before acceptance.
/// </param>
public sealed record KeyImportRequest(KeyOperationId OperationId, string Alias, TransferableKeyMaterial Material);

/// <summary>
/// A request to destroy a stored key, tagged with a caller-minted idempotency key.
/// </summary>
/// <remarks>
/// The <see cref="InstanceId"/> makes deletion precise: an alias that was already deleted and
/// re-created holds a <em>different</em> key instance, and this request will not destroy it.
/// </remarks>
/// <param name="OperationId">The caller-minted idempotency key for this logical operation.</param>
/// <param name="Alias">The alias to delete, within the store's namespace.</param>
/// <param name="InstanceId">The exact key instance the caller intends to destroy.</param>
public sealed record KeyDeleteRequest(KeyOperationId OperationId, string Alias, KeyInstanceId InstanceId);

/// <summary>
/// A request to sign a single byte string with a stored key, under an explicitly named
/// algorithm and encoding.
/// </summary>
/// <remarks>
/// The store signs the exact supplied bytes under exactly the requested advertised algorithm.
/// A mismatch between the algorithm and the addressed key, or an algorithm the store does not
/// advertise, fails with <see cref="KeyStoreError.Unsupported"/> before any backend work —
/// there is no fallback to a "close enough" curve, hash, or encoding.
/// </remarks>
/// <param name="Alias">The alias of the key to sign with, within the store's namespace.</param>
/// <param name="InstanceId">
/// The key instance the caller believes the alias holds. A stale id — because the alias was
/// deleted and re-created — fails rather than signing under a different key.
/// </param>
/// <param name="Algorithm">
/// The advertised algorithm identifier, which also fixes the observable signature encoding
/// (see <see cref="KeyStoreAlgorithms"/>).
/// </param>
/// <param name="Data">
/// The exact bytes to sign. Hashing, if the algorithm performs any, happens inside the
/// algorithm; nothing is prepended, appended, or canonicalized.
/// </param>
public sealed record KeySignRequest(
    string Alias, KeyInstanceId InstanceId, KeyStoreAlgorithmId Algorithm, ReadOnlyMemory<byte> Data);

/// <summary>
/// A request to produce a BBS multi-message signature with a stored BLS12-381 G2 key.
/// </summary>
/// <remarks>
/// Multi-message signing is exactly the operation a credential issuer wants behind a custody
/// boundary, and the BBS primitive itself takes a raw private scalar — which excludes precisely
/// the keys a custody store exists to hold. Semantics are the draft-pinned ones of
/// <see cref="IBbsCryptoProvider.Sign"/>; the store composes that provider internally and adds
/// no protocol meaning.
/// </remarks>
/// <param name="Alias">The alias of the BLS12-381 G2 key to sign with, within the store's namespace.</param>
/// <param name="InstanceId">The key instance the caller believes the alias holds.</param>
/// <param name="Algorithm">
/// The advertised BBS algorithm identifier — see <see cref="KeyStoreAlgorithms.BbsBls12381Sha256"/>.
/// Plain BLS signing is never accepted here, and is never advertised as BBS.
/// </param>
/// <param name="Messages">
/// The ordered set of messages to sign. Must contain at least one message; order is part of
/// what is signed.
/// </param>
/// <param name="Header">
/// The BBS signature <c>header</c>, fixed by the signer and bound into the signature — the
/// same value must be supplied to verify or to derive a proof. Pass
/// <see cref="ReadOnlyMemory{T}.Empty"/> to bind no header.
/// </param>
public sealed record KeyBbsSignRequest(
    string Alias,
    KeyInstanceId InstanceId,
    KeyStoreAlgorithmId Algorithm,
    IReadOnlyList<ReadOnlyMemory<byte>> Messages,
    ReadOnlyMemory<byte> Header);

/// <summary>
/// A request to perform ECDH against a stored key-agreement key and return the raw shared
/// secret Z.
/// </summary>
/// <remarks>
/// No KDF, truncation, or normalization is applied — identical to
/// <see cref="IKeyStore.DeriveSharedSecretAsync"/> and
/// <see cref="ICryptoProvider.DeriveSharedSecret"/>. Apply a NIST SP 800-56A-conformant KDF
/// (Concat KDF, HKDF, KMAC) before using the result as keying material.
/// </remarks>
/// <param name="Alias">The alias of the key-agreement key, within the store's namespace.</param>
/// <param name="InstanceId">The key instance the caller believes the alias holds.</param>
/// <param name="Algorithm">The advertised ECDH algorithm identifier — see <see cref="KeyStoreAlgorithms"/>.</param>
/// <param name="PeerPublicKey">
/// The peer's public key in the canonical encoding for the curve: raw 32 bytes for X25519;
/// SEC1 compressed (<c>0x02</c>/<c>0x03</c> ‖ X) or uncompressed (<c>0x04</c> ‖ X ‖ Y) for the
/// NIST curves.
/// </param>
public sealed record KeyAgreementRequest(
    string Alias, KeyInstanceId InstanceId, KeyStoreAlgorithmId Algorithm, ReadOnlyMemory<byte> PeerPublicKey);

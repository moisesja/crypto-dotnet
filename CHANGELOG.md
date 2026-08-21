# Changelog

All notable changes to **NetCrypto** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-08-20

### Fixed

- **`TransferableKeyMaterial.FromKeyPair` now validates key type and both key lengths before
  creating the one-way transfer owner**, matching `FromRawKey`. A malformed `KeyPair`—including
  the common 64-byte libsodium Ed25519 secret-key representation where NetCrypto requires the
  32-byte seed—previously crossed the custody boundary and was discoverable only after the
  receiving store spent the transfer's single `Consume`. Undefined key types and malformed
  public/private lengths now fail immediately with parameter-named `ArgumentException`; valid
  callers are unchanged. (#30)

## [1.7.0] - 2026-08-18

### Changed

- **`TransferableKeyMaterial` consumption is now public** — `Consume<T>`, the
  `KeyMaterialReader<T>` delegate, and `Discard()` are public so key stores implemented
  outside this assembly (an HSM-, KMS-, or Vault-backed `ICapableKeyStore`) can accept
  routed imports at all. Previously the owner's only read path was `internal` with
  `InternalsVisibleTo` limited to `NetCrypto.Tests`, so the only import-capable store
  that could exist was the in-assembly `CapableInMemoryKeyStore`. The once-only latch,
  zeroization in `finally`, the `IsConsumed` signal, and the replay-path `Discard` all
  hold for every caller, and no export format or second read is added. What the widening
  does change is the threat model, now stated in the type's own docs and PRD FR-7b rule
  7: a live instance is a **bearer secret**, readable by whoever holds it — including
  anything a `KeyImportRequest` is routed through, such as a DI decorator or logging
  wrapper. Construct it late and hand it straight to the store you mean to trust. (#28)

### Fixed

- **A key material reader no longer runs while the material's lock is held**, so it can take
  its own locks without deadlocking. Because publishing `Consume` (above) makes the reader
  arbitrary out-of-assembly code, and a real store's reader takes the store's own mutex, holding
  the instance lock across that call spliced the instance into the application's lock order: an
  ordinary two-lock cycle (thread A reads while holding the store mutex; thread B disposes the
  material while holding that mutex) deadlocked both threads and left the secret **stranded
  un-wiped in the pinned buffer** for the process lifetime. The reader now runs with the lock
  released — the lock guards only the state transitions and the zeroization — which also keeps
  `IsConsumed` and `Dispose` responsive while a read is in flight and turns a cross-thread
  re-entry into the same refusal as a same-thread one. Surfaced by the adversarial pass; the
  path became reachable only by publishing `Consume` in this release, so no shipped version was
  exposed. (#28)
- **A key material reader can no longer re-enter `Consume`.** `Monitor` is reentrant and
  the consumption latch only closes on the way out, so a reader that called `Consume`
  again on the material it was reading took a *second* read (the internal read counter
  reached 2, against a contract of "never exceeds one") and zeroized the pinned buffers
  the outer read was still borrowing — leaving the accepting store to commit an
  **all-zero key**. The nested call is now refused with `InvalidOperationException`, and
  a `Dispose()`/`Discard()` that arrives during a read latches the instance disposed
  immediately (`IsConsumed` reports `true`, every other member throws
  `ObjectDisposedException`) while only the physical wipe defers to the in-flight
  `Consume`'s completion — idempotent and non-throwing throughout. Reading `KeyType` or
  `PublicKey` from inside a reader (before any dispose) is unaffected. This is PRD FR-7b rule 14 applied to
  the import reader; the path became reachable only by publishing `Consume` in this
  release, so no shipped version was exposed. (#28)

## [1.6.0] - 2026-08-13

### Added

- **`ICapableKeyStore`** — the contract a production custody backend (cloud KMS, HSM partition,
  encrypted software keystore) needs in order to sit behind `IKeyStore` without its consumer
  inventing a parallel signer surface downstream. Ships as a **derived** interface plus new
  types: `IKeyStore` gains no member, so every existing store implementation, `ISigner`,
  `KeyStoreSigner`, and `InMemoryKeyStore` caller stays source- and binary-compatible. It adds no
  export operation anywhere, no KDF, and no protocol semantics. (#26)
  - **Capability discovery** — `IKeyStoreCapabilityProvider.GetCapabilitiesAsync` returning a
    deeply immutable `KeyStoreCapabilitySet` of `(KeyType, KeyStoreOperation, algorithm,
    MaxInputBytes)` tuples, with a `Revision` stable for the store instance's lifetime. Backends
    differ by configuration — an HSM partition without BLS, a KMS without X25519 — and without
    discovery the first real operation is the probe. This generalizes the one capability probe
    NetCrypto already had, `IBbsCryptoProvider.IsAvailable`. Honesty is bidirectional: every
    advertised tuple works, and every unadvertised one fails with `Unsupported` *before* key
    creation or signing, never as a silent downgrade.
  - **`KeyInstanceId`** — immutable, never-reused identity for a key instance, carried on
    `StoredKeyInfo` (optional, `null` on legacy paths) and on every capable result. Aliases are
    reusable and KMS aliases can be rebound; a stale reference now fails instead of silently
    signing under whatever key answers to the name. This generalizes to the whole surface the
    alias-rebinding defense `KeyStoreSigner` could only apply on the recoverable path (#21),
    where a signature happens to encode its own signer.
  - **`KeyStoreNamespaceId`** — least-privilege scoping enforced on every member, including the
    inherited `IKeyStore` ones, so multi-tenant scoping is a contract property rather than an
    alias-prefix convention. Naming is not authorization.
  - **Durably idempotent mutations** — `GenerateAsync`/`ImportAsync`/`DeleteAsync` over
    `KeyGenerateRequest`/`KeyImportRequest`/`KeyDeleteRequest`, identified by
    `(NamespaceId, KeyMutationKind, KeyOperationId)`, plus `GetMutationOutcomeAsync` returning a
    durable `KeyMutationOutcome` receipt. A retry after a lost acknowledgement replays instead of
    double-creating; the same id with a different request is `IdempotencyConflict` rather than a
    silent overwrite. The canonical request fingerprint is length-prefixed, so no two distinct
    requests can collide.
  - **Algorithm- and encoding-bearing operations** — `SignAsync(KeySignRequest)` and
    `DeriveSharedSecretAsync(KeyAgreementRequest)` select a `KeyStoreAlgorithmId` from the
    `KeyStoreAlgorithms` table (`ed25519`, `es256-der`/`es256-p1363`, `es384-*`, `es512-*`,
    `es256k`, `bls12381g{1,2}-basic`, `ecdh-*`, `bbs-bls12381-sha256`). The identifier binds the
    observable encoding, which is what finally makes the existing `EcdsaSignatureFormat`
    distinction reachable for a key that never leaves its store — JOSE/JWS/COSE/WebAuthn mandate
    IEEE P1363, X.509/CMS use DER, and the by-reference path previously could not ask for either.
  - **`SignBbsAsync`** — BBS multi-message signing with a store-held BLS12-381 G2 key. The same
    shape #21 fixed for recoverable ECDSA: the primitive takes a raw private scalar, which
    excludes exactly the keys a custody store exists to hold. Advertised only where the platform
    can really do it; plain BLS signing is never advertised or accepted as BBS.
  - **`TransferableKeyMaterial`** — a one-way, single-use import owner with **no** private-key
    read, format, or export surface, holding the secret in a pinned buffer (the #17 zeroization
    infrastructure). Handing a `KeyPair` to a store leaves the caller with a live export surface,
    since `KeyPair.PrivateKey` clones the secret on every read; this closes that. Read exactly
    once at acceptance, then zeroized and latched permanently unreadable; a failure *before*
    acceptance leaves it usable for exactly one retry; a recognized replay destroys it without
    reading it, so an `OutcomeUnknown` import is reconciled through the receipt rather than by
    resubmitting key material.
  - **`KeyStoreException` / `KeyStoreError`** — the portable taxonomy (`Unsupported`,
    `IdempotencyConflict`, `AccessDenied`, `Throttled`, `Unavailable`, `OutcomeUnknown`) with an
    optional `RetryAfter`, so callers can back off, fail over, page an operator, or reconcile
    without catching vendor SDK exception types. No backend, native, or platform exception type
    escapes a capable-store member; the original is preserved as `InnerException`. Argument
    faults stay parameter-named `ArgumentException` (NFR-3), and the legacy `IKeyStore` members
    keep their documented BCL exceptions unchanged.
- **`CapableInMemoryKeyStore` + `InMemoryKeyStoreBackend`** — the reference implementation and
  contract oracle, a **sibling** of `InMemoryKeyStore` (which is untouched). The backend is
  separate because the two properties it underwrites are only meaningful across instances:
  namespace isolation is a claim about two stores over *one* backend, and receipt durability is a
  claim about a receipt outliving the store instance that wrote it.

### Fixed

- **`InMemoryKeyStore.DeriveSharedSecretAsync` no longer leaks a platform
  `CryptographicException`** for a peer public key that is the right length but unusable — an
  off-curve point, a low-order X25519 point, a compressed point with no solution on the curve.
  These now surface as the parameter-named `ArgumentException("peerPublicKey")` the method's
  contract already promised, with the platform exception preserved as `InnerException`. NFR-3
  reserves `CryptographicException` for genuine crypto failures and forbids it doubling as the
  catch-all for malformed input; the wrong-*length* case was already correct, so only invalid
  input behavior changes and no valid-input behavior is affected. Found by the issue #26
  input-validation sweep while auditing the new store's inherited surface.

### Security hardening

Four integrity gaps in the new surface, found by the issue #26 adversarial pass and NFR-3 sweep
before release. Each is recorded here because the shape looked correct without them, and a
downstream backend author would inherit the same mistakes:

- **Provider output is verified against the key it claims to speak for**, not merely
  length-checked. A hostile or buggy `ICryptoProvider` could otherwise return a well-formed
  signature made under a *different* key — or, for DER, any bytes at all — and the store would
  hand it to the caller. Verification runs through an internal `DefaultCryptoProvider` rather than
  the injected one, so a provider cannot both forge a signature and bless it. This is NFR-6.2
  applied to the whole capable surface, generalizing what `KeyStoreSigner` already does on the
  recoverable path.
- **Identifiers and aliases must be well-formed UTF-16.** `Encoding.UTF8` uses replacement
  fallback, so every unpaired surrogate — and U+FFFD itself — encodes to the same three bytes. Two
  distinct mutation requests could therefore share one fingerprint, and the second would silently
  *replay* the first, returning a success receipt naming an alias the caller never asked for.
  Well-formed surrogate pairs remain legal.
- **Import proves the transferred public key belongs to the transferred private key**, and
  `TransferableKeyMaterial.FromRawKey` rejects wrong-length material at construction. Without
  this, `StoredKeyInfo.PublicKey` — the verification identity downstream DID/VC code publishes —
  was attacker-chosen, and a 1-byte "P-256 key pair" could cross the custody boundary and be
  published as real, failing only at first use.
- **A provider cannot re-enter the store.** `Monitor` is reentrant, so a provider callback
  previously walked straight through the backend lock; a nested delete then zeroized the pinned
  buffer that the in-flight private-key borrow was still reading, and the store returned a
  signature for a key it had just destroyed.
- Also: a caller-supplied `Messages` list whose enumerator and indexer disagree can no longer sign
  past `MaxInputBytes`; a `with` expression can no longer install a value a constructor would have
  reject (validation moved onto the `init` accessors, which `with` does call); a
  `CryptographicException` over caller-supplied key material is reported as a parameter fault
  rather than a retryable `Unavailable`; a provider cannot fabricate a cancellation the caller
  never requested; and a provider-internal argument fault is no longer blamed on the caller.

Further gaps found by PR #27 review, fixed before release with regression tests proven
genuine by reverting each guard:

- **BBS output no longer self-certifies.** The return-path check previously asked the injected
  provider to verify its own signature, so a provider lying in both `Sign` and `Verify` passed 80
  bytes of noise. The reference store now advertises BBS only when both its configured producer
  and the independent in-repo `DefaultBbsCryptoProvider` verifier are available; there is no
  same-provider fallback in the supported no-native mode. The producer also receives a separate
  deep copy of the messages, so it cannot rewrite the mutable `byte[]` elements that the
  independent verifier uses as evidence.
- **Generate/import no longer leak backend exceptions by type.** Generator-originated
  `ObjectDisposedException`, fabricated `OperationCanceledException`, internal
  `ArgumentException`, native load failures, and other backend faults now surface as
  `KeyStoreException(Unavailable)` with the original as `InnerException`. Only a private-key
  rejection explicitly naming the forwarded `privateKey` remains a caller argument fault.
- **Generator output is checked before commit.** A same-type `KeyPair` can still pair key A's
  public bytes with key B's private bytes. Generate and import now independently re-derive the
  public half from the returned private half and reject a mismatch as `Unavailable`, before any
  key or mutation receipt is stored.
- **`KeyStoreCapability` preserves its cross-field invariant under `with`.** Mutating `Operation`
  alone could keep an algorithm on a Generate capability (or strip the one Sign requires); the
  `Operation` accessor now re-validates the pairing. Changing operation and algorithm across that
  divide requires constructing a new capability.
- **BBS bounds the message count (4096 in the reference store) and byte total before copying.**
  `Messages.Count` is untrusted and `MaxInputBytes` cannot limit a count of zero-byte messages, so
  a list reporting `int.MaxValue` produced `OutOfMemoryException` at the snapshot allocation.
  Absurd counts — negative included — now fail as parameter-named argument faults. Oversized
  headers/messages stop before copying, and a list whose indexer cannot honor its own `Count`
  becomes `ArgumentException("request")` rather than leaking `IndexOutOfRangeException`.

Plus the two notes from the approving review: the legacy `SignAsync` overload's XML docs now state
it carries no return-path identity check and point at `SignAsync(KeySignRequest)`, and the legacy
`GenerateAsync` enters the reentrancy scope before invoking the key generator, matching the
request-based path.

### Documentation

- **README gains an "Implementing a capable key store" section** — the ten contract rules and the
  algorithm-identifier table, written for authors of downstream backend adapters, since the shape
  alone does not communicate the contract.
- **New sample** `NetCrypto.Samples.CapableKeyStore` (discovery → validate → sign, plus namespace
  scoping, idempotent retry, instance-id rebind rejection, import ownership, and BBS by
  reference), added to the samples index. It exits 0 with and without the native BBS library.
- **PRD `FR-7b`** records the full normative contract and its acceptance criteria, alongside the
  concept-to-FR traceability row; `netcrypto-concept.md` §2.6 notes the custody boundary.

## [1.5.0] - 2026-08-05

### Fixed

- **RFC 8812 ES256K high-S interoperability:** `DefaultCryptoProvider.Verify` now accepts a
  mathematically valid high-S secp256k1 signature by normalizing it to the equivalent low-S form
  before the NBitcoin verification call. Signing remains deterministic and low-S; malformed or
  out-of-range compact scalars still return `false`. This removes an inherited Bitcoin/BIP-62
  policy from the general-purpose verification path — neither RFC 8812 nor FIPS 186-5 requires
  low-S — and brings secp256k1 in line with how the NIST curves in this provider have always
  behaved. Protocols requiring low-S canonicality must enforce `S ≤ n/2` themselves;
  `KeyStoreSigner`'s recoverable-output guard and `Secp256k1Recoverable` are unchanged. (#23)

### Documentation

- **ECDSA signature non-uniqueness is now stated on the API surface.** `ICryptoProvider.Verify`,
  the README, `RecoverableSignature`, and the signing sample now record that `(R, S)` and
  `(R, n-S)` are both valid for _every_ ECDSA key type here — P-256/384/521 included, where this
  was already true and undocumented — and that replay caches, dedup sets, and idempotency checks
  must therefore key on the message (nonce/`jti`/digest) rather than on signature bytes. Issue #23
  asked that whichever way the policy landed be documented; the caveat is deliberately written
  against ECDSA in general rather than secp256k1 alone, since scoping it to one curve is what made
  the property undiscoverable in the first place.

### Internal

- **Public API baseline promoted.** `PublicAPI.Shipped.txt` had not been updated since GA 1.0.0,
  so every API added in 1.1.0, 1.2.0, 1.3.0 and 1.4.0 — `Base64Url`, the AEAD size constants,
  `IKeyStore.DeriveSharedSecretAsync`, `IRecoverableDigestSigner`, `RecoverableSignature`,
  `KeyPair.WithPrivateKey`, the `IDisposable` members, `KeyTypeExtensions.ToUncompressed` — was
  still recorded as _unshipped_ despite being published to NuGet. All 35 entries are now in the
  shipped baseline and `PublicAPI.Unshipped.txt` is empty again, restoring the analyzer's ability
  to distinguish frozen surface from surface added since the last release. No public API changed.

## [1.4.0] - 2026-07-26

### Added

- **`IRecoverableDigestSigner`** — the abstraction over the FR-12 recoverable-secp256k1
  primitive, so keys held behind `ISigner`/`IKeyStore` (HSM-first, non-extractable) can produce
  recoverable digest signatures for EVM flows (did:ethr EIP-155 transactions, ERC-1056
  meta-transactions). `SignDigestAsync(digest32, ct)` signs a caller-supplied 32-byte digest
  **as-is** (no internal hashing) and returns a **`RecoverableSignature`** — a new
  `readonly record struct` pairing the 64-byte compact `R‖S` with the **raw** recovery id
  (0–3). The FR-12 boundary is inherited verbatim: no Keccak and no EVM `v`-encoding anywhere
  in NetCrypto; both remain the wallet layer's job. (#21)
- **Implementations:** `KeyPairSigner` and `KeyStoreSigner` now implement
  `IRecoverableDigestSigner` (the signer returned by `IKeyStore.CreateSignerAsync`
  pattern-matches to it), and `InMemoryKeyStore` implements the new
  **`IKeyStore.SignDigestAsync(alias, digest32, ct)`** member. On `IKeyStore` the member ships
  as a **default interface implementation that throws `NotSupportedException`**, so every
  external store implementation stays source- and binary-compatible and opts in explicitly.
  `KeyPairSigner`/`InMemoryKeyStore` sign via the `KeyPair.WithPrivateKey` borrow (no
  private-key heap copy, consistent with the #17 zeroization work). (#21)
- Input contract (NFR-3): a digest that is not exactly 32 bytes throws a parameter-named
  `ArgumentException` before any crypto operation at every entry point; a non-secp256k1 key
  throws `NotSupportedException` naming the key type (recoverable ECDSA is a secp256k1
  capability — Ed25519/BLS have no recovery-id concept); unknown alias throws
  `KeyNotFoundException` and disposed signer/store throws `ObjectDisposedException`, matching
  the existing `SignAsync` semantics. The digest content is opaque — no semantic validation
  (an all-zero digest is a valid ECDSA input). (#21)

### Security

- **`KeyStoreSigner.SignDigestAsync` verifies the store's output at the boundary.** Because the
  backing `IKeyStore` may be an arbitrary external provider (HSM, cloud KMS), the returned
  signature is now checked before being handed back: it must be a structurally valid recoverable
  signature (64-byte `R‖S`, recovery id 0–3), must be low-S normalized, **and** must recover to
  the signer's advertised `PublicKey`, otherwise a `CryptographicException` is thrown. The
  provider-owned signature array is cloned before validation and only the verified clone is
  returned; the advertised public key is held as a private snapshot; and separate digest copies
  are retained for verification and passed to the provider. A cached non-secp256k1 key type is
  rejected before the provider is called. This closes review findings covering malformed and
  high-S provider results, mutable provider/caller buffers, and alias rebinding (delete + recreate
  a key under the same alias) letting an old signer emit a signature that recovers to a
  _different_ key than it advertises. (#21)
- **The `IKeyStore.SignDigestAsync` default implementation now validates the digest length** (bad
  length → parameter-named `ArgumentException("digest32")`) before signalling `NotSupportedException`,
  so the "parameter-named `ArgumentException` at every entry point" contract holds for stores that
  rely on the default. (#21)
- **`RecoverableSignature` equality is documented as reference-based** on `Signature64` (matching the
  raw-tuple return of `Secp256k1Recoverable.Sign`): RFC 6979 determinism makes two signings of the
  same key+digest byte-identical, but the values are not `Equals`/`==`-equal, so callers building
  deduplication or replay caches must compare `Signature64` by content. (#21)

## [1.3.0] - 2026-07-24

### Added

- **`KeyTypeExtensions.ToUncompressed(this KeyType, byte[])`** — public, validated EC point
  decompression (33/49/67-byte compressed SEC1 → 65/97/133-byte `0x04‖X‖Y`), the inverse of
  `NormalizeToCompressed`, for secp256k1, P-256, P-384, and P-521. Already-uncompressed input is
  accepted as a validated pass-through (returned as a defensive copy); an off-curve point never
  passes through unchecked. Null → `ArgumentNullException`; everything else invalid (wrong
  length/prefix, X with no curve solution, off-curve point, identity encoding, non-EC key type)
  → parameter-named `ArgumentException`. Unblocks net-did's did:ethr resolver, which derives
  Ethereum addresses (`keccak256(X‖Y)[-20:]`) from bare compressed secp256k1 keys and previously
  had to call `NBitcoin.Secp256k1` directly for this one operation. (#19)

## [1.2.0] - 2026-07-10

### Added

- **`KeyPair : IDisposable`** — `Dispose()` deterministically zeroizes the key material (via
  `CryptographicOperations.ZeroMemory`) instead of leaving it on the heap until garbage
  collection; afterwards any key-material access throws `ObjectDisposedException` (`KeyType`
  stays readable) and disposal is idempotent. The canonical private-key copy now lives in a
  **pinned** allocation, so a compacting GC cannot duplicate the secret before the wipe. (#17)
- **`KeyPair.WithPrivateKey<T>(Func<ReadOnlySpan<byte>, T>)`** — a borrow API that lends the
  private key as a span over the canonical pinned copy. Unlike the `PrivateKey` getter (which
  clones the secret onto the heap on every read), borrowing creates no copy, so there is nothing
  new to zeroize. All internal NetCrypto consumers (`InMemoryKeyStore`, `KeyPairSigner`,
  `DeriveX25519FromEd25519`) switched to it. (#17)
- **`InMemoryKeyStore : IDisposable`** — disposing the store zeroizes every stored key pair, and
  further operations throw `ObjectDisposedException`. (#17)
- **`KeyPairSigner : IDisposable`** — the signer owns the wrapped `KeyPair` by default (disposing
  the signer destroys the key); a new `KeyPairSigner(keyPair, crypto, ownsKeyPair)` overload opts
  out for externally managed pairs. (#17)

### Changed

- **`InMemoryKeyStore.DeleteAsync` now destroys the evicted key** — the removed `KeyPair` is
  disposed (zeroized), so delete is a destruction operation, not just a directory removal. A
  caller that imported a pair and kept using the same instance after deleting its alias will now
  observe `ObjectDisposedException`; the store documents that it takes ownership of imported
  pairs. (#17)
- **Key-generation intermediates are wiped** — the Ed25519 expanded scalar and clamped X25519
  scalar in `DeriveX25519FromEd25519` (now stack-allocated and cleared), exported NSec private
  blobs, `ECParameters.D` after every platform key import (ECDSA sign, NIST ECDH, and generator
  restore paths), secp256k1 scalar buffers, the BLS IKM and `ToBendian()` scalar copies, and the
  transient private-key clone inside `JwkConverter.ToPrivateJwk` are all zeroized in `finally`
  blocks. The EC private-scalar range check now compares fixed-length big-endian bytes instead of
  materializing the scalar in an unwipeable `BigInteger`. (#17)

### Docs

- XML docs on `KeyPair`, `WithPrivateKey`, and `ToPrivateJwk` state the managed-memory
  best-effort caveat explicitly: zeroization shrinks the exposure window (JIT spills,
  caller-held clones, and JWK `d` strings remain outside the library's control). (#17)

## [1.1.0] - 2026-06-14

Targeting **1.1.0** — additive changes from the didcomm-dotnet → NetCrypto integration (#10, #11, #12).

### Added

- **`IKeyStore.DeriveSharedSecretAsync(alias, peerPublicKey, ct)`** — a key-agreement (ECDH) operation
  on the key-store abstraction, the encryption-side counterpart to `SignAsync`. It performs ECDH against
  a stored key-agreement private key and returns the **raw shared secret Z** (no KDF applied — the caller
  still owns the Concat-KDF/HKDF step, matching `ICryptoProvider.DeriveSharedSecret`). This lets a
  non-extractable / HSM-bound key participate in ECDH-based decryption (JOSE `ECDH-ES`/`ECDH-1PU`, DIDComm
  anoncrypt/authcrypt) without the private scalar ever leaving the store. Implemented by `InMemoryKeyStore`
  for X25519, P-256, P-384, and P-521; demonstrated in the `KeyAgreement` sample. (#11)
- **`Base64Url` codec** — `Base64Url.Encode(ReadOnlySpan<byte>) → string` (RFC 4648 §5, no `=` padding)
  and `Base64Url.Decode(ReadOnlySpan<char>) → byte[]` (tolerates optional padding but otherwise strict —
  rejects whitespace and any non-alphabet character rather than silently stripping it, so each byte string
  has exactly one accepted textual form), a thin wrapper over the BCL `System.Buffers.Text.Base64Url`.
  A single source of truth for the JOSE/JWK byte boundary so consumers stop re-implementing it. (#12)
- **Unified AEAD size metadata** — each content-encryption cipher now exposes its key/nonce/tag sizes as
  `public const int`: `AesGcmCipher` (32/12/16), `AesCbcHmacCipher` (`KeySizeBytes` 64 / `IvSizeBytes` 16 /
  `TagSizeBytes` 32), `XChaCha20Poly1305Cipher` (32/24/16). A JOSE builder can size the CEK and IV/nonce
  from the source of truth instead of a hard-coded table. (#12)

### Security

- **Wrong-length EC public keys now throw a parameter-named `ArgumentException`.** An adversarial
  review of the new `IKeyStore.DeriveSharedSecretAsync` receive path found that a wrong-length NIST EC
  public/peer key surfaced as an opaque platform `CryptographicException` (or, for an in-range short
  coordinate, could be silently accepted as a different point) instead of the parameter-named
  `ArgumentException` the NFR-3 contract requires. `DefaultCryptoProvider.ImportEcPublicKey` now validates
  the SEC1 length against the curve up front (compressed `1+coordLen`, uncompressed `1+2·coordLen`),
  closing the gap for `DeriveSharedSecret` / `IKeyStore.DeriveSharedSecretAsync` and the ECDSA `Verify`
  import path. No invalid-curve weakness was found — off-curve points of the correct length were already
  rejected with `CryptographicException`; this only tightens the _malformed-length_ exception type.
- **`JwkConverter.ExtractPublicKey` now documents its on-curve guarantee.** The method already
  validated EC `(x, y)` coordinates against the stated curve (via `EcPointValidator.EnsureOnCurve`)
  before returning; that invalid-curve defense (RFC 7518 §6.2.2) is now stated explicitly in the
  public XML contract and pinned by a regression test using a _fabricated, self-consistent_
  (valid-length but off-curve) JWK. Consumers doing `ExtractPublicKey → DeriveSharedSecret` on an
  untrusted `epk` inherit the protection by default rather than relying on undocumented behavior. (#10)

## [1.0.0] - 2026-06-13

First stable (GA) release. The public API is frozen: `PublicAPI.Shipped.txt` is the
authoritative contract and `PublicAPI.Unshipped.txt` is empty. From here, additive changes
bump the minor version and breaking changes the major. No `--prerelease` flag is required.

This release also includes the malformed-input security hardening developed as `1.0.0-preview.3`,
which was never published as a standalone release.

### Security

- Malformed key inputs now surface as a **parameter-named `ArgumentException`** instead of leaking
  a backend exception type (`System.FormatException` from NSec, `Nethermind.Crypto.Bls+BlsException`,
  or a platform `CryptographicException`). Up-front validation was added at every backend hand-off:
  Ed25519 / X25519 (32-byte length), NIST EC private keys (per-curve scalar length **and**
  `0 < D < n` range), and BLS12-381 (32-byte length + invalid-scalar mapping).
- `DefaultKeyGenerator.DeriveX25519PublicKeyFromEd25519` now rejects inputs that map to a
  **low-order Curve25519 point** (e.g. the all-zero Ed25519 key), instead of minting a degenerate,
  small-subgroup X25519 `PublicKeyReference`.
- The NFR-3 fuzz suite no longer carries a "known backend deviations" allow-list; any non-contract
  exception fails the suite.

### Changed

- Stabilized to GA `1.0.0` — the package is now a non-prerelease NuGet release.

### Documentation

- Documented the supported **native platform RID matrix** (`osx-arm64`, `osx-x64`, `linux-x64`,
  `linux-arm64`, `win-x64`) and that the published `.nupkg` ships `runtimes/{rid}/native/`
  transitively, verified by release CI against the packed artifact and a BBS smoke test. (#4)
- Documented that the supported BBS keygen path is `DefaultKeyGenerator.Generate(KeyType.Bls12381G2)`
  / `Bls12381G1`, and that raw FFI keygen is intentionally internal. (#6)
- Confirmed `EcPointValidator.EnsureOnCurve` as the public EC on-curve validation entry point, with
  point decompression intentionally internal. (#7)

## [1.0.0-preview.2] - 2026-06-13

### Added

- Exposed the BBS signature **`header`** parameter on `IBbsCryptoProvider` /
  `DefaultBbsCryptoProvider` (`Sign`, `Verify`, `DeriveProof`, `VerifyProof`) as an optional
  `ReadOnlySpan<byte>` (default empty). The header is fixed by the signer and committed by both
  verification and any derived proof — letting a consumer bind application data (e.g. the W3C
  `bbs-2023` mandatory-disclosure group) that a holder cannot drop or alter. (#2)

### Changed

- **Breaking (pre-GA):** renamed the `nonce` parameter on `DeriveProof` / `VerifyProof` to
  `presentationHeader` — it is the BBS presentation header (`ph`), distinct from the new signature
  `header`. Positional callers are unaffected; named-argument (`nonce:`) callers must update.

## [1.0.0-preview.1] - 2026-06-11

Initial preview. NetCrypto consolidates every cryptographic primitive for the NetCid/NetDid
library stack behind stable interfaces, so no domain library binds directly to a specific backend.

### Added

- **Key model:** `KeyType` (Ed25519, X25519, P-256/384/521, secp256k1, BLS12-381 G1/G2), `KeyPair`,
  `PublicKeyReference`, and multibase/multicodec encoding (`MultibasePublicKey`) via NetCid.
- **Signing & verification** (`ICryptoProvider` / `DefaultCryptoProvider`): EdDSA (Ed25519), ECDSA
  on the NIST curves (DER and IEEE P1363), secp256k1 (64-byte compact, low-S signing), and BLS12-381
  (G1/G2 variants, hash-to-curve).
- **Recoverable secp256k1 ECDSA** (`Secp256k1Recoverable`) over a caller-supplied 32-byte digest,
  returning the raw recovery id (no EVM `v`-encoding).
- **BBS selective-disclosure signatures** (`IBbsCryptoProvider` / `DefaultBbsCryptoProvider`,
  BLS12-381-SHA-256, draft-irtf-cfrg-bbs-signatures-10): sign, verify, derive-proof, verify-proof;
  `BbsCiphersuite`; `BbsUnavailableException`; and the supported **BBS-absent mode** (`IsAvailable`).
- **Key generation** (`IKeyGenerator` / `DefaultKeyGenerator`) for all key types, including
  Ed25519→X25519 derivation.
- **Key agreement:** X25519 (with an HKDF-SHA256 convenience) and raw ECDH "Z" for X25519 and
  P-256/384/521.
- **KDFs:** HKDF (SHA-256/384/512) and Concat KDF (NIST SP 800-56A).
- **AEADs:** AES-256-GCM (`A256GCM`), AES-256-CBC + HMAC-SHA-512 (`A256CBC-HS512`),
  XChaCha20-Poly1305 (`XC20P`); and AES Key Wrap (`A256KW`).
- **Hashing:** SHA-256/384/512 and Keccak-256 (original padding, not SHA3-256).
- **JWK conversion** (`JwkConverter`) for all key types.
- **Signing & key-store abstractions:** `ISigner`, `KeyPairSigner`, `KeyStoreSigner`, `IKeyStore`,
  `InMemoryKeyStore`.
- **EC point validation** (`EcPointValidator.EnsureOnCurve`) — the invalid-curve-attack defense.
- **Dependency injection:** `AddNetCrypto()` (swap-seam via `TryAdd`).
- **Native BBS distribution** for five RIDs (`osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64`,
  `win-x64`), packed into the single NuGet package; the repository stays source-only.

[Unreleased]: https://github.com/moisesja/crypto-dotnet/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.0.0-preview.2...v1.0.0
[1.0.0-preview.2]: https://github.com/moisesja/crypto-dotnet/compare/v1.0.0-preview.1...v1.0.0-preview.2
[1.0.0-preview.1]: https://github.com/moisesja/crypto-dotnet/releases/tag/v1.0.0-preview.1

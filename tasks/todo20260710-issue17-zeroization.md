# Issue #17 — Deterministic zeroization for asymmetric key material

Plan for https://github.com/moisesja/crypto-dotnet/issues/17 (additive, semver-minor).

## Design decisions

- `KeyPair : IDisposable`; private key stored in a **pinned** allocation
  (`GC.AllocateArray<byte>(len, pinned: true)`) so the GC cannot copy the secret around the
  heap before the wipe. `Dispose()` zeroizes both private and public backing arrays
  (idempotent); post-dispose access to any key-material member throws
  `ObjectDisposedException`. No finalizer (issue design: disposal-based; non-disposing
  callers keep today's behavior exactly).
- Borrow API: `public T WithPrivateKey<T>(Func<ReadOnlySpan<byte>, T> use)` — span-based,
  no heap copy escapes (net10.0 `Func` allows ref-struct type args). XML docs point the
  `PrivateKey` clone getter at it and state the managed-memory best-effort caveat.
- Internal `[SetsRequiredMembers]` span ctor `KeyPair(KeyType, ReadOnlySpan<byte> pub, ReadOnlySpan<byte> priv)`
  so generator paths never mint intermediate private-key arrays that the public init-props
  would clone-and-orphan. Explicit `public KeyPair()` preserved (shipped API).
- `InMemoryKeyStore : IDisposable`: `Dispose()` disposes all stored pairs; `DeleteAsync`
  disposes the evicted pair (delete now *destroys*); `SignAsync`/`DeriveSharedSecretAsync`
  use the borrow API; `GenerateAsync` disposes the fresh pair on duplicate-alias failure;
  ownership semantics documented on `ImportAsync` (store takes ownership).
- `KeyPairSigner : IDisposable`: owns-and-disposes by default (secure default), new
  3-arg ctor overload `ownsKeyPair: false` for the non-owning case; `SignAsync` borrows.
- `DefaultKeyGenerator`: `DeriveX25519FromEd25519` runs inside one borrow (was 3 clones per
  call) with stackalloc SHA-512 expansion, cleared; `GenerateEcDsa` wipes `parameters.D`;
  Restore*/Generate* paths use the span ctor + wipe temps in `finally`; BLS builds from a
  single wiped `sk.ToBendian()` copy; stackalloc seed spans cleared after use.
- `DefaultCryptoProvider`: `SignEcDsa`/`DeriveNistSharedSecret` wipe `ECParameters.D` after
  `ImportParameters`; `ImportEcPrivateKey` range check switches from `BigInteger` (an
  unwipeable heap copy of the scalar) to a fixed-length big-endian byte compare against the
  curve-order bytes.
- `JwkConverter.ToPrivateJwk` wipes its private-key clone after encoding `d` (the JWK string
  itself is unwipeable — documented caveat).

## Checklist

- [ ] `KeyPair`: IDisposable + pinned storage + borrow API + guards + docs
- [ ] `InMemoryKeyStore`: IDisposable, destroying delete, borrow in sign/ECDH
- [ ] `KeyPairSigner`: IDisposable + ownership overload + borrow
- [ ] `DefaultKeyGenerator`: wipe intermediates (Ed25519 expanded scalar, X25519 scalar, D, seed copies)
- [ ] `DefaultCryptoProvider`: wipe `ECParameters.D`; BigInteger scalar copy removed
- [ ] `JwkConverter.ToPrivateJwk`: wipe clone
- [ ] `PublicAPI.Unshipped.txt` entries for the new surface
- [ ] Tests: dispose-throw + zeroed-backing-store (reflection), borrow API, store delete/dispose destruction, signer ownership
- [ ] Full build + test suite green
- [ ] PRD FR-18 section, CHANGELOG entry, Keys sample updated
- [ ] Adversarial agent pass (writes & runs exploit code) — per lessons L4/L6
- [ ] Branch + PR referencing #17

## Review

Implemented all 7 design points; full solution builds clean (no CS/RS warnings), 861 tests
green (the 5 `BbsUnavailableTests` failures are pre-existing/environmental — the native BBS lib
is present locally, so the "without native library" asserts fail; identical on clean `main`).
API-coverage check passes; new public surface declared in PublicAPI.Unshipped.txt (semver minor).

### Adversarial pass (two agents, write-and-run exploit code — L4/L6)

1. **EC scalar range-check equivalence** — the `BigInteger` → fixed-length byte-compare rewrite
   was proven equivalent via ~27,600 differential comparisons + boundary pins (D=0 reject, D=1
   and D=n−1 accept, D≥n reject, unsigned compare confirmed, constants are the exact FIPS orders
   at the exact 32/48/66-byte scalar lengths). No divergence. No finding.
2. **Zeroization / key-lifecycle** — post-dispose recovery blocked on every vector for all 8 key
   types; span cannot escape the borrow (compile-time); backward-compat and store-ownership
   behave as documented. **One real Medium finding (F1):** a concurrent borrow-vs-dispose TOCTOU
   let `Dispose` zero the pinned buffer mid-borrow, yielding a *silent wrong signature* (no
   throw). Fixed: `KeyPair` now serializes every backing-array read and the wipe under a
   per-instance `_gate` lock, so a racing dispose either waits for the in-flight borrow or makes
   the borrow throw `ObjectDisposedException` — never a half-wiped read. Regression test
   `WithPrivateKey_ConcurrentDispose_NeverSignsOverAZeroedKey` (2000 rounds) pins it.
   - Test-quality note taken: replaced the tautological `fixed`-pointer "pinning" test (POH
     membership isn't observable from managed code) with one asserting the guarantee that
     matters — the secret survives a compacting GC and zeroes on dispose — and dropped the
     no-longer-needed `AllowUnsafeBlocks`.

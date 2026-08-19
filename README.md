# NetCrypto

Unified cryptographic primitives for the NetCid/NetDid library stack: EdDSA, ECDSA
(NIST curves and secp256k1, including recoverable), BLS12-381, BBS selective-disclosure
signatures, X25519/ECDH, KDFs, AEADs, hashing (including Keccak-256), a key model with
multibase/multicodec encoding, signing and key-store abstractions, and JWK conversion.

NetCrypto is the single home for every cryptographic primitive in the stack, behind
stable interfaces, so that no domain library (`net-did`, `dataproofs-dotnet`,
`credentials-dotnet`, `didcomm-dotnet`) binds directly to a specific crypto backend.

```
dotnet add package NetCrypto
```

> **Stable release.** NetCrypto has been generally available since `1.0.0` and ships as a stable
> package — no `--prerelease` flag is required. `PublicAPI.Shipped.txt` is the authoritative
> contract for every published API; `PublicAPI.Unshipped.txt` holds only surface added since the
> last release and is empty on a tagged release. Semantic versioning applies — additive changes
> bump the minor version, breaking changes the major; any pre-GA `1.0.0-preview.*` packages are
> superseded. See [CHANGELOG.md](CHANGELOG.md) for the release history and the current version.

Target framework: **net10.0**. Depends on [`NetCid`](https://www.nuget.org/packages/NetCid)
for multibase/multicodec encoding.

## Quick start

```csharp
using NetCrypto;

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

using var keyPair = keyGen.Generate(KeyType.Ed25519); // Dispose zeroizes the key material
byte[] signature = keyPair.WithPrivateKey(            // borrow the secret — no heap copy escapes
    privateKey => crypto.Sign(keyPair.KeyType, privateKey, data));
bool valid = crypto.Verify(keyPair.KeyType, keyPair.PublicKey, data, signature);

Console.WriteLine(keyPair.MultibasePublicKey); // z6Mk... (multicodec + base58btc)
```

With dependency injection (`Microsoft.Extensions.DependencyInjection`):

```csharp
services.AddNetCrypto(); // TryAdd: your own ICryptoProvider/IBbsCryptoProvider/IKeyGenerator
                         // registrations made BEFORE this call win (the swap seam).
```

## Learning the API: samples

The **primary usage documentation** is [`samples/README.md`](samples/README.md) — eleven
standalone, runnable console programs covering 100% of the public API surface
(enforced in CI by `tools/ApiCoverageCheck`). Start with `NetCrypto.Samples.Keys` and
follow the reading order in the samples index.

## Implementing a capable key store

`IKeyStore` says "sign with the key behind this alias". That is enough for an in-memory store
and not enough for a custody backend — a cloud KMS, an HSM partition, an encrypted software
keystore — where the consumer additionally needs to know what the backend can do *before* first
use, which tenant it may touch, which **key instance** an alias currently holds, how to retry a
mutation that may or may not have been applied, and which encoding a signature comes back in.

`ICapableKeyStore : IKeyStore, IKeyStoreCapabilityProvider` (1.6.0) is that contract. It is
purely additive: `IKeyStore` gains no member, so every existing store, `ISigner`,
`KeyStoreSigner`, and `InMemoryKeyStore` caller is source- and binary-compatible. It adds no
export operation anywhere, no KDF, and no protocol semantics.
`CapableInMemoryKeyStore` is the reference implementation and the contract oracle;
`samples/NetCrypto.Samples.CapableKeyStore` is the worked example.

If you are writing a backend adapter, these fourteen rules are the contract — the shape alone is not:

1. **Discovery honesty is bidirectional.** Everything you advertise must work; everything you do
   not advertise must fail with `KeyStoreError.Unsupported` *before* any key creation, signing,
   or agreement. Never silently downgrade the algorithm, curve, hash, or encoding. Discovery is
   side-effect-free and returns a deeply immutable snapshot whose `Revision` is stable for the
   instance lifetime. **A temporary outage is `Unavailable`, never an empty capability set** — an
   empty set is indistinguishable from "this backend can do nothing" and makes callers reroute
   permanently around a backend that is merely down.
2. **Algorithm ids bind the observable encoding.** `es256-der` and `es256-p1363` are the same
   curve and hash but different wire bytes; JOSE/JWS/COSE/WebAuthn mandate the latter, X.509/CMS
   the former. Use the identifiers on `KeyStoreAlgorithms`, and never reuse one of them for
   different bytes. You may advertise identifiers of your own — that is why
   `KeyStoreAlgorithmId` is a string rather than a closed enum.
3. **Instance identity is immutable and never reused.** Mint a fresh `KeyInstanceId` on generate
   and import; make it permanently unusable on delete; yield a *different* one when the alias is
   re-created. This is what makes alias rebinding detectable rather than silent.
4. **Namespace scoping is least-privilege**, and it applies to the inherited `IKeyStore` members
   too. Naming is not authorization.
5. **Mutations are durably idempotent** under `(NamespaceId, KeyMutationKind, KeyOperationId)`.
   Commit the mutation, a canonical request fingerprint, and the receipt atomically. Same id and
   same request replays; same id and a different request is `IdempotencyConflict`. Make the
   fingerprint encoding unambiguous across field boundaries — length-prefix it; a
   delimiter-joined encoding lets an alias containing the delimiter collide with another request.
6. **Cancellation never lies.** Before irreversible acceptance it changes nothing and throws
   `OperationCanceledException`. After acceptance, return success, definite failure, or
   `OutcomeUnknown` — never cancellation as an implied rollback.
7. **Import transfers ownership exactly once,** through `TransferableKeyMaterial`. Your
   acceptance path is `material.Consume(reader)` — you supply a `KeyMaterialReader<T>`, get the
   raw bytes as spans valid only for that call, and the material latches unreadable and zeroizes
   on the way out whether or not your reader succeeded. Copy what you need and own wiping your
   copy; do not let the spans escape, and do not call back into the material from inside the
   reader (a nested `Consume` is refused). A failure before acceptance leaves it usable for
   exactly one retry; a recognized replay must destroy it *without reading it* — that is
   `material.Discard()` — because an `OutcomeUnknown` import is reconciled through
   `GetMutationOutcomeAsync` only, and private material is never resubmitted.
8. **BBS is advertised only where you can really do it,** and plain BLS signing is never
   advertised or accepted as BBS.
9. **Bounds are finite.** Every capability carries a positive `MaxInputBytes`; `null` and `0` are
   not available to mean "unbounded".
10. **Errors are portable.** Surface `KeyStoreException` with the taxonomy (`Unsupported`,
    `IdempotencyConflict`, `AccessDenied`, `Throttled`, `Unavailable`, `OutcomeUnknown`) plus
    `RetryAfter` where the backend gives one, and let no vendor SDK exception type escape. Keep
    argument faults as parameter-named `ArgumentException` — a caller's own mistake must not be
    retried as a backend condition.

The last four are integrity obligations rather than shape rules. Each was found by an
adversarial pass against an implementation that already looked correct, so none of them is
optional (PRD FR-7b, obligations 11-14):

11. **Produced output must speak for the advertised key.** Length is not identity. Before any
    signature reaches the caller, verify it under the public key you yourself advertise for that
    instance, using a verifier *independent of* the provider that produced it — otherwise a
    provider that forged the signature also blesses it. Failure is `Unavailable`.
12. **Identifiers and aliases must be well-formed UTF-16.** `Encoding.UTF8` uses replacement
    fallback, so every unpaired surrogate — and U+FFFD itself — encodes to the same three bytes.
    Two distinct identifiers would then share a mutation fingerprint and one caller's mutation
    would silently *replay* another's. Reject at the boundary, with a parameter name.
13. **Import must prove the public key belongs to the private key.** `StoredKeyInfo.PublicKey` is
    the verification identity downstream DID/VC code publishes. Derive the public key from the
    material you just consumed and reject a mismatch before commit; matching `KeyType` and length
    prove nothing. The transfer is spent either way — you have already seen the secret.
14. **A callback must not re-enter what invoked it.** `Monitor` is reentrant, so a provider
    callback would otherwise walk straight through your backend lock. Refuse same-thread
    re-entry. The same applies to your `KeyMaterialReader<T>`: do not call back into the material
    you are reading (NetCrypto refuses a nested `Consume` for you).

### Algorithm identifiers

| Id | KeyType | Operation | Observable encoding |
|---|---|---|---|
| `ed25519` | Ed25519 | Sign | 64-byte EdDSA (RFC 8032) |
| `es256-der` / `es256-p1363` | P-256 | Sign | DER / 64-byte `R‖S` |
| `es384-der` / `es384-p1363` | P-384 | Sign | DER / 96-byte `R‖S` |
| `es512-der` / `es512-p1363` | P-521 | Sign | DER / 132-byte `R‖S` |
| `es256k` | secp256k1 | Sign | 64-byte compact `R‖S` (no DER variant exists) |
| `bls12381g1-basic` / `bls12381g2-basic` | BLS12-381 G1 / G2 | Sign | 96- / 48-byte BLS basic |
| `ecdh-x25519` / `ecdh-p256` / `ecdh-p384` / `ecdh-p521` | resp. | KeyAgreement | raw Z: 32 / 32 / 48 / 66 bytes |
| `bbs-bls12381-sha256` | BLS12-381 G2 | BbsSign | 80-byte BBS (draft-10) |

## Algorithm and specification conformance

Every primitive is tested against the test vectors of its governing specification.

| Capability | Algorithm(s) | Backend | Specification | Vectors in test suite |
|---|---|---|---|---|
| Signatures | EdDSA (Ed25519) | NSec (libsodium) | RFC 8032 | §7.1 TEST 1–3 |
| Signatures | ECDSA P-256 / P-384 / P-521, DER and IEEE P1363 | .NET BCL | FIPS 186-5 | cross-format + round-trip |
| Signatures | ECDSA secp256k1 (SHA-256 prehash, 64-byte compact; low-S signing, low/high-S verification) | NBitcoin.Secp256k1 | SEC 2 / RFC 8812 ES256K | round-trip + high-S interop |
| Signatures | Recoverable secp256k1 over a caller-supplied digest | NBitcoin.Secp256k1 | SEC 2; raw recovery id (no EVM `v`-encoding) | EIP-155 example vector |
| Signatures | BLS12-381 (G1 and G2 variants, hash-to-curve) | Nethermind.Crypto.Bls | RFC 9380 DSTs | round-trip + parity |
| Signatures | **BBS** (multi-message, selective disclosure) | zkryptium 0.6 via Rust FFI | **draft-irtf-cfrg-bbs-signatures-10 (pinned)** | §8.4.1 BLS12-381-SHA-256 KeyGen fixture |
| Key agreement | X25519 (+ HKDF-SHA256 convenience) | NSec | RFC 7748 / RFC 5869 | two-party equality |
| Key agreement | Raw ECDH Z: X25519, P-256, P-384, P-521 | BCL | RFC 7518 §4.6 usage | two-party equality |
| KDF | Concat KDF | managed | NIST SP 800-56A §5.8.1 | parity tests |
| KDF | HKDF (SHA-256/384/512) | BCL | RFC 5869 | Appendix A cases 1, 3 |
| Hashing | SHA-256 / SHA-384 / SHA-512 | BCL | FIPS 180-4 | known answers ("abc", "") |
| Hashing | **Keccak-256** (original padding `0x01` — *not* SHA3-256) | vendored sponge | Keccak submission / Ethereum | KATs, 1000-input differential vs reference, SHA3 negative control, address KAT |
| AEAD | AES-256-GCM (`A256GCM`) | BCL `AesGcm` | NIST SP 800-38D | NIST CAVP vectors |
| AEAD | AES-256-CBC + HMAC-SHA-512 (`A256CBC-HS512`) | composed from BCL | RFC 7518 §5.2.2 | Appendix B.3 |
| AEAD | XChaCha20-Poly1305 (`XC20P`) | NSec | draft-irtf-cfrg-xchacha-03 | Appendix A.3 |
| Key wrap | AES Key Wrap (`A256KW`) | managed | RFC 3394 | §4.3, §4.6 |
| Key model | `KeyType` ⇄ multicodec, `MultibasePublicKey` | NetCid | multiformats | golden parity values |
| Key repr. | JWK ⇄ raw key bytes (all key types) | Microsoft.IdentityModel.Tokens | RFC 7517 | round-trips |

**ECDSA signatures are not unique per message.** For every ECDSA key type above — P-256, P-384,
P-521 and secp256k1 — both `(R, S)` and `(R, n − S)` are valid signatures over the same key and
message, and `Verify` accepts both. Neither FIPS 186-5 nor RFC 8812 imposes a low-S rule; that is
a Bitcoin/BIP-62 convention. Two consequences worth designing around:

- **Never key a replay cache, dedup set, or idempotency check on signature bytes.** Re-submitting
  the other encoding defeats it. Bind replay protection to the message — a nonce, `jti`, or digest.
- **If your protocol requires BIP-62/EIP-2 canonical signatures, enforce `S ≤ n/2` yourself** at
  your boundary. NetCrypto's own `KeyStoreSigner` does exactly this for recoverable EVM output.

secp256k1 signing remains deterministic and low-S; only verification is permissive, normalizing a
valid high-S signature to its equivalent low-S form before the Bitcoin-oriented backend check so
RFC 8812 ES256K peers interoperate ([#23](https://github.com/moisesja/crypto-dotnet/issues/23)).
This aligned secp256k1 with the NIST curves' long-standing behavior rather than introducing a new
one. `Secp256k1Recoverable` is likewise high-S tolerant and documents that recovery hands the
canonicality decision to the caller.

> **BBS terminology.** "BBS" is the CFRG name for the scheme historically called BBS+.
> Conformance is pinned to draft-10 via zkryptium 0.6; the `BbsCiphersuite` parameter
> (only `Bls12381Sha256` in v1) and the FFI isolation contain future draft churn.
>
> **BBS header vs presentation header.** `Sign`/`Verify`/`DeriveProof`/`VerifyProof` take an
> optional `header` (default empty): data the *signer* binds at sign time and that every
> derived proof commits — the holder cannot drop or alter it (e.g. the W3C `bbs-2023`
> cryptosuite binds its mandatory-disclosure group here). It is distinct from the
> `presentationHeader` (`ph`) on `DeriveProof`/`VerifyProof`, which the *holder* chooses at
> derive time (typically the verifier's challenge).

## Native BBS library and the supported "BBS-absent" mode

BBS is the only non-managed primitive: the `zkryptium-ffi` Rust crate
([`native/zkryptium-ffi/`](native/zkryptium-ffi/)) is compiled per platform and shipped
**inside this single NuGet package** under `runtimes/{rid}/native/`. A consumer that restores
NetCrypto gets the BBS native payload transitively — no per-consumer native assets are needed.

### Supported native platform matrix

| RID | Library file | BBS at runtime |
|---|---|---|
| `osx-arm64`  | `libzkryptium_ffi.dylib` | ✅ built + smoke-executed in CI |
| `osx-x64`    | `libzkryptium_ffi.dylib` | ✅ shipped (cross-compiled; Rosetta-capable hosts load it) |
| `linux-x64`  | `libzkryptium_ffi.so`    | ✅ built + smoke-executed in CI |
| `linux-arm64`| `libzkryptium_ffi.so`    | ✅ shipped (cross-compiled) |
| `win-x64`    | `zkryptium_ffi.dll`      | ✅ built + smoke-executed in CI |

On any of these RIDs `IBbsCryptoProvider.IsAvailable` returns `true` after a plain
`dotnet restore`. The tag-triggered release workflow **fails the build** if any RID's native
payload is missing from the produced `.nupkg` (the "Verify nupkg contains all five RIDs" step),
publishes a SHA-256 checksum per binary, and then **smoke-tests** the packed package — installing
it into a clean console app and running a BBS sign/verify round-trip — so the guarantee is
verified against the actual published artifact, not the source tree.

**All managed primitives work with no native library present** (unlisted platforms,
or environments that prohibit native code). This is a supported, CI-tested mode:

```csharp
var bbs = new DefaultBbsCryptoProvider();
if (!bbs.IsAvailable)
{
    // Probe never throws. Any BBS operation would throw BbsUnavailableException
    // (InnerException carries the original native load error).
}
```

### BBS key generation

The supported way to mint a BBS keypair is the **standard key generator** — the same one used
for every other key type:

```csharp
var keyPair = new DefaultKeyGenerator().Generate(KeyType.Bls12381G2); // or Bls12381G1
// keyPair.PrivateKey (32-byte BLS12-381 scalar), keyPair.PublicKey (96-byte G2 / 48-byte G1)
byte[] sig = new DefaultBbsCryptoProvider().Sign(keyPair.PrivateKey, messages);
```

`Bls12381G2` (96-byte public key) is the variant the BBS provider signs/verifies with. Raw FFI
keygen (`bbs_keygen`) is **intentionally internal** — there is no public raw-keygen helper, by
design, to keep the public surface minimal and backend-agnostic. See
[`samples/NetCrypto.Samples.Bbs`](samples/NetCrypto.Samples.Bbs) for an end-to-end example.

The repository itself is source-only — every shipped binary is cross-compiled by the
tag-triggered release workflow from pinned sources, with SHA-256 checksums published
as release assets.

## Architecture notes

- **Single provider, swappable via DI (Posture 1).** `DefaultCryptoProvider` implements
  `ICryptoProvider` for all key types; consumers with special requirements (e.g. a
  FIPS 140-3-validated module) replace the registration — `AddNetCrypto()` uses `TryAdd`,
  so a registration made before it wins. The designated evolution path is a per-`KeyType`
  provider registry behind the unchanged `ICryptoProvider` facade; no registry exists in v1.
- **Backend isolation.** No type from NSec, NBitcoin, Nethermind, or the FFI appears in
  any public signature (enforced by `Microsoft.CodeAnalysis.PublicApiAnalyzers` with a
  committed `PublicAPI.Shipped.txt`, plus a reflection test). Sanctioned exceptions:
  `NetCid` types and `Microsoft.IdentityModel.Tokens.JsonWebKey`.
- **EC point validation.** `EcPointValidator.EnsureOnCurve(KeyType, x, y)` is the public
  on-curve validation entry point — the invalid-curve-attack defense (RFC 7518 §6.2.2). Point
  *decompression* (`DecompressEcPoint` / `DecompressSecp256k1Point`) is an internal implementation
  detail and is **not** part of the public surface; validating a key never requires it.
- **Boundaries.** EVM `v`-encoding/RLP/transactions, JOSE/JWE/SD-JWT envelopes,
  Data Integrity proofs, ECDH-ES/1PU assembly, and concrete HSM/KMS stores are
  deliberately out of scope — they belong to the consumer layers. `ICapableKeyStore` gives a
  store the *self-description* that makes routing possible; it does not add the routing, and no
  router, profile, or policy machinery ships here.
- **Security posture.** None of the wrapped backends is independently audited or
  FIPS-validated; this is documented openly rather than implied otherwise.

## Building from source

```bash
# Managed code + tests (BBS tests require the native library, see below)
dotnet build NetCrypto.sln
dotnet test NetCrypto.sln --filter "Category!=BbsAbsent"

# Native BBS library for your host platform (Rust toolchain pinned in rust-toolchain.toml)
cd native/zkryptium-ffi && cargo build --release
# Rebuild so the test/sample projects pick up the binary, then run everything:
cd ../.. && dotnet build NetCrypto.sln && dotnet test NetCrypto.sln --filter "Category!=BbsAbsent"

# Without the native library (supported BBS-absent mode):
dotnet test NetCrypto.sln --filter "Category!=NativeFFI"
```

## License

Apache-2.0. See [LICENSE](LICENSE).

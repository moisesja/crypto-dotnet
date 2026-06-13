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

> **Stable release.** NetCrypto is published as a stable **`1.0.0`** (GA) — no `--prerelease`
> flag is required. The public API is frozen: `PublicAPI.Shipped.txt` is the authoritative
> contract and `PublicAPI.Unshipped.txt` is empty. Semantic versioning applies — additive
> changes bump the minor version, breaking changes the major; any pre-GA `1.0.0-preview.*`
> packages are superseded by `1.0.0`.

Target framework: **net10.0**. Depends on [`NetCid`](https://www.nuget.org/packages/NetCid)
for multibase/multicodec encoding.

## Quick start

```csharp
using NetCrypto;

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

var keyPair = keyGen.Generate(KeyType.Ed25519);
byte[] signature = crypto.Sign(keyPair.KeyType, keyPair.PrivateKey, data);
bool valid = crypto.Verify(keyPair.KeyType, keyPair.PublicKey, data, signature);

Console.WriteLine(keyPair.MultibasePublicKey); // z6Mk... (multicodec + base58btc)
```

With dependency injection (`Microsoft.Extensions.DependencyInjection`):

```csharp
services.AddNetCrypto(); // TryAdd: your own ICryptoProvider/IBbsCryptoProvider/IKeyGenerator
                         // registrations made BEFORE this call win (the swap seam).
```

## Learning the API: samples

The **primary usage documentation** is [`samples/README.md`](samples/README.md) — ten
standalone, runnable console programs covering 100% of the public API surface
(enforced in CI by `tools/ApiCoverageCheck`). Start with `NetCrypto.Samples.Keys` and
follow the reading order in the samples index.

## Algorithm and specification conformance

Every primitive is tested against the test vectors of its governing specification.

| Capability | Algorithm(s) | Backend | Specification | Vectors in test suite |
|---|---|---|---|---|
| Signatures | EdDSA (Ed25519) | NSec (libsodium) | RFC 8032 | §7.1 TEST 1–3 |
| Signatures | ECDSA P-256 / P-384 / P-521, DER and IEEE P1363 | .NET BCL | FIPS 186-5 | cross-format + round-trip |
| Signatures | ECDSA secp256k1 (SHA-256 prehash, 64-byte compact) | NBitcoin.Secp256k1 | SEC 2 | round-trip + parity |
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
  deliberately out of scope — they belong to the consumer layers.
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

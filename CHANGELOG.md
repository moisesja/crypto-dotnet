# Changelog

All notable changes to **NetCrypto** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  and `Base64Url.Decode(ReadOnlySpan<char>) → byte[]` (tolerates optional padding), a thin wrapper over the
  BCL `System.Buffers.Text.Base64Url`. A single source of truth for the JOSE/JWK byte boundary so consumers
  stop re-implementing it. (#12)
- **Unified AEAD size metadata** — each content-encryption cipher now exposes its key/nonce/tag sizes as
  `public const int`: `AesGcmCipher` (32/12/16), `AesCbcHmacCipher` (`KeySizeBytes` 64 / `IvSizeBytes` 16 /
  `TagSizeBytes` 32), `XChaCha20Poly1305Cipher` (32/24/16). A JOSE builder can size the CEK and IV/nonce
  from the source of truth instead of a hard-coded table. (#12)

### Security
- **`JwkConverter.ExtractPublicKey` now documents its on-curve guarantee.** The method already
  validated EC `(x, y)` coordinates against the stated curve (via `EcPointValidator.EnsureOnCurve`)
  before returning; that invalid-curve defense (RFC 7518 §6.2.2) is now stated explicitly in the
  public XML contract and pinned by a regression test using a *fabricated, self-consistent*
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
  on the NIST curves (DER and IEEE P1363), secp256k1 (64-byte compact, low-S), and BLS12-381
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

[1.0.0]: https://github.com/moisesja/crypto-dotnet/compare/v1.0.0-preview.2...v1.0.0
[1.0.0-preview.2]: https://github.com/moisesja/crypto-dotnet/compare/v1.0.0-preview.1...v1.0.0-preview.2
[1.0.0-preview.1]: https://github.com/moisesja/crypto-dotnet/releases/tag/v1.0.0-preview.1

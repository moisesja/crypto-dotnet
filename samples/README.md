# NetCrypto Samples

Small, self-contained console programs that demonstrate every public surface of
NetCrypto. Each sample is heavily commented, prints what it is doing, and
**exits with code 0 on success** (any assertion failure exits non-zero), so they
double as smoke tests:

```bash
dotnet run --project samples/<Name>
```

e.g. `dotnet run --project samples/NetCrypto.Samples.Keys`.

## Projects

| Project | What it demonstrates |
| --- | --- |
| `NetCrypto.Samples.Keys` | Key generation and restoration via `IKeyGenerator`, public-key references, multibase encoding, and Ed25519 → X25519 derivation. |
| `NetCrypto.Samples.Signing` | `ICryptoProvider` Sign/Verify for every signing-capable `KeyType`, plus `EcdsaSignatureFormat` (DER vs. IEEE P1363). |
| `NetCrypto.Samples.Signers` | The `ISigner` abstraction: `KeyPairSigner`, `IKeyStore` / `KeyStoreSigner`, and `StoredKeyInfo` — signing without ever touching private key bytes. |
| `NetCrypto.Samples.Hashing` | SHA-2 family hashing (`Hash`) and Ethereum's original `Keccak256`, checked against published test vectors. |
| `NetCrypto.Samples.KeyAgreement` | ECDH key agreement (X25519 and NIST curves) plus HKDF key derivation — Alice and Bob land on the same shared key. |
| `NetCrypto.Samples.Encryption` | AEAD symmetric encryption (ciphertext + tag + associated data) and AES key wrap, including tamper-detection failure paths. |
| `NetCrypto.Samples.Jwk` | `JwkConverter`: mapping NetCrypto's raw key model to and from RFC 7517 `JsonWebKey`. |
| `NetCrypto.Samples.EvmSigning` | Recoverable secp256k1 signatures for Ethereum: signing a digest, recovering the public key/address, and the raw recovery-id boundary (PRD FR-12). |
| `NetCrypto.Samples.Bbs` | BBS signatures (BLS12-381) for selective disclosure: multi-message signing, proof derivation, and proof verification. |
| `NetCrypto.Samples.DependencyInjection` | `AddNetCrypto()` wiring all default providers into `Microsoft.Extensions.DependencyInjection`, with application code depending only on interfaces. |

## Start here — suggested reading order

1. **Keys** — every other sample starts by generating a key.
2. **Signing** — the core Sign/Verify provider.
3. **Signers** — the signing abstraction the rest of the stack uses.
4. **Hashing** — digests used by signing and EVM samples.
5. **KeyAgreement** — ECDH + HKDF.
6. **Encryption** — AEAD ciphers and key wrap.
7. **Jwk** — moving keys across the JOSE wire format.
8. **EvmSigning** — recoverable secp256k1 / Ethereum.
9. **Bbs** — selective-disclosure BBS signatures.
10. **DependencyInjection** — putting it all together in a DI container.

## A note on the BBS sample

BBS is the only NetCrypto primitive backed by a native library (zkryptium-ffi),
so `NetCrypto.Samples.Bbs` has **two supported modes**:

- **Native library present** — runs the full sign → derive proof → verify flow.
- **Native library absent** — `IBbsCryptoProvider.IsAvailable` reports `false`,
  the sample demonstrates the `BbsUnavailableException` an unguarded call
  produces, and still **exits 0**: BBS-absent is a supported configuration,
  not an error.

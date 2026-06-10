# zkryptium-ffi

C-ABI wrapper around [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium)'s BBS signature implementation (BLS12-381-SHA-256 ciphersuite, IETF draft-irtf-cfrg-bbs-signatures-10).

This crate compiles to a native shared library (`cdylib`) consumed by NetCrypto via P/Invoke.

## Prerequisites

- [Rust](https://rustup.rs/) toolchain — pinned to the version in `rust-toolchain.toml`
  (rustup selects it automatically inside this directory)
- For cross-compilation: the appropriate target toolchain (see below)

## Building

### Current platform only

```bash
cargo build --release
```

Output: `target/release/libzkryptium_ffi.{dylib,so}` or `zkryptium_ffi.dll`

### Using the build script

```bash
# Build for the current platform and copy to the .NET runtimes directory
./build-all.sh

# Build for all supported platforms (requires cross-compilation toolchains)
./build-all.sh --all
```

The script places binaries into:
```
src/NetCrypto/runtimes/{rid}/native/
```

### Manual cross-compilation

```bash
# Add a target
rustup target add x86_64-unknown-linux-gnu

# Build for that target
cargo build --release --target x86_64-unknown-linux-gnu
```

## Supported platforms

> **Note:** No compiled binaries are committed to this repository. Release CI builds all
> five RIDs below and packs them into the NetCrypto NuGet package under
> `runtimes/{rid}/native/`. For local development, build with `./build-all.sh` or
> `cargo build --release --target <target>` and copy the output to
> `src/NetCrypto/runtimes/{rid}/native/`.
> If the native library is missing at runtime, `IBbsCryptoProvider.IsAvailable` reports
> `false` and the BBS operations throw `BbsUnavailableException` — running without BBS is
> a supported mode; every non-BBS primitive keeps working.

| RID | Rust target | Library name |
|-----|------------|--------------|
| `osx-arm64` | `aarch64-apple-darwin` | `libzkryptium_ffi.dylib` |
| `osx-x64` | `x86_64-apple-darwin` | `libzkryptium_ffi.dylib` |
| `linux-x64` | `x86_64-unknown-linux-gnu` | `libzkryptium_ffi.so` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | `libzkryptium_ffi.so` |
| `win-x64` | `x86_64-pc-windows-gnu` | `zkryptium_ffi.dll` |

## Exported functions

All functions return `0` on success, `-1` on error.

| Function | Description |
|----------|-------------|
| `bbs_keygen` | Generate BBS keypair from IKM plus optional `key_info` (SK: 32 bytes, PK: 96 bytes). Pass null/0 for `key_info` to use the spec default (empty string); the key-generation DST is always the spec default. |
| `bbs_sk_to_pk` | Derive public key from secret key |
| `bbs_sign` | Sign an ordered set of messages |
| `bbs_verify` | Verify a BBS signature against the full message set |
| `bbs_proof_gen` | Derive a selective-disclosure zero-knowledge proof |
| `bbs_proof_verify` | Verify a selective-disclosure proof |

## Message encoding

Messages and indices are passed as flat byte buffers with a simple TLV-like encoding:

**Messages**: `[u32 count][u32 len_0][bytes_0][u32 len_1][bytes_1]...`

**Indices**: `[u32 count][u32 idx_0][u32 idx_1]...`

All `u32` values are **little-endian**.

## Running tests

```bash
cargo test
```

## Verifying exports

```bash
# macOS
nm -gU target/release/libzkryptium_ffi.dylib | grep bbs

# Linux
nm -D target/release/libzkryptium_ffi.so | grep bbs
```

## Security audit

`cargo audit` runs in CI against `Cargo.lock`. The only currently-allowed
advisory is:

| ID | Crate | Status | Reachability |
|---|---|---|---|
| [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097) | `rand 0.8.5` | Unsound | **Not reachable.** The advisory describes unsound behavior "with a custom logger using `rand::rng()`". Neither this FFI shim nor `zkryptium 0.6.x` installs a custom logger or calls `rand::rng()` with one. `rand` is reached only via standard BBS key generation and signing, which do not exercise the unsound code path. |

CI ignores this advisory via `cargo audit --ignore RUSTSEC-2026-0097`.
Any other warning fails the job — keeping the dependency tree clean is
intentional. Re-evaluate on every `zkryptium` upgrade.

## Troubleshooting

### Linux cross-compilation from macOS

You'll need a Linux cross-compiler. Using [cross](https://github.com/cross-rs/cross):

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
```

### Windows cross-compilation from macOS/Linux

```bash
# Install MinGW toolchain (macOS)
brew install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

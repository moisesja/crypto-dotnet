#!/usr/bin/env bash
# Build zkryptium-ffi native library for all supported platforms.
#
# Usage:
#   ./build-all.sh              # build for the current host only
#   ./build-all.sh --all        # build for all targets (requires cross-compilation toolchains)
#
# Output binaries are placed under:
#   ../../src/NetCrypto/runtimes/{rid}/native/
#
set -euo pipefail
cd "$(dirname "$0")"

DEST_BASE="../../src/NetCrypto/runtimes"

build_target() {
    local target="$1"
    local rid="$2"
    local libname="$3"

    echo "Building for $target (RID: $rid)..."
    cargo build --release --target "$target"

    local dest="$DEST_BASE/$rid/native"
    mkdir -p "$dest"
    cp "target/$target/release/$libname" "$dest/"
    echo "  -> $dest/$libname"
}

# Always build for the current host
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)
        build_target "aarch64-apple-darwin" "osx-arm64" "libzkryptium_ffi.dylib"
        ;;
    Darwin-x86_64)
        build_target "x86_64-apple-darwin" "osx-x64" "libzkryptium_ffi.dylib"
        ;;
    Linux-x86_64)
        build_target "x86_64-unknown-linux-gnu" "linux-x64" "libzkryptium_ffi.so"
        ;;
    Linux-aarch64)
        build_target "aarch64-unknown-linux-gnu" "linux-arm64" "libzkryptium_ffi.so"
        ;;
    *)
        echo "Unknown host: $(uname -s)-$(uname -m)"
        exit 1
        ;;
esac

# Cross-compile for all targets if --all is passed
if [[ "${1:-}" == "--all" ]]; then
    echo ""
    echo "Cross-compiling for all targets..."

    # macOS arm64
    rustup target add aarch64-apple-darwin 2>/dev/null || true
    build_target "aarch64-apple-darwin" "osx-arm64" "libzkryptium_ffi.dylib"

    # macOS x64
    rustup target add x86_64-apple-darwin 2>/dev/null || true
    build_target "x86_64-apple-darwin" "osx-x64" "libzkryptium_ffi.dylib"

    # Linux x64
    rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true
    build_target "x86_64-unknown-linux-gnu" "linux-x64" "libzkryptium_ffi.so"

    # Linux arm64
    rustup target add aarch64-unknown-linux-gnu 2>/dev/null || true
    build_target "aarch64-unknown-linux-gnu" "linux-arm64" "libzkryptium_ffi.so"

    # Windows x64
    rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
    build_target "x86_64-pc-windows-gnu" "win-x64" "zkryptium_ffi.dll"
fi

echo ""
echo "Done."

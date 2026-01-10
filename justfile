# Once just v1.39.0 is widely deployed, simplify with the `read` function.
NIGHTLY_VERSION := trim(read(justfile_directory() / "nightly-version"))

_default:
  @just --list

# Install rbmt (Rust Bitcoin Maintainer Tools).
@_install-rbmt:
  cargo install --quiet --git https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools.git --rev $(cat {{justfile_directory()}}/rbmt-version) cargo-rbmt

# Check everything with both feature sets.
check: check-native check-standalone

# Build everything with both feature sets.
build: build-native build-standalone

# Test everything with both feature sets.
test: test-native test-standalone

# Lint everything with both feature sets.
lint: lint-native lint-standalone

# Run cargo fmt
fmt:
  cargo +{{NIGHTLY_VERSION}} fmt --all

# Check with native features.
[group('native')]
check-native:
  cargo check --all --all-targets --no-default-features --features native

# Build with native features.
[group('native')]
build-native:
  cargo build --all --all-targets --no-default-features --features native

# Test with native features.
[group('native')]
test-native:
  cargo test --all-targets --no-default-features --features native

# Lint with native features.
[group('native')]
lint-native:
  cargo +{{NIGHTLY_VERSION}} clippy --all --all-targets --no-default-features --features native -- --deny warnings

# Check with standalone features.
[group('standalone')]
check-standalone:
  cargo check --all --all-targets --no-default-features --features standalone

# Build with standalone features.
[group('standalone')]
build-standalone:
  cargo build --all --all-targets --no-default-features --features standalone

# Test with standalone features.
[group('standalone')]
test-standalone:
  cargo test --all-targets --no-default-features --features standalone

# Lint with standalone features.
[group('standalone')]
lint-standalone:
  cargo +{{NIGHTLY_VERSION}} clippy --all --all-targets --no-default-features --features standalone -- --deny warnings

# Generate documentation.
docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +{{NIGHTLY_VERSION}} doc --all-features {{flags}}

# Update the recent and minimal lock files using rbmt.
[group('tools')]
@update-lock-files: _install-rbmt
  rustup run {{NIGHTLY_VERSION}} cargo rbmt lock

# Run CI tasks with rbmt.
[group('ci')]
@ci task toolchain="stable" lock="recent": _install-rbmt
  RBMT_LOG_LEVEL=quiet rustup run {{toolchain}} cargo rbmt --lock-file {{lock}} {{task}}

# Test crate.
[group('ci')]
ci-test: (ci "test stable")

# Lint crate.
[group('ci')]
ci-lint: (ci "lint" NIGHTLY_VERSION)

# Bitcoin core integration tests.
[group('ci')]
ci-integration: (ci "integration")

# Update vendored secp256k1 files from upstream.
[group('tools')]
update-vendor secp_path="":
  #!/usr/bin/env bash
  set -euo pipefail

  # Use provided path or default to $HOME/src/secp256k1
  if [ -n "{{secp_path}}" ]; then
    SECP_SRC="{{secp_path}}"
  else
    SECP_SRC="$HOME/src/secp256k1"
  fi

  VENDOR_DIR="{{justfile_directory()}}/vendor/secp256k1"

  if [ ! -d "$SECP_SRC" ]; then
    echo "Error: secp256k1 source not found at $SECP_SRC"
    echo "Usage: just update-vendor [path-to-secp256k1]"
    echo "Default: \$HOME/src/secp256k1"
    exit 1
  fi

  echo "Updating vendored secp256k1 from $SECP_SRC..."

  # Clean existing vendored files to avoid bloat
  echo "  - Cleaning existing vendored files..."
  rm -rf "$VENDOR_DIR/include/secp256k1"*.h
  rm -rf "$VENDOR_DIR/src/modules"/*
  rm -f "$VENDOR_DIR/src"/*.h
  rm -f "$VENDOR_DIR/src/secp256k1.c"
  rm -f "$VENDOR_DIR/src/precomputed"*.c

  # Copy headers
  echo "  - Copying headers..."
  cp -R "$SECP_SRC"/include/secp256k1* "$VENDOR_DIR/include/"

  # Copy module implementations
  echo "  - Copying modules..."
  cp -R "$SECP_SRC"/src/modules/* "$VENDOR_DIR/src/modules/"

  # Copy source headers
  echo "  - Copying source headers..."
  cp "$SECP_SRC"/src/*.h "$VENDOR_DIR/src/"

  # Copy main secp256k1.c
  echo "  - Copying secp256k1.c..."
  cp "$SECP_SRC"/src/secp256k1.c "$VENDOR_DIR/src/"

  # Copy precomputed tables (large files)
  echo "  - Copying precomputed tables..."
  cp "$SECP_SRC"/src/precomputed_ecmult.c "$VENDOR_DIR/src/"
  cp "$SECP_SRC"/src/precomputed_ecmult_gen.c "$VENDOR_DIR/src/"

  echo "✓ Vendored files updated successfully!"
  echo ""
  echo "Updated files:"
  echo "  - Headers:       include/secp256k1*.h"
  echo "  - Modules:       src/modules/*"
  echo "  - Source:        src/*.h, src/secp256k1.c"
  echo "  - Tables:        src/precomputed_*.c (2.5MB)"
  echo ""
  echo "Next steps:"
  echo "  1. Test native build:  just test-native"
  echo "  2. Verify BIP-374:     cargo test --features native --test test_vectors"

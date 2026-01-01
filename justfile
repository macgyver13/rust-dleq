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

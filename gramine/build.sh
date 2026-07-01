#!/usr/bin/env bash
# Build and sign both Gramine SGX manifests.
# Prerequisites: gramine-sgx package installed, SGX driver loaded, PCCS running.
# Usage: ./gramine/build.sh

set -euo pipefail

ARCH_LIBDIR="${ARCH_LIBDIR:-/lib/x86_64-linux-gnu}"
GRAMINE_DIR="$(dirname "$0")"
BINARY_DIR="${BINARY_DIR:-/usr/local/bin}"

echo "==> Building mandate-tee manifest"
gramine-manifest \
  -Dgramine.libos="$(gramine-get-config libos)" \
  -Dgramine.runtimedir="$(gramine-get-config runtime_dir)" \
  -Darch_libdir="$ARCH_LIBDIR" \
  -Dlog_level=error \
  "$GRAMINE_DIR/manifest.mandate.template" \
  "$GRAMINE_DIR/manifest.mandate"

gramine-sgx-sign \
  --manifest "$GRAMINE_DIR/manifest.mandate" \
  --output   "$GRAMINE_DIR/manifest.mandate.sgx"

echo "==> Building reputation-tee manifest"
gramine-manifest \
  -Dgramine.libos="$(gramine-get-config libos)" \
  -Dgramine.runtimedir="$(gramine-get-config runtime_dir)" \
  -Darch_libdir="$ARCH_LIBDIR" \
  -Dlog_level=error \
  "$GRAMINE_DIR/manifest.reputation.template" \
  "$GRAMINE_DIR/manifest.reputation"

gramine-sgx-sign \
  --manifest "$GRAMINE_DIR/manifest.reputation" \
  --output   "$GRAMINE_DIR/manifest.reputation.sgx"

echo "==> Done. Run enclaves with:"
echo "    gramine-sgx $GRAMINE_DIR/manifest.mandate.sgx"
echo "    gramine-sgx $GRAMINE_DIR/manifest.reputation.sgx"

# Print MRENCLAVE values for key-pinning in the gateway
echo ""
echo "==> MRENCLAVE values (put these in BYZ_MANDATE_MRENCLAVE / BYZ_REPUTATION_MRENCLAVE):"
gramine-sgx-sigstruct-view "$GRAMINE_DIR/manifest.mandate.sig"   | grep -i mrenclave
gramine-sgx-sigstruct-view "$GRAMINE_DIR/manifest.reputation.sig" | grep -i mrenclave

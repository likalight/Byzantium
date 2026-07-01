#!/usr/bin/env bash
set -euo pipefail

echo "Running Byzantium E2E tests..."
cargo test -p byz-gateway --test e2e -- --nocapture --test-threads=1
echo "E2E tests passed."

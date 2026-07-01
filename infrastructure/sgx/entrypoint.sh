#!/bin/bash
set -euo pipefail

# Start both TEE services inside Gramine SGX enclaves.
# Each enclave gets its own attestation quote; rails verify both before trusting output.

SERVICE=${BYZ_TEE_SERVICE:-mandate}

case "$SERVICE" in
  mandate)
    echo "[SGX] Starting byz-mandate-tee inside Gramine enclave"
    exec gramine-sgx byz-mandate
    ;;
  reputation)
    echo "[SGX] Starting byz-reputation-tee inside Gramine enclave"
    exec gramine-sgx byz-reputation
    ;;
  both)
    echo "[SGX] Starting both TEE services"
    gramine-sgx byz-mandate &
    gramine-sgx byz-reputation &
    wait
    ;;
  *)
    echo "Unknown service: $SERVICE. Use mandate | reputation | both"
    exit 1
    ;;
esac

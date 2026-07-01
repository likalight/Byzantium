# =============================================================================
# Byzantium Gateway — Multi-Stage Production Dockerfile
# =============================================================================
# Stage 1: builder  — compiles the release binary with full Rust toolchain
# Stage 2: runtime  — minimal Debian image that ships only the binary
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
FROM rust:1.78-slim-bookworm AS builder

# System dependencies required to compile OpenSSL-linked crates and sqlx.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ---------------------------------------------------------------------------
# Dependency caching layer
# Copy only the manifests first and build a skeleton workspace so that Cargo
# can fetch and compile all dependencies before the real source is available.
# This layer is invalidated only when Cargo.toml / Cargo.lock change.
# ---------------------------------------------------------------------------
COPY Cargo.toml Cargo.lock ./

# Recreate the workspace member directories with minimal stub sources so that
# `cargo build` can resolve and compile all dependency crates.
RUN set -eux; \
    for crate in \
        crates/byz-common \
        crates/byz-crypto \
        crates/byz-identity \
        crates/byz-mandate \
        crates/byz-reputation \
        crates/byz-receipt \
        crates/byz-anchor \
        crates/byz-proof \
        crates/byz-store \
        crates/byz-tee \
        crates/byz-gateway \
        crates/byz-rail-x402 \
        crates/byz-rail-a2a \
        crates/byz-rail-eip3009 \
        crates/byz-rail-solana \
    ; do \
        mkdir -p "$crate/src"; \
        echo 'fn main() {}' > "$crate/src/main.rs"; \
        touch "$crate/src/lib.rs"; \
    done

# Copy each crate's Cargo.toml so Cargo sees the full dependency graph.
COPY crates/byz-common/Cargo.toml      crates/byz-common/
COPY crates/byz-crypto/Cargo.toml      crates/byz-crypto/
COPY crates/byz-identity/Cargo.toml    crates/byz-identity/
COPY crates/byz-mandate/Cargo.toml     crates/byz-mandate/
COPY crates/byz-reputation/Cargo.toml  crates/byz-reputation/
COPY crates/byz-receipt/Cargo.toml     crates/byz-receipt/
COPY crates/byz-anchor/Cargo.toml      crates/byz-anchor/
COPY crates/byz-proof/Cargo.toml       crates/byz-proof/
COPY crates/byz-store/Cargo.toml       crates/byz-store/
COPY crates/byz-tee/Cargo.toml         crates/byz-tee/
COPY crates/byz-gateway/Cargo.toml     crates/byz-gateway/
COPY crates/byz-rail-x402/Cargo.toml   crates/byz-rail-x402/
COPY crates/byz-rail-a2a/Cargo.toml    crates/byz-rail-a2a/
COPY crates/byz-rail-eip3009/Cargo.toml crates/byz-rail-eip3009/
COPY crates/byz-rail-solana/Cargo.toml crates/byz-rail-solana/

# Build dependencies only (stub sources).
# SQLX_OFFLINE=true skips the live-DB query check during the dep-cache build.
RUN SQLX_OFFLINE=true cargo build --release -p byz-gateway 2>&1 | tail -5 || true

# ---------------------------------------------------------------------------
# Real source build
# Remove stub artifacts so Cargo rebuilds crates with real sources.
# ---------------------------------------------------------------------------
COPY crates/ crates/

# Touch source files so Cargo detects them as newer than the cached stubs.
RUN find crates -name "*.rs" -exec touch {} +

# SQLX_OFFLINE controls whether sqlx uses the pre-generated .sqlx/ cache.
# Default false so local `docker build` works without a pre-generated cache.
# CI passes --build-arg SQLX_OFFLINE=true after running `cargo sqlx prepare`.
ARG SQLX_OFFLINE=false
ENV SQLX_OFFLINE=${SQLX_OFFLINE}

RUN cargo build --release -p byz-gateway

# Verify the binary was produced.
RUN test -f target/release/byz-gateway || \
    (echo "ERROR: binary target/release/byz-gateway not found" && exit 1)

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies:
#   ca-certificates — TLS root CAs for outbound HTTPS (zkMe, RPC, SP1 network)
#   libssl3         — OpenSSL shared library linked by reqwest / sqlx
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated non-root user and group.
RUN groupadd --system --gid 10001 byzantium \
 && useradd  --system --uid 10001 --gid byzantium \
             --no-create-home --shell /usr/sbin/nologin \
             byzantium

# Copy the compiled binary from the builder stage.
COPY --from=builder /build/target/release/byz-gateway /usr/local/bin/byzantium

# Ensure the binary is executable and owned by root (non-writable by the
# runtime user, following the principle of least privilege).
RUN chmod 755 /usr/local/bin/byzantium

# The gateway serves traffic on this port. Must match GATEWAY_PORT env var.
EXPOSE 8080

# Drop privileges before starting.
USER byzantium

# Health check — relies on the /health endpoint implemented by byz-gateway.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["sh", "-c", "wget -qO- http://127.0.0.1:${GATEWAY_PORT:-8080}/health || exit 1"]

CMD ["/usr/local/bin/byzantium"]

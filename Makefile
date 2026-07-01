# =============================================================================
# Byzantium Gateway — Makefile
# =============================================================================
# Usage: make <target>
# All targets that shell out use $() for variable expansion so they work on
# both GNU Make (Linux/macOS) and make via Git Bash on Windows.
# =============================================================================

.PHONY: all dev down build check test e2e lint fmt docker-build docker-push \
        migrate migrate-dry-run migrate-revert logs shell clean help \
        gramine-build sqlx-prepare zk-build zk-setup seed \
        publish-ts publish-rs-sdk publish-rs-common \
        sdk-build sdk-publish sdk-version \
        tls-setup k8s-certs load-test \
        seal-secrets k8s-secrets k8s-backup backup-now \
        dashboard dashboard-build

# -----------------------------------------------------------------------------
# Variables — override on the command line: make docker-push IMAGE_TAG=v1.2.3
# -----------------------------------------------------------------------------
IMAGE_REPO  := ghcr.io/byzantium/gateway
IMAGE_TAG   := latest
IMAGE       := $(IMAGE_REPO):$(IMAGE_TAG)

CARGO       := cargo
DOCKER      := docker
DC          := docker-compose
SQLX        := sqlx

# Target binary produced by `cargo build --release`
BIN         := target/release/byz-gateway

# Kubernetes namespace
K8S_NS      := byzantium

# -----------------------------------------------------------------------------
# Default target
# -----------------------------------------------------------------------------
all: check build test

# -----------------------------------------------------------------------------
# Local development (docker-compose)
# -----------------------------------------------------------------------------

## dev: Start all backing services (Postgres, Redis, Neo4j, ImmuDB) in the
##      background. The Rust gateway itself runs via `cargo run` outside compose.
dev:
	$(DC) up -d
	@echo ""
	@echo "Services started. Run 'make logs' to follow gateway logs."
	@echo "Start the gateway with: cargo run -p byz-gateway"

## down: Stop and remove all compose containers (data volumes are preserved).
down:
	$(DC) down

## logs: Follow the gateway container logs (Ctrl-C to stop).
logs:
	$(DC) logs -f gateway

## shell: Open an interactive shell inside the running gateway container.
shell:
	$(DC) exec gateway /bin/sh

# -----------------------------------------------------------------------------
# Rust build & quality
# -----------------------------------------------------------------------------

## build: Compile the gateway in release mode.
build:
	$(CARGO) build --release -p byz-gateway

## check: Run workspace type-checking and Clippy lints.
check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace -- -D warnings

## test: Run the full workspace test suite.
test:
	$(CARGO) test --workspace

## e2e: Run end-to-end integration tests (in-memory, no external services required).
e2e:
	bash scripts/run-e2e.sh

## lint: Alias for check (type-check + clippy).
lint: check

## fmt: Format all Rust source files in place.
fmt:
	$(CARGO) fmt --all

## fmt-check: Verify formatting without modifying files (useful in CI).
fmt-check:
	$(CARGO) fmt --all -- --check

# -----------------------------------------------------------------------------
# Database migrations (sqlx-cli)
# install: cargo install sqlx-cli --no-default-features --features postgres
# -----------------------------------------------------------------------------

## migrate: Apply all pending migrations against DATABASE_URL.
migrate:
	$(SQLX) migrate run --database-url "$(DATABASE_URL)"

## migrate-dry-run: Show which migrations would be applied without running them.
migrate-dry-run:
	$(SQLX) migrate info --database-url "$(DATABASE_URL)"

## migrate-revert: Revert the most recently applied migration (use with care).
migrate-revert:
	$(SQLX) migrate revert --database-url "$(DATABASE_URL)"

# -----------------------------------------------------------------------------
# Docker image
# -----------------------------------------------------------------------------

## docker-build: Build production Docker image (run make sqlx-prepare first for faster offline builds).
docker-build:
	$(DOCKER) build \
		--tag $(IMAGE) \
		--label "org.opencontainers.image.revision=$$(git rev-parse --short HEAD)" \
		--label "org.opencontainers.image.created=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		.

## docker-push: Push the image to GHCR.
##              Authenticate first: echo $GHCR_TOKEN | docker login ghcr.io -u <user> --password-stdin
docker-push: docker-build
	$(DOCKER) push $(IMAGE)

## docker-run: Run the image locally with environment loaded from .env.
docker-run: docker-build
	$(DOCKER) run --rm \
		--env-file .env \
		-p 8080:8080 \
		--name byzantium-gateway \
		$(IMAGE)

# -----------------------------------------------------------------------------
# Kubernetes helpers
# -----------------------------------------------------------------------------

## k8s-apply: Apply all manifests in deploy/k8s/ to the byzantium namespace.
k8s-apply:
	kubectl apply -n $(K8S_NS) -f deploy/k8s/

## k8s-rollout: Watch the rolling update progress.
k8s-rollout:
	kubectl rollout status deployment/byzantium-gateway -n $(K8S_NS)

## k8s-restart: Force a rolling restart of the gateway deployment.
k8s-restart:
	kubectl rollout restart deployment/byzantium-gateway -n $(K8S_NS)

## seal-secrets: Seal secrets for k8s (requires kubeseal + cluster connection)
seal-secrets:
	kubeseal --format yaml < deploy/k8s/secrets.yaml.template \
		> deploy/k8s/sealed-secrets/byzantium-sealed.yaml
	@echo "Sealed secrets written. Safe to commit."

## k8s-secrets: Deploy sealed secrets to cluster
k8s-secrets: seal-secrets
	kubectl apply -f deploy/k8s/sealed-secrets/byzantium-sealed.yaml

## k8s-backup: Deploy PostgreSQL backup CronJob to k8s
k8s-backup:
	kubectl apply -f deploy/k8s/backup/postgres-backup-cronjob.yaml

## backup-now: Trigger an immediate backup (k8s)
backup-now:
	kubectl create job --from=cronjob/postgres-backup backup-manual-$(shell date +%s)

## tls-setup: Obtain Let's Encrypt certificate for nginx (requires DOMAIN and EMAIL env vars)
tls-setup:
	bash nginx/certbot-setup.sh

## k8s-certs: Deploy cert-manager issuers and certificate (requires BYZANTIUM_DOMAIN and CERT_MANAGER_EMAIL)
k8s-certs:
	envsubst < deploy/k8s/cert-manager/issuer.yaml | kubectl apply -f -
	envsubst < deploy/k8s/cert-manager/certificate.yaml | kubectl apply -f -
	envsubst < deploy/k8s/ingress.yaml | kubectl apply -f -

# -----------------------------------------------------------------------------
# ZK / SGX
# -----------------------------------------------------------------------------

## gramine-build: Build and sign Gramine SGX manifests (requires gramine installed)
gramine-build:
	bash gramine/build.sh

## ZK Proofs

zk-build: ## Build SP1 disclosure proof guest circuit (requires SP1 toolchain: https://docs.succinct.xyz)
	cd programs/disclosure-proof && cargo prove build
	@echo "Guest ELF written to programs/disclosure-proof/elf/"

zk-setup: ## Install the SP1 toolchain (one-time setup)
	curl -L https://sp1.succinct.xyz | bash
	sp1up

# -----------------------------------------------------------------------------
# Database extras
# -----------------------------------------------------------------------------

## sqlx-prepare: Regenerate sqlx offline query cache (requires running PostgreSQL)
sqlx-prepare:
	DATABASE_URL=postgres://byzantium:byzantium@localhost:5432/byzantium \
		cargo sqlx prepare --workspace
	@echo "Commit the .sqlx/ directory to enable SQLX_OFFLINE builds"

# -----------------------------------------------------------------------------
# Housekeeping
# -----------------------------------------------------------------------------

seed: ## Seed dev environment with test agents and mandates
	bash scripts/seed.sh

## clean: Remove Cargo build artifacts and dangling Docker images.
clean:
	$(CARGO) clean
	$(DOCKER) image prune -f

## help: Print this help message.
help:
	@grep -E '^##' Makefile | sed 's/^## //' | column -t -s ':'

# -----------------------------------------------------------------------------
# Publishing
# -----------------------------------------------------------------------------

dashboard: ## Start the admin dashboard dev server (http://localhost:3000)
	cd dashboard && npm install && npm run dev

dashboard-build: ## Build the admin dashboard for production
	cd dashboard && npm install && npm run build

load-test: ## Run k6 load test against local stack (requires k6 installed)
	k6 run tests/load/trust_check.js \
		-e BYZANTIUM_URL=http://localhost:8080 \
		-e BYZANTIUM_API_KEY=dev-key-local

publish-ts: ## Publish @byzantium/sdk to npm (run: npm login first)
	cd sdk/typescript && npm run build && npm publish --access public

sdk-build: ## Build TypeScript SDK
	cd sdk/typescript && npm run build

sdk-publish: ## Publish SDK to npm (requires NPM_TOKEN env var)
	cd sdk/typescript && npm publish --access public

sdk-version: ## Bump SDK patch version and tag for release
	cd sdk/typescript && npm version patch
	git add sdk/typescript/package.json
	git commit -m "chore: bump SDK version"
	git tag sdk-v$$(node -p "require('./sdk/typescript/package.json').version")
	@echo "Run: git push && git push --tags"

publish-rs-sdk: ## Publish byz-sdk to crates.io (run: cargo login first)
	cargo publish -p byz-sdk --dry-run
	@echo "Remove --dry-run to publish for real"

publish-rs-common: ## Publish byz-common to crates.io
	cargo publish -p byz-common --dry-run
	@echo "Remove --dry-run to publish for real"

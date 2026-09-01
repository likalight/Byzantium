# Contributing to Byzantium

Thanks for considering it. This document covers how to get set up, what the CI
gate expects, and the conventions that matter in a codebase whose job is to
decide how much money an autonomous agent may move.

## Development setup

**Prerequisites:** Rust 1.75+, Docker, Node 18+ (for the TypeScript SDK).

```bash
git clone https://github.com/likalight/Byzantium.git
cd byzantium
cp .env.example .env
docker compose up -d postgres redis neo4j    # backing services only
cargo test --workspace
```

Most crates run entirely in memory and need no services at all:

```bash
cargo test -p byz-underwrite -p byz-reputation -p byz-provenance -p byz-tap
```

## The CI gate

Three commands. All three must pass before a PR is reviewed:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`-D warnings` is deliberate. A warning that is allowed to persist stops being
read, and this is not a codebase where "we'll clean it up later" is a good
default.

## Conventions

### Tests describe behaviour, not methods

Name a test after the property it protects, so a failure reads as a sentence:

```rust
#[test]
fn tiny_clean_volume_earns_a_tiny_score() { … }

#[test]
fn a_session_key_cannot_grant_itself_more_than_the_agent_has() { … }
```

Not `test_score()` or `test_delegate_2()`.

### Adversarial tests are the point

Any change to scoring, limits, delegation, or verification should come with a
test for how someone would abuse it. The existing suite covers bust-out farming,
wash trading, sybil splitting, forged provenance, replay, credential swapping,
and scope-widening delegation. If your change opens a new avenue, close it in
the same PR.

### Comments explain *why*, never *what*

The code already says what it does. Comment the reasoning that is not
recoverable from reading it — especially the security or risk property a line is
protecting:

```rust
// Rounding up matters: this is used for haircuts, and rounding a haircut
// down understates exposure.
let scaled = (self.minor_units as u128 * bps as u128).div_ceil(10_000u128);
```

### Money is integer-only

Never introduce a float into a limit, an exposure, or a balance. `Money` carries
minor units and a currency, and currencies have different minor-unit exponents —
JPY has none. A limit that drifts is a limit that can be crossed.

### Signed payloads are canonical and ordered

Anything covered by a signature must serialise deterministically. `serde_json`'s
map is a `BTreeMap` here, so key order is stable across processes — do not
replace it with an order-preserving map, and sort any vector before it enters a
signing payload. A verifier on another host reconstructs those bytes
independently; a different ordering is indistinguishable from a forgery.

**If you add a field to a signed struct, add it to the signing payload too.** An
unsigned field is a field an attacker can choose.

## Pull requests

- Branch from `develop`. `main` is release-only.
- One logical change per PR. A scoring change and a refactor are two PRs.
- Update `CHANGELOG.md` under `[Unreleased]`.
- If you change an endpoint, update `openapi.yaml` and `docs/api.md`.
- Describe the failure mode your change prevents, not only the change.

## Security-sensitive areas

Changes to these get closer review, and should say explicitly what property they
preserve:

| Area | The property |
|---|---|
| `byz-underwrite/engine.rs` | Growth stays sublinear and bounded per window |
| `byz-reputation/scorer.rs` | Standing cannot be farmed with volume or patience |
| `byz-provenance/verifier.rs` | Only runtime-signed evidence counts; replay is refused |
| `byz-passport/delegation.rs` | Delegation narrows, never widens |
| `byz-tap/signature.rs` | The covered-component list is itself signed |
| `byz-common/limits.rs` | Every field a relying party trusts is inside the signature |

Please do **not** open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

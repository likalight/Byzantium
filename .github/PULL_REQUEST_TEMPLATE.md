## What this changes

<!-- One paragraph. What is different after this PR? -->

## Why

<!-- The failure mode this prevents, or the capability it enables. -->

## Risk surface

- [ ] This does **not** touch limits, scoring, signatures, delegation, or enforcement
- [ ] This **does** — and I have described the abuse case below

<!-- If it does: how would someone exploit this to obtain a larger limit than
     they should have, or get a draw honoured that should have been refused?
     What in this PR closes that? -->

## Signed payloads

- [ ] No signed struct changed
- [ ] A signed struct changed, and **every new field is inside the signing payload**

<!-- A field outside the signature is a field an attacker can choose. -->

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Tests added for the behaviour, named after the property they protect
- [ ] Adversarial test added, if this could be abused
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `openapi.yaml` and `docs/api.md` updated, if an endpoint changed

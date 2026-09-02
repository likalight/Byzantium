# Security policy

Byzantium issues credentials that other systems use to decide how much money an
autonomous agent may move. A flaw here is a flaw in someone else's risk
controls, so we would much rather hear about it early and awkwardly than late
and politely.

## Reporting a vulnerability

**Do not open a public issue.**

Use [GitHub private vulnerability reporting](https://github.com/likalight/Byzantium/security/advisories/new),
which is enabled on this repository and reaches the maintainers directly without
disclosing anything publicly. Include:

- what the issue is, and which component
- how to reproduce it — a failing test is ideal
- what an attacker gains
- anything you think we would get wrong in a fix

We aim to acknowledge within **2 business days** and to give an assessment with
a remediation timeline within **10 business days**.

We will credit you in the release notes unless you would rather we didn't.

## Scope

In scope:

- The underwriting engine, scorer, and anything that changes an issued limit
- Signature construction and verification (`byz-crypto`, `byz-tap`)
- Delegation and the agent passport
- Provenance verification and replay defence
- The gateway's authentication and authorisation
- SQL injection, deserialisation, and resource-exhaustion paths

Out of scope:

- The `dashboard/` demo UI
- Findings that require an already-compromised runtime signing key
- Missing rate limits on a locally-run development instance
- Reports produced solely by an automated scanner with no demonstrated impact

## What we consider severe

Ranked by how we would actually triage them:

| Severity | Example |
|---|---|
| **Critical** | Forging a limit attestation, or getting one honoured that the issuer did not sign |
| **Critical** | Widening a delegation's scope, or using a revoked key |
| **High** | Farming standing at a rate the growth controls are meant to prevent |
| **High** | Getting unsigned or replayed provenance counted as evidence |
| **High** | Consuming more of an exposure window than the limit permits — including via a race |
| **Medium** | Learning another operator's evidence, standing, or limits |
| **Medium** | Denial of service against issuance or verification |

## Design notes relevant to reports

Some things that look like bugs are deliberate, and the reasoning may save you
time:

- **A new agent scores zero.** That is intentional — a non-zero default is a free
  limit for anyone who can generate a keypair.
- **Unsigned provenance is ignored, not down-weighted.** Partial credit would be
  an incentive to flood the endpoint.
- **Attestations are short-lived rather than individually revocable.** Revocation
  is expressed as a per-subject cutoff, because per-credential revocation lists
  are the part of every credential system that fails in production.
- **Attestations carry an evidence hash, never the evidence.** If you can recover
  trace *contents* from an attestation, that is a serious finding.

## Cryptography

All signatures are ML-DSA (Dilithium3) via `pqcrypto-dilithium`. If you find a
misuse of the primitive — nonce handling, key reuse, a signature over
non-canonical bytes, a field outside the signed payload — treat it as critical
and report it directly.

### Known risk: the signature crate is unmaintained

`pqcrypto-dilithium`, `pqcrypto-kyber` and `pqcrypto-traits` are flagged
unmaintained by RustSec, and every signature this system produces depends on
them. We would rather write that down than have you discover it with
`cargo audit`.

There is no known defect in them today — the advisories describe crates going
quiet, not exploitable bugs — and the underlying algorithm is a NIST standard
rather than anything bespoke. But an unmaintained dependency in the signing path
is a real risk and it is on the register, not dismissed.

The migration path is to a maintained ML-DSA implementation. It is a contained
change in principle, because all signing and verification goes through
`byz-crypto`, but it touches every signed structure in the system and so is
sequenced deliberately rather than done in a hurry.

### Dependency advisories we have accepted

`.cargo/audit.toml` lists the advisories we have assessed as unreachable, each
with the path that pulls the crate in, why the described attack does not apply,
and the condition that would make us revisit. If you think one of those
judgements is wrong, that is a legitimate and welcome report.

# Senior Security — Repository Security & Compliance Review Skill

Self-contained, evidence-based repository security and compliance review skill (`OWASP ASVS 5.0.0`, `NIST SSDF 1.1`, `NIST SP 800-53 Rev 5`, `OWASP Top 10:2025`), combining STRIDE/DREAD threat modeling, bounded secret scanning, deterministic compliance probes, and cryptographically verified review ledgers.

## Structure

- `SKILL.md` — Main skill instructions and 5-step evidence-backed repository compliance workflow.
- `references/`
  - `assessment-method.md` — Evidence standard (`verified_pass`, `verified_fail`, `not_verified`, `not_applicable`), severity criteria, and versioned Control ID Reference Table (`OWASP-ASVS-5.0.0`, `NIST-SSDF-1.1`, `NIST-800-53`, `OWASP-TOP10-2025`).
  - `coverage-and-context.md` — Three-ledger coverage accounting (mechanical scan, semantic code review, control evaluation) and batch context-window discipline.
  - `threat-modeling-guide.md` — STRIDE and DREAD threat modeling reference.
  - `security-architecture-patterns.md` — Zero Trust, defense-in-depth, and secure design patterns.
  - `cryptography-implementation.md` — Cryptographic implementation patterns and key management.
- `scripts/` (Python 3 standard library only, zero external dependencies)
  - `repo_coverage.py` — Working-tree inventory and SHA-256 manifest builder (`O_NOFOLLOW` + TOCTOU safe).
  - `secret_scanner.py` — Bounded 64 KiB streaming secret candidate scanner with full credential redaction.
  - `compliance_probes.py` — Deterministic enterprise security & compliance probe collector across 6 suites (`ci_supply_chain`, `dependency_integrity`, `container_iac`, `crypto_and_sinks`, `api_authz_surface`, `governance_sdlc`).
  - `read_evidence.py` — Bounded evidence reader (`--lines`, batch `--slice`, and automatic `--update-ledger` receipt generation).
  - `verify_review.py` — Cryptographic and line-range verifier for `review-ledger.json` against `coverage-manifest.json`.
  - `threat_modeler.py` — Optional STRIDE/DREAD candidate threat generator.
- `tests/`
  - `test_security_tools.py` — Unit and regression test suite (`14` tests).

## Quick Start

```bash
# 1. Build repository coverage manifest
python3 -B scripts/repo_coverage.py /path/to/repo --ledger files.jsonl --output coverage-manifest.json

# 2. Scan for candidate secrets and compliance probe leads
python3 -B scripts/secret_scanner.py /path/to/repo --format json --coverage-output secrets-coverage.jsonl --output secrets.json
python3 -B scripts/compliance_probes.py /path/to/repo --json --output probes.json

# 3. Read bounded source slices in batch and automatically update review-ledger.json
python3 -B scripts/read_evidence.py --root /path/to/repo \
  --slice src/auth.py:1-120 \
  --slice src/db.py:1-90 \
  --number-lines \
  --update-ledger review-ledger.json \
  --flow authentication_and_storage

# 4. Verify review ledger against repository HEAD
python3 -B scripts/verify_review.py review-ledger.json --root /path/to/repo
```

## Running Tests

```bash
python3 -B -m unittest discover -s tests -v
```

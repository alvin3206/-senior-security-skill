# Coverage and Bounded Context Management

## Three independent coverage dimensions

Report these three dimensions separately—never conflate byte scanning with code comprehension:

1. **Mechanical scan coverage** (`repo_coverage.py`, `secret_scanner.py`, `compliance_probes.py`): tracks discovered regular files, `scanned_text_bytes`, skipped binaries/symlinks, and excluded directories (`.git`, `node_modules`, etc.). Excluded directories and Git history are unscanned scope, not clean files.
2. **Semantic review coverage** (`read_evidence.py` + `verify_review.py`): tracks the exact files, `sha256` digests, and inclusive line ranges `[start_line, end_line]` read and analyzed by the reviewer in `review-ledger.json`.
3. **Control coverage**: counts selected requirements by status (`verified_pass`, `verified_fail`, `not_verified`, `not_applicable`).

## Efficient batch inspection with `read_evidence.py`

To minimize multi-turn context overhead and prevent manual line-number or hash errors in `review-ledger.json`, inspect risk-bearing slices in batches and pass `--update-ledger`:

```bash
python3 <skill-dir>/scripts/read_evidence.py --root <repo> \
  --slice src/auth/login.py:1-120 \
  --slice src/api/orders.py:40-140 \
  --number-lines \
  --receipt <audit-dir>/reads.jsonl \
  --update-ledger <audit-dir>/review-ledger.json \
  --flow "auth-and-orders"
```

- Each `--slice path:START-END` reads inclusive 1-based lines (capped at 32 KiB per slice, 64 KiB per batch), computes the file's `sha256` with `O_NOFOLLOW` and TOCTOU checks, and automatically merges `complete_line_ranges` into `review-ledger.json`.
- For single-line minified files or byte-offset continuation, use `python3 <skill-dir>/scripts/read_evidence.py <path> --root <repo> --offset <byte_offset> --bytes 8192` and follow `next_offset`.
- Before reporting semantic coverage counts, run `python3 <skill-dir>/scripts/verify_review.py <audit-dir>/review-ledger.json --root <repo>` to confirm all recorded hashes and line bounds match the repository at `HEAD`.

## Context window budget and compaction resilience

- **Progressive loading**: keep `SKILL.md`, the architecture summary, and active batch slices in context. Load `threat-modeling-guide.md`, `security-architecture-patterns.md`, or `cryptography-implementation.md` only when designing specific mitigations.
- **Avoid raw output spikes**: never dump whole repositories or unbounded `grep` outputs into stdout. Write `files.jsonl`, `secrets.json`, and `probes.json` to `<audit-dir>/` outside the target repository, then inspect targeted slices.
- **Resuming after context compaction**: treat `review-ledger.json` and `probes.json` on disk as external state. If earlier source excerpts were compacted out of context, re-read the exact `file:start-end` slice with `read_evidence.py` before asserting a confirmed finding or `verified_pass` control.

# Assessment Method and Control Reference

## Evidence states

Assign one status per selected control requirement:

- `verified_pass`: inspected or tested over the stated scope with concrete `file:line` evidence showing effective enforcement.
- `verified_fail`: inspected evidence contradicts the requirement in scope; link the confirmed finding.
- `not_verified`: untested, runtime/deployment configuration unavailable, tooling absent, or only superficial keyword evidence exists. Keep `not_verified` items in the assessment denominator.
- `not_applicable`: explicit scope rationale (e.g., no database or container runtime in scope). Absence of evidence is `not_verified`, never `not_applicable`.

A comment, policy note, or decorator name without verified enforcement does not establish `verified_pass`. A product code vulnerability (such as SQL injection) establishes `verified_fail` for the technical control (`OWASP-ASVS-5.0.0:V5.3`), not automatically for the SDLC code-review practice (`NIST-SSDF-1.1:PW.7`), which is evaluated from CI/SAST and review configuration evidence.

## Versioned control reference catalog

Use these exact version-qualified identifiers when mapping repository evidence (or cite the user's requested framework edition):

| Domain | OWASP ASVS 5.0.0 | NIST SSDF 1.1 (SP 800-218) | NIST SP 800-53 Rev 5 | OWASP Top 10:2025 | What to verify in repository |
|---|---|---|---|---|---|
| **Architecture & Threat Modeling** | `V1.1` Architecture & Threat Modeling | `PW.1` Design to Meet Security Requirements / `PW.2` Review Design | `SA-8` Security Engineering Principles / `PL-8` Security Architecture | `A06` Insecure Design | Trust boundaries, DFD entry points, privilege separation, abuse-case mitigations |
| **Authentication** | `V2.1` Password Security / `V2.2` General Authenticator | `PW.1` | `IA-2` Identification & Authentication / `IA-5` Authenticator Management | `A07` Authentication Failures | MFA enforcement, brute-force rate limiting, credential verification flows |
| **Session Management** | `V3.2` Session Binding / `V3.4` Cookie-Based Sessions | `PW.5` Secure Coding Practices | `SC-23` Session Authenticity | `A07` Authentication Failures | Token rotation on login, expiry, `Secure`, `HttpOnly`, `SameSite` flags |
| **Access Control (AuthZ)** | `V4.1` General Access Control / `V4.2` Operation & Object Level (BOLA/IDOR) | `PW.5` | `AC-3` Access Enforcement / `AC-6` Least Privilege | `A01` Broken Access Control | Server-side role/permission checks on every route, session-bound object ownership |
| **Validation, Injection & Deserialization** | `V5.2` Sanitization & Sandboxing / `V5.3` Output Encoding & Injection Prevention | `PW.5` | `SI-10` Information Input Validation | `A05` Injection / `A08` Integrity Failures | Parameterized queries, no `eval`/`exec`/`shell_exec`/unsafe `yaml.load`/`pickle`, SSRF allowlists |
| **Cryptography & Secrets** | `V6.2` Algorithms / `V6.4` Secret Management | `PS.1` Protect Code & Secrets | `SC-13` Cryptographic Protection / `SC-28` Protection at Rest | `A04` Cryptographic Failures | Argon2id/bcrypt/scrypt for passwords, AEAD (AES-GCM/ChaCha20), CSPRNG tokens, no hardcoded secrets |
| **Error Handling & Logging** | `V7.1` Log Content / `V7.4` Error Handling | `PW.5` | `AU-2` Event Logging / `SI-11` Error Handling | `A09` Logging Failures / `A10` Exceptional Conditions | Fail-closed exception handling, no stack-trace or secret leakage in logs/responses |
| **Communications & TLS** | `V9.1` Client/Server TLS Security | `PW.5` | `SC-8` Transmission Confidentiality & Integrity | `A04` Cryptographic Failures | TLS 1.2+/1.3 enforcement, certificate verification enabled (`verify=True`) |
| **File Upload & Storage** | `V12.1` File Upload & Integrity | `PW.5` | `SI-10` / `SC-7` Boundary Protection | `A01` Broken Access Control | Path traversal prevention, server-generated filenames, storage outside web root |
| **API & CORS Security** | `V13.1` Generic Web Service / `V14.5` HTTP Headers & CORS | `PW.5` | `AC-4` Information Flow Enforcement | `A01` / `A02` Security Misconfiguration | Non-wildcard CORS for authenticated APIs, schema validation, rate limits |
| **Container & Config Hardening** | `V14.1` Build & Deploy / `V14.3` Unintended Disclosure | `PW.6` Configure Build & Hardening | `CM-2` Baseline Configuration / `CM-6` Configuration Settings | `A02` Security Misconfiguration | Non-root container `USER`, immutable image `@sha256` digests, debug disabled by default |
| **Supply Chain & CI/CD Integrity** | `V14.2` Dependency & Supply Chain | `PS.1` / `PS.2` Release Integrity / `PS.3` Archive / `PW.4` Third-Party Components | `SA-12` Supply Chain Protection / `SR-3` Supply Chain Controls | `A03` Software Supply Chain / `A08` Integrity Failures | Committed lockfiles with hashes, pinned build backends, SHA-pinned CI actions, minimal `GITHUB_TOKEN` permissions |
| **SDLC Code Analysis & Testing** | — | `PW.7` Code Review & Static Analysis / `PW.8` Executable Testing | `SA-11` Developer Testing & Evaluation | — | SAST/linter configs covering primary repo languages, negative security tests |
| **Vulnerability Disclosure & Triage** | — | `RV.1` Identify Vulnerabilities / `RV.2` Assess & Remediate / `RV.3` Root Cause | `RA-5` Vulnerability Monitoring & Scanning / `SI-2` Flaw Remediation | `A03` Software Supply Chain | Tracked `SECURITY.md`, Dependabot/Renovate config, lockfile update hygiene |

## Control record schema

```json
{
  "framework": "OWASP-ASVS",
  "version": "5.0.0",
  "requirement_id": "V4.2",
  "scope": "allocations route",
  "status": "verified_fail",
  "evidence": [{"revision": "commit", "path": "app/routes/allocations.js", "lines": [16, 28], "sha256": "hash"}],
  "procedure": "Trace userId parameter from route handler to DAO query and check session ownership binding",
  "observed_result": "URL userId is passed directly to getByUserIdAndThreshold without comparing against req.session.userId",
  "limitations": ["runtime WAF rules not inspected"]
}
```

## Disposition and retest

Track each finding as `open`, `mitigated-pending-verification`, `verified-fixed`, or `accepted-risk` (with named authority, rationale, and expiration). After remediation, re-inspect the modified code flow at the new commit and execute a targeted negative/bypass test. Removing a leaked credential from a commit does not revoke it; rotation is mandatory.

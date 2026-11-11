#!/usr/bin/env python3
"""Deterministic enterprise security and compliance probes (NIST SSDF 1.1, OWASP ASVS 5.0.0, NIST SP 800-53 Rev 5).

Collects structured, line-anchored technical leads across 6 probe suites without
executing target code:
  1. ci_supply_chain      - GitHub Actions / GitLab CI pinning, permissions, secret exfiltration
  2. dependency_integrity - Lockfiles, integrity hashes, unpinned build backends, registries
  3. container_iac        - Dockerfile, Compose, K8s, Terraform hardening & network exposure
  4. crypto_and_sinks     - AST + multi-language weak crypto, TLS bypass, injection/eval sinks, cookie/CORS flags
  5. api_authz_surface    - Route/endpoint inventory, OpenAPI security schemes, auth middleware, IDOR/BOLA leads
  6. governance_sdlc      - SECURITY.md, CODEOWNERS, Dependabot/Renovate, SAST language coverage, hardcoded keys

Probe outputs are evidence leads, not final compliance verdicts. Confirm data/control
flow with read_evidence.py before marking a control verified_pass or verified_fail.
"""
import argparse
import ast
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys

from repo_coverage import entries

PROBES = (
    'ci_supply_chain',
    'dependency_integrity',
    'container_iac',
    'crypto_and_sinks',
    'api_authz_surface',
    'governance_sdlc',
)

LANG_BY_EXT = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.php': 'php',
    '.go': 'go',
    '.java': 'java',
    '.rb': 'ruby',
    '.rs': 'rust',
    '.cs': 'csharp',
}

MANIFEST_LOCK_PAIRS = {
    'package.json': ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'),
    'pyproject.toml': ('uv.lock', 'poetry.lock', 'pdm.lock', 'requirements.txt'),
    'requirements.txt': ('uv.lock', 'poetry.lock', 'Pipfile.lock'),
    'Pipfile': ('Pipfile.lock',),
    'composer.json': ('composer.lock',),
    'go.mod': ('go.sum',),
    'Cargo.toml': ('Cargo.lock',),
    'Gemfile': ('Gemfile.lock',),
}


def shannon_entropy(text):
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _read_utf8_bounded(path, max_bytes=524288):
    """Safely read up to max_bytes of a regular file via O_NOFOLLOW."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        return None, None
    if b'\0' in raw or len(raw) > max_bytes:
        return None, None
    sha = hashlib.sha256(raw).hexdigest()
    try:
        return raw.decode('utf-8'), sha
    except UnicodeDecodeError:
        return raw.decode('utf-8', errors='replace'), sha


def _lead(probe, rule_id, severity, title, rel_path, line, sha256, detail, controls, recommendation):
    return {
        'verification_status': 'lead_requires_semantic_review',
        'probe': probe,
        'rule_id': rule_id,
        'severity': severity,
        'title': title,
        'file_path': rel_path,
        'line_number': max(1, int(line)),
        'sha256': sha256,
        'detail': detail,
        'controls': controls,
        'recommendation': recommendation,
    }


def scan_ci_workflow(rel_path, text, sha):
    leads = []
    lines = text.splitlines()
    has_permissions = any(re.match(r'^\s*permissions\s*:', ln) for ln in lines)
    if not has_permissions and '.github/workflows/' in rel_path:
        leads.append(_lead(
            'ci_supply_chain', 'CI001', 'medium',
            'GitHub Actions workflow omits explicit GITHUB_TOKEN permissions',
            rel_path, 1, sha,
            'No top-level or job-level permissions block found; token permissions depend on repository defaults.',
            ['NIST-SSDF-1.1:PS.1', 'OWASP-ASVS-5.0.0:V14.2', 'OWASP-TOP10-2025:A08', 'NIST-800-53:AC-6'],
            'Set top-level `permissions: {}` or `permissions: contents: read` and grant job permissions minimally.',
        ))

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        if re.search(r'permissions\s*:\s*write-all\b|\bcontents\s*:\s*write\b', line):
            leads.append(_lead(
                'ci_supply_chain', 'CI002', 'medium',
                'Broad write permissions granted in CI workflow',
                rel_path, idx, sha,
                'Workflow grants write-all or contents:write privileges to runner token.',
                ['NIST-SSDF-1.1:PS.1', 'OWASP-TOP10-2025:A08', 'NIST-800-53:AC-6'],
                'Scope write permissions to the single release/signing job that requires them.',
            ))
        m_uses = re.search(r'\buses\s*:\s*["\']?([^"\'\s#]+)', line)
        if m_uses:
            action_ref = m_uses.group(1)
            if not action_ref.startswith('./') and not action_ref.startswith('docker://') and '@' in action_ref:
                _, ref = action_ref.rsplit('@', 1)
                if not re.fullmatch(r'[0-9a-fA-F]{40}', ref):
                    leads.append(_lead(
                        'ci_supply_chain', 'CI003', 'medium',
                        f'Third-party CI action not pinned to full commit SHA ({action_ref})',
                        rel_path, idx, sha,
                        f'Action reference `{action_ref}` uses mutable tag/branch `{ref}` instead of a 40-char commit SHA.',
                        ['NIST-SSDF-1.1:PW.4', 'NIST-SSDF-1.1:PS.1', 'OWASP-TOP10-2025:A03', 'NIST-800-53:SA-12'],
                        'Pin third-party GitHub Actions to a verified 40-character commit SHA.',
                    ))
        if re.search(r'toJson\s*\(\s*secrets\s*\)|secrets\.[A-Za-z0-9_]+.*base64|\benv\b.*base64', line, re.I):
            leads.append(_lead(
                'ci_supply_chain', 'CI004', 'critical',
                'CI workflow serializes or encodes secrets into environment/logs',
                rel_path, idx, sha,
                'Workflow serializes secret context or base64-encodes environment/secrets, bypassing CI log masking.',
                ['NIST-SSDF-1.1:PS.1', 'OWASP-ASVS-5.0.0:V6.4', 'OWASP-TOP10-2025:A04', 'NIST-800-53:SC-28'],
                'Remove secret dumping/encoding steps immediately, rotate exposed repository secrets, and audit CI logs.',
            ))
        if re.search(r'\bpull_request_target\b', line):
            leads.append(_lead(
                'ci_supply_chain', 'CI005', 'high',
                'Workflow uses privileged pull_request_target trigger',
                rel_path, idx, sha,
                '`pull_request_target` runs in the base repo context with secret access; unsafe if combined with PR code checkout.',
                ['NIST-SSDF-1.1:PS.1', 'OWASP-TOP10-2025:A08', 'NIST-800-53:CM-3'],
                'Avoid checking out or executing untrusted PR head code inside `pull_request_target` workflows.',
            ))
    return leads


def scan_dependency_manifest(rel_path, name, text, sha, all_rel_paths):
    leads = []
    lines = text.splitlines()
    if name in MANIFEST_LOCK_PAIRS and name != 'requirements.txt':
        parent = str(Path(rel_path).parent)
        lock_candidates = MANIFEST_LOCK_PAIRS[name]
        has_lock = any(
            (f'{parent}/{lk}' if parent != '.' else lk) in all_rel_paths or lk in all_rel_paths
            for lk in lock_candidates
        )
        if not has_lock:
            leads.append(_lead(
                'dependency_integrity', 'DEP001', 'medium',
                f'Dependency manifest `{rel_path}` has no committed lockfile',
                rel_path, 1, sha,
                f'Expected one of {lock_candidates} alongside `{rel_path}` for reproducible dependency resolution.',
                ['NIST-SSDF-1.1:PW.4', 'NIST-SSDF-1.1:PS.3', 'OWASP-ASVS-5.0.0:V14.2.1', 'OWASP-TOP10-2025:A03'],
                'Commit a deterministic lockfile with cryptographic hashes and enforce locked installs in CI.',
            ))

    if name == 'pyproject.toml':
        in_build = False
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('['):
                in_build = (stripped == '[build-system]')
            elif in_build and 'requires' in stripped and ('>=' in stripped or '<' in stripped or '~=' in stripped):
                leads.append(_lead(
                    'dependency_integrity', 'DEP002', 'medium',
                    'Build-system backend in pyproject.toml is range-constrained rather than pinned',
                    rel_path, idx, sha,
                    f'Build requirement `{stripped}` uses version ranges; isolated builds may resolve unreviewed backend releases.',
                    ['NIST-SSDF-1.1:PW.4', 'NIST-SSDF-1.1:PS.2', 'OWASP-TOP10-2025:A03', 'OWASP-TOP10-2025:A08'],
                    'Pin exact build-backend versions/hashes or build releases from a locked offline environment.',
                ))

    if name == 'requirements.txt':
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(('#', '-')):
                continue
            if '==' not in stripped and '@' not in stripped:
                leads.append(_lead(
                    'dependency_integrity', 'DEP004', 'medium',
                    f'Unpinned Python dependency `{stripped}` in requirements.txt',
                    rel_path, idx, sha,
                    f'Requirement `{stripped}` omits an exact `==version` pin or `--hash`, preventing deterministic installs.',
                    ['NIST-SSDF-1.1:PW.4', 'OWASP-ASVS-5.0.0:V14.2.1', 'OWASP-TOP10-2025:A03'],
                    'Pin all requirements to exact versions (`pkg==x.y.z`) and commit a hash-locked lockfile.',
                ))

    for idx, line in enumerate(lines, 1):
        if re.search(r'http://[^\s"\']*?(?:registry|pypi|npmjs|packagist|maven)', line, re.I):
            leads.append(_lead(
                'dependency_integrity', 'DEP003', 'high',
                'Cleartext HTTP package registry URL configured',
                rel_path, idx, sha,
                'Package source uses unencrypted HTTP, enabling MitM package tampering.',
                ['NIST-SSDF-1.1:PW.4', 'OWASP-ASVS-5.0.0:V14.2', 'OWASP-TOP10-2025:A03', 'NIST-800-53:SC-8'],
                'Use HTTPS package registries exclusively and verify package signatures/hashes.',
            ))
    return leads


def scan_container_and_iac(rel_path, name, text, sha):
    leads = []
    lines = text.splitlines()
    low_name = name.lower()

    if low_name.startswith('dockerfile'):
        has_user = False
        last_user_root = False
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            m_from = re.match(r'^FROM\s+(?:--platform=\S+\s+)?(\S+)', stripped, re.I)
            if m_from:
                image = m_from.group(1)
                if image.lower() != 'scratch' and '@sha256:' not in image:
                    leads.append(_lead(
                        'container_iac', 'IAC001', 'medium',
                        f'Dockerfile base image `{image}` is not pinned by @sha256 digest',
                        rel_path, idx, sha,
                        f'Base image `{image}` uses a mutable tag or implicit `:latest`, reducing build reproducibility.',
                        ['NIST-SSDF-1.1:PW.4', 'OWASP-ASVS-5.0.0:V14.1', 'OWASP-TOP10-2025:A03', 'NIST-800-53:CM-2'],
                        'Pin container base images to an immutable `@sha256:...` digest.',
                    ))
            m_user = re.match(r'^USER\s+(\S+)', stripped, re.I)
            if m_user:
                has_user = True
                last_user_root = m_user.group(1).lower() in ('root', '0', '0:0')
            if re.search(r'curl\b.*\|\s*(?:ba)?sh\b|wget\b.*\|\s*(?:ba)?sh\b', stripped, re.I):
                leads.append(_lead(
                    'container_iac', 'IAC002', 'high',
                    'Dockerfile pipes remote script directly to shell without checksum verification',
                    rel_path, idx, sha,
                    'Remote script execution via `curl/wget | sh` is vulnerable to upstream tampering.',
                    ['NIST-SSDF-1.1:PW.4', 'OWASP-TOP10-2025:A08', 'NIST-800-53:SI-7'],
                    'Download the installer, verify its cryptographic SHA256 checksum, then execute.',
                ))
        if not has_user or last_user_root:
            leads.append(_lead(
                'container_iac', 'IAC003', 'medium',
                'Dockerfile does not switch to a non-root USER',
                rel_path, 1, sha,
                'Container runs as root by default (or switches back to root), increasing blast radius on compromise.',
                ['OWASP-ASVS-5.0.0:V14.1', 'OWASP-TOP10-2025:A02', 'NIST-800-53:AC-6'],
                'Create and switch to an unprivileged `USER` before `ENTRYPOINT`/`CMD`.',
            ))

    if low_name in ('compose.yml', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml'):
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if re.search(r'\bimage\s*:\s*\S+:latest\b', stripped):
                leads.append(_lead(
                    'container_iac', 'IAC004', 'medium',
                    'Compose configuration pulls mutable `:latest` image tag',
                    rel_path, idx, sha,
                    'Using `:latest` means runtime containers may not match the audited source revision.',
                    ['NIST-SSDF-1.1:PS.2', 'OWASP-TOP10-2025:A03', 'NIST-800-53:CM-2'],
                    'Pin image tags to immutable release versions or `@sha256` digests.',
                ))
            if re.search(r'\bprivileged\s*:\s*true\b|/var/run/docker\.sock', stripped):
                leads.append(_lead(
                    'container_iac', 'IAC005', 'high',
                    'Privileged container mode or Docker socket mount in Compose file',
                    rel_path, idx, sha,
                    'Privileged mode or docker.sock access grants host-equivalent root capabilities.',
                    ['OWASP-TOP10-2025:A02', 'NIST-800-53:AC-6', 'NIST-800-53:SC-39'],
                    'Remove `privileged: true` and avoid mounting `/var/run/docker.sock`; use rootless/dropped capabilities.',
                ))
    return leads


def scan_python_ast(rel_path, text, sha):
    leads = []
    try:
        tree = ast.parse(text, filename=rel_path)
    except SyntaxError:
        return leads

    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            raw_parts = [c.value for c in node.values if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            joined = ' '.join(raw_parts)
            if re.search(r'\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b', joined, re.I):
                line = getattr(node, 'lineno', 1)
                leads.append(_lead(
                    'crypto_and_sinks', 'PY007', 'high',
                    'SQL query constructed via Python f-string interpolation',
                    rel_path, line, sha,
                    f'f-string builds raw SQL query `{joined[:60]}...` with interpolated expressions.',
                    ['OWASP-ASVS-5.0.0:V5.3', 'OWASP-TOP10-2025:A05', 'NIST-800-53:SI-10'],
                    'Use parameterized SQLAlchemy/DB-API queries with bound parameters instead of f-strings.',
                ))
        if isinstance(node, ast.Call):
            func_name = ''
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                base = node.func.value.id if isinstance(node.func.value, ast.Name) else ''
                func_name = f'{base}.{node.func.attr}' if base else node.func.attr

            line = getattr(node, 'lineno', 1)
            if func_name in ('eval', 'exec', 'from_pyfile', 'pickle.loads', 'marshal.loads'):
                leads.append(_lead(
                    'crypto_and_sinks', 'PY001', 'high',
                    f'Dynamic code execution or unsafe deserialization sink `{func_name}()`',
                    rel_path, line, sha,
                    f'Call to `{func_name}` at line {line}; verify whether input crosses a trust boundary.',
                    ['OWASP-ASVS-5.0.0:V5.2', 'OWASP-TOP10-2025:A05', 'OWASP-TOP10-2025:A08', 'NIST-800-53:SI-10'],
                    'Avoid dynamic code execution or pickle deserialization on untrusted data; validate trust boundary.',
                ))
            elif func_name == 'yaml.load':
                has_safe_loader = any(
                    kw.arg == 'Loader' and 'Safe' in ast.dump(kw.value)
                    for kw in node.keywords
                )
                if not has_safe_loader:
                    leads.append(_lead(
                        'crypto_and_sinks', 'PY002', 'high',
                        'Unsafe YAML loader invoked without explicit SafeLoader',
                        rel_path, line, sha,
                        'Unsafe YAML loading permits arbitrary Python object instantiation.',
                        ['OWASP-ASVS-5.0.0:V5.2', 'OWASP-TOP10-2025:A08', 'NIST-800-53:SI-10'],
                        'Use yaml.safe_load() or pass Loader=yaml.SafeLoader.',
                    ))
            elif func_name.endswith(('md5', 'sha1')) and ('hashlib' in func_name or func_name in ('md5', 'sha1')):
                leads.append(_lead(
                    'crypto_and_sinks', 'PY003', 'medium',
                    f'Weak cryptographic hash `{func_name}` invoked',
                    rel_path, line, sha,
                    'MD5 and SHA-1 are collision-weak and unsuitable for passwords, signatures, or security tokens.',
                    ['OWASP-ASVS-5.0.0:V6.2', 'OWASP-TOP10-2025:A04', 'NIST-800-53:SC-13'],
                    'Use Argon2id/bcrypt/scrypt for passwords and SHA-256/HMAC-SHA256 for integrity.',
                ))
            for kw in node.keywords:
                if kw.arg == 'debug' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    leads.append(_lead(
                        'crypto_and_sinks', 'PY006', 'high',
                        'Application server started with `debug=True`',
                        rel_path, line, sha,
                        'Enabling debug mode in Flask/WSGI exposes interactive debugger/stack traces and arbitrary code execution risk.',
                        ['OWASP-ASVS-5.0.0:V14.3', 'OWASP-TOP10-2025:A02', 'NIST-800-53:CM-6'],
                        'Disable debug mode (`debug=False`) by default and run under a production WSGI server.',
                    ))
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    leads.append(_lead(
                        'crypto_and_sinks', 'PY004', 'high',
                        'Subprocess invoked with `shell=True`',
                        rel_path, line, sha,
                        'Shell invocation exposes command injection if any argument incorporates untrusted input.',
                        ['OWASP-ASVS-5.0.0:V5.3', 'OWASP-TOP10-2025:A05', 'NIST-800-53:SI-10'],
                        'Pass command arguments as a list with `shell=False`.',
                    ))
                if kw.arg == 'verify' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    leads.append(_lead(
                        'crypto_and_sinks', 'PY005', 'high',
                        'TLS certificate verification disabled (`verify=False`)',
                        rel_path, line, sha,
                        'Disabling TLS certificate validation allows MitM interception.',
                        ['OWASP-ASVS-5.0.0:V9.1', 'OWASP-TOP10-2025:A04', 'NIST-800-53:SC-8'],
                        'Enable TLS certificate verification and configure a trusted CA bundle.',
                    ))
    return leads


CODE_SINK_PATTERNS = [
    (
        'SINK001', 'high',
        'Server-side JavaScript/PHP/shell dynamic execution (`eval` / `shell_exec` / `system` / `passthru`)',
        re.compile(r'\b(?:eval|shell_exec|passthru|proc_open|popen)\s*\('),
        {'.js', '.jsx', '.ts', '.tsx', '.php', '.rb'},
        ['OWASP-ASVS-5.0.0:V5.2', 'OWASP-ASVS-5.0.0:V5.3', 'OWASP-TOP10-2025:A05', 'NIST-800-53:SI-10'],
        'Eliminate dynamic code/shell execution on request data; use safe parsers or parameterized APIs.',
    ),
    (
        'SINK002', 'high',
        'MongoDB `$where` server-side JavaScript query operator',
        re.compile(r'\$where\s*:'),
        {'.js', '.jsx', '.ts', '.tsx', '.py', '.php'},
        ['OWASP-ASVS-5.0.0:V5.3', 'OWASP-TOP10-2025:A05', 'NIST-800-53:SI-10'],
        'Replace `$where` JavaScript expressions with standard typed MongoDB query operators.',
    ),
    (
        'SINK003', 'high',
        'Raw SQL query constructed with string interpolation or concatenation',
        re.compile(r'(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;\n]{0,120}(?:\.\s*\$_(?:GET|POST|REQUEST)|["\']\s*\.\s*\$|\$\{[^}]+\}|\+\s*(?:req\.|request\.|params))', re.I),
        {'.php', '.js', '.ts', '.py', '.java', '.rb', '.go'},
        ['OWASP-ASVS-5.0.0:V5.3', 'OWASP-TOP10-2025:A05', 'NIST-800-53:SI-10'],
        'Use parameterized queries / prepared statements with bound parameters.',
    ),
    (
        'SINK004', 'high',
        'File upload handler moving file without visible content/path allowlisting',
        re.compile(r'\bmove_uploaded_file\s*\('),
        {'.php'},
        ['OWASP-ASVS-5.0.0:V12.1', 'OWASP-TOP10-2025:A01', 'NIST-800-53:SI-10'],
        'Generate random server-side filenames, validate MIME/extension allowlists, and store outside the web root.',
    ),
    (
        'CRYPTO010', 'medium',
        'Weak hash or non-CSPRNG token primitive (`md5` / `sha1` / `uniqid` / `Math.random`)',
        re.compile(r'\b(?:md5|sha1)\s*\(|\buniqid\s*\(|\bMath\.random\s*\('),
        {'.php', '.js', '.jsx', '.ts', '.tsx', '.java', '.rb'},
        ['OWASP-ASVS-5.0.0:V6.2', 'OWASP-ASVS-5.0.0:V3.2', 'OWASP-TOP10-2025:A04', 'NIST-800-53:SC-13'],
        'Use Argon2id/bcrypt for passwords and CSPRNG (`crypto.randomBytes`, `random_bytes`, `secrets`) for tokens.',
    ),
    (
        'CONFIG001', 'medium',
        'Insecure session cookie or host-validation default configuration',
        re.compile(r'SESSION_COOKIE_SECURE["\']?\s*[:=]\s*(?:False|false|0)\b|SESSION_COOKIE_SAMESITE["\']?\s*[:=]\s*(?:None|null)\b|TRUSTED_HOSTS["\']?\s*[:=]\s*(?:None|null)\b|httponly["\']?\s*[:=]\s*false\b', re.I),
        {'.py', '.js', '.ts', '.php', '.rb', '.json', '.yml', '.yaml'},
        ['OWASP-ASVS-5.0.0:V3.4', 'OWASP-TOP10-2025:A02', 'OWASP-TOP10-2025:A07', 'NIST-800-53:SC-23'],
        'Enforce `Secure`, `HttpOnly`, and `SameSite` on session cookies and validate `Host` headers in production.',
    ),
    (
        'CONFIG002', 'medium',
        'Wildcard CORS header (`Access-Control-Allow-Origin: *`)',
        re.compile(r'Access-Control-Allow-Origin["\']?\s*[:,]\s*["\']\*["\']', re.I),
        {'.php', '.js', '.ts', '.py', '.go', '.java', '.rb'},
        ['OWASP-ASVS-5.0.0:V14.5', 'OWASP-TOP10-2025:A01', 'OWASP-TOP10-2025:A02', 'NIST-800-53:AC-4'],
        'Restrict CORS origins to trusted domains whenever authenticated or sensitive API data is returned.',
    ),
]


def scan_code_sinks_and_api(rel_path, ext, text, sha):
    leads = []
    routes = []
    lines = text.splitlines()

    if ext == '.py':
        leads.extend(scan_python_ast(rel_path, text, sha))

    seen_rule_line = set()
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(('//', '#', '/*', '*')):
            continue

        for rule_id, sev, title, regex, exts, controls, rec in CODE_SINK_PATTERNS:
            if ext in exts and regex.search(line):
                key = (rule_id, idx)
                if key not in seen_rule_line:
                    seen_rule_line.add(key)
                    leads.append(_lead(
                        'crypto_and_sinks', rule_id, sev, title,
                        rel_path, idx, sha,
                        f'Matched pattern `{rule_id}` on line {idx}.',
                        controls, rec,
                    ))

        # High-entropy / hardcoded credential assignment check (governance_sdlc / secret lead)
        m_assign = re.search(
            r'(?:\b(password|passwd|secret|secret_key|token_secret|api_secret|encryption_key|signing_key|private_key)\b|\[["\'](SECRET_KEY|JWT_SECRET_KEY|API_KEY)["\']\])["\']?\s*(?:=>|[:=])\s*["\']([^"\'${\s]{4,})["\']',
            line,
            re.I,
        )
        if m_assign:
            var_name = m_assign.group(1) or m_assign.group(2)
            val = m_assign.group(3)
            if not val.lower().startswith(('change', 'your_', 'example', 'todo', 'dummy', 'none', 'null', 'true', 'false', 'updated', 'required', 'invalid', 'missing')) and not val.endswith('.'):
                ent = shannon_entropy(val)
                if ent >= 2.0 or len(val) >= 6:
                    leads.append(_lead(
                        'governance_sdlc', 'SEC010', 'high',
                        f'Hardcoded credential or key assignment to `{var_name}` ([REDACTED])',
                        rel_path, idx, sha,
                        f'Variable `{var_name}` assigned a literal string (length={len(val)}, entropy={ent:.2f}); value redacted.',
                        ['OWASP-ASVS-5.0.0:V6.4', 'OWASP-TOP10-2025:A04', 'NIST-800-53:IA-5'],
                        'Load secrets and cryptographic keys from a secret manager or high-entropy environment variables.',
                    ))

        # Route / Endpoint discovery (api_authz_surface)
        m_express = re.search(r'\b(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\'](.*)', line, re.I)
        if m_express:
            method, route_path, rest = m_express.group(1).upper(), m_express.group(2), m_express.group(3)
            has_auth = bool(re.search(r'auth|login|isLoggedIn|require|verify|check|admin|role|jwt|session', rest, re.I))
            routes.append({
                'framework': 'express',
                'method': method,
                'route': route_path,
                'file_path': rel_path,
                'line_number': idx,
                'sha256': sha,
                'auth_middleware_visible_on_line': has_auth,
            })
            if ':' in route_path or 'userId' in route_path or 'id' in route_path.lower():
                leads.append(_lead(
                    'api_authz_surface', 'API001', 'medium',
                    f'Parameterized route `{method} {route_path}` requires BOLA/IDOR ownership verification',
                    rel_path, idx, sha,
                    f'Route accepts object/user identifier `{route_path}` (inline auth middleware visible={has_auth}); verify server-side session ownership binding.',
                    ['OWASP-ASVS-5.0.0:V4.2', 'OWASP-TOP10-2025:A01', 'NIST-800-53:AC-3'],
                    'Verify that the handler binds resource lookup to the authenticated session user rather than trusting URL/body IDs.',
                ))
            elif not has_auth and method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                leads.append(_lead(
                    'api_authz_surface', 'API002', 'medium',
                    f'State-changing route `{method} {route_path}` has no inline auth middleware',
                    rel_path, idx, sha,
                    f'State-changing route `{method} {route_path}` has no visible inline auth middleware; check router-level guards and CSRF protection.',
                    ['OWASP-ASVS-5.0.0:V4.1', 'OWASP-TOP10-2025:A01', 'NIST-800-53:AC-3'],
                    'Confirm authentication, role authorization, and CSRF controls on this endpoint.',
                ))

        m_py_route = re.search(r'@\w+\.(route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', line)
        if m_py_route:
            verb, route_path = m_py_route.group(1).upper(), m_py_route.group(2)
            window_lines = '\n'.join(lines[idx:min(len(lines), idx + 4)])
            has_auth = bool(re.search(r'login_required|auth|permission|role_required|jwt_required', window_lines, re.I))
            routes.append({
                'framework': 'python_web',
                'method': verb,
                'route': route_path,
                'file_path': rel_path,
                'line_number': idx,
                'sha256': sha,
                'auth_middleware_visible_on_line': has_auth,
            })

        # PHP REST controller / direct object parameter detection
        if ext == '.php' and re.search(r'function\s+(?:get|post|put|delete|create|update)\b', line, re.I):
            window_lines = '\n'.join(lines[max(0, idx - 3):min(len(lines), idx + 15)])
            has_auth = bool(re.search(r'auth|token|session|login|permission|role', window_lines, re.I))
            if not has_auth:
                leads.append(_lead(
                    'api_authz_surface', 'API003', 'high',
                    f'Controller action `{stripped[:60]}` lacks visible authentication/authorization check',
                    rel_path, idx, sha,
                    'PHP controller method handles state/data operations with no visible session or token check in its header.',
                    ['OWASP-ASVS-5.0.0:V4.1', 'OWASP-TOP10-2025:A01', 'NIST-800-53:AC-3'],
                    'Enforce authentication and object/role authorization before executing controller actions.',
                ))

        # OpenAPI / Connexion operationId route discovery
        if ext in ('.yml', '.yaml') and re.match(r'^\s*operationId\s*:\s*(\S+)', line):
            op_id = re.match(r'^\s*operationId\s*:\s*(\S+)', line).group(1)
            prev_window = '\n'.join(lines[max(0, idx - 18):idx])
            has_sec = 'security:' in prev_window or 'bearerAuth' in prev_window
            routes.append({
                'framework': 'openapi',
                'method': 'OPENAPI_OP',
                'route': op_id,
                'file_path': rel_path,
                'line_number': idx,
                'sha256': sha,
                'auth_middleware_visible_on_line': has_sec,
            })
            if not has_sec and any(k in op_id.lower() for k in ('debug', 'populate', 'createdb', 'delete', 'update', 'admin', 'get_all_users')):
                leads.append(_lead(
                    'api_authz_surface', 'API004', 'high',
                    f'OpenAPI operation `{op_id}` has no security scheme declared in spec',
                    rel_path, idx, sha,
                    f'Sensitive or state-changing operation `{op_id}` is exposed without a `security:` requirement in `{rel_path}`.',
                    ['OWASP-ASVS-5.0.0:V4.1', 'OWASP-ASVS-5.0.0:V13.1', 'OWASP-TOP10-2025:A01', 'NIST-800-53:AC-3'],
                    'Require `security: [bearerAuth: []]` and enforce role/ownership checks in the handler.',
                ))

    return leads, routes


def build_control_matrix(leads, governance):
    """Summarize automated evidence leads against versioned NIST SSDF, OWASP ASVS, and NIST 800-53 controls."""
    catalog = [
        ('NIST-SSDF-1.1', 'PO.1', 'Define security requirements and governance roles (CODEOWNERS / policy)'),
        ('NIST-SSDF-1.1', 'PS.1', 'Protect code and CI/CD workflows from unauthorized access/tampering'),
        ('NIST-SSDF-1.1', 'PS.2', 'Provide a mechanism for verifying software release integrity'),
        ('NIST-SSDF-1.1', 'PS.3', 'Archive and protect each software release and dependency lockfile'),
        ('NIST-SSDF-1.1', 'PW.4', 'Verify third-party software components, lockfiles, and build backends'),
        ('NIST-SSDF-1.1', 'PW.7', 'Review and/or analyze human-readable code to identify vulnerabilities'),
        ('NIST-SSDF-1.1', 'RV.1', 'Identify and confirm vulnerabilities on an ongoing basis (SECURITY.md / Dependabot)'),
        ('OWASP-ASVS-5.0.0', 'V3.4', 'Cookie-based session management (Secure, HttpOnly, SameSite)'),
        ('OWASP-ASVS-5.0.0', 'V4.1', 'General access control design and least privilege enforcement'),
        ('OWASP-ASVS-5.0.0', 'V4.2', 'Operation-level and object-level access control (IDOR/BOLA prevention)'),
        ('OWASP-ASVS-5.0.0', 'V5.2', 'Sanitization and sandboxing (avoid eval, unsafe deserialization)'),
        ('OWASP-ASVS-5.0.0', 'V5.3', 'Output encoding and injection prevention (SQLi, command injection, NoSQLi)'),
        ('OWASP-ASVS-5.0.0', 'V6.2', 'Algorithms (strong password hashing Argon2id/bcrypt, no MD5/SHA1)'),
        ('OWASP-ASVS-5.0.0', 'V6.4', 'Secret management (no hardcoded keys or CI secret leaks)'),
        ('OWASP-ASVS-5.0.0', 'V9.1', 'Communications security (TLS verification enabled)'),
        ('OWASP-ASVS-5.0.0', 'V14.1', 'Build and container hardening (non-root user, digest pinning)'),
        ('OWASP-ASVS-5.0.0', 'V14.2', 'Dependency and CI supply-chain integrity'),
        ('OWASP-ASVS-5.0.0', 'V14.3', 'Unintended security disclosure (debug mode disabled)'),
    ]
    matrix = []
    for framework, req_id, description in catalog:
        tag = f'{framework}:{req_id}'
        matching = [
            {'rule_id': ld['rule_id'], 'severity': ld['severity'], 'file_path': ld['file_path'], 'line_number': ld['line_number'], 'title': ld['title']}
            for ld in leads
            if tag in ld['controls']
        ]
        matrix.append({
            'framework': framework,
            'requirement_id': req_id,
            'description': description,
            'status': 'candidate_gap_leads_found' if matching else 'not_verified_by_probes_alone',
            'lead_count': len(matching),
            'leads': matching[:10],
            'note': 'Automated probe leads require semantic code review and runtime/process verification before final status assignment.',
        })
    return matrix


def run_probes(root_path, selected_probes=PROBES, exclude_dirs=('.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__')):
    root = Path(root_path).resolve()
    discovered_files = []
    skipped = []
    for path, reason in entries(root, tuple(exclude_dirs)):
        rel = str(path.relative_to(root)) if root.is_dir() and path != root else path.name
        if reason:
            skipped.append({'path': rel, 'reason': reason})
        else:
            discovered_files.append((path, rel))

    all_rel_paths = {rel for _, rel in discovered_files}
    lang_counts = {}
    leads = []
    routes = []
    codeql_langs = set()

    for abs_path, rel_path in discovered_files:
        name = abs_path.name
        ext = abs_path.suffix.lower()
        if ext in LANG_BY_EXT:
            lang = LANG_BY_EXT[ext]
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        text, sha = _read_utf8_bounded(abs_path)
        if text is None:
            continue

        if 'ci_supply_chain' in selected_probes and (
            rel_path.startswith('.github/workflows/') and ext in ('.yml', '.yaml')
            or name == '.gitlab-ci.yml'
        ):
            leads.extend(scan_ci_workflow(rel_path, text, sha))
            for m_lang in re.finditer(r'language\s*:\s*\[([^\]]+)\]|language\s*:\s*([a-zA-Z0-9_-]+)', text):
                raw_langs = m_lang.group(1) or m_lang.group(2)
                for item in raw_langs.split(','):
                    cleaned = item.strip().strip('"\'').lower()
                    if cleaned:
                        codeql_langs.add(cleaned)

        if 'dependency_integrity' in selected_probes and name in MANIFEST_LOCK_PAIRS:
            leads.extend(scan_dependency_manifest(rel_path, name, text, sha, all_rel_paths))

        if 'container_iac' in selected_probes and (
            name.lower().startswith('dockerfile')
            or name.lower() in ('compose.yml', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml')
        ):
            leads.extend(scan_container_and_iac(rel_path, name, text, sha))

        if ext in ('.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.go', '.java', '.rb', '.yml', '.yaml', '.json'):
            file_leads, file_routes = scan_code_sinks_and_api(rel_path, ext, text, sha)
            if 'crypto_and_sinks' in selected_probes:
                leads.extend([ld for ld in file_leads if ld['probe'] == 'crypto_and_sinks'])
            if 'api_authz_surface' in selected_probes:
                leads.extend([ld for ld in file_leads if ld['probe'] == 'api_authz_surface'])
                routes.extend(file_routes)
            if 'governance_sdlc' in selected_probes:
                leads.extend([ld for ld in file_leads if ld['probe'] == 'governance_sdlc'])

    has_security_md = any(p.lower() in ('security.md', '.github/security.md', 'docs/security.md') for p in all_rel_paths)
    has_codeowners = any(p in ('CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS') for p in all_rel_paths)
    has_dependabot = any(p in ('.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json') for p in all_rel_paths)

    primary_lang = max(lang_counts.items(), key=lambda kv: kv[1])[0] if lang_counts else None
    if 'governance_sdlc' in selected_probes:
        if not has_security_md:
            leads.append(_lead(
                'governance_sdlc', 'GOV001', 'low',
                'No tracked SECURITY.md vulnerability disclosure policy found',
                '.', 1, None,
                'Repository does not contain `SECURITY.md` or `.github/SECURITY.md` for coordinated vulnerability reporting.',
                ['NIST-SSDF-1.1:RV.1', 'NIST-800-53:RA-5'],
                'Add a `SECURITY.md` documenting supported versions and private vulnerability reporting channels.',
            ))
        if not has_dependabot and any(Path(p).name in MANIFEST_LOCK_PAIRS for p in all_rel_paths):
            leads.append(_lead(
                'governance_sdlc', 'GOV002', 'low',
                'No tracked Dependabot or Renovate configuration found',
                '.', 1, None,
                'Automated dependency vulnerability/update configuration (`.github/dependabot.yml` or `renovate.json`) was not found in the repo.',
                ['NIST-SSDF-1.1:PW.4', 'NIST-SSDF-1.1:RV.1', 'OWASP-TOP10-2025:A03'],
                'Enable automated dependency vulnerability scanning and lockfile update PRs.',
            ))
        if codeql_langs and primary_lang and primary_lang not in codeql_langs:
            leads.append(_lead(
                'governance_sdlc', 'GOV003', 'medium',
                f'Configured SAST languages {sorted(codeql_langs)} omit primary repository language `{primary_lang}`',
                '.github/workflows', 1, None,
                f'Repository primary language by file count is `{primary_lang}` ({lang_counts.get(primary_lang)} files), but workflow analysis only targets {sorted(codeql_langs)}.',
                ['NIST-SSDF-1.1:PW.7', 'NIST-800-53:SA-11'],
                f'Extend SAST / static analysis coverage to include `{primary_lang}`.',
            ))

    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    leads.sort(key=lambda x: (sev_rank.get(x['severity'], 4), x['file_path'], x['line_number'], x['rule_id']))

    by_severity = {}
    by_probe = {}
    for ld in leads:
        by_severity[ld['severity']] = by_severity.get(ld['severity'], 0) + 1
        by_probe[ld['probe']] = by_probe.get(ld['probe'], 0) + 1

    governance_summary = {
        'security_md_present': has_security_md,
        'codeowners_present': has_codeowners,
        'automated_dep_updates_present': has_dependabot,
        'language_distribution': lang_counts,
        'primary_language': primary_lang,
        'configured_sast_languages': sorted(codeql_langs),
    }

    return {
        'target': str(root),
        'scan_date': datetime.now().isoformat(),
        'assessment_status': 'automated_probe_leads_not_final_compliance_verdict',
        'probes_executed': list(selected_probes),
        'summary': {
            'total_leads': len(leads),
            'by_severity': by_severity,
            'by_probe': by_probe,
            'discovered_routes': len(routes),
            'files_examined': len(discovered_files),
            'skipped_entries': len(skipped),
        },
        'governance_posture': governance_summary,
        'control_matrix_leads': build_control_matrix(leads, governance_summary),
        'api_route_inventory': routes[:100],
        'leads': leads,
    }


def sample_report():
    """Embedded deterministic sample fixture for Gate G9 (--sample --json)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / '.github' / 'workflows').mkdir(parents=True)
        (root / '.github' / 'workflows' / 'ci.yml').write_text(
            'name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n',
            encoding='utf-8',
        )
        (root / 'Dockerfile').write_text('FROM python:latest\nEXPOSE 8080\n', encoding='utf-8')
        dyn_call = 'ev' + 'al(id)'
        (root / 'app.py').write_text(
            f'import hashlib\nfrom flask import Flask\napp = Flask(__name__)\n@app.route("/user/<id>")\ndef user(id):\n    return {dyn_call}\n',
            encoding='utf-8',
        )
        report = run_probes(root)
        report['target'] = 'embedded-sample-fixture'
        return report


def format_text(report):
    lines = [
        '=' * 72,
        'ENTERPRISE SECURITY & COMPLIANCE PROBE REPORT (LEADS ONLY)',
        '=' * 72,
        f"Target: {report['target']}",
        f"Status: {report['assessment_status']}",
        f"Total Leads: {report['summary']['total_leads']}  (Routes discovered: {report['summary']['discovered_routes']})",
        f"By Severity: {json.dumps(report['summary']['by_severity'])}",
        f"By Probe:    {json.dumps(report['summary']['by_probe'])}",
        '',
        'TOP LEADS (inspect with read_evidence.py before confirming):',
    ]
    for ld in report['leads'][:25]:
        lines.append(
            f"  [{ld['severity'].upper()}] {ld['rule_id']} ({ld['probe']}) "
            f"{ld['file_path']}:{ld['line_number']} — {ld['title']}"
        )
        lines.append(f"      Controls: {', '.join(ld['controls'])}")
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('path', nargs='?', help='Repository or directory path to probe')
    p.add_argument('--probe', action='append', choices=PROBES, help='Run specific probe suite(s); default runs all')
    p.add_argument('--exclude-dir', action='append', default=['.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__'])
    p.add_argument('--json', action='store_true', help='Emit JSON report on stdout')
    p.add_argument('--format', choices=['text', 'json'], default='text', help='Output format (text or json)')
    p.add_argument('--output', '-o', type=Path, help='Write report to file outside scanned root')
    p.add_argument('--sample', action='store_true', help='Run against an embedded sample fixture and exit 0')
    args = p.parse_args()

    want_json = args.json or args.format == 'json'
    if args.sample:
        rep = sample_report()
        out = json.dumps(rep, indent=2) if want_json else format_text(rep)
        print(out)
        return 0

    if not args.path:
        p.error('path is required unless --sample is passed')

    target = Path(args.path).resolve()
    if not target.exists():
        print(json.dumps({'status': 'error', 'message': f'path does not exist: {target}'}), file=sys.stderr)
        return 2

    if args.output:
        dest = args.output.resolve()
        if dest == target or (target.is_dir() and target in dest.parents):
            p.error('output file must be outside scanned root')

    probes = tuple(args.probe) if args.probe else PROBES
    report = run_probes(target, selected_probes=probes, exclude_dirs=tuple(args.exclude_dir))
    rendered = json.dumps(report, indent=2) if want_json else format_text(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n', encoding='utf-8')
    else:
        print(rendered)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

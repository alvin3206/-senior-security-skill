#!/usr/bin/env python3
"""
Secret Scanner

Detects hardcoded secrets, API keys, and credentials in source code.
Identifies exposed secrets before they reach version control.

Usage:
    python secret_scanner.py /path/to/project
    python secret_scanner.py /path/to/file.py
    python secret_scanner.py /path/to/project --format json
    python secret_scanner.py --list-patterns
"""

import argparse
import json
from datetime import datetime
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
from repo_coverage import entries, scan_stream, OVERLAP


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretPattern:
    pattern_id: str
    name: str
    description: str
    regex: str
    severity: Severity
    file_extensions: List[str]
    recommendation: str


@dataclass
class SecretFinding:
    pattern_id: str
    name: str
    severity: Severity
    file_path: str
    line_number: int
    matched_text: str
    recommendation: str


# Secret patterns database
SECRET_PATTERNS = [
    # Cloud Provider Keys
    SecretPattern(
        pattern_id="AWS001",
        name="AWS Access Key ID",
        description="AWS access key identifier",
        regex=r'AKIA[0-9A-Z]{16}',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml", ".conf"],
        recommendation="Use IAM roles or AWS Secrets Manager instead of hardcoded keys"
    ),
    SecretPattern(
        pattern_id="AWS002",
        name="AWS Secret Access Key",
        description="AWS secret access key",
        regex=r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".conf"],
        recommendation="Use IAM roles or AWS Secrets Manager instead of hardcoded secrets"
    ),
    SecretPattern(
        pattern_id="GCP001",
        name="Google Cloud API Key",
        description="Google Cloud Platform API key",
        regex=r'AIza[0-9A-Za-z\-_]{35}',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use service accounts or Google Secret Manager"
    ),
    SecretPattern(
        pattern_id="AZURE001",
        name="Azure Storage Key",
        description="Azure storage account key",
        regex=r'(?:AccountKey|account_key)\s*[:=]\s*["\']?[A-Za-z0-9+/=]{88}["\']?',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".cs", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use Azure Key Vault or managed identities"
    ),

    # Authentication Tokens
    SecretPattern(
        pattern_id="JWT001",
        name="JSON Web Token",
        description="Hardcoded JWT token",
        regex=r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".json"],
        recommendation="Generate tokens dynamically, never hardcode"
    ),
    SecretPattern(
        pattern_id="GITHUB001",
        name="GitHub Token",
        description="GitHub personal access token or OAuth token",
        regex=r'(?:github_pat_[A-Za-z0-9_]{22,255}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use GitHub App authentication or environment variables"
    ),
    SecretPattern(
        pattern_id="GITLAB001",
        name="GitLab Token",
        description="GitLab personal access or pipeline token",
        regex=r'glpat-[A-Za-z0-9\-_]{20,}',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml"],
        recommendation="Use CI/CD variables or environment variables"
    ),
    SecretPattern(
        pattern_id="SLACK001",
        name="Slack Token",
        description="Slack API token",
        regex=r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use environment variables or secrets manager"
    ),
    SecretPattern(
        pattern_id="STRIPE001",
        name="Stripe API Key",
        description="Stripe secret key (publishable keys excluded)",
        regex=r'sk_(?:test|live)_[0-9a-zA-Z]{24,}',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use environment variables, never commit API keys"
    ),
    SecretPattern(
        pattern_id="TWILIO001",
        name="Twilio Auth Token",
        description="Explicitly assigned Twilio auth token; SIDs are identifiers",
        regex=r'\btwilio[_-]?auth[_-]?token["\']?\s*[:=]\s*["\']?[a-f0-9]{32}\b',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use environment variables for Twilio credentials"
    ),
    SecretPattern(
        pattern_id="SENDGRID001",
        name="SendGrid API Key",
        description="SendGrid API key",
        regex=r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use environment variables for email service credentials"
    ),

    # Cryptographic Keys
    SecretPattern(
        pattern_id="CRYPTO001",
        name="RSA Private Key",
        description="RSA private key in PEM format",
        regex=r'-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".pem", ".key", ".txt"],
        recommendation="Store private keys in secure key management systems"
    ),
    SecretPattern(
        pattern_id="CRYPTO002",
        name="EC Private Key",
        description="Elliptic curve private key",
        regex=r'-----BEGIN EC PRIVATE KEY-----',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".pem", ".key"],
        recommendation="Use hardware security modules or key management services"
    ),
    SecretPattern(
        pattern_id="CRYPTO003",
        name="OpenSSH Private Key",
        description="OpenSSH private key",
        regex=r'-----BEGIN OPENSSH PRIVATE KEY-----',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".pem", ".key", ".txt"],
        recommendation="Never commit SSH keys to repositories"
    ),
    SecretPattern(
        pattern_id="CRYPTO004",
        name="PGP Private Key",
        description="PGP/GPG private key block",
        regex=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".asc", ".gpg", ".txt"],
        recommendation="Store PGP keys in secure key rings, not source code"
    ),

    # Generic Patterns
    SecretPattern(
        pattern_id="GEN001",
        name="Generic API Key",
        description="Generic API key or secret pattern",
        regex=r'(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml"],
        recommendation="Use environment variables or secrets manager"
    ),
    SecretPattern(
        pattern_id="GEN002",
        name="Generic Secret",
        description="Generic secret or token pattern",
        regex=r'(?:(?:secret|token|auth[_-]?token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']|(?:SECRET_KEY|JWT_SECRET_KEY)["\'\]]*\s*[:=]\s*["\'][^"\'\s]{6,}["\'])',
        severity=Severity.HIGH,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Store secrets in environment variables or secret managers"
    ),
    SecretPattern(
        pattern_id="GEN003",
        name="Password in Config",
        description="Password in configuration file",
        regex=r'(?:(?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{8,}(?<!\.)["\']|register_user\s*\(\s*["\'][^"\']+["\']\s*,\s*["\'][^"\']{4,}["\'])',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml", ".conf", ".ini"],
        recommendation="Never hardcode passwords. Use secret managers"
    ),
    SecretPattern(
        pattern_id="GEN004",
        name="Database Connection String",
        description="Database connection string with credentials",
        regex=r'(?:mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@[^/]+',
        severity=Severity.CRITICAL,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yml", ".yaml", ".json"],
        recommendation="Use environment variables for database credentials"
    ),

    # Low Severity Patterns
    SecretPattern(
        pattern_id="LOW001",
        name="TODO with Secret",
        description="TODO comment mentioning secrets or credentials",
        regex=r'(?:#|//|/\*)\s*(?:TODO|FIXME|XXX).*(?:secret|password|credential|key)',
        severity=Severity.LOW,
        file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php"],
        recommendation="Address security TODOs before deployment"
    ),
]


def scan_file(file_path: Path, patterns: List[SecretPattern], coverage=None) -> List[SecretFinding]:
    """Scan text regardless of filename; never emit credential fragments."""
    findings = []
    seen = set()
    record = {"path": str(file_path)}
    compiled = [(p, re.compile(p.regex, re.IGNORECASE)) for p in patterns]

    def visit(window, first_line):
        for offset, line in enumerate(window.split('\n')):
            for pattern, regex in compiled:
                for match in regex.finditer(line):
                    # Deduplicate overlap; one finding per rule/line is sufficient.
                    key = (pattern.pattern_id, first_line + offset)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(SecretFinding(pattern.pattern_id, pattern.name,
                        pattern.severity, str(file_path), first_line + offset,
                        "[REDACTED]", pattern.recommendation))
    scan_stream(file_path, record, visit)
    if coverage is not None:
        coverage.append(record)
    if record['status'] == 'skipped':
        return []
    return findings


def scan_directory(dir_path: Path, patterns: List[SecretPattern],
                   exclude_dirs=None, coverage=None) -> List[SecretFinding]:
    findings = []
    for file_path, reason in entries(dir_path, tuple(exclude_dirs or ['.git'])):
        if reason:
            if coverage is not None:
                coverage.append({"path": str(file_path), "bytes_read": 0,
                    "status": "error" if reason.startswith('walk_error') else "skipped", "reason": reason})
            continue
        findings.extend(scan_file(file_path, patterns, coverage))
    order = list(Severity)
    return sorted(findings, key=lambda f: (order.index(f.severity), f.file_path, f.line_number))


def format_text_report(findings: List[SecretFinding], path: str) -> str:
    """Format findings as text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("SECRET CANDIDATE SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"Target: {path}")
    lines.append("")

    # Summary
    by_severity = {}
    for finding in findings:
        sev = finding.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1

    lines.append("SUMMARY:")
    lines.append(f"  Total Candidates Found: {len(findings)}")
    for sev in ["critical", "high", "medium", "low"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"  {sev.upper()}: {count}")
    lines.append("")

    if not findings:
        lines.append("No matching candidates found within the reported scope.")
        lines.append("=" * 70)
        return "\n".join(lines)

    # Group by severity
    current_severity = None
    for finding in findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append("-" * 70)
            lines.append(f"[{current_severity.value.upper()}]")
            lines.append("-" * 70)

        lines.append("")
        lines.append(f"  [{finding.pattern_id}] {finding.name}")
        lines.append(f"  File: {finding.file_path}:{finding.line_number}")
        lines.append(f"  Match: {finding.matched_text}")
        lines.append(f"  Fix: {finding.recommendation}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("IMPORTANT: Review all findings and rotate exposed credentials!")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_json_report(findings: List[SecretFinding], path: str) -> Dict:
    """Format findings as JSON."""
    return {
        "target": path,
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total": len(findings),
            "by_severity": {
                sev.value: sum(1 for f in findings if f.severity == sev)
                for sev in Severity
            }
        },
        "findings": [
            {
                "verification_status": "unverified_candidate",
                "pattern_id": f.pattern_id,
                "name": f.name,
                "severity": f.severity.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "matched_text": f.matched_text,
                "recommendation": f.recommendation
            }
            for f in findings
        ]
    }


def list_patterns():
    """List all secret patterns."""
    print("\n" + "=" * 60)
    print("SECRET DETECTION PATTERNS")
    print("=" * 60)

    for pattern in sorted(SECRET_PATTERNS, key=lambda p: p.pattern_id):
        print(f"\n[{pattern.pattern_id}] {pattern.name}")
        print(f"  Severity: {pattern.severity.value.upper()}")
        print(f"  Description: {pattern.description}")


def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner - Detect hardcoded secrets in code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a project directory
  python secret_scanner.py /path/to/project

  # Scan a single file
  python secret_scanner.py /path/to/config.py

  # Output as JSON
  python secret_scanner.py /path/to/project --format json

  # List all detection patterns
  python secret_scanner.py --list-patterns

  # Save report to file
  python secret_scanner.py /path/to/project --output report.txt
        """
    )

    parser.add_argument(
        "path",
        nargs="?",
        help="Path to scan (file or directory)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--list-patterns", "-l",
        action="store_true",
        help="List all detection patterns"
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report"
    )

    parser.add_argument("--coverage-output", help="Per-file JSONL coverage outside scanned root")
    parser.add_argument("--exclude-dir", action="append", default=[".git"])
    args = parser.parse_args()

    if args.list_patterns:
        list_patterns()
        return

    if not args.path:
        parser.error("path is required (or use --list-patterns)")

    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {path}")
        sys.exit(2)

    # Filter patterns by severity
    patterns = SECRET_PATTERNS
    if args.severity:
        severity_order = ["critical", "high", "medium", "low"]
        min_index = severity_order.index(args.severity)
        allowed = set(Severity(s) for s in severity_order[:min_index + 1])
        patterns = [p for p in patterns if p.severity in allowed]

    for destination in (args.output, args.coverage_output):
        if destination:
            dest = Path(destination).resolve()
            root = path.resolve()
            if dest == root or (path.is_dir() and root in dest.parents):
                parser.error("output files must be outside scanned root")
    coverage = []
    # Scan
    if path.is_file():
        findings = scan_file(path, patterns, coverage)
    else:
        findings = scan_directory(path, patterns, args.exclude_dir, coverage)

    counts = {status: sum(r['status'] == status for r in coverage)
              for status in ('scanned', 'partial', 'skipped', 'error')}
    coverage_summary = {"counts": counts, "bytes_read": sum(r['bytes_read'] for r in coverage),
        "scanned_text_bytes": sum(r['bytes_read'] for r in coverage if r['status'] == 'scanned'),
        "identified_regular_file_bytes": sum(r.get('size_bytes', 0) for r in coverage),
        "git_history": "not_scanned", "semantic_review": "not_performed",
        "excluded_directories": args.exclude_dir,
        "detector_limitations": ["regex candidates require validation", "UTF-8 text only",
            "matches spanning more than %s bytes across windows are not guaranteed" % OVERLAP],
        "ledger": args.coverage_output}
    if args.coverage_output:
        with open(args.coverage_output, 'w', encoding='utf-8') as ledger:
            for row in coverage:
                ledger.write(json.dumps(row) + '\n')
    # Format output
    if args.format == "json":
        report = format_json_report(findings, str(path))
        report["coverage"] = coverage_summary
        output = json.dumps(report, indent=2)
    else:
        output = format_text_report(findings, str(path)) + "\nCoverage: " + json.dumps(coverage_summary)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Incomplete execution takes precedence; findings remain in the report.
    if counts["error"] or counts["partial"]:
        sys.exit(2)
    # Exit code based on findings
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()

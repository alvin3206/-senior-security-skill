import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import secret_scanner as scanner
import repo_coverage as coverage
import threat_modeler as threats
import verify_review
import read_evidence
import compliance_probes


class SecurityToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.key = 'AKIA' + 'Z' * 16

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, name, content):
        path = self.root / name
        path.write_text(content)
        ledger = []
        findings = scanner.scan_file(path, scanner.SECRET_PATTERNS, ledger)
        return findings, ledger

    def test_env_extensions_comments_and_redaction(self):
        for name in ('.env', '.env.local', 'app.tsx', 'README.md', 'Dockerfile', 'id_rsa'):
            with self.subTest(name=name):
                found, ledger = self.scan(name, '# pattern regex key=' + self.key)
                self.assertTrue(any(f.pattern_id == 'AWS001' for f in found))
                self.assertEqual(ledger[0]['status'], 'scanned')
                self.assertNotIn(self.key, json.dumps(scanner.format_json_report(found, name)))
                self.assertTrue(all(f.matched_text == '[REDACTED]' for f in found))

    def test_large_file_tail_and_boundary_line_numbers(self):
        prefix = ('# filler\n' * 160000)
        found, ledger = self.scan('large.py', prefix + self.key + '\n')
        aws = [f for f in found if f.pattern_id == 'AWS001']
        self.assertEqual([f.line_number for f in aws], [160001])
        self.assertEqual(ledger[0]['bytes_read'], len(prefix) + len(self.key) + 1)
        prefix = 'x' * (coverage.CHUNK - 10)
        found, ledger = self.scan('minified.js', prefix + self.key + 'x' * 1000000)
        self.assertEqual(len([f for f in found if f.pattern_id == 'AWS001']), 1)
        self.assertEqual(ledger[0]['status'], 'scanned')

    def test_binary_invalid_encoding_missing_and_symlink(self):
        f = self.root / 'binary'
        f.write_bytes(b'a\0b')
        row = {}
        coverage.scan_stream(f, row)
        self.assertEqual((row['status'], row['reason']), ('skipped', 'binary_nul'))
        f.write_bytes(b'abc\xff')
        row = {}
        coverage.scan_stream(f, row)
        self.assertEqual(row['status'], 'partial')
        row = {}
        coverage.scan_stream(self.root / 'missing', row)
        self.assertEqual(row['status'], 'error')
        link = self.root / 'link'
        link.symlink_to(f)
        self.assertIn((link, 'symlink'), list(coverage.entries(self.root)))
        row = {}
        coverage.scan_stream(link, row)
        self.assertEqual(row['status'], 'error')

    def test_utf8_across_window(self):
        f = self.root / 'utf8'
        f.write_bytes(b'a' * (coverage.CHUNK - 1) + '中文'.encode())
        row = {}
        coverage.scan_stream(f, row)
        self.assertEqual(row['status'], 'scanned')

    def test_public_key_negative_and_private_key_positive(self):
        found, _ = self.scan('keys.txt', 'pk_live_' + 'A' * 30 + '\n-----BEGIN PRIVATE KEY-----')
        self.assertNotIn('STRIPE001', [f.pattern_id for f in found])
        self.assertIn('CRYPTO001', [f.pattern_id for f in found])

    def test_identifiers_and_lock_hashes_are_not_twilio_credentials(self):
        found, _ = self.scan('uv.lock', 'sha256:' + 'ac' + 'a' * 62 + '\nAC' + 'b' * 32 + '\nSK' + 'c' * 32)
        self.assertNotIn('TWILIO001', [f.pattern_id for f in found])
        found, _ = self.scan('.env', 'TWILIO_AUTH_TOKEN="' + 'a' * 32 + '"')
        self.assertIn('TWILIO001', [f.pattern_id for f in found])

    def test_cli_reports_incomplete_and_rejects_self_output(self):
        (self.root / '.env').write_text(self.key)
        (self.root / 'bad').write_bytes(b'\xff')
        cmd = [sys.executable, '-B', str(SCRIPTS / 'secret_scanner.py'), str(self.root), '--format', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report['coverage']['counts']['partial'], 1)
        self.assertGreater(report['summary']['total'], 0)
        result = subprocess.run(cmd + ['--output', str(self.root / 'self.json')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'self.json').exists())

    def test_inventory_exclusions_are_explicit(self):
        (self.root / '.git').mkdir()
        (self.root / '.git' / 'config').write_text('hidden')
        (self.root / 'vendor').mkdir()
        (self.root / 'vendor' / 'code').write_text('included')
        with tempfile.TemporaryDirectory() as out:
            ledger = Path(out) / 'ledger.jsonl'
            result = coverage.inventory(self.root, ledger)
            rows = [json.loads(s) for s in ledger.read_text().splitlines()]
        self.assertEqual(result['counts'], {'skipped': 1, 'scanned': 1})
        self.assertEqual(rows[0]['reason'], 'excluded')
        self.assertEqual(rows[1]['path'], 'vendor/code')

    def test_bounded_evidence_windows_and_partial_lines(self):
        f = self.root / 'source.py'
        f.write_text('one\ntwo\nthree')
        first = read_evidence.read_window(self.root, 'source.py', 0, 6)
        self.assertEqual(first['byte_range'], [0, 6])
        self.assertEqual(first['complete_line_ranges'], [[1, 1]])
        self.assertFalse(first['whole_file_displayed'])
        second = read_evidence.read_window(self.root, 'source.py', first['next_offset'], 7)
        self.assertEqual(second['complete_line_ranges'], [[3, 3]])
        self.assertEqual(first['content'] + second['content'], f.read_text())
        self.assertEqual(first['sha256'], second['sha256'])
        with self.assertRaises(ValueError):
            read_evidence.read_window(self.root, 'source.py', 0, 1000000)
        with self.assertRaises(ValueError):
            read_evidence.read_window(self.root, '../outside')
        f.write_text('x' * 1200000 + 'TAIL')
        tail = read_evidence.read_window(self.root, 'source.py', 1199990, 32)
        self.assertTrue(tail['content'].endswith('TAIL'))
        self.assertEqual(tail['complete_line_ranges'], [])
        self.assertLessEqual(len(tail['content'].encode()), 32)

    def test_json_quoted_generic_key_and_byte_denominators(self):
        found, _ = self.scan('config.json', '{"api_key": "' + 'Z' * 24 + '"}')
        self.assertIn('GEN001', [f.pattern_id for f in found])
        (self.root / 'binary').write_bytes(b'x' * 100 + b'\0')
        with tempfile.TemporaryDirectory() as out:
            result = coverage.inventory(self.root, Path(out) / 'files.jsonl')
        text_size = (self.root / 'config.json').stat().st_size
        self.assertEqual(result['scanned_text_bytes'], text_size)
        self.assertEqual(result['bytes_read'], text_size + 101)

    def test_review_ledger_rejects_fabricated_ranges_and_stale_hashes(self):
        f = self.root / 'code.py'
        f.write_text('one\ntwo\nthree\n')
        sha, _ = verify_review.file_identity(f)
        ledger = {'revision': 'fixture', 'completed': [{'path': 'code.py', 'sha256': sha, 'ranges': [[1, 2], [2, 3]]}]}
        result = verify_review.verify(self.root, ledger)
        self.assertTrue(result['valid'])
        self.assertEqual(result['claimed_unique_lines'], 3)
        self.assertEqual(result['semantic_verification'], 'not_performed')
        ledger['completed'][0]['ranges'] = [[1, 4]]
        self.assertFalse(verify_review.verify(self.root, ledger)['valid'])
        ledger['completed'][0]['ranges'] = [[1, 3]]
        f.write_text('changed\ntwo\nthree\n')
        self.assertFalse(verify_review.verify(self.root, ledger)['valid'])
        ledger['completed'][0]['path'] = '../outside'
        self.assertFalse(verify_review.verify(self.root, ledger)['valid'])

    def test_threats_are_explicitly_unverified_and_assets_preserved(self):
        report = threats.format_json_report('API', threats.get_threats_for_component('API'), ['customer-data'])
        self.assertEqual(report['assets'], ['customer-data'])
        self.assertEqual(report['assessment_status'], 'candidate_catalogue_not_verified')
        self.assertTrue(report['limitations'])

    def test_line_windows_batch_slices_and_auto_ledger_roundtrip(self):
        (self.root / 'a.py').write_text('line1\nline2\nline3\nline4\nline5\n')
        (self.root / 'b.py').write_text('alpha\nbeta\ngamma\n')
        res = read_evidence.read_window_lines(self.root, 'a.py', 2, 4, number_lines=True)
        self.assertEqual(res['complete_line_ranges'], [[2, 4]])
        self.assertIn('2: line2', res['numbered_content'])
        with tempfile.TemporaryDirectory() as out:
            ledger_path = Path(out) / 'review-ledger.json'
            receipt_path = Path(out) / 'reads.jsonl'
            cmd = [
                sys.executable, '-B', str(SCRIPTS / 'read_evidence.py'),
                '--root', str(self.root),
                '--slice', 'a.py:1-3',
                '--slice', 'a.py:3-5',
                '--slice', 'b.py:1-2',
                '--number-lines',
                '--receipt', str(receipt_path),
                '--update-ledger', str(ledger_path),
                '--flow', 'auth-flow',
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            ledger = json.loads(ledger_path.read_text())
            verified = verify_review.verify(self.root, ledger)
            self.assertTrue(verified['valid'], verified['errors'])
            self.assertEqual(verified['claimed_files'], 2)
            self.assertEqual(verified['claimed_unique_lines'], 7)

    def test_compliance_probes_suites_and_sample_json(self):
        (self.root / '.github' / 'workflows').mkdir(parents=True)
        (self.root / '.github' / 'workflows' / 'ci.yml').write_text(
            'name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo "${{ toJson(secrets) }}" | base64\n'
        )
        (self.root / 'Dockerfile').write_text('FROM php:latest\nRUN curl https://example.com/install.sh | sh\n')
        (self.root / 'pyproject.toml').write_text('[build-system]\nrequires = ["flit_core>=3.11,<4"]\n')
        (self.root / 'app.py').write_text(
            'import hashlib\nimport yaml\ndef bad(x):\n    hashlib.md5(x.encode())\n    yaml.load(x)\n    return eval(x)\n'
        )
        report = compliance_probes.run_probes(self.root)
        rule_ids = {ld['rule_id'] for ld in report['leads']}
        for expected in ('CI001', 'CI003', 'CI004', 'IAC001', 'IAC002', 'IAC003', 'DEP001', 'DEP002', 'PY001', 'PY002', 'PY003', 'GOV001'):
            self.assertIn(expected, rule_ids)
        proc = subprocess.run(
            [sys.executable, '-B', str(SCRIPTS / 'compliance_probes.py'), '--sample', '--json'],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        sample_data = json.loads(proc.stdout)
        self.assertGreater(sample_data['summary']['total_leads'], 0)


if __name__ == '__main__':
    unittest.main()

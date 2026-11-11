#!/usr/bin/env python3
"""Check review-ledger hashes/range bounds, not whether a human/model understood code."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def file_identity(path):
    digest = hashlib.sha256()
    size = lines = 0
    last = b''
    with path.open('rb') as stream:
        before = path.stat()
        while True:
            block = stream.read(65536)
            if not block:
                break
            digest.update(block)
            size += len(block)
            lines += block.count(b'\n')
            last = block[-1:]
        after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('file changed while validating')
    return digest.hexdigest(), lines + int(bool(size) and last != b'\n')


def verify(root, ledger):
    root = Path(root).resolve()
    errors = []
    reviewed_lines = 0
    ranges_by_path = {}
    if not isinstance(ledger, dict) or not isinstance(ledger.get('completed'), list):
        return {'valid': False, 'errors': ['completed must be a list'], 'semantic_verification': 'not_performed'}
    if not isinstance(ledger.get('revision'), str) or not ledger['revision']:
        errors.append('revision is required')
    if (root/'.git').exists():
        proc = subprocess.run(['git','-C',str(root),'rev-parse','HEAD'], capture_output=True,text=True)
        if proc.returncode or proc.stdout.strip() != ledger.get('revision'):
            errors.append('ledger revision differs from repository HEAD or HEAD is unavailable')
    for number, row in enumerate(ledger['completed']):
        label = f'completed[{number}]'
        if not isinstance(row, dict):
            errors.append(label + ': must be an object');continue
        rel = row.get('path')
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:
            errors.append(label + ': path must be relative and inside root');continue
        path = root/rel
        if any((root/Path(*Path(rel).parts[:i])).is_symlink() for i in range(1,len(Path(rel).parts)+1)):
            errors.append(rel + ': symlink paths are not allowed');continue
        try:
            path.resolve().relative_to(root)
            if not path.is_file():raise ValueError('not a regular file')
            sha, count = file_identity(path)
        except (OSError, ValueError) as exc:
            errors.append(rel + ': ' + str(exc));continue
        if row.get('sha256') != sha:
            errors.append(rel + ': missing or stale sha256')
        ranges = row.get('ranges')
        if not isinstance(ranges, list) or not ranges:
            errors.append(rel + ': nonempty ranges required');continue
        for span in ranges:
            if (not isinstance(span, list) or len(span) != 2 or
                any(type(n) is not int for n in span) or not 1 <= span[0] <= span[1] <= count):
                errors.append(rel + f': invalid range {span!r}; file has {count} lines')
            else:
                ranges_by_path.setdefault(rel, []).append(span)
    for ranges in ranges_by_path.values():
        end = 0
        for start, stop in sorted(ranges):
            reviewed_lines += max(0, stop - max(end, start-1))
            end = max(end, stop)
    return {'valid': not errors, 'errors': errors, 'claimed_files':len(ranges_by_path),
            'claimed_unique_lines':reviewed_lines, 'semantic_verification':'not_performed',
            'limitation':'Valid hashes and bounds do not prove these ranges were read or understood; compare tool receipts and evidence.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('ledger', type=Path)
    p.add_argument('--root', type=Path, required=True)
    args=p.parse_args()
    try:
        result=verify(args.root,json.loads(args.ledger.read_text()))
    except (OSError,ValueError) as exc:
        result={'valid':False,'errors':[str(exc)],'semantic_verification':'not_performed'}
    print(json.dumps(result,indent=2))
    return 0 if result['valid'] else 2

if __name__=='__main__':raise SystemExit(main())

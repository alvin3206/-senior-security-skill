#!/usr/bin/env python3
"""Streaming file inventory. Byte coverage is not semantic review coverage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

CHUNK = 65536
OVERLAP = 4096


def entries(root, excluded=('.git',)):
    root = Path(root)
    if root.is_symlink():
        yield root, 'symlink'
    elif root.is_file():
        yield root, None
    elif root.is_dir():
        def walk(directory):
            try:
                with os.scandir(directory) as items:
                    children = sorted(items, key=lambda x: x.name)
            except OSError as exc:
                yield Path(directory), 'walk_error:' + type(exc).__name__
                return
            for entry in children:
                path = Path(entry.path)
                if entry.name in excluded:
                    yield path, 'excluded'
                elif entry.is_symlink():
                    yield path, 'symlink'
                elif entry.is_dir(follow_symlinks=False):
                    yield from walk(path)
                else:
                    yield path, None
        yield from walk(root)
    else:
        yield root, 'missing_or_unsupported'


def scan_stream(path, record, visit=None):
    """Read every byte of regular UTF-8 text, bounded memory even without newlines.

    visit receives overlapping decoded windows and their starting line number.
    Patterns spanning > OVERLAP bytes are outside the detector's guarantee.
    """
    record.update(bytes_read=0, status='error', sha256=None)
    digest = hashlib.sha256()
    try:
        # O_NOFOLLOW prevents replacing a checked file with a symlink before open.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                record.update(status='skipped', reason='not_regular')
                return
            record['size_bytes'] = before.st_size
            tail = b''
            line = 1
            invalid = False
            import codecs
            decoder = codecs.getincrementaldecoder('utf-8')('strict')
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                digest.update(block)
                record['bytes_read'] += len(block)
                if b'\0' in block:
                    record.update(status='skipped', reason='binary_nul')
                    return
                try:
                    decoder.decode(block)
                except UnicodeDecodeError:
                    invalid = True
                    decoder.reset()
                window = tail + block
                if visit:
                    visit(window.decode('utf-8', errors='replace'), line - tail.count(b'\n'))
                line += block.count(b'\n')
                tail = window[-OVERLAP:]
            try:
                decoder.decode(b'', final=True)
            except UnicodeDecodeError:
                invalid = True
            after = os.fstat(stream.fileno())
            record['sha256'] = digest.hexdigest()
            changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            record.update(status='partial' if invalid or changed else 'scanned',
                          reason='changed_during_scan' if changed else 'invalid_utf8' if invalid else None)
    except OSError as exc:
        record.update(status='error', reason=type(exc).__name__)


def inventory(root, ledger, excluded=('.git',)):
    root = Path(root).absolute()
    counts = {}
    total_bytes = 0
    text_bytes = 0
    identified_bytes = 0
    with open(ledger, 'w', encoding='utf-8') as out:
        for path, reason in entries(root, excluded):
            row = {'path': str(path.relative_to(root)) if root.is_dir() else path.name}
            if reason:
                row.update(status='error' if reason.startswith('walk_error') or reason == 'missing_or_unsupported' else 'skipped', reason=reason, bytes_read=0)
            else:
                scan_stream(path, row)
            counts[row['status']] = counts.get(row['status'], 0) + 1
            total_bytes += row['bytes_read']
            text_bytes += row['bytes_read'] if row['status'] == 'scanned' else 0
            identified_bytes += row.get('size_bytes', 0)
            out.write(json.dumps(row) + '\n')
    return {'root': str(root), 'ledger': str(ledger), 'counts': counts, 'bytes_read': total_bytes,
            'scanned_text_bytes': text_bytes, 'identified_regular_file_bytes': identified_bytes,
            'scope': 'working tree only; excluded directories are opaque, not counted as files',
            'semantic_review': 'not_performed', 'git_history': 'not_scanned'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('path')
    p.add_argument('--ledger', required=True, help='JSONL destination outside scanned root')
    p.add_argument('--exclude-dir', action='append', default=['.git'])
    args = p.parse_args()
    root = Path(args.path).resolve()
    target = Path(args.ledger).resolve()
    if target == root or root in target.parents:
        p.error('ledger must be outside scanned root')
    report = inventory(root, target, tuple(args.exclude_dir))
    print(json.dumps(report, indent=2))
    return 2 if report['counts'].get('error') or report['counts'].get('partial') else 0


if __name__ == '__main__':
    raise SystemExit(main())

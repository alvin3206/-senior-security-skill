#!/usr/bin/env python3
"""Read bounded byte or line windows with source identity, batch slices, and automatic ledger updates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

MAX_WINDOW_BYTES = 32768
MAX_BATCH_BYTES = 65536


def _validate_target(root, relative):
    root = Path(root).resolve()
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ValueError('path must be relative and inside root')
    if any((root / Path(*rel.parts[:i])).is_symlink() for i in range(1, len(rel.parts) + 1)):
        raise ValueError('symlinks are not supported')
    path = root / rel
    path.resolve().relative_to(root)
    return root, rel, path


def _ensure_outside_root(root, destination, label='output'):
    root = Path(root).resolve()
    dest = Path(destination).resolve()
    if dest == root or root in dest.parents:
        raise ValueError(f'{label} must be outside the source repository')
    return dest


def merge_ranges(ranges):
    """Merge overlapping or adjacent inclusive [start, end] line intervals."""
    valid = sorted(
        [int(a), int(b)]
        for a, b in ranges
        if isinstance(a, int) and isinstance(b, int) and 1 <= a <= b
    )
    merged = []
    for start, end in valid:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return merged


def read_window(root, relative, offset=0, length=8192):
    """Read a bounded byte window [offset, offset+length) with exact line coordinates."""
    root, rel, path = _validate_target(root, relative)
    if offset < 0 or not 1 <= length <= MAX_WINDOW_BYTES:
        raise ValueError(f'offset must be nonnegative; bytes must be 1..{MAX_WINDOW_BYTES}')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    digest = hashlib.sha256()
    content = bytearray()
    prefix_newlines = 0
    previous = b''
    position = 0
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular file')
        if offset > before.st_size:
            raise ValueError('offset exceeds file size')
        while True:
            block = stream.read(65536)
            if not block:
                break
            digest.update(block)
            prefix_end = min(len(block), max(0, offset - position))
            prefix_newlines += block[:prefix_end].count(b'\n')
            if position <= offset - 1 < position + len(block):
                previous = block[offset - 1 - position:offset - position]
            lo = max(0, offset - position)
            hi = min(len(block), offset + length - position)
            if lo < hi:
                content.extend(block[lo:hi])
            position += len(block)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('file changed during read; discard this excerpt')
    raw = bytes(content)
    if b'\0' in raw:
        raise ValueError('binary window; no text excerpt emitted')
    try:
        text = raw.decode('utf-8')
        decoding = 'valid_utf8'
    except UnicodeDecodeError:
        text = raw.decode('utf-8', errors='replace')
        decoding = 'boundary_split_or_invalid_utf8; reread with overlap or use an encoding-aware tool'
    start_line = prefix_newlines + 1
    end = offset + len(raw)
    first_complete = start_line + int(offset > 0 and previous != b'\n')
    last_complete = start_line + raw.count(b'\n') - 1
    if end == position and raw and not raw.endswith(b'\n'):
        last_complete += 1
    ranges = [[first_complete, last_complete]] if first_complete <= last_complete and decoding == 'valid_utf8' else []
    return {
        'path': rel.as_posix(),
        'sha256': digest.hexdigest(),
        'size_bytes': position,
        'byte_range': [offset, end],
        'range_convention': 'half-open bytes; inclusive lines',
        'start_line': start_line,
        'complete_line_ranges': ranges,
        'next_offset': end if end < position else None,
        'whole_file_displayed': offset == 0 and end == position,
        'decoding': decoding,
        'semantic_review': 'not_performed',
        'content': text,
    }


def read_window_lines(root, relative, start_line=1, end_line=120, max_bytes=MAX_WINDOW_BYTES, number_lines=False):
    """Read an inclusive 1-based line range [start_line, end_line], capped at max_bytes."""
    root, rel, path = _validate_target(root, relative)
    if start_line < 1 or end_line < start_line:
        raise ValueError('line range must satisfy 1 <= start_line <= end_line')
    if not 1 <= max_bytes <= MAX_WINDOW_BYTES:
        raise ValueError(f'max_bytes must be 1..{MAX_WINDOW_BYTES}')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    digest = hashlib.sha256()
    selected = bytearray()
    total_bytes = 0
    total_lines = 0
    current_line = 1
    byte_start = None
    byte_end = None
    last_complete_line = start_line - 1
    truncated_mid_line = False
    has_nul = False
    last_byte = b''

    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular file')
        while True:
            raw_line = stream.readline(65536)
            if not raw_line:
                break
            digest.update(raw_line)
            if b'\0' in raw_line:
                has_nul = True
            line_start_pos = total_bytes
            total_bytes += len(raw_line)
            last_byte = raw_line[-1:]
            ended_newline = raw_line.endswith(b'\n')

            if start_line <= current_line <= end_line and not truncated_mid_line:
                if byte_start is None:
                    byte_start = line_start_pos
                remaining = max_bytes - len(selected)
                if remaining <= 0:
                    truncated_mid_line = True
                elif len(raw_line) <= remaining:
                    selected.extend(raw_line)
                    byte_end = total_bytes
                    if ended_newline:
                        last_complete_line = current_line
                else:
                    selected.extend(raw_line[:remaining])
                    byte_end = line_start_pos + remaining
                    truncated_mid_line = True

            if ended_newline:
                total_lines += 1
                current_line += 1
        after = os.fstat(stream.fileno())

    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('file changed during read; discard this excerpt')
    if has_nul:
        raise ValueError('binary file; no text excerpt emitted')
    if total_bytes and last_byte != b'\n':
        total_lines += 1
        if start_line <= current_line <= end_line and not truncated_mid_line and byte_end == total_bytes:
            last_complete_line = current_line

    if total_lines == 0:
        byte_start = 0
        byte_end = 0
        ranges = []
    elif start_line > total_lines:
        raise ValueError(f'start_line {start_line} exceeds file line count {total_lines}')
    else:
        if byte_start is None:
            byte_start = total_bytes
            byte_end = total_bytes
        ranges = [[start_line, last_complete_line]] if start_line <= last_complete_line else []

    raw = bytes(selected)
    try:
        text = raw.decode('utf-8')
        decoding = 'valid_utf8'
    except UnicodeDecodeError:
        text = raw.decode('utf-8', errors='replace')
        decoding = 'boundary_split_or_invalid_utf8; reread with overlap or use an encoding-aware tool'
        ranges = []

    next_line = (last_complete_line + 1) if ranges and last_complete_line < total_lines else None
    result = {
        'path': rel.as_posix(),
        'sha256': digest.hexdigest(),
        'size_bytes': total_bytes,
        'total_lines': total_lines,
        'byte_range': [byte_start or 0, byte_end or 0],
        'range_convention': 'half-open bytes; inclusive lines',
        'start_line': start_line,
        'complete_line_ranges': ranges,
        'next_offset': byte_end if (byte_end is not None and byte_end < total_bytes) else None,
        'next_line': next_line,
        'whole_file_displayed': (byte_start == 0 and byte_end == total_bytes),
        'decoding': decoding,
        'semantic_review': 'not_performed',
        'content': text,
    }
    if number_lines and ranges:
        lines = text.splitlines()
        result['numbered_content'] = '\n'.join(
            f'{start_line + idx}: {line_text}' for idx, line_text in enumerate(lines)
        )
    return result


def parse_slice_spec(spec):
    """Parse 'path/to/file.py:10-80' or 'path/to/file.py:10:80' or 'path/to/file.py'."""
    if ':' not in spec:
        return spec, 1, 120
    path_part, range_part = spec.rsplit(':', 1)
    sep = '-' if '-' in range_part else ':' if ':' in range_part else None
    if not sep:
        line_no = int(range_part)
        return path_part, line_no, line_no + 80
    start_s, end_s = range_part.split(sep, 1)
    return path_part, int(start_s), int(end_s)


def _detect_revision(root):
    root = Path(root).resolve()
    if (root / '.git').exists():
        proc = subprocess.run(
            ['git', '-C', str(root), 'rev-parse', 'HEAD'],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    return 'working-tree'


def update_review_ledger(root, ledger_path, results, flow=None):
    """Automatically update review-ledger.json with verified sha256 and complete_line_ranges."""
    ledger_dest = _ensure_outside_root(root, ledger_path, 'ledger')
    revision = _detect_revision(root)
    if ledger_dest.exists():
        try:
            ledger = json.loads(ledger_dest.read_text(encoding='utf-8'))
        except ValueError as exc:
            raise ValueError(f'existing ledger is invalid JSON: {exc}') from exc
    else:
        ledger = {
            'revision': revision,
            'completed': [],
            'pending': [],
            'unresolved': [],
        }

    if not isinstance(ledger, dict):
        raise ValueError('ledger root must be a JSON object')
    ledger['revision'] = ledger.get('revision') or revision
    completed = ledger.setdefault('completed', [])
    if not isinstance(completed, list):
        raise ValueError('ledger.completed must be a list')

    by_path = {}
    for entry in completed:
        if isinstance(entry, dict) and isinstance(entry.get('path'), str):
            by_path[entry['path']] = entry

    for item in results:
        ranges = item.get('complete_line_ranges') or []
        if not ranges:
            continue
        rel_path = item['path']
        sha = item['sha256']
        existing = by_path.get(rel_path)
        if existing is None or existing.get('sha256') != sha:
            existing = {
                'path': rel_path,
                'sha256': sha,
                'ranges': merge_ranges(ranges),
            }
            if flow:
                existing['flows'] = [flow]
            if rel_path in by_path:
                idx = completed.index(by_path[rel_path])
                completed[idx] = existing
            else:
                completed.append(existing)
            by_path[rel_path] = existing
        else:
            existing['ranges'] = merge_ranges((existing.get('ranges') or []) + ranges)
            if flow:
                flows = existing.setdefault('flows', [])
                if flow not in flows:
                    flows.append(flow)

    ledger_dest.parent.mkdir(parents=True, exist_ok=True)
    ledger_dest.write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8')
    return ledger


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('path', nargs='?', help='Path relative to root (or path:start-end)')
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--bytes', type=int, default=8192)
    p.add_argument('--lines', help='1-based inclusive line range START:END or START-END')
    p.add_argument('--slice', action='append', default=[], help='Batch slice spec path:START-END (repeatable)')
    p.add_argument('--receipt', type=Path, help='Append metadata-only JSONL outside repository')
    p.add_argument('--update-ledger', type=Path, help='Automatically merge verified ranges and sha256 into review-ledger.json outside repository')
    p.add_argument('--flow', help='Optional flow/control name recorded when updating review ledger')
    p.add_argument('--number-lines', action='store_true', help='Include 1-based line numbers in numbered_content')
    args = p.parse_args()
    try:
        if args.receipt:
            _ensure_outside_root(args.root, args.receipt, 'receipt')
        if args.update_ledger:
            _ensure_outside_root(args.root, args.update_ledger, 'ledger')

        if args.slice:
            slices = []
            total_batch_bytes = 0
            for spec in args.slice:
                rel_path, start_line, end_line = parse_slice_spec(spec)
                budget = min(args.bytes, MAX_WINDOW_BYTES, max(1, MAX_BATCH_BYTES - total_batch_bytes))
                item = read_window_lines(
                    args.root, rel_path, start_line, end_line,
                    max_bytes=budget, number_lines=args.number_lines,
                )
                total_batch_bytes += item['byte_range'][1] - item['byte_range'][0]
                slices.append(item)
                if total_batch_bytes >= MAX_BATCH_BYTES:
                    break
            if args.receipt:
                args.receipt.parent.mkdir(parents=True, exist_ok=True)
                with args.receipt.open('a', encoding='utf-8') as stream:
                    for item in slices:
                        receipt = {k: v for k, v in item.items() if k not in ('content', 'numbered_content')}
                        stream.write(json.dumps(receipt) + '\n')
            if args.update_ledger:
                update_review_ledger(args.root, args.update_ledger, slices, flow=args.flow)
            print(json.dumps({'slices': slices, 'count': len(slices), 'total_bytes': total_batch_bytes}, ensure_ascii=False))
            return 0

        if not args.path:
            raise ValueError('either positional path or --slice is required')

        if args.lines:
            sep = '-' if '-' in args.lines else ':'
            start_s, end_s = args.lines.split(sep, 1)
            result = read_window_lines(
                args.root, args.path, int(start_s), int(end_s),
                max_bytes=min(args.bytes, MAX_WINDOW_BYTES),
                number_lines=args.number_lines,
            )
        elif ':' in args.path and not (Path(args.root) / args.path).exists():
            rel_path, start_line, end_line = parse_slice_spec(args.path)
            result = read_window_lines(
                args.root, rel_path, start_line, end_line,
                max_bytes=min(args.bytes, MAX_WINDOW_BYTES),
                number_lines=args.number_lines,
            )
        else:
            result = read_window(args.root, args.path, args.offset, args.bytes)
            if args.number_lines and result.get('complete_line_ranges'):
                base_line = result['start_line']
                result['numbered_content'] = '\n'.join(
                    f'{base_line + idx}: {line_text}'
                    for idx, line_text in enumerate(result['content'].splitlines())
                )

        if args.receipt:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt = {k: v for k, v in result.items() if k not in ('content', 'numbered_content')}
            with args.receipt.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(receipt) + '\n')
        if args.update_ledger:
            update_review_ledger(args.root, args.update_ledger, [result], flow=args.flow)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({'status': 'error', 'message': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

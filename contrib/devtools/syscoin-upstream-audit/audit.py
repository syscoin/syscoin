#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Read-only Git comparison and conservative SYSCOIN marker inventory.

This reports review candidates, not semantic ownership. It never edits source.
Requires only Python's standard library and locally available Git objects.
"""
import argparse
from collections import Counter
import difflib
import json
from pathlib import Path
import re
import subprocess

UPSTREAM = 'e4fef4ae65c68ebd34774700dc4801c24313d469'
VENDORS = ('src/leveldb/', 'src/secp256k1/', 'src/crc32c/', 'src/minisketch/',
           'src/univalue/', 'src/immer/', 'src/crypto/ethash/', 'src/crypto/sph_')
SOURCE_EXT = {'.cpp', '.h', '.c', '.cc', '.hpp', '.mm', '.m'}
RAW_STRING = r'(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\([\s\S]*?\)(?P=delimiter)"'
STRING = r'"(?:\\(?:\r?\n|.)|[^"\\\r\n])*"'
CHAR = r"'(?:\\(?:\r?\n|.)|[^'\\\r\n])*'"
# Match preprocessing-number tokens before character literals, so apostrophe
# digit separators cannot swallow neighboring declarations as fake strings.
NUMBER = r"(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[A-Za-z_0-9.]|'[A-Za-z_0-9])*"
LEX = re.compile('|'.join((RAW_STRING, r'//[^\n]*', r'/\*[\s\S]*?\*/', NUMBER, STRING, CHAR)))
TOKEN = re.compile('|'.join((RAW_STRING, STRING, CHAR, NUMBER, r'[A-Za-z_$][\w$]*', r'<=>|>>=|<<=|->\*|\.\*|\.\.\.|::|->|\+\+|--|&&|\|\||<<|>>|<=|>=|==|!=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|[^\s]')))
MARK = re.compile(r'(?://|/\*+|^\s*\*|^\s*)\s*(?:SYSCOIN\b(?!_)|END\s+SYSCOIN\b)', re.I)
BEGIN = re.compile(r'\bSYSCOIN\s*:?\s*BEGIN\b', re.I)
END = re.compile(r'\bSYSCOIN\s*:?\s*END\b|\bEND\s+SYSCOIN\b', re.I)
REGION = re.compile(BEGIN.pattern + '|' + END.pattern, re.I)


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def tree(repo, ref):
    result = {}
    for row in git(repo, 'ls-tree', '-r', '-z', ref).split(b'\0'):
        if not row:
            continue
        info, name = row.split(b'\t', 1)
        mode, kind, oid = info.decode().split()
        if kind == 'blob':
            result[name.decode()] = (mode, oid)
    return result


class Blobs:
    def __init__(self, repo):
        self.proc = subprocess.Popen(['git', '-C', str(repo), 'cat-file', '--batch'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def read(self, oid):
        self.proc.stdin.write((oid + '\n').encode())
        self.proc.stdin.flush()
        fields = self.proc.stdout.readline().split()
        if len(fields) != 3 or fields[1] != b'blob':
            raise RuntimeError('Expected available blob: ' + oid)
        value = self.proc.stdout.read(int(fields[2]))
        assert self.proc.stdout.read(1) == b'\n'
        return value

    def close(self):
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.wait()


def normalize(s):
    # Product-name/path substitutions only; amounts, network parameters,
    # protocol identifiers and BTC/SYS currency tokens are NOT normalized.
    return s.replace('SYSCOIN', 'BITCOIN').replace('Syscoin', 'Bitcoin').replace('syscoin', 'bitcoin')


def strip_comments(s):
    return LEX.sub(lambda m: ' ' + '\n' * m[0].count('\n') if m[0].startswith(('//', '/*')) else m[0], s)


def syntax_only(s):
    # Preserve newlines for exact current-source positions, hide string braces.
    return LEX.sub(lambda m: '\n' * m[0].count('\n'), s)


def comments_only(s):
    # Do not recognize marker-looking contents of C++ strings/raw strings.
    chunks = []
    previous = 0
    for match in LEX.finditer(s):
        chunks.append(re.sub(r'[^\r\n]', ' ', s[previous:match.start()]))
        value = match[0]
        chunks.append(value if value.startswith(('//', '/*')) else re.sub(r'[^\r\n]', ' ', value))
        previous = match.end()
    chunks.append(re.sub(r'[^\r\n]', ' ', s[previous:]))
    return ''.join(chunks)


def marker_map(text):
    lines = text.splitlines()
    code = syntax_only(text).splitlines()
    comments = comments_only(text).splitlines()
    explicit, local, nearby, issues = set(), set(), set(), []
    stack = []
    marks = []
    for n, line in enumerate(comments, 1):
        if not MARK.search(line):
            continue
        marks.append(n)
        boundaries = list(REGION.finditer(line))
        if boundaries:
            for boundary in boundaries:
                if BEGIN.fullmatch(boundary[0]):
                    stack.append(n)
                elif stack:
                    explicit.update(range(stack.pop(), n + 1))
                else:
                    issues.append({'line': n, 'kind': 'unmatched_or_legacy_end', 'text': lines[n - 1].strip()})
        else:
            # A local tag covers a syntax-bounded next item, not the rest of a
            # file. If parsing is unclear it remains a nearby-marker candidate.
            first = n
            while first <= len(code) and not code[first - 1].strip():
                first += 1
            if first > len(code):
                continue
            start = first
            depth = 0
            opened = False
            limit = min(len(code), first + 30)
            while first <= len(code):
                item = code[first - 1]
                if item.lstrip().startswith('#'):
                    local.add(first)
                    break
                for c in item:
                    if c == '{':
                        depth += 1
                        opened = True
                    elif c == '}':
                        depth -= 1
                if opened and depth <= 0:
                    local.update(range(start, first + 1))
                    break
                if not opened and ';' in item:
                    local.update(range(start, first + 1))
                    break
                if not opened and first >= limit:
                    break
                first += 1
        nearby.update(range(max(1, n - 3), min(len(lines), n + 8) + 1))
    issues.extend({'line': n, 'kind': 'unclosed_begin', 'text': lines[n - 1].strip()} for n in stack)
    return explicit, local, nearby, issues, marks


def category(path):
    if path.startswith(VENDORS):
        return 'vendor'
    if path.startswith('src/qt/locale/'):
        return 'translation'
    if path.startswith(('test/', 'src/test/', 'src/bench/', 'src/qt/test/', 'src/wallet/test/')):
        return 'test'
    if path.startswith('src/') and Path(path).suffix in SOURCE_EXT:
        return 'production'
    if path.startswith(('doc/', 'share/')) or Path(path).suffix in {'.md', '.txt', '.png', '.svg'}:
        return 'documentation_or_asset'
    return 'build_config_other'


def analyze(repo, upstream, target, out):
    upstream = git(repo, 'rev-parse', upstream + '^{commit}').decode().strip()
    target = git(repo, 'rev-parse', target + '^{commit}').decode().strip()
    old_tree, new_tree = tree(repo, upstream), tree(repo, target)
    source = Blobs(repo)
    inventory, hunks, marker_issues, matched = [], [], [], set()
    try:
        for path, (mode, oid) in sorted(new_tree.items()):
            old_path = path if path in old_tree else normalize(path)
            row = {'path': path, 'category': category(path), 'mode': mode}
            if old_path not in old_tree:
                row['status'] = 'no_upstream_path'
                inventory.append(row)
                continue
            matched.add(old_path)
            row['upstream_path'] = old_path
            if oid == old_tree[old_path][1]:
                row['status'] = 'identical'
                inventory.append(row)
                continue
            old_data, new_data = source.read(old_tree[old_path][1]), source.read(oid)
            if b'\0' in old_data or b'\0' in new_data:
                row['status'] = 'binary_difference'
                inventory.append(row)
                continue
            try:
                old, new = old_data.decode('utf8'), new_data.decode('utf8')
            except UnicodeDecodeError:
                row['status'] = 'non_utf8_difference'
                inventory.append(row)
                continue
            if normalize(old) == normalize(new):
                row['status'] = 'product_rename_only'
                inventory.append(row)
                continue
            row['status'] = 'changed'
            if row['category'] not in {'production', 'test'} or Path(path).suffix not in SOURCE_EXT:
                row['marker_audit'] = 'separate_non_cpp_review'
                inventory.append(row)
                continue
            old_lines, new_lines = old.splitlines(), new.splitlines()
            explicit, local, nearby, issues, marks = marker_map(new)
            comment_lines = comments_only(new).splitlines()
            marker_issues.extend({'path': path, **issue} for issue in issues)
            old_clean, new_clean = strip_comments(old).splitlines(), strip_comments(new).splitlines()
            old_clean.extend([''] * (len(old_lines) - len(old_clean)))
            new_clean.extend([''] * (len(new_lines) - len(new_clean)))
            counts = Counter()
            matcher = difflib.SequenceMatcher(None, [normalize(s).strip() for s in old_lines],
                                              [normalize(s).strip() for s in new_lines], autojunk=False)
            for kind, a, b, c, d in matcher.get_opcodes():
                if kind == 'equal':
                    continue
                old_code = [m[0] for m in TOKEN.finditer(normalize('\n'.join(old_clean[a:b])))]
                new_code = [m[0] for m in TOKEN.finditer(normalize('\n'.join(new_clean[c:d])))]
                if old_code == new_code:
                    status = 'comment_or_format_only'
                else:
                    changed_lines = [n + 1 for n in range(c, d) if new_clean[n].strip()]
                    if not changed_lines:
                        anchors = range(c + 1, max(c + 2, d + 1))
                        # A zero-width deletion just before a newly marked item
                        # is outside that item. Require context on both sides.
                        explicit_context = any(n in explicit for n in anchors)
                        local_context = any(n in local or n in marks for n in anchors)
                        if c == d:
                            explicit_context = (c in explicit and c + 1 in explicit and
                                                not (c < len(comment_lines) and BEGIN.search(comment_lines[c])))
                            local_context = c in local and c + 1 in local
                        if explicit_context:
                            status = 'explicit_removal_context'
                        elif local_context:
                            status = 'local_removal_context'
                        else:
                            status = 'removed_upstream_code'
                    elif all(n in explicit for n in changed_lines):
                        status = 'explicit_region'
                    elif all(n in explicit or n in local for n in changed_lines):
                        status = 'local_syntax_marker'
                    elif any(n in explicit or n in local or n in nearby for n in changed_lines):
                        status = 'partly_marked_or_ambiguous'
                    else:
                        status = 'no_marker_candidate'
                counts[status] += 1
                if status == 'comment_or_format_only':
                    continue
                hunks.append({'path': path, 'upstream_path': old_path, 'category': row['category'],
                              'kind': kind, 'status': status,
                              'old_start': a + 1, 'old_count': b - a,
                              'new_start': c + 1, 'new_count': d - c,
                              'nearest_marker_distance': min((abs(c + 1 - n) for n in marks), default=None),
                              'before': old_lines[a:b], 'after': new_lines[c:d]})
            row['hunks'] = dict(counts)
            inventory.append(row)
    finally:
        source.close()
    removed = [{'upstream_path': p, 'category': category(p)} for p in sorted(old_tree.keys() - matched)]
    result = {'upstream': upstream, 'target': target, 'product_rename_normalization': ['SYSCOIN/BITCOIN', 'Syscoin/Bitcoin', 'syscoin/bitcoin'],
              'warning': 'Candidate inventory, not semantic proof of Syscoin ownership. Later upstream backports, inherited fork code and legacy local markers require manual review. Deleted code is retained in the report, not automatically reinserted.',
              'inventory': inventory, 'removed_upstream_files': removed, 'hunks': hunks, 'marker_issues': marker_issues}
    out.mkdir(parents=True, exist_ok=True)
    (out / 'audit.json').write_bytes((json.dumps(result, indent=2) + '\n').encode('utf-8'))
    summary = {'upstream': upstream, 'target': target, 'tracked_files': len(new_tree),
               'file_statuses': dict(Counter(r['status'] for r in inventory)),
               'production_file_statuses': dict(Counter(r['status'] for r in inventory if r['category'] == 'production')),
               'hunks_by_category': {cat: dict(Counter(h['status'] for h in hunks if h['category'] == cat)) for cat in ('production', 'test')},
               'removed_upstream_files': len(removed), 'marker_issues': len(marker_issues)}
    (out / 'summary.json').write_bytes((json.dumps(summary, indent=2) + '\n').encode('utf-8'))
    review = [h for h in hunks if h['status'] in {'no_marker_candidate', 'partly_marked_or_ambiguous', 'removed_upstream_code'}]
    by_file = Counter(h['path'] for h in review if h['category'] == 'production')
    rows = ['# Upstream marker candidate inventory', '', f'Bitcoin comparison: `{upstream}`. Syscoin: `{target}`.', '', result['warning'], '',
            '| Production file | Candidate hunks |', '| --- | ---: |']
    rows += [f'| `{p}` | {n} |' for p, n in by_file.most_common()]
    rows += ['', '## Marker structure issues', ''] + [f"- `{x['path']}:{x['line']}`: {x['kind']} — `{x['text']}`" for x in marker_issues]
    if not marker_issues:
        rows.append('None.')
    (out / 'inventory.md').write_bytes(('\n'.join(rows) + '\n').encode('utf-8'))
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--upstream', default=UPSTREAM)
    parser.add_argument('--target', default='HEAD')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    analyze(args.repo, args.upstream, args.target, args.output)

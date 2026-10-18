#!/usr/bin/env python3
"""Extract public upstream Orchard vectors; never generate wallet secrets.

The source arrays come from the pinned dual-licensed Orchard repository. The
output preserves source hashes/field lengths and is checked by existing APIs.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN = '616a669df8c9a59c33d47064d3ce04b25d026b2e'


def records(text, first):
    starts = list(re.finditer(r'TestVector\s*\{\s*' + first + r'\s*:', text))
    result = []
    for match in starts:
        begin = text.index('{', match.start()); end = begin + 1; depth = 1
        while depth:
            if text[end] == '{': depth += 1
            if text[end] == '}': depth -= 1
            end += 1
        body = text[begin + 1:end - 1]
        fields = {}
        at = 0
        while at < len(body):
            field = re.search(r'(\w+)\s*:\s*', body[at:])
            if not field: break
            name = field[1]; start = at + field.end()
            if body[start] == '[':
                stop = start + 1; level = 1
                while level:
                    if body[stop] == '[': level += 1
                    if body[stop] == ']': level -= 1
                    stop += 1
                value = ast.literal_eval(body[start:stop])
            else:
                stop = body.index(',', start)
                value = int(body[start:stop].replace('_', ''))
            fields[name] = value
            at = stop + 1
        result.append(fields)
    return result


def hex_arrays(value):
    if isinstance(value, dict): return {k: hex_arrays(v) for k, v in value.items()}
    if isinstance(value, list):
        if all(type(x) is int and 0 <= x <= 255 for x in value): return bytes(value).hex()
        return [hex_arrays(x) for x in value]
    return value


def main():
    source = Path(sys.argv[1]); output = Path(sys.argv[2])
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != PIN: raise RuntimeError('wrong upstream Orchard commit')
    sections, provenance = {}, {}
    for name, first in [('keys', 'sk'), ('note_encryption', 'incoming_viewing_key'),
                        ('commitment_tree', 'empty_roots'), ('merkle_path', 'leaves')]:
        relative = f'src/test_vectors/{name}.rs'; raw = (source / relative).read_bytes()
        frozen = subprocess.check_output(['git', '-C', str(source), 'show', PIN + ':' + relative])
        if raw != frozen: raise RuntimeError('modified upstream vector source')
        values = records(raw.decode(), first)
        if not values: raise RuntimeError('no parsed vectors: ' + name)
        sections[name] = hex_arrays(values)
        provenance[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    result = {'scope': 'PUBLIC_UPSTREAM_TEST_KEYS_NEVER_FUND_THESE_KEYS', 'orchardCommit': PIN,
              'license': 'MIT OR Apache-2.0', 'sources': provenance, **sections}
    with output.open('x') as f: json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps({name: len(sections[name]) for name in sections}))


if __name__ == '__main__': main()

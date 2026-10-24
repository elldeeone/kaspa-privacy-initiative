#!/usr/bin/env python3
"""Literal seed canary only. One private leaf; no derivation or decryption."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

DOMAIN = '32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d'
CHUNK = 65536


def need(value):
    if not value:
        raise ValueError('literal-seed-canary-input')


def hx(value, width):
    need(type(value) is str and len(value) == 2 * width
         and all(c in '0123456789abcdef' for c in value))
    return bytes.fromhex(value)


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False))


def allowlist(raw, expected):
    need(hashlib.sha256(raw).digest() == hx(expected, 32))
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'files'}
         and value['schema'] == 'kpx7-new-owner-seed-export-allowlist/v1'
         and type(value['files']) is list and 1 <= len(value['files']) <= (1 << 32) - 2)
    names, total = set(), 0
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'})
        name = row['path']; need(type(name) is str and name and '\\' not in name and '\0' not in name)
        path = PurePosixPath(name)
        need(path.parts and not path.is_absolute() and '..' not in path.parts
             and str(path) == name and name not in names)
        need(type(row['bytes']) is int and 0 <= row['bytes'] < 1 << 64)
        hx(row['sha256'], 32); names.add(name); total += row['bytes']; need(total < 1 << 64)
    need(total + len(raw) < 1 << 64)
    return value['files'], total


def open_leaf(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and (not private or stat.S_IMODE(info.st_mode) == 0o600))
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd); raise


def read_owner(path):
    with open_leaf(path, private=True) as source:
        value = parse(source.read())
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'participant_id_hex32',
         'seed_hex32', 'initial_position', 'input_receipt_hex216'})
    need(value['schema'] == 'kpx7-unfunded-owner-state/v1' and value['domain_hex32'] == DOMAIN
         and type(value['initial_position']) is int and 0 <= value['initial_position'] < 3)
    hx(value['participant_id_hex32'], 32); hx(value['input_receipt_hex216'], 216)
    return hx(value['seed_hex32'], 32)


def scan(owner, raw_allowlist, expected, candidates):
    rows, total = allowlist(raw_allowlist, expected)
    private_info = owner.lstat()
    need(stat.S_ISREG(private_info.st_mode) and private_info.st_nlink == 1
         and stat.S_IMODE(private_info.st_mode) == 0o600)
    # Authenticate the complete public selection BEFORE the one private read.
    for index, row in enumerate(rows):
        h = hashlib.sha256(); count = 0
        with open_leaf(candidates / (str(index) + '.bin')) as source:
            for chunk in iter(lambda: source.read(CHUNK), b''):
                h.update(chunk); count += len(chunk)
        need(count == row['bytes'] and h.hexdigest() == row['sha256'])
    seed = read_owner(owner)  # The only private leaf/content read in this program.
    needles = (seed, seed.hex().encode(), seed.hex().upper().encode())
    # The public selection itself is also a candidate. Paths can leak a
    # literal seed even when the referenced file contents are clean.
    matched = int(any(needle in raw_allowlist or any(needle in row['path'].encode() for row in rows)
                      for needle in needles))
    for index in range(len(rows)):
        found, overlap = False, b''
        with open_leaf(candidates / (str(index) + '.bin')) as source:
            for chunk in iter(lambda: source.read(CHUNK), b''):
                window = overlap + chunk
                found |= any(needle in window for needle in needles)
                overlap = window[-63:]
        matched += int(found)
    return {'schema': 'kpx7-new-owner-seed-export-result/v1',
        'status': 'FAIL' if matched else 'PASS', 'candidate_count': len(rows) + 1,
        'candidate_bytes': total + len(raw_allowlist), 'matched_candidate_count': matched,
        'scope': 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF'}


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--owner', type=Path, required=True)
    p.add_argument('--allowlist', type=Path, required=True)
    p.add_argument('--allowlist-sha256', required=True)
    p.add_argument('--candidates', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    try:
        a = p.parse_args()
        with open_leaf(a.allowlist) as source:
            raw = source.read()
        result = scan(a.owner, raw, a.allowlist_sha256, a.candidates)
        fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as output:
            output.write((json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode())
            output.flush(); os.fsync(output.fileno())
    except Exception:
        p.exit(2, 'seed export canary refused; no private material exported\n')

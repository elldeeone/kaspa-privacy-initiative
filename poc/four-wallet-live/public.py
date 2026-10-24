"""Public-only strict data/path helpers; never open an owner backup."""
from pathlib import Path
import copy
import hashlib
import json
import os
import re
import stat
import uuid

ROOT = Path(__file__).resolve().parents[2]
MAX = 2_870_000_000_000_000_000
ROLES = ('A', 'B', 'C', 'D')


def need(value, code):
    if not value:
        raise ValueError('four-wallet-live:' + code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
        parse_float=lambda _: (_ for _ in ()).throw(ValueError('four-wallet-live:float')),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('four-wallet-live:constant')))


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'canonical-sha256')
    return value


def trial(value):
    need(type(value) is str and str(uuid.UUID(value)) == value
         and uuid.UUID(value).version == 4, 'canonical-trial-uuid4')
    return value


def amount(value, *, positive=False):
    need(type(value) is int and (0 < value if positive else 0 <= value) and value <= MAX,
         'integer-sompi-range')
    return value


def checked(value):
    path = Path(value)
    need('..' not in path.parts, 'canonical-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'path-symlink')
    return path


def forbidden_backups(trial_directory):
    base = checked(trial_directory)
    return tuple(base / 'owners' / role / 'backup.json' for role in ROLES)


def forbidden_identities(trial_directory):
    private = forbidden_backups(trial_directory)
    identities = set()
    for path in private:
        if path.exists():
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode), 'regular-owner-backup-metadata')
            identities.add((info.st_dev, info.st_ino))
    return frozenset(identities)


def guard_public_paths(paths, trial_directory):
    """All metadata is checked before the first listed public byte is read."""
    private = forbidden_backups(trial_directory)
    identities = forbidden_identities(trial_directory)
    result = []
    for value in paths:
        path = checked(value)
        need(not any(path == p or path.is_relative_to(p.parent) for p in private),
             'public-path-inside-private-owner-directory')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in identities,
             'public-file-backup-alias')
        result.append(path)
    return tuple(result)


def read_stable_public(path, trial_directory):
    """Stable/alias-guarded bytes, without claiming external hash authority."""
    path, = guard_public_paths((path,), trial_directory)
    forbidden = forbidden_identities(trial_directory)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (before.st_dev, before.st_ino) not in forbidden,
         'guarded-public-file-before-open')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        need(stat.S_ISREG(opened.st_mode)
             and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
             and (opened.st_dev, opened.st_ino) not in forbidden,
             'public-file-swapped-before-first-byte')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        after = os.fstat(fd)
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(before, k) for k in attributes) ==
             tuple(getattr(after, k) for k in attributes) and len(raw) == before.st_size,
             'public-source-stable-bytes')
        return raw
    finally:
        os.close(fd)


def read_public(path, expected_sha256, trial_directory):
    sha(expected_sha256)
    raw = read_stable_public(path, trial_directory)
    need(digest(raw) == expected_sha256, 'public-source-integrity')
    return raw


def write_new(path, value):
    path = checked(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    raw = value if type(value) is bytes else encoded(value) + b'\n'
    try:
        with os.fdopen(os.dup(fd), 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def case_summary(case):
    """Structural fingerprints/accounting, NOT Native/SDK/proof validation."""
    fields(case, ('transaction', 'entries'), 'case-fields')
    body, entries = case['transaction'], case['entries']
    fields(body, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
                  'gas', 'payload', 'mass'), 'body-fields')
    need(type(body['version']) is int and body['version'] == 1, 'version-one')
    sha(body['id'])
    need(type(body['inputs']) is list and body['inputs'] and type(entries) is list
         and len(entries) == len(body['inputs']), 'populated-input-count')
    need(type(body['outputs']) is list and body['outputs'], 'positive-output-count')
    points = []
    for item, entry in zip(body['inputs'], entries):
        fields(item, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'), 'input-fields')
        fields(item['previousOutpoint'], ('transactionId', 'index'), 'point-fields')
        sha(item['previousOutpoint']['transactionId'])
        need(type(item['previousOutpoint']['index']) is int
             and 0 <= item['previousOutpoint']['index'] < 1 << 32, 'point-index')
        need(type(item['sequence']) is int and 0 <= item['sequence'] < 1 << 64,
             'input-sequence')
        need(type(item['computeBudget']) is int and 0 <= item['computeBudget'] < 1 << 16,
             'native-u16-budget')
        need(type(item['signatureScript']) is str
             and re.fullmatch('(?:[0-9a-f]{2})*', item['signatureScript']), 'signature-hex')
        fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'),
               'input-context-fields')
        amount(entry['amount'], positive=True)
        need(type(entry['blockDaaScore']) is int and 0 <= entry['blockDaaScore'] < 1 << 64
             and entry['isCoinbase'] is False and entry['covenantId'] is None,
             'ordinary-input-context')
        need(type(entry['scriptPublicKey']) is str
             and re.fullmatch('0000(?:[0-9a-f]{2})+', entry['scriptPublicKey']), 'input-script')
        points.append((item['previousOutpoint']['transactionId'], item['previousOutpoint']['index']))
    need(len(set(points)) == len(points), 'distinct-inputs')
    for item in body['outputs']:
        fields(item, ('value', 'scriptPublicKey', 'covenant'), 'output-fields')
        amount(item['value'], positive=True)
        need(item['covenant'] is None and type(item['scriptPublicKey']) is str
             and re.fullmatch('0000(?:[0-9a-f]{2})+', item['scriptPublicKey']), 'ordinary-output')
    for key in ('lockTime', 'gas', 'mass'):
        need(type(body[key]) is int and 0 <= body[key] < 1 << 64, 'native-header-integer')
    need(type(body['subnetworkId']) is str and re.fullmatch('[0-9a-f]{40}', body['subnetworkId'])
         and type(body['payload']) is str and re.fullmatch('(?:[0-9a-f]{2})*', body['payload']),
         'native-header-bytes')
    incoming = amount(sum(item['amount'] for item in entries), positive=True)
    outgoing = amount(sum(item['value'] for item in body['outputs']), positive=True)
    fee = amount(incoming - outgoing)
    projection = copy.deepcopy(case)
    for item in projection['transaction']['inputs']:
        del item['computeBudget']
        del item['signatureScript']
    return {'transaction_id': body['id'], 'case_sha256': digest(encoded(case)),
        'financial_projection_sha256': digest(encoded(projection)), 'source_sompi': incoming,
        'outputs_sompi': outgoing, 'fee_sompi': fee,
        'compute_budgets': [row['computeBudget'] for row in body['inputs']],
        'storage_mass': body['mass'], 'input_outpoints':
            [copy.deepcopy(row['previousOutpoint']) for row in body['inputs']]}

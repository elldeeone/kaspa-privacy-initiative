#!/usr/bin/env python3
"""Owner-side finite derived-byte export check; no network or authorization.

The launcher authenticates/mounts this finite public source closure and exactly
one backup leaf. Public history is replayed with the existing wallet predicate
before that leaf is read. This does not authenticate a chain checkpoint itself.
Literal seed coverage is a separate checker. Random proving blinds, unpublished
invoice indices and material absent from seed plus selected history are outside
this finite coverage. No original is authorized by this source alone.

The numeric candidate framing and byte/hex scan follow the reviewed literal
worker 64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import sys

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
import support
import history
import payment

CHUNK = 65536
SCOPE = 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF'


def need(value):
    if not value:
        raise ValueError('derived-export-check-refused')


def identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns'))


def namespace(owner, candidates, output):
    """The only allowed private content source is this exact root-mounted leaf."""
    need(owner == Path('/BACKUP.json') and candidates == Path('/candidates')
         and output == Path('/out/RESULTS.json'))
    need(not any(Path(name).exists() for name in
                 ('/home', '/var', '/root', '/owner', '/private')))
    info = owner.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600 and not owner.is_symlink())
    return info


def manifest(raw, expected):
    need(hashlib.sha256(raw).digest() == support.hx(expected, 32))
    value = support.parse(raw)
    support.fields(value, ('schema', 'files'), 'derived-candidate-fields')
    need(value['schema'] == 'kpxa-derived-export-candidates/v1'
         and type(value['files']) is list
         and 1 <= len(value['files']) <= (1 << 32) - 2)
    names, total = set(), 0
    for row in value['files']:
        support.fields(row, ('path', 'bytes', 'sha256'), 'derived-candidate-row')
        name = row['path']
        need(type(name) is str and name and '\\' not in name and '\0' not in name)
        path = PurePosixPath(name)
        need(path.parts and not path.is_absolute() and '..' not in path.parts
             and str(path) == name and name not in names)
        need(type(row['bytes']) is int and 0 <= row['bytes'] < 1 << 64)
        support.hx(row['sha256'], 32)
        names.add(name)
        total += row['bytes']
        need(total < 1 << 64)
    need(total + len(raw) < 1 << 64)
    return value['files'], total


def checked_chunks(path, owner_info):
    """No alias of the selected private leaf may be opened as public material."""
    need(not path.is_symlink())
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and (before.st_dev, before.st_ino) != (owner_info.st_dev, owner_info.st_ino))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(before))
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            yield chunk
        need(identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before))
    finally:
        os.close(fd)


def authenticate_candidates(rows, candidates, owner_info):
    for index, row in enumerate(rows):
        digest, count = hashlib.sha256(), 0
        for chunk in checked_chunks(candidates / (str(index) + '.bin'), owner_info):
            digest.update(chunk)
            count += len(chunk)
        need(count == row['bytes'] and digest.hexdigest() == row['sha256'])


def public_read(path, expected, owner_info):
    path = support.checked(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and (info.st_dev, info.st_ino) != (owner_info.st_dev, owner_info.st_ino))
    return support.read(path, expected)


def selected_public_path(path, owner_info, *, present=True):
    path = support.checked(path)
    need(path.is_relative_to(Path('/public')))
    if present:
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and (info.st_dev, info.st_ino) != (owner_info.st_dev, owner_info.st_ino))


def accepted_history(a, owner_info):
    need(a.assets == Path('/public/ASSETS.json') and a.history == Path('/public/HISTORY.json')
         and a.context == Path('/public/CONTEXT.json'))
    raw_assets = public_read(a.assets, a.assets_sha256, owner_info)
    selected = support.parse(raw_assets)
    # The existing wallet loader owns semantic checks. This precheck only keeps
    # every transitive public read away from the one private root-mounted leaf.
    for key in ('relation', 'crypto', 'recipient', 'wire', 'trees'):
        selected_public_path(selected[key]['path'], owner_info)
    for role in ('spend', 'output', 'exit'):
        selected_public_path(selected[role]['manifest'], owner_info)
        selected_public_path(selected[role]['pk'], owner_info, present=False)
    assets = support.Assets(raw_assets, a.assets_sha256)
    context = support.parse(public_read(a.context, a.context_sha256, owner_info))
    support.fields(context, ('schema', 'domain_hex32', 'genesis_sha256', 'checkpoint'),
                   'derived-history-context-fields')
    need(context['schema'] == 'kpxa-selected-history-context/v1'
         and context['domain_hex32'] == support.DOMAIN.hex())
    accepted = history.load(public_read(a.history, a.history_sha256, owner_info),
                            context['checkpoint'], context['genesis_sha256'], assets)
    return assets, accepted


def original_seed(owner, before):
    need(identity(owner.lstat()) == identity(before))
    # This is the only private content read. No private hash or path is returned.
    value = support.parse(support.read(owner, private=True))
    support.fields(value, ('schema', 'domain_hex32', 'seed_hex32'), 'derived-backup-fields')
    need(value['schema'] == 'kpxa-original-seed-backup/v1'
         and value['domain_hex32'] == support.DOMAIN.hex())
    seed = support.hx(value['seed_hex32'], 32)
    need(identity(owner.lstat()) == identity(before))
    return seed


def derived_needles(seed, assets, accepted):
    """Reuse actual receiver/decryption paths; do not enumerate guessed indices."""
    receiver = assets.receiver(seed)
    owned = history.claims(accepted, receiver, assets)
    payment.reconcile_payouts(accepted, receiver, assets)
    indices = {0, 0xffffffff} | {claim.receipt.index for claim in owned}
    by_nf = {claim.nf: claim for claim in owned}
    for event in accepted.exits:
        if event['nf'] not in by_nf:
            continue
        # Same historical prefix used by payment.reconcile_payouts. The shared
        # helper selects the existing payout key; no derivation is duplicated.
        prefix = history.History(accepted.state, 1, event['point'],
                                 accepted.deliveries[:event['delivery_count']])
        earlier = history.claims(prefix, receiver, assets)
        indices.add(payment.payout_index(prefix, earlier, by_nf[event['nf']]))
    material = set()
    for index in indices:
        keys = receiver.keys(index)
        for secret in (keys.owner_secret, keys.nf_secret, keys.native_secret,
                       keys.delivery_secret, keys.invoice.incoming):
            need(type(secret) is bytes and len(secret) == 32)
            material.add(secret)
        invoice = keys.invoice
        material.add(invoice.encode())
        material.add(invoice.owner + invoice.incoming + invoice.key_commitment
                     + invoice.native_pk + invoice.delivery_pk)
    for claim in owned:
        material.update((claim.receipt.note_bytes(), claim.receipt.encode(), claim.receipt.rho))
    need(material and all(type(raw) is bytes and len(raw) >= 32 for raw in material))
    return tuple({form for raw in material for form in
                  (raw, raw.hex().encode(), raw.hex().upper().encode())})


def scan_candidates(rows, total, raw_manifest, candidates, owner_info, needles):
    matched = int(any(needle in raw_manifest
                      or any(needle in row['path'].encode() for row in rows)
                      for needle in needles))
    overlap_size = max(map(len, needles)) - 1
    for index, row in enumerate(rows):
        found, overlap, count, digest = False, b'', 0, hashlib.sha256()
        for chunk in checked_chunks(candidates / (str(index) + '.bin'), owner_info):
            digest.update(chunk)
            count += len(chunk)
            window = overlap + chunk
            found |= any(needle in window for needle in needles)
            overlap = window[-overlap_size:]
        # Reauthenticate while scanning: a mutable candidate cannot gain a pass.
        need(count == row['bytes'] and digest.hexdigest() == row['sha256'])
        matched += int(found)
    return {'schema': 'kpxa-derived-export-result/v1',
            'status': 'FAIL' if matched else 'PASS', 'candidate_count': len(rows) + 1,
            'candidate_bytes': total + len(raw_manifest), 'matched_candidate_count': matched,
            'scope': SCOPE, 'literal_seed_coverage': False}


def execute(a):
    before = namespace(a.owner, a.candidates, a.output)
    need(a.allowlist == Path('/ALLOWLIST.json'))
    raw_manifest = public_read(a.allowlist, a.allowlist_sha256, before)
    rows, total = manifest(raw_manifest, a.allowlist_sha256)
    authenticate_candidates(rows, a.candidates, before)
    assets, accepted = accepted_history(a, before)  # Public verification precedes backup read.
    seed = original_seed(a.owner, before)
    needles = derived_needles(seed, assets, accepted)
    result = scan_candidates(rows, total, raw_manifest, a.candidates, before, needles)
    need(identity(a.owner.lstat()) == identity(before))
    support.write_new(a.output, support.encoded(result) + b'\n')
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('owner', 'allowlist', 'candidates', 'output', 'assets', 'history', 'context'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('allowlist', 'assets', 'history', 'context'):
        p.add_argument('--' + name + '-sha256', required=True)
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        execute(p.parse_args())
    except Exception:
        p.exit(2, 'derived export check refused; no private material exported.\n')

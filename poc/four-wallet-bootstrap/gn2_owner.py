#!/usr/bin/env python3
"""One owner's original backup and public entry record; no submit/prover API."""
import argparse
import os
from pathlib import Path
import secrets
import stat

from gn2_backup import SCHEMA, SECP_N, decode_backup
from gn2_common import (GENESIS, NOTE_FLOOR, ROOT, amount, checked, digest, encoded,
                        fields, hx, need, outside, parse, public_bytes, reference,
                        regular, uuid_text, write_new)
from gn2 import approval_digest, record, validate_genesis
from gn2_entry import initial_record
from gn2_runtime import SDK_PINS, Runtime
from gn2_selection import entry_selection, load_identity, load_profile

ROLES = ('A', 'B', 'C', 'D')


def init_owner(identity, identity_sha256, trial_id, role, note_value, output, runtime):
    """Called inside an isolated namespace with this owner's output alone."""
    uuid_text(trial_id)
    need(role in ROLES, 'four-wallet-role')
    need((role in ('A', 'C')) == (note_value is not None), 'initial-note-funders-only')
    if note_value is not None:
        amount(note_value, True)
        need(note_value >= NOTE_FLOOR, 'initial-note-floor')
    domain = hx(identity['child_domain_hex32'], 32)
    output = outside(output)
    info = output.stat()
    need(output.is_dir() and stat.S_IMODE(info.st_mode) == 0o700
         and not any(output.iterdir()), 'fresh-empty-own-output-directory')
    # Separate OS draws: no derivation of the ordinary funding key from the
    # shielded seed, and no coordinator-generated dictionary of four seeds.
    seed = secrets.token_bytes(32)
    while True:
        funding = secrets.token_bytes(32)
        if 0 < int.from_bytes(funding, 'big') < SECP_N:
            break
    backup_value = {'schema': SCHEMA, 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'domain_hex32': domain.hex(), 'trial_id': trial_id,
        'seed_hex32': seed.hex(), 'funding_secret_hex32': funding.hex()}
    raw_backup = encoded(backup_value) + b'\n'
    own = decode_backup(raw_backup, domain, trial_id)
    recipient = reference('recipient')
    wallet = recipient.Receiver(own.seed, domain, runtime.crypto)
    invoices = {str(i): wallet.invoice(i).encode().hex() for i in (0, 1)}
    funding_public = runtime.crypto.xonly(own.funding_key)
    address = runtime.address(funding_public)
    initial = None
    if note_value is not None:
        receipt = recipient.Receipt.for_invoice(wallet.invoice(0), note_value, secrets.token_bytes(32))
        cipher = runtime.crypto.seal(wallet.invoice(0).delivery_pk, receipt.encode())
        # Own receipt is re-opened immediately, before making the immutable
        # public record. The signer repeats this from the original backup.
        opened = wallet.open(cipher)
        need(opened.encode() == receipt.encode(), 'own-initial-receipt-roundtrip')
        initial = record(receipt.note_bytes(), cipher, domain).hex()
    public = {'schema': 'kpx6-owner-initial-public/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'financial_profile_id': identity['financial_profile_id'],
        'profile_identity_sha256': identity_sha256, 'domain_hex32': domain.hex(),
        'trial_id': trial_id, 'role': role, 'invoices_hex208': invoices,
        'funding': address, 'initial_record_hex496': initial}
    # Neither the backup bytes nor their digest are returned or logged.
    write_new(output / 'backup.json', raw_backup, 0o600)
    write_new(output / 'owner-init.json', encoded(public) + b'\n', 0o400)
    return public


def _private_backup(path, expected):
    """Read the one original compound file without hashing or logging it."""
    path = checked(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as file:
        before = os.fstat(file.fileno())
        need((before.st_dev, before.st_ino) == (expected.st_dev, expected.st_ino)
             and stat.S_IMODE(before.st_mode) == 0o600, 'original-backup-file-changed')
        raw = file.read()
        after = os.fstat(file.fileno())
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(before, key) for key in attributes)
             == tuple(getattr(after, key) for key in attributes), 'original-backup-mutated')
    return raw


def sign_entry(args):
    """Own record/quote checks precede reading this owner's one backup."""
    uuid_text(args.trial_id)
    owner = outside(args.owner)
    backup, info = regular(owner / 'backup.json')
    need(stat.S_IMODE(info.st_mode) == 0o600, 'original-compound-backup-mode')
    forbidden = ((info.st_dev, info.st_ino),)
    own_record = owner / 'owner-init.json'
    output = outside(args.output)
    need(not output.exists(), 'fresh-own-signature-output')
    # Every caller-supplied public file is metadata-checked against the backup
    # before the FIRST caller-public-file byte is read or hashed.
    for path in (args.profile, args.case, own_record, args.crypto, args.node, args.native,
                 *(args.sdk_dir / name for name in SDK_PINS),
                 ROOT / 'poc/four-wallet-profile/selection.py',
                 ROOT / 'poc/future-recipient/v2/recipient.py',
                 ROOT / 'poc/compact-batch-lifecycle/primitives.py'):
        regular(path, forbidden)
    need(stat.S_IMODE(own_record.stat().st_mode) == 0o400, 'immutable-original-public-record-mode')
    profile = load_profile(args.profile, args.profile_sha256, forbidden)
    case = parse(public_bytes(args.case, forbidden))
    original = parse(public_bytes(own_record, forbidden))
    role = original['role']
    need(role in ('A', 'C'), 'only-initial-contributors-sign-GN2')
    index = 0 if role == 'A' else 1
    selected = entry_selection(profile)
    own_row = initial_record(original, profile, args.trial_id, role)
    derived = validate_genesis(case, selected, args.trial_id)
    actual_row = hx(case['transaction']['payload'])[88 + index * 496:88 + (index + 1) * 496]
    need(actual_row == own_row, 'own-original-initial-record-must-match-entry')
    runtime = Runtime(paths={'crypto': args.crypto, 'node': args.node,
        'native-validator': args.native}, sdk_dir=args.sdk_dir, forbidden=forbidden)
    output.mkdir(parents=True, mode=0o700)
    normalized, metrics = runtime.normalize(case, output / 'independent-quote')
    need(normalized == case, 'own-entry-body-official-ID-and-storage-mass')
    need(type(args.fee_rate) is int and 0 < args.fee_rate < 1 << 64, 'own-entry-reference-fee-rate')
    required = args.fee_rate * metrics['mining_mass']
    derived = validate_genesis(case, selected, args.trial_id, required_fee=required)
    runtime.roundtrip(case)
    # Only now read own private bytes. Ordinary entry has no proving-key
    # dependency and starts no proof-generation worker.
    own = decode_backup(_private_backup(backup, info), profile.domain, args.trial_id)
    recipient = reference('recipient')
    wallet = recipient.Receiver(own.seed, profile.domain, runtime.crypto)
    opened = wallet.open(own_row[200:464])
    need(opened.note_bytes() == own_row[:168] and opened.commitment() == own_row[168:200]
         and opened.index == 0
         and {str(i): wallet.invoice(i).encode().hex() for i in (0, 1)} == original['invoices_hex208'],
         'own-original-backup-rederives-exact-initial-receipt')
    funding_pk = runtime.crypto.xonly(own.funding_key)
    source_spk = '000020' + funding_pk.hex() + 'ac'
    need(source_spk == original['funding']['script_public_key']
         and source_spk == case['entries'][index]['scriptPublicKey'], 'own-funding-key-designated-input')
    signature = runtime.signature(case, index, own.funding_key)
    contribution = derived['contributions'][index]
    export = {'schema': 'kpx6-GN2-owner-approval/v1', 'financial_profile_sha256': profile.profile_sha256,
        'trial_id': args.trial_id, 'input_index': index, 'signature_script_hex66': signature.hex(),
        'unsigned_case_approval_sha256': approval_digest(case, selected, args.trial_id, args.fee_rate),
        'own_initial_public_record_sha256': digest(own_row), 'own_receipt_rederived': True,
        'quote': {'fee_rate_sompi_per_mass': args.fee_rate, 'mining_mass': metrics['mining_mass'],
            'storage_mass': metrics['storage_mass'], 'total_entry_fee_sompi': required,
            'owner_entry_fee_sompi': contribution['entry_fee_sompi']}}
    write_new(output / 'APPROVAL.json', encoded(export) + b'\n', 0o400)
    return export


def main(args):
    os.umask(0o077)
    if args.operation == 'sign-entry':
        return sign_entry(args)
    need(args.operation == 'init', 'selected-owner-operation')
    # No existing private owner backup is read during identity creation.
    identity = load_identity(args.identity, args.identity_sha256)
    runtime = Runtime(paths={'crypto': args.crypto, 'node': args.node},
        sdk_dir=args.sdk_dir, require_native=False)
    return init_owner(identity, args.identity_sha256, args.trial_id, args.role,
        args.note_value, args.output, runtime)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    init = sub.add_parser('init')
    init.add_argument('--identity', type=Path, required=True)
    init.add_argument('--identity-sha256', required=True)
    init.add_argument('--trial-id', required=True)
    init.add_argument('--role', choices=ROLES, required=True)
    init.add_argument('--note-value', type=int)
    init.add_argument('--output', type=Path, required=True)
    init.add_argument('--crypto', type=Path, required=True)
    init.add_argument('--node', type=Path, required=True)
    init.add_argument('--sdk-dir', type=Path, required=True)
    sign = sub.add_parser('sign-entry')
    sign.add_argument('--owner', type=Path, required=True)
    sign.add_argument('--profile', type=Path, required=True)
    sign.add_argument('--profile-sha256', required=True)
    sign.add_argument('--case', type=Path, required=True)
    sign.add_argument('--trial-id', required=True)
    sign.add_argument('--output', type=Path, required=True)
    sign.add_argument('--fee-rate', type=int, default=100)
    sign.add_argument('--crypto', type=Path, required=True)
    sign.add_argument('--node', type=Path, required=True)
    sign.add_argument('--native', type=Path, required=True)
    sign.add_argument('--sdk-dir', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        print(encoded(main(arguments)).decode())
    except (ValueError, OSError, KeyError, TypeError):
        # Never interpolate a backup, scalar, root seed or private request.
        parser.exit(1, 'owner initialization refused\n')

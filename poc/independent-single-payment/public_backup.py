#!/usr/bin/env python3
"""Original backup for ONE already-public, unsafe ADR59 setup actor only.

This setup command derives no spend witness and reads no PK/prover/main backup.
The exact existing backup schema contains no actor label. Never fund this seed.
Run once per actor in separate processes; do not print/hash/publish the backup.
"""
import argparse
import hmac
import json
import os
from pathlib import Path

from public_fixture import actor_wallet, load_profile, read_note
from reuse import ROOT, load


def materialize(profile, actor, public_note_path, output):
    c = load()
    p = c.primitives
    record, _ = read_note(c.receiver.no_symlinks(public_note_path).read_bytes(), profile)
    p.need(record['actor_position'] == actor, 'own-public-setup-record')
    # Check the supplied spelling before resolving it, then test canonical
    # containment: Path.absolute() alone retains '..' and is only lexical.
    output = c.receiver.no_symlinks(output)
    output = c.receiver.no_symlinks(output.resolve(strict=False))
    p.need(not output.is_relative_to(ROOT) and not output.exists()
           and output.parent.is_dir(), 'fresh-original-backup-outside-Git')
    wallet = actor_wallet(profile, actor)
    p.need(wallet.invoice(0).encode().hex() == record['initial_invoice_hex208']
           and wallet.invoice(1).encode().hex() == record['payment_invoice_hex208'],
           'own-original-backup-public-invoice-binding')
    value = {'schema': 'kpx4-compact-batch-seed-backup/v1',
        'network_id': 'testnet-10',
        'genesis_hash_hex': 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
        'domain_hex32': profile.domain.hex(), 'seed_hex32': wallet._seed.hex()}
    encoded = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as writer:
        writer.write(encoded)
        writer.flush()
        os.fsync(writer.fileno())
    restored = c.receiver.backup(output, profile.domain)
    p.need(hmac.compare_digest(restored, wallet._seed), 'original-backup-roundtrip')
    return {'classification': 'PUBLIC_UNSAFE_DO_NOT_FUND_ORIGINAL_SETUP_BACKUP',
        'original_backup_written': True, 'exact_existing_backup_schema': True,
        'actor_label_in_backup': False, 'own_public_invoices_bound': True,
        'backup_bytes_seed_or_hash_exported': False,
        'spend_witness_PK_prover_native_main_or_network_read': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--actor', type=int, choices=(0, 1), required=True)
    parser.add_argument('--public-note', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args()
        profile = load_profile(args.profile, args.profile_sha256)
        print(json.dumps(materialize(profile, args.actor, args.public_note, args.output), sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit('public original-backup setup refused') from None

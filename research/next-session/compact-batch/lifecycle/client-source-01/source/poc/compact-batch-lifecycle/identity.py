#!/usr/bin/env python3
"""One-command fresh unfunded local owner backups; never reads old identities."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import uuid

from primitives import fixed, need
import receiver

ROOT = Path(__file__).resolve().parents[2]
INSTANCE = ROOT / 'research/next-session/compact-batch/PUBLIC-INSTANCE-01.json'
INSTANCE_SHA = 'b3a97af8c9caea15bc793175d934e96c3f4c6f7937b7e8b25bc8c82e10bc327f'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'


def write(path, value):
    with path.open('x') as file:
        json.dump(value, file, sort_keys=True, indent=2)
        file.write('\n')
    path.chmod(0o600)


def new(output, instance=INSTANCE):
    output = receiver.no_symlinks(output)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-identity-outside-Git')
    raw = receiver.no_symlinks(instance).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == INSTANCE_SHA, 'selected-public-instance')
    selected = json.loads(raw)
    need(selected['schema'] == 'kpx4-compact-batch-public-instance/v1'
         and selected['network_id'] == 'testnet-10' and selected['genesis_hash_hex'] == GENESIS,
         'selected-instance-schema')
    domain = bytes.fromhex(selected['domain_hex32'])
    fixed(domain)
    crypto, v2 = receiver.Crypto(), receiver.module()
    output.mkdir(parents=True, mode=0o700)
    backups = output / 'backups'
    backups.mkdir(mode=0o700)
    rows, invoices = [], []
    for ordinal in range(33):
        seed = secrets.token_bytes(32)
        wallet = v2.Receiver(seed, domain, crypto)
        invoice = wallet.invoice(0)
        path = backups / (uuid.uuid4().hex + '.json')
        write(path, {'schema': 'kpx4-compact-batch-seed-backup/v1', 'network_id': 'testnet-10',
                     'genesis_hash_hex': GENESIS, 'domain_hex32': domain.hex(), 'seed_hex32': seed.hex()})
        rows.append({'backup': str(path), 'public_invoice_hex208': invoice.encode().hex()})
        if ordinal:
            invoices.append(invoice.encode().hex())
    # This funding key controls only a separately supplied ordinary source in
    # local contexts. Its creation authorizes no chain query or broadcast.
    while True:
        secret = secrets.token_bytes(32)
        try:
            funding_pk = crypto.xonly(secret)
            break
        except v2.Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
    write(output / 'PRIVATE-PLAN.json', {'schema': 'kpx4-compact-batch-private-owner-plan/v1',
        'classification': 'LOCAL_PRIVATE_REHEARSAL_NO_FUNDING_AUTHORIZATION',
        'publish_or_hash': False, 'trial_id': selected['trial_id'], 'domain_hex32': domain.hex(),
        'payer': rows[0], 'receivers': rows[1:], 'funding_secret_hex32': secret.hex(),
        'funding_spk_hex': '000020' + funding_pk.hex() + 'ac'})
    write(output / 'PUBLIC-INVOICES.json', {'schema': 'kpx4-compact-batch-public-invoices/v1',
        'domain_hex32': domain.hex(), 'recipient_public_invoices_hex208': invoices})
    return {'software_original_backups_created': 33, 'recipient_public_invoice_count': 32,
            'all_seeds_fresh_OS_entropy': True, 'old_identity_or_proof_PK_read': False,
            'funding_broadcast_or_network': False, 'private_paths_seeds_or_hashes_emitted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    create = sub.add_parser('new')
    create.add_argument('--output', type=Path, required=True)
    create.add_argument('--instance', type=Path, default=INSTANCE)
    args = parser.parse_args()
    print(json.dumps(new(args.output, args.instance), sort_keys=True))

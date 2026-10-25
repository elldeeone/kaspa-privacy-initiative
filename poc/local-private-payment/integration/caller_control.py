#!/usr/bin/env python3
"""Known-public-seed control of the concrete isolated caller IPC, no network."""
import argparse
import hashlib
from pathlib import Path
import runpy
import sys

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
import campaign
from support import DOMAIN, digest, encoded, parse, write_new


def run(a):
    h = runpy.run_path(campaign.HELPER)
    caller = campaign.Campaign.__new__(campaign.Campaign)
    caller.h, caller.public_read, caller.m = h, h['read'], h['m']
    caller.private = campaign.PRIVATE / 'public-owner-api-control-01'
    caller.output = Path(a.output)
    caller.private.mkdir(mode=0o700)
    caller.output.mkdir(parents=True, mode=0o700)
    caller.counter = 0
    caller.assets = parse(h['read'](str(a.assets), a.assets_sha256))
    caller.fees = parse(h['read'](str(a.native_fee_policy), a.native_fee_policy_sha256))
    caller.selection = {'wallet_assets': {'path': str(a.assets), 'sha256': a.assets_sha256},
        'native_fee_policy': {'path': str(a.native_fee_policy), 'sha256': a.native_fee_policy_sha256},
        'wallet_source_sha256': {name: digest(h['read'](str(campaign.BASE / name))) for name in campaign.SOURCES}}
    original = parse(h['read'](str(a.public_history), a.public_history_sha256))
    genesis = original['genesis']
    checkpoint = {key: genesis[key] for key in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}
    fixture = {'schema': original['schema'], 'domain_hex32': DOMAIN.hex(),
        'genesis': genesis, 'transitions': [], 'head': checkpoint}
    context = {'schema': 'kpxa-selected-history-context/v1', 'domain_hex32': DOMAIN.hex(),
        'genesis_sha256': digest(encoded(genesis)), 'checkpoint': checkpoint}
    head = {}
    for name, value in [('HISTORY.json', fixture), ('CONTEXT.json', context)]:
        path = caller.output / name
        write_new(path, encoded(value) + b'\n')
        head[name] = {'path': str(path), 'sha256': digest(encoded(value) + b'\n')}
    # These constants are explicitly public. Only each isolated owner worker
    # opens its file; the caller never reads/hashes these backup bytes afterward.
    backups = []
    for i in range(2):
        path = caller.private / ('public-dummy-original-' + str(i))
        seed = hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED ' + bytes([i])).digest()
        write_new(path, encoded({'schema': 'kpxa-original-seed-backup/v1',
            'domain_hex32': DOMAIN.hex(), 'seed_hex32': seed.hex()}) + b'\n', 0o600)
        backups.append(path)
    invoice = caller.owner(backups[1], 'invoice', head)
    component = caller.output / 'action-0001'
    caller.owner(backups[0], 'campaign-pay', head, output=component, invoice=invoice,
        request={'schema': 'kpxa-private-campaign-payment-request/v1', 'payment_sompi': 500_000_000,
                 'fee_cap_sompi': 50_000_000, 'selection_kind': 'any'})
    # Verify the exported public projection, never any private stage/file.
    from support import Assets
    assets = Assets(h['read'](str(a.assets), a.assets_sha256), a.assets_sha256)
    raw = h['read'](str(component / 'PROJECTION.bin'))
    body = assets.wire.parse_projection(raw).body
    assets.wire.require_current_head(raw, bytes.fromhex(checkpoint['state_hex112']),
        bytes.fromhex(checkpoint['outpoint_hex36']), checkpoint['reserve_sompi'], assets.tail)
    assets.relation.verify('spend', assets.wire.spend_statement(raw), body.spends[0].proof)
    for output in body.outputs:
        assets.relation.output(output.tuple_bytes)
    assets.relation.balance([body.spends[0].cv], [output.cv for output in body.outputs], body.fee, body.delta)
    result = {'schema': 'kpxa-isolated-caller-public-control/v1',
        'classification': 'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY', 'actual_private_seed_claim': False,
        'original_seed_restore_scan_then_payment': True, 'authenticated_private_invoice_leaf_IPC': True,
        'caller_backup_or_invoice_or_witness_contents_or_hashes_read': False,
        'genuine_Spend_and_two_Output_verified': True, 'exact_current_head_checked': True,
        'fee_sompi': body.fee, 'network_or_broadcast': False, 'outer_native_Full_or_testnet_claim': False}
    write_new(caller.output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'native-fee-policy', 'public-history', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('assets-sha256', 'native-fee-policy-sha256', 'public-history-sha256'):
        p.add_argument('--' + name, required=True)
    print(encoded(run(p.parse_args())).decode())

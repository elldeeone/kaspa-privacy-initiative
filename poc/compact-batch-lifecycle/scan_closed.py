#!/usr/bin/env python3
"""Recover one original recipient after a fully drained synthetic prefix.

This read-only scan has no prover or proving parameter input. Public history
receives real Native Full replay before the one original backup is opened.
The result confirms the spent receipt and payout-key derivation, not an
accepted-chain payout, a payout spend, or currentness.
"""
import argparse
import hmac
import json
from pathlib import Path

import actions
import history
import owner
import receiver
from native_runtime import DOMAIN, EMITTER, NATIVE, NODE, SDK, SDK_FILES, Runtime, save
from primitives import need, parse, u32


def payout_destination(seed, wallet, claim, founding):
    """Exact original cashout derivation, including nonzero scalar retry."""
    prefix = (b'KPX3PAY\0' + wallet.domain + actions.point_bytes(founding)
              + claim.receipt.commitment() + u32(claim.position))
    for retry in range(1 << 32):
        secret = hmac.digest(seed, prefix + u32(retry), 'sha256')
        try:
            native_pk = wallet.crypto.xonly(secret)
        except receiver.module().Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
            continue
        if native_pk != claim.receipt.native_pk:
            return b'\0\0\x20' + native_pk + b'\xac'
    raise ValueError('payout-scalar-exhausted')


def run(args):
    absent = args.must_be_absent
    need(all(not path.exists() and not path.is_symlink() for path in absent),
         'original-controller-source-or-cache-visible')
    paths = [args.selection, args.descriptor, args.history, EMITTER, NATIVE, NODE,
             SDK, *SDK_FILES, receiver.SOURCE, receiver.CRYPTO]
    backup, output = owner.metadata_guard(args.backup, paths, args.output)
    selected = owner.selection(Path(args.selection).read_bytes(), 'compact2')
    descriptor, _, _ = history.descriptor(Path(args.descriptor).read_bytes(),
                                         selected['descriptor_sha256'])
    raw = Path(args.history).read_bytes()
    public = parse(raw)
    output.mkdir(parents=True, mode=0o700)
    replayed = history.replay(raw, descriptor, selected['descriptor_sha256'],
                              Runtime(), output / 'public-replay')
    snapshot = replayed['snapshot']
    need(replayed['reserve_sompi'] == 0 and replayed['current_outpoint'] is None,
         'completed-terminal-prefix-required')
    crypto, v2 = receiver.Crypto(), receiver.module()
    seed = receiver.backup(backup, DOMAIN)
    wallet = v2.Receiver(seed, DOMAIN, crypto)
    recovered = receiver.recover(wallet, snapshot, snapshot.state(DOMAIN))
    need(len(recovered.owned) == 1 and recovered.owned[0].spent
         and not recovered.owned[0].owner_action_available,
         'one-original-receipt-now-spent')
    claim = recovered.owned[0]
    destination = payout_destination(seed, wallet, claim, descriptor['founding_outpoint'])
    matches = []
    for record in public['records'][1:]:
        body = record['transaction']
        auth = history.hexbytes(body['payload'])[:528]
        if claim.nf not in (auth[204:236], auth[236:268]):
            continue
        payout = int.from_bytes(auth[484:492], 'little')
        fee = int.from_bytes(auth[196:204], 'little')
        remaining = int.from_bytes(auth[476:484], 'little')
        position = 1 if remaining else 0
        need(payout > 0 and auth[492:528] == destination
             and body['outputs'][position]['scriptPublicKey'] == destination.hex()
             and body['outputs'][position]['value'] == payout
             and payout + fee == claim.receipt.value_sompi,
             'own-spent-note-exact-authorized-payout-key')
        matches.append((body['id'], payout, fee))
    need(len(matches) == 1, 'exactly-one-own-native-payout')
    transaction_id, payout, fee = matches[0]
    summary = {'schema': 'kpx4-compact-batch-closed-original-backup-scan/v1',
        'classification': 'SUPPLIED_SYNTHETIC_CONTEXTS_NOT_ACCEPTED_OR_CURRENT',
        'provided_history_record_count': len(public['records']),
        'all_provided_bodies_Native_Full_all_engines': True,
        'original_backup_own_receipt_count': 1, 'own_spent_receipt_count': 1,
        'own_available_claim_count': 0,
        'payout_secret_rederived_and_public_key_matches_exact_native_output': True,
        'selected_payout_transaction_id': transaction_id,
        'native_payout_sompi': payout, 'fee_sompi': fee,
        'reserve_after_sompi': 0, 'prover_or_proving_parameters_used': False,
        'original_path_absence_probe_count': len(absent),
        'all_requested_original_paths_absent': True if absent else None,
        'other_owner_backups_or_controller_maps_opened': False,
        'private_secret_note_nf_position_or_input_hash_exported': False,
        'accepted_chain_currentness_payout_spend_or_live_readiness_claimed': False}
    save(output / 'RESULTS.json', summary)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'descriptor', 'history', 'backup', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    try:
        print(json.dumps(run(parser.parse_args()), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit('closed original-backup scan refused') from None

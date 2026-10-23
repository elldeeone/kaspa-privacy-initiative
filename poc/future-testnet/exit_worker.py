#!/usr/bin/env python3
"""Owner exits with only recipient backups, public records and native tools.

The controller mounts this worker without the payer profile, prover or PK.
Chain acceptance is a separate adapter step; this worker never opens a socket.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from core import (CLASS, GENESIS, Core, Crypto, Receiver, Snapshot, dump_snapshot, exact, load,
                  native_call, outpoint, parse_snapshot, quote, recover, save,
                  verify_link)


def run(inputs, output):
    public = load(inputs / 'identity.json')
    head = load(inputs / 'head.json')
    selected = head['recipient']
    if selected not in ('bob', 'charlie') or {p.name for p in (inputs / 'backups').iterdir()} != {selected + '.json'}:
        raise ValueError('exactly one recipient backup must be mounted')
    if (public['classification'] != CLASS or public['network_id'] != 'testnet-10'
            or public['genesis_hash_hex'] != GENESIS
            or head['trial_id'] != public['trial_id']
            or head['domain_hex32'] != public['domain_hex32']):
        raise ValueError('recipient trial/domain/network mismatch')
    forbidden = head['excluded_paths']
    if any(Path(p).exists() for p in forbidden):
        raise ValueError('payer/prover/PK unexpectedly mounted')
    save(output / 'services-absent-before-authorization.json', {
        'payer_profile_present': False, 'prover_present': False, 'proving_key_present': False,
        'preferred_service_present': False, 'checked_absent_paths': forbidden,
        'available_inputs': [selected + ' seed-only backup', 'public trial identity',
            'complete public records/current head', 'native validator', 'crypto bridge'],
        'withdrawal_authorization_created_before_marker': False})
    core = Core(public['domain_hex32'], public['trial_id'])
    if hashlib.sha256((inputs / 'crypto').read_bytes()).hexdigest() != public['runtime_pins']['bridge_sha256']:
        raise ValueError('mounted crypto bridge identity mismatch')
    crypto = Crypto(inputs / 'crypto')
    current = parse_snapshot(head['snapshot'])
    payment = head['payment_value_sompi']
    reserve = head['reserve_sompi']
    if type(payment) is not int or reserve != payment * (2 if selected == 'bob' else 1):
        raise ValueError('recipient exact current liability')
    previous = inputs / 'previous'
    if core.state(current).hex() != head['state_hex112']:
        raise ValueError('current public state mismatch')
    results, links, snapshots = {}, [], {}
    for label, position in [(selected, 2 if selected == 'bob' else 3)]:
        backup = load(inputs / 'backups' / (label + '.json'))
        if (backup['schema'] != 'kpx2-tn10-seed-backup/v1'
                or backup['network_id'] != 'testnet-10'
                or backup['genesis_hash_hex'] != GENESIS
                or backup['domain_hex32'] != public['domain_hex32']):
            raise ValueError('seed-only backup profile mismatch')
        restored = Receiver(exact(backup['seed_hex32'], 32), core.domain, crypto)
        invoice = restored.invoice(0)
        if invoice.encode().hex() != public['identities'][label]['invoice_hex208']:
            raise ValueError('backup does not reproduce public recipient identity')
        # V2's local mathematical record pin is deliberately separate from the
        # adapter's trusted-node accepted-body/current-head claim.
        expected = current.pin(core.domain)
        recovered = recover(restored, expected, current)
        claims = [c for c in recovered.owned if c.position == position and not c.spent]
        if len(claims) != 1 or recovered.all_owned_unspent_sompi != payment:
            raise ValueError('recipient credit/current NF mismatch')
        claim = claims[0]

        def make_reveal(fee):
            payload, _ = core.reveal_payload(restored, claim, expected, current, fee)
            return {'state_hex': core.state(current).hex(),
                'previous_txid_raw_hex': outpoint(previous)[:32].hex(), 'previous_index': 0,
                'reserve_sompi': reserve, 'payload_hex': payload.hex(),
                'native_secret_hex': restored.keys(claim.receipt.index).native_secret.hex(),
                'vk_hex': head['vk_hex328']}

        fee, vector, _ = quote(inputs / 'native', 'reveal', make_reveal, output / (label + '-quotes'))
        directory = output / (label + '-reveal')
        native_call(inputs / 'native', 'reveal-run', vector, directory)
        links.append(verify_link(previous, directory))
        current, _ = core.insert(current, claim.nf)
        reserve -= payment
        body = load(directory / 'transaction.json')
        index = 1 if reserve else 0
        payout = body['outputs'][index]
        if (payout['value'] != payment - fee
                or payout['scriptPublicKey'] != '000020' + claim.receipt.native_pk.hex() + 'ac'):
            raise ValueError('native owner payout amount/SPK mismatch')
        if reserve:
            if (body['outputs'][0]['value'] != reserve
                    or exact((directory / 'successor-state.hex').read_text().strip(), 112) != core.state(current)):
                raise ValueError('native successor reserve/root mismatch')
        elif len(body['outputs']) != 1:
            raise ValueError('terminal reserve output remains')
        results[label] = {'position': position, 'payment_value_sompi': payment,
            'fee_sompi': fee, 'payout_sompi': payment - fee, 'payout_index': index,
            'payout_outpoint_hex36': outpoint(directory, index).hex(),
            'seed_only_restore': True, 'current_nullifier_hex32': claim.nf.hex()}
        snapshots['after-bob' if label == 'bob' else 'terminal'] = dump_snapshot(current)
        previous = directory
    if reserve != (payment if selected == 'bob' else 0) or len(current.nullifiers) != (4 if selected == 'bob' else 5):
        raise ValueError('successor reserve/NF accounting')
    for label in (selected,):
        backup = load(inputs / 'backups' / (label + '.json'))
        receiver = Receiver(exact(backup['seed_hex32'], 32), core.domain, crypto)
        if recover(receiver, current.pin(core.domain), current).all_owned_unspent_sompi != 0:
            raise ValueError('selected recipient liability survived exit')
    result = {'schema': 'kpx2-tn10-native-exits/v1', 'trial_id': public['trial_id'],
        'domain_hex32': public['domain_hex32'], 'oracle_stage': head['oracle_stage'],
        'recipients': results, 'links': links, 'snapshots': snapshots,
        'final_state_hex112': core.state(current).hex(), 'reserve_sompi': reserve,
        'liability_sompi': reserve, 'native_Full_operations': 1,
        'prover_or_pk_available_during_exit': False, 'testnet_payout_confirmed': False}
    save(output / 'RESULTS.json', result)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    result = run(a.inputs, a.output)
    print(json.dumps({'trial_id': result['trial_id'], 'native_Full_operations': 1,
        'reserve_sompi': result['reserve_sompi'], 'liability_sompi': result['liability_sompi']}))

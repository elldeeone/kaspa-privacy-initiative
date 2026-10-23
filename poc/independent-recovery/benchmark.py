#!/usr/bin/env python3
"""UNPROVED synthetic public replay scaling; never a wallet/network input."""
from bisect import bisect_left
import hashlib
import hmac
import gc
import json
from pathlib import Path
import random
import sys
import time

from policy_template import approved_policy
from replay import (GENESIS, NOTE_FLOOR, ZERO, State, digest, h, nf_leaf, outpoint,
                    p2pk, p2sh, replay, u32)

DOMAIN = bytes.fromhex("9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c")
FEE = 1_000


def u64(value):
    return value.to_bytes(8, 'little')


def note(index, value, native_pk):
    # All derivation material is deliberately public synthetic data; no actual
    # invoice, recipient encryption, witness proof or native signature exists.
    encoded = u32(index)
    s, k = h(b'UNPROVED-OWNER', encoded), h(b'UNPROVED-NF-KEY', encoded)
    incoming = h(b'UNPROVED-INCOMING', encoded)
    raw = (h(b'KPX1OWN\0', DOMAIN, s, incoming) + incoming + u64(value)
           + h(b'UNPROVED-RHO', encoded) + h(b'KPX1KEY\0', DOMAIN, k) + native_pk)
    return raw, k


def nf_insert(state, value, ordered):
    number = int.from_bytes(value, 'little')
    at = bisect_left(ordered, number)
    assert at > 0 and (at == len(ordered) or ordered[at] != number)
    pred_index = state.nf_positions[ordered[at - 1].to_bytes(32, 'little')]
    pred = state.entries[pred_index]
    index = len(state.entries)
    witness = (u32(pred_index) + pred['value'] + pred['next_value'] + u32(pred['next_index'])
               + state.nf.path(pred_index))
    replacement = {'value': pred['value'], 'next_value': value, 'next_index': index}
    state.nf.set(pred_index, nf_leaf(replacement))
    witness += state.nf.path(index)
    added = {'value': value, 'next_value': pred['next_value'], 'next_index': pred['next_index']}
    state.entries[pred_index] = replacement
    state.entries.append(added)
    state.nf_positions[value] = index
    state.nf.set(index, nf_leaf(added))
    ordered.insert(at, number)
    return witness


def body(previous, outputs, payload, signature, identifier, budget):
    return {'version': 1, 'id': identifier,
        'inputs': [{'previousOutpoint': previous, 'signatureScript': signature.hex(),
                    'sequence': str((1 << 64) - 1), 'computeBudget': budget}],
        'outputs': [{'value': str(value), 'scriptPublicKey': script, 'covenant': None}
                    for value, script in outputs],
        'lockTime': '0', 'subnetworkId': '00' * 20, 'gas': '0',
        'payload': payload.hex(), 'storageMass': '0'}


def entry(point, amount, script):
    return {'outpoint': point, 'amount_sompi': str(amount), 'script_public_key': script,
            'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None}


def generate(operations, public_vk):
    if not 2 <= operations <= 10_000:
        raise ValueError('declared operation range')
    rng = random.Random(202610230049)
    actions = operations - 1
    reserve = NOTE_FLOOR * (actions + 1) + FEE * actions
    # Valid public P2PK from an existing DO_NOT_FUND known-answer fixture; no SK.
    pk = bytes.fromhex('fa9a6cd7bcc78750092f97ffa7cd1847062f2ccda30a7d283b6ec717819202ad')
    genesis, spine_key = note(0, reserve, pk)
    cipher = rng.randbytes(264)
    state = State(DOMAIN, genesis, cipher)
    policy = approved_policy(DOMAIN, public_vk)
    redeem = b'\x4c\x70' + state.encoded() + policy
    source = {'transactionId': h(b'UNPROVED-SOURCE').hex(), 'index': 0}
    genesis_id = h(b'UNPROVED-GENESIS-ID').hex()
    payload = b'KPX2GN01' + DOMAIN + genesis + h(b'KPX1NOT\0', DOMAIN, genesis) + cipher + h(cipher)
    tx = body(source, [(reserve, p2sh(redeem))], payload, b'\x41' + bytes([1]) * 64 + b'\x01', genesis_id, 10)
    source_entry = entry(source, reserve + FEE, p2pk(pk))
    rows = [{'transaction': tx, 'input_contexts': [source_entry]}]
    queries = {tuple(source.values()): {'outpoint': source, 'amount_sompi': str(reserve + FEE),
        'script_public_key': p2pk(pk), 'queried': True, 'entry': None}}
    descriptor = {'schema': 'kpx2-recovery-descriptor/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'domain_hex32': DOMAIN.hex(),
        'founding_outpoint': outpoint(tx), 'birth_start_hash': h(b'UNPROVED-BIRTH-ANCHOR').hex(),
        'initial_redeem_hex': redeem.hex(), 'vk_hex328': public_vk.hex(),
        'immutable_policy_sha256': h(policy).hex()}
    ordered = [0]
    spine, spine_position, spine_value = genesis, 0, reserve
    for action in range(actions):
        old_state = state.encoded()
        previous = outpoint(tx)
        old_redeem = b'\x4c\x70' + old_state + policy
        old_spk = p2sh(old_redeem)
        context = entry(previous, reserve, old_spk)
        queries[tuple(previous.values())] = {'outpoint': previous, 'amount_sompi': str(reserve),
            'script_public_key': old_spk, 'queried': True, 'entry': None}
        old_cm = h(b'KPX1NOT\0', DOMAIN, spine)
        real_nf = hmac.digest(spine_key, b'KPX1NF\0\0' + DOMAIN + old_cm + u32(spine_position), 'sha256')
        dummy_nf = hmac.digest(h(b'UNPROVED-DUMMY-KEY', u32(action)),
            b'KPX2DMY\0' + DOMAIN + h(b'UNPROVED-DUMMY-SEED', u32(action)) + b'\x01', 'sha256')
        witness = nf_insert(state, real_nf, ordered) + nf_insert(state, dummy_nf, ordered)
        next_spine_value = spine_value - NOTE_FLOOR - FEE
        new_spine, new_key = note(action * 2 + 1, next_spine_value, pk)
        leaf, _ = note(action * 2 + 2, NOTE_FLOOR, pk)
        cm0, cm1 = h(b'KPX1NOT\0', DOMAIN, new_spine), h(b'KPX1NOT\0', DOMAIN, leaf)
        ciphers = rng.randbytes(528)
        next_position = len(state.deliveries)
        for cm, ciphertext in ((cm0, ciphers[:264]), (cm1, ciphers[264:])):
            path = state.cm.path(len(state.deliveries))
            witness += path
            state.append(cm, ciphertext, path)
        next_reserve = reserve - FEE
        auth = (b'KPX2AU01' + DOMAIN + bytes.fromhex(previous['transactionId']) + u32(0)
            + old_state + u64(reserve) + u64(FEE) + real_nf + dummy_nf + cm0 + cm1
            + h(ciphers) + state.encoded() + u64(next_reserve))
        assert len(auth) == 484 and len(witness) == 3344
        payload = auth + ciphers + witness
        # Nonzero fixed-width bytes only: NOT a Groth16 proof. ID is NOT a
        # Kaspa transaction hash. No accepted-header/confirmation fields exist.
        signature = b'\x41' + bytes(65) + b'\x4c\x80' + bytes([1]) * 128 + b'\x4d' + len(old_redeem).to_bytes(2, 'little') + old_redeem
        identifier = h(b'UNPROVED-PRIVATE-ID', u32(action), h(auth)).hex()
        next_redeem = b'\x4c\x70' + state.encoded() + policy
        tx = body(previous, [(next_reserve, p2sh(next_redeem))], payload, signature, identifier, 1600)
        rows.append({'transaction': tx, 'input_contexts': [context]})
        spine, spine_key, spine_position = new_spine, new_key, next_position
        spine_value, reserve = next_spine_value, next_reserve
    head = outpoint(tx)
    head_entry = entry(head, reserve, tx['outputs'][0]['scriptPublicKey'])
    queries[tuple(head.values())] = {'outpoint': head, 'amount_sompi': str(reserve),
        'script_public_key': head_entry['script_public_key'], 'queried': True, 'entry': head_entry}
    bundle = {'schema': 'kpx2-unproved-synthetic/v1', 'context': 'UNPROVED_SYNTHETIC',
        'network_id': 'testnet-10', 'genesis_hash_hex': GENESIS, 'descriptor_sha256': digest(descriptor),
        'transactions': rows, 'declared_view': {'queries': list(queries.values())}}
    expected = {'operations': operations, 'cm_records': len(state.deliveries), 'nf_records': len(state.entries),
        'state_hex112': state.encoded().hex(), 'reserve_sompi': reserve, 'unspent_positive_notes': actions + 1,
        'synthetic_spine_value_sompi': spine_value}
    assert reserve == NOTE_FLOOR * (actions + 1) and spine_value == NOTE_FLOOR
    return descriptor, bundle, expected


def main():
    operations, vk_path, fixture_path, report_path = int(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
    if fixture_path.exists() or report_path.exists():
        raise ValueError('fresh benchmark outputs required')
    started = time.monotonic()
    descriptor, bundle, expected = generate(operations, vk_path.read_bytes())
    generation_seconds = time.monotonic() - started
    writing = time.monotonic()
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    with fixture_path.open('x', encoding='utf8') as file:
        json.dump({'descriptor': descriptor, 'fetched': bundle}, file,
                  sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        file.write('\n')
    fixture_sha256 = hashlib.sha256()
    with fixture_path.open('rb') as file:
        for block in iter(lambda: file.read(1 << 20), b''):
            fixture_sha256.update(block)
    encoding_hash_seconds = time.monotonic() - writing
    # Release the generated object before loading the on-disk fixture, as a
    # fresh client would. This is not a network download or a wallet scanner.
    del descriptor, bundle
    gc.collect()
    decoding = time.monotonic()
    with fixture_path.open(encoding='utf8') as file:
        parsed = json.load(file)
    json_decode_seconds = time.monotonic() - decoding
    descriptor, bundle = parsed['descriptor'], parsed['fetched']
    began = time.monotonic()
    result = replay(descriptor, bundle, context='UNPROVED_SYNTHETIC')
    replay_seconds = time.monotonic() - began
    assert result['head']['state_hex112'] == expected['state_hex112']
    assert len(result['operations']) == expected['operations']
    assert len(result['deliveries']) == expected['cm_records'] and len(result['nullifiers']) == expected['nf_records']
    assert result['head']['reserve_sompi'] == expected['reserve_sompi']
    assert result['completeness']['complete'] is False and result['groth16_and_signatures'] == 'UNCHECKED_SYNTHETIC'
    report = {'classification': 'UNPROVED_SYNTHETIC_PUBLIC_REPLAY_SCALING_ONLY', 'passed': True,
        'expected': expected, 'fixture_json_bytes': fixture_path.stat().st_size,
        'fixture_sha256': fixture_sha256.hexdigest(), 'generation_seconds': generation_seconds,
        'encoding_and_hash_seconds': encoding_hash_seconds, 'json_decode_seconds': json_decode_seconds,
        'json_decode_measured': True, 'parsed_bundle_already_in_memory_at_replay_start': True,
        'public_replay_seconds': replay_seconds,
        'declared_json_transfer_seconds_at_20_mbit_per_second': fixture_path.stat().st_size * 8 / 20_000_000,
        'actual_network_transfer_measured': False, 'native_execution_or_proof_verification': False,
        'complete_wallet_recovery_qualified': False, 'ciphertexts_are_real_recipient_encryption': False,
        'synthetic_transaction_ids_are_kaspa_hashes': False, 'crypto_or_chain_acceptance_claimed': False,
        'context': result['context'], 'complete': result['completeness']['complete'],
        'public_replay_complete': result['completeness']['public_replay_complete'],
        'note': 'Exact public transition/hash/witness work only. Generation/encoding/download arithmetic is separate from actual RPC/history availability, recipient scanning, signatures, Groth16, SDK IDs and payout observation.'}
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('classification', 'passed', 'fixture_json_bytes', 'public_replay_seconds')}))


if __name__ == '__main__':
    main()

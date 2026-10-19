#!/usr/bin/env python3
"""Check public evidence consistency; this does not implement Kaspa consensus."""
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path


def summarize(root):
    read = lambda p: json.loads((root / p).read_text())
    result = read('result.json')
    original = read('public/bob.bundle.json')
    bob = read('public/0003.json')
    alice = read('public/0002.json')
    before = read('public/0001.json')
    a = bytes.fromhex(original['authorization'])
    proof = bytes.fromhex(original['proof'])
    witness = bytes.fromhex(bob['inputs'][0]['signatureScript'])
    assert len(a) == 262 and len(proof) == 128
    assert proof == witness[2:130]
    assert a == bytes.fromhex(bob['payload'])[8:270]
    assert witness[133 + 37:133 + 37 + 1539] == bytes.fromhex(alice['payload'])[640:]
    assert bob['inputs'][0]['previousOutpoint'] == {'transactionId': alice['id'], 'index': 0}
    previous_state = bytes.fromhex(before['payload'])[640:]
    current_state = bytes.fromhex(alice['payload'])[640:]
    count = a[40]
    expected_anchor = bytes([count]) + current_state[3:3 + 32 * count] + bytes(32 * (24 - count))
    assert hashlib.sha256(expected_anchor).digest() == a[41:73]
    assert count == previous_state[1] < current_state[1]
    report = read('bob-prover-stopped.json')
    assert report['report']['proof_sha256'] == hashlib.sha256(proof).hexdigest()
    stopped = datetime.fromisoformat(report['stoppedAt'].replace('Z', '+00:00'))
    alice_submit = datetime.fromisoformat(read('live/0002.submission.json')['submittedAt'].replace('Z', '+00:00'))
    assert stopped < alice_submit
    confirmation = read('rebuilder/0003.confirmed.json')
    assert confirmation['outputs'][1]['amount'] == bob['outputs'][1]['value']
    assert confirmation['outputs'][1]['txid'] == bob['id']
    assert read('rebuilder/isolation.json')['publicOnly'] is True
    assert result['bob']['additionalProofs'] == 0
    assert result['terminalReserveSpent'] and result['allClaimsDrained']
    assert read('chain-confirmed.json')['exactBodyAndFullHashMatches'] == 6
    fees = sum(int(read(f'public/{i:04}.metrics.json')['metrics']['fee_sompi']) for i in range(6))
    assert fees == int(result['totalFeeSompi'])
    source = read('public/source-utxo.json')
    assert sum(int(u['amount']) for u in result['finalOrdinaryOutputs']) + fees == int(source['amount'])
    return {
        'role': result['role'], 'confirmed_transactions': 6,
        'proof_bytes_equal': True, 'authorization_bytes_equal': True,
        'proof_sha256': hashlib.sha256(proof).hexdigest(),
        'authorization_anchor_count': count, 'current_commitment_count': current_state[1],
        'current_nullifier_count_before_bob_exit': current_state[2],
        'bob_prover_stopped_before_alice_submission': True,
        'additional_proofs': 0, 'public_rebuild_process_ms': result['bob']['rebuildingMs'],
        'inner_public_rebuild_us': result['bob']['report']['extra']['public_rebuild_us'],
        'initial_bob_proving_ms': report['report']['proving_ms'],
        'bob_payout_sompi': bob['outputs'][1]['value'],
        'bob_exit_fee_sompi': result['bob']['feeSompi'],
        'total_fee_sompi': str(fees), 'terminal_reserve_spent': True,
        'bob_transaction_id': bob['id'], 'alice_transaction_id': alice['id'],
        'binary_sha256': result['binarySha256'],
        'scope': 'Consistency of exported public evidence; not independent consensus or privacy verification',
    }


if __name__ == '__main__':
    print(json.dumps(summarize(Path(sys.argv[1])), indent=2))

#!/usr/bin/env python3
"""Check public evidence consistency; this does not implement Kaspa consensus."""
import hashlib
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path


def summarize(root):
    read = lambda p: json.loads((root / p).read_text())
    result = read('result.json')
    original = read('public/bob.bundle.json')
    payments=result['paymentsAfterBobAuthorization']
    count_tx=result['confirmedTransactions']
    step=payments+2
    bob = read(f'public/{step:04}.json')
    alice = read(f'public/{step-1:04}.json')
    before = read('public/0001.json')
    a = bytes.fromhex(original['authorization'])
    proof = bytes.fromhex(original['proof'])
    witness = bytes.fromhex(bob['inputs'][0]['signatureScript'])
    assert len(a) == 265 and len(proof) == 128
    assert proof == witness[2:130]
    assert a == bytes.fromhex(bob['payload'])[8:273]
    assert witness[133 + 36:133 + 36 + 105] == bytes.fromhex(alice['payload'])[643:748]
    assert bob['inputs'][0]['previousOutpoint'] == {'transactionId': alice['id'], 'index': 0}
    previous_state=bytes.fromhex(before['payload'])[643:748]
    current_state=bytes.fromhex(alice['payload'])[643:748]
    count=int.from_bytes(a[40:44],'little')
    assert count==int.from_bytes(previous_state[1:5],'little')==3
    assert int.from_bytes(current_state[1:5],'little')==3+2*payments
    assert int.from_bytes(current_state[5:9],'little')==1+payments
    # Independently verify that the old count/root is in the current archive.
    payload=bytes.fromhex(bob['payload']);index=(count-1)//2
    h=hashlib.sha256(bytes([3])+a[40:76]).digest()
    for level in range(16):
        sibling=payload[748+32*level:748+32*(level+1)]
        h=hashlib.sha256(bytes([1])+(sibling+h if index & (1<<level) else h+sibling)).digest()
    assert h==current_state[73:105]
    report = read('bob-prover-stopped.json')
    assert report['report']['proof_sha256'] == hashlib.sha256(proof).hexdigest()
    stopped = datetime.fromisoformat(report['stoppedAt'].replace('Z', '+00:00'))
    alice_submit = datetime.fromisoformat(read('live/0002.submission.json')['submittedAt'].replace('Z', '+00:00'))
    assert stopped < alice_submit
    confirmation = read(f'rebuilder/{step:04}.confirmed.json')
    assert confirmation['outputs'][1]['amount'] == bob['outputs'][1]['value']
    assert confirmation['outputs'][1]['txid'] == bob['id']
    isolation = read('rebuilder/isolation.json')
    assert isolation['publicOnly'] is True
    assert not any(isolation[k] for k in ['hostHomeAccessible', 'provingKeyAccessible', 'walletAccessible'])
    assert result['bob']['additionalProofs'] == 0
    assert result['terminalReserveSpent'] and result['allClaimsDrained']
    assert read('chain-confirmed.json')['exactBodyAndFullHashMatches'] == count_tx
    all_stopped = read('all-payment-provers-stopped.json')
    assert all_stopped['aliceStopped'] and all_stopped['bobStopped']
    bob_submit = datetime.fromisoformat(read(f'rebuilder/{step:04}.submission.json')['submittedAt'].replace('Z', '+00:00'))
    assert datetime.fromisoformat(all_stopped['stoppedAt'].replace('Z', '+00:00')) < bob_submit
    for label in ['alice-prover', 'bob-prover']:
        assert datetime.fromisoformat(read(label+'/process-exit.json')['exitedAt'].replace('Z', '+00:00')) < bob_submit
    assert result['bob']['paymentsObserved']==payments
    assert all(read(label+'/process-exit.json')['code']==0 for label in ['alice-prover','bob-prover','alice-cleanup-prover','carol-cleanup-prover'])
    fees = sum(int(read(f'public/{i:04}.metrics.json')['metrics']['fee_sompi']) for i in range(count_tx))
    assert fees == int(result['totalFeeSompi'])
    source = read('public/source-utxo.json')
    assert sum(int(u['amount']) for u in result['finalOrdinaryOutputs']) + fees == int(source['amount'])
    labels = ['alice-prover', 'bob-prover', 'alice-cleanup-prover', 'carol-cleanup-prover']
    reports = [json.loads(p.read_text()) for label in labels for p in (root/label).glob('*.report.json')]
    assert len(reports) == count_tx-1
    assert len({r['proof_sha256'] for r in reports}) == len(reports)
    proving = [r['proving_ms'] for r in reports]
    sample_payments = sorted({1, min(10, payments), payments})
    samples = {str(i): read(f'public/{i+1:04}.metrics.json')['metrics'] for i in sample_payments}
    assert len({(m['estimated_bytes'], m['compute_mass'], m['fee_sompi']) for m in samples.values()}) == 1
    funding_fee = int(read('public/0000.metrics.json')['metrics']['fee_sompi'])
    confirmed_at = datetime.fromisoformat(confirmation['observedAt'].replace('Z', '+00:00'))
    first_submit = datetime.fromisoformat(read('live/0000.submission.json')['submittedAt'].replace('Z', '+00:00'))
    last_confirm = datetime.fromisoformat(read(f'live/{count_tx-1:04}.confirmed.json')['observedAt'].replace('Z', '+00:00'))
    return {
        'role': result['role'], 'confirmed_transactions': count_tx, 'payments_after_bob_authorization':payments,
        'proof_bytes_equal': True, 'authorization_bytes_equal': True,
        'proof_sha256': hashlib.sha256(proof).hexdigest(),
        'authorization_anchor_count': count, 'current_commitment_count': int.from_bytes(current_state[1:5],'little'),
        'current_nullifier_count_before_bob_exit': int.from_bytes(current_state[5:9],'little'),
        'bob_prover_stopped_before_alice_submission': True,
        'both_original_provers_stopped_before_bob_submission': True,
        'bob_rebuilder_has_no_wallet_or_proving_key': True,
        'additional_proofs': 0, 'public_rebuild_process_ms': result['bob']['rebuildingMs'],
        'inner_public_rebuild_us': result['bob']['report']['extra']['public_rebuild_us'],
        'initial_bob_proving_ms': report['report']['proving_ms'],
        'bob_payout_sompi': bob['outputs'][1]['value'],
        'bob_exit_fee_sompi': result['bob']['feeSompi'],
        'pool_fee_sompi': str(fees-funding_fee), 'funding_fee_sompi': str(funding_fee),
        'private_proofs': len(reports),
        'private_proving_ms': {'min': min(proving), 'median': statistics.median(proving), 'max': max(proving), 'sum': sum(proving)},
        'cold_parameter_load_ms': {label: read(label+'/ready.json')['parameter_load_ms'] for label in labels},
        'sample_payment_metrics': samples,
        'public_discovery_ms': read('rebuilder/discovery.json')['discoveryMs'],
        'bob_submission_to_payout_observation_ms': (confirmed_at-bob_submit).total_seconds()*1000,
        'first_submission_to_terminal_payout_observation_ms': (last_confirm-first_submit).total_seconds()*1000,
        'total_fee_sompi': str(fees), 'terminal_reserve_spent': True,
        'bob_transaction_id': bob['id'], 'alice_transaction_id': alice['id'],
        'binary_sha256': result['binarySha256'],
        'scope': 'Consistency of exported public evidence; not independent consensus or privacy verification',
    }


if __name__ == '__main__':
    print(json.dumps(summarize(Path(sys.argv[1])), indent=2))

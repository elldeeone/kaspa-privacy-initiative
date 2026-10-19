#!/usr/bin/env python3
"""Recheck the sanitized H7 ledger without wallet files or the receiver list.

Uses the existing independent Python state checker. Set KPI_BINARY to also run
the pinned native validator. Neither mode establishes current chain acceptance.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def check(root):
    read = lambda p: json.loads(p.read_text())
    exported = read(root / 'export.json')
    for name, hashes in exported['files'].items():
        file = (root / name).resolve()
        assert file.is_relative_to(root.resolve())
        assert hashlib.sha256(file.read_bytes()).hexdigest() == hashes['export_sha256'], name
    public = root / 'public'
    descriptor = read(public / 'descriptor.json')
    assert descriptor['network'] == 'testnet-10'
    assert hashlib.sha256((public / 'vk.bin').read_bytes()).hexdigest() == descriptor['vk_sha256']
    spec = importlib.util.spec_from_file_location('compact_check', Path(__file__).with_name('check-compact-state.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    native_checks = 0
    with tempfile.TemporaryDirectory(prefix='kpi-public-check-') as tmp:
        temp = Path(tmp)
        # Adapt only public descriptor fields; no receiver list or wallet data.
        (temp / 'manifest.json').write_text(json.dumps({
            'network': descriptor['network'], 'domain': descriptor['domain'],
            'initial_state': {'commitments': [descriptor['initial_commitment']]},
        }))
        for step in range(6):
            shutil.copyfile(public / f'{step:04}.json', temp / f'{step:04}.json')
        state = module.check(temp)
        assert state['all_claims_drained'] and state['spends'] == state['commitments'] == 5
        source = read(public / 'source-utxo.json')
        assert source == descriptor['source']
        ledger = {(source['txid'], source['index']): source}
        fees = 0
        for step in range(6):
            tx = read(public / f'{step:04}.json')
            if step == 0:
                assert tx['id'] == descriptor['funding']['txid']
                assert tx['outputs'][0]['value'] == descriptor['reserve_sompi']
            inputs = [ledger.pop((i['previousOutpoint']['transactionId'], i['previousOutpoint']['index'])) for i in tx['inputs']]
            fee = sum(int(u['amount']) for u in inputs) - sum(int(o['value']) for o in tx['outputs'])
            assert fee > 0
            assert fee == int(read(public / f'{step:04}.metrics.json')['metrics']['fee_sompi'])
            fees += fee
            if os.environ.get('KPI_BINARY'):
                (temp / 'inputs.json').write_text(json.dumps(inputs))
                subprocess.run([os.environ['KPI_BINARY'], 'validate', str(public / f'{step:04}.json'), str(temp / 'inputs.json')],
                               check=True, capture_output=True)
                native_checks += 1
            for index, output in enumerate(tx['outputs']):
                ledger[tx['id'], index] = {'txid': tx['id'], 'index': index, 'amount': output['value'],
                                         'spk': output['scriptPublicKey'], 'daa': '0', 'is_coinbase': False}
        accounting = read(root / 'accounting.json')
        assert fees == int(accounting['totalFeeSompi'])
        assert sum(int(u['amount']) for u in ledger.values()) + fees == int(source['amount'])
        assert {tuple((u['txid'], u['index'])) for u in accounting['finalOrdinaryOutputs']} == set(ledger)
        for index in [1, 2, 0]:
            result = read(root / f'recovered-{index}/output/result.json')
            payout = result['payout']
            assert ledger[payout['txid'], payout['index']] == payout
            assert result['newPrivateProofs'] == 1 and result['privateBackupOnly']
            assert not result['originalManifestUsed']
            assert not result['sources'][0]['accepted'] and result['sources'][1]['accepted']
            if exported['role'] != 'offline':
                assert result['confirmed']
    return {'role': exported['role'], 'exportHashesChecked': len(exported['files']),
            'nativeTransactionsValidated': native_checks, 'state': state, 'totalFeeSompi': str(fees),
            'scope': 'Public artifact consistency/native validation; no live RPC, secret ownership or cryptographic audit claim'}


if __name__ == '__main__':
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))

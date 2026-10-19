#!/usr/bin/env python3
"""Allowlisted public evidence export; never copy wallet/proving/unused bundles."""
import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get('KPI_DEPOSIT_EVIDENCE', HERE / 'evidence/2026-10-20-deposits'))
prepared, evaluation, funding, *live = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('public_checker', HERE / 'check-deposit-state.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def read(p):
    return json.loads(p.read_text())


def save(p, value):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2) + '\n')


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def wallet_summary(value):
    result = dict(value)
    result['exits'] = [{k: v for k, v in e.items() if k != 'transaction'}
                       for e in value['exits']]
    return result


def public(source, target):
    for name in ['descriptor.json', 'vk.bin', 'history.json']:
        copy(source / name, target / name)
    save(target.parent / 'independent-check.json', checker.check(target))


def isolation(source, target, root):
    # Keep mount inventory without publishing private workstation paths.
    text = source.read_text().replace(str(root), '<trial>')
    text = text.replace('/home/luke/.local/share/kpi-compact-tests/params-v1', '<parameters>')
    save(target, json.loads(text))


def preparation(root, target):
    identity = root / 'identity.json'
    existing = target / 'generation-identity.json'
    if existing.exists():
        assert read(existing) == read(identity), 'refusing to replace another trial identity'
    for i in range(4):
        source = root / f'prover-{i}'
        for name in ['prepared.json', '0000.metrics.json', 'process-exit.json', 'resources.txt']:
            copy(source / name, target / f'prover-{i}' / name)
        isolation(source / 'isolation.json', target / f'prover-{i}/isolation.json', root)
    copy(root / 'identity.json', target / 'generation-identity.json')
    copy(root / 'prepared.json', target / 'provers-stopped.json')


def saved_equality(root, wallets):
    comparisons = []
    for wallet in wallets:
        index = wallet['wallet']
        raw = (root / f'prover-{index}/saved.json').read_bytes()
        saved = json.loads(raw)
        assert hashlib.sha256(raw).hexdigest() == wallet['savedProofFileSha256']
        assert saved['count'] == 3 + 2 * index
        for note, exit in enumerate(wallet['exits']):
            tx = exit['transaction']
            auth = bytes.fromhex(tx['payload'])[8:273]
            proof = bytes.fromhex(tx['inputs'][0]['signatureScript'])[2:130]
            assert auth == bytes.fromhex(saved['bundles'][note]['authorization'])
            assert proof == bytes.fromhex(saved['bundles'][note]['proof'])
            comparisons.append({'wallet': index, 'note': note,
                                'preparedCount': saved['count'], 'settledCount': exit['current_count'],
                                'authorizationSha256': hashlib.sha256(auth).hexdigest(),
                                'proofSha256': hashlib.sha256(proof).hexdigest(),
                                'unchanged': True, 'transactionId': tx['id']})
    return comparisons


offline = read(evaluation / 'offline-result.json')
assert offline['offline_pass']
existing = OUT / 'offline/preparation/generation-identity.json'
if existing.exists():
    assert read(existing) == read(prepared / 'identity.json'), 'different offline fixture: choose a new evidence path'
summary = {k: v for k, v in offline.items() if k != 'orders'}
summary['orders'] = []
for order in offline['orders']:
    label = 'order-' + ''.join(map(str, order['order']))
    public(evaluation / label / 'public', OUT / 'offline' / label / 'public')
    wallets = [wallet_summary(w) for w in order['wallets']]
    save(OUT / 'offline' / label / 'saved-proof-equality.json', saved_equality(prepared, order['wallets']))
    summary['orders'].append({**order, 'wallets': wallets})
    for w in wallets:
        source = evaluation / label / f'wallet-{w["wallet"]}'
        target = OUT / 'offline' / label / f'wallet-{w["wallet"]}'
        isolation(source / 'isolation.json', target / 'isolation.json', prepared)
        copy(source / 'process-exit.json', target / 'process-exit.json')
save(OUT / 'offline/result.json', summary)
save(OUT / 'offline/native-rejections.json',
     [{k: v for k, v in r.items() if k != 'private_error'}
      for r in read(evaluation / 'controls/native-rejections.json')])
copy(evaluation / 'independent-public-check.json', OUT / 'offline/independent-public-check.json')
copy(prepared.parent / 'capacity.stdout.json', OUT / 'offline/capacity.json')
preparation(prepared, OUT / 'offline/preparation')

plan = read(funding / 'result.json')
assert plan['complete']
rows = []
for i in range(plan['steps']):
    source = funding / f'{i:04d}'
    rows.append({'transaction': read(source / 'transaction.json'),
                 'inputs': [{k: v for k, v in u.items() if k != 'origin'}
                            for u in read(source / 'inputs.json')],
                 'build': read(source / 'build.json'),
                 'validation': read(source / 'validation.json'),
                 'confirmed': read(source / 'confirmed.json')})
save(OUT / 'ordinary-funding/result.json', plan)
save(OUT / 'ordinary-funding/transactions.json', rows)

for root in live:
    result = read(root / 'result.json')
    assert result['complete'] and result['network'] == 'testnet-10'
    target = OUT / result['role']
    existing = target / 'preparation/generation-identity.json'
    if existing.exists():
        assert read(existing) == read(root / 'identity.json'), 'different live fixture: choose a new evidence path'
    public(root / 'public', target / 'public')
    preparation(root, target / 'preparation')
    comparisons = saved_equality(root, result['wallets'])
    stops = [read(root / f'prover-{i}/process-exit.json')['stoppedAt'] for i in range(4)]
    submissions = [read(root / f'exit-wallet-{i}/exit-{j}/submission.json')['at']
                   for i in range(4) for j in range(2)]
    assert max(stops) < min(submissions)
    for i in range(3):
        assert stops[i] < read(root / f'prover-{i+1}/submission.json')['at']
    save(target / 'saved-proof-equality.json', {'comparisons': comparisons,
         'allProversStoppedBeforeAnyExit': True, 'eachProverStoppedBeforeNextAdmission': True})
    result['wallets'] = [wallet_summary(w) for w in result['wallets']]
    save(target / 'result.json', result)
    save(target / 'node-info.json', read(root / 'node.json')['info'])
    copy(root / 'chain-confirmed.json', target / 'chain-confirmed.json')
    for name in ['0000.json', '0000.metrics.json', 'sources.json', 'confirmed.json']:
        copy(root / 'allocation' / name, target / 'allocation' / name)
    copy(root / 'allocation-input.json', target / 'allocation/input.json')
    copy(root / 'public/0000.metrics.json', target / 'genesis.metrics.json')
    for w in result['wallets']:
        source = root / f'exit-wallet-{w["wallet"]}'
        destination = target / f'wallet-{w["wallet"]}'
        isolation(source / 'isolation.json', destination / 'isolation.json', root)
        copy(source / 'process-exit.json', destination / 'process-exit.json')
        for i in range(2):
            for name in ['submission.json', 'response.json', 'confirmed.json', 'settlement.resources.txt']:
                copy(source / f'exit-{i}' / name, destination / f'exit-{i}' / name)

pins = {}
for name in ['deposits-funding.mjs', 'src/bin/kpi-compact-funding.rs',
             'runtime.mjs', 'chain.mjs',
             'src/compact/deposits/tests.rs', 'examples/deposit-capacity.rs',
             'check-deposit-state.py', 'export-deposits.py']:
    pins[name] = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
save(OUT / 'supplementary-source-pins.json', pins)
print(json.dumps({'export': str(OUT), 'files': sum(p.is_file() for p in OUT.rglob('*')),
                  'liveRuns': len(live), 'privateBundlesExported': False}))

#!/usr/bin/env python3
"""Export completed v3 races with an explicit public-file allowlist."""
import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('trial', type=Path)
p.add_argument('destination', type=Path)
a = p.parse_args()
r, d = a.trial, a.destination
read = lambda f: json.loads(f.read_text())
digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
result = read(r / 'result.json')
prepared = read(r / 'prepared.json')
assert result['success'] and result['winnerStoppedBeforeLoserPayout']
assert result['terminalReserveSpent'] and result['confirmedTransactions'] == 5
assert result['submittedTransactions'] == 6
assert sorted(w['rebuilds'] for w in result['wallets']) == [0, 1]
assert int(result['remainingSompi']) + int(result['acceptedFeeSompi']) == int(result['startingSompi'])
assert result['sourceHashes'] == prepared['sources']
for step, expected in prepared['transactions'].items():
    assert digest(r / 'public' / (step + '.json')) == expected
d.mkdir(parents=True, exist_ok=False)

def save(name, value):
    target = d / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2) + '\n')

def copy(name):
    target = d / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(r / name, target)

for name in ['prepared.json', 'result.json', 'anchor.json', 'barrier/go.json', 'funding-input.json',
             'chain-confirmed.json', 'chain-retrieval.json', 'node-before.json',
             'public/manifest.json', 'public/source-utxo.json', 'public/vk.bin',
             'logs/fees.stdout.json']:
    copy(name)
assert (d / 'public/vk.bin').stat().st_size == 328
for step in range(3):
    for suffix in ['.json', '.metrics.json']:
        copy(f'public/{step:04}{suffix}')
for f in sorted((r / 'live').glob('*.json')):
    assert re.fullmatch(r'(node|000[0-4](?:\.(?:inputs|submission|response|confirmed)|-validate\.stdout)?)\.json', f.name)
    copy('live/' + f.name)

for index in range(2):
    prefix = f'agents/{index}/'
    agent = r / prefix
    for name in ['seed.json', 'seed-confirmed.json', 'ready.json', 'node.json',
                 'result.json', 'process-exit.json']:
        copy(prefix + name)
    patterns = [r'attempt-[01]\.(transaction|proof|submission|response)\.json',
                r'adopt-[34]\.json', r'stale-proof-control\.json']
    for f in sorted(agent.glob('*.json')):
        if any(re.fullmatch(pattern, f.name) for pattern in patterns):
            copy(prefix + f.name)
    for f in sorted((agent / 'logs').glob('*.json')):
        if re.fullmatch(r'(attempt-[01]|adopt-[34])(?:\.inputs|-validate\.stdout)\.json|reused-proof\.json', f.name):
            copy(prefix + 'logs/' + f.name)
    for relative in ['agent-isolation.json', 'wallet0-isolated/namespace.json']:
        source = agent / relative
        value = read(source)
        assert value['otherWalletsMounted'] is False and value['hostHomeAccessible'] is False
        value.pop('mounts')
        value['originalRecordSha256'] = digest(source)
        save(prefix + relative, value)
    copy(prefix + 'wallet0-isolated/ready.json')
    copy(prefix + 'wallet0-isolated/prover-exit.json')

save('export.json', {
    'trialIdentity': r.name,
    'preparedSha256': digest(r / 'prepared.json'),
    'chainSha256': digest(r / 'chain-confirmed.json'),
    'scope': 'Synthetic TN10 liveness test; one correct node view, not an anonymity measurement or cryptographic audit.',
    'omitted': ['wallet keys', 'note witnesses and randomness', 'private host mount paths',
                'proving parameters', 'unfiltered process logs'],
    'unacceptedCandidates': 'attempt transaction files include the initial conflicting candidate; chain-confirmed.json contains accepted transactions only.'
})

# Never print secret values. Check binary, hex and parsed JSON array encodings.
secrets = []
for index in range(2):
    wallet = read(r / f'wallet{index}/wallet.json')
    for field in ['spending', 'viewing', 'native']:
        secrets.append(bytes(wallet['wallet'][field]))
    if wallet['genesis_note']:
        secrets.append(bytes(wallet['genesis_note']['rho']))

def check_json(value):
    if isinstance(value, dict):
        assert not ({'spending', 'viewing', 'native', 'rho', 'secret', 'privateKey'} & value.keys()), 'secret-shaped field in export'
        for child in value.values():
            check_json(child)
    elif isinstance(value, list):
        if len(value) == 32 and all(type(x) is int and 0 <= x < 256 for x in value):
            assert bytes(value) not in secrets, 'secret array in export'
        for child in value:
            check_json(child)

for f in d.rglob('*'):
    if not f.is_file():
        continue
    content = f.read_bytes()
    for secret in secrets:
        assert secret not in content and secret.hex().encode() not in content, 'secret material in export'
    if f.suffix == '.json':
        check_json(read(f))
save('sha256.json', {str(f.relative_to(d)): digest(f) for f in sorted(d.rglob('*')) if f.is_file()})
print(json.dumps({'files': sum(f.is_file() for f in d.rglob('*')), 'knownSecretScan': 'passed', 'exported': str(d)}))

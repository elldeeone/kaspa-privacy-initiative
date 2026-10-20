#!/usr/bin/env python3
"""Allowlist export: accepted bodies, costs and checks; no private capabilities."""
import hashlib
import json
import sys
from pathlib import Path


def read(p):
    return json.loads(p.read_text())


def save(p, v):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('x') as f:
        json.dump(v, f, indent=2, sort_keys=True)
        f.write('\n')


def digest_hex(value):
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


offline, rehearsal, trial, target, *funding = map(Path, sys.argv[1:])
assert not target.exists(), 'fresh evidence directory required'
gate = read(offline / 'offline-result.json')
assert gate['offline_pass'] and gate['fourWalletsPaid'] and gate['sixSavedProofsUnchanged']
vk = (offline / 'public/vk.bin').read_bytes()
assert len(vk) == 328
save(target / 'verification-key.json', {'hex': vk.hex(), 'sha256': hashlib.sha256(vk).hexdigest()})
save(target / 'offline/summary.json', {k: gate[k] for k in (
    'offline_pass', 'binarySha256', 'sources', 'checked', 'controls',
    'fourWalletsPaid', 'sixSavedProofsUnchanged', 'noWalletOrPKInExitProcesses')})
initial = offline / 'qualification-initial-invalid.json'
if initial.exists():
    invalid = read(initial)
    save(target / 'offline/qualification-correction.json', {
        'initialNegativeControlsValidEvidence': False,
        'cause': 'Descriptor reserialization changed its byte hash and masked the intended rejection checks.',
        'fix': 'Copy unchanged descriptor bytes exactly; assert the intended cause for each rejection.',
        'initialControls': invalid['controls'],
        'correctedControls': gate['controls'],
        'correctedBeforePoolFunding': True,
        'ordinaryConsolidationBeforeCorrection': True,
    })

for role, root in [('rehearsal', rehearsal), ('trial', trial)]:
    result = read(root / 'result.json')
    assert (root / 'public/vk.bin').read_bytes() == vk
    identity = read(root / 'identity.json')
    save(target / role / 'identity.json', {k: identity[k] for k in (
        'role', 'createdAt', 'freshUnfundedMs', 'binarySha256', 'sources',
        'network', 'vk_sha256', 'unfunded', 'fresh_wallets')})
    assert result['complete'] and result['role'] == role
    assert result['allFourWalletsPaid'] and result['allProofAuthBytesUnchanged']
    assert result['remainingReserveSompi'] == '0' and result['confirmedTransactions'] == 15
    chain = read(root / 'chain-confirmed.json')
    accepted = {r['transaction']['id']: r['transaction'] for r in chain['transactions']}
    assert len(accepted) == 15
    rows, reuse, isolation = [], [], []
    for wallet in result['wallets']:
        index = wallet['wallet']
        saved = read(root / f'capabilities/wallet-{index}.json')
        assert len(saved['bundles']) == len(wallet['receipts'])
        for b, receipt in zip(saved['bundles'], wallet['receipts']):
            raw = accepted[receipt['transaction']['id']]
            assert raw == receipt['transaction'] and receipt['confirmed']
            proof = bytes.fromhex(raw['inputs'][0]['signatureScript'])[2:130].hex()
            auth = bytes.fromhex(raw['payload'])[8:385].hex()
            assert proof == b['proof'] and auth == b['authorization']
            reuse.append({'wallet': index, 'transactionId': raw['id'],
                          'savedProofSha256': digest_hex(b['proof']),
                          'acceptedProofSha256': digest_hex(proof),
                          'savedAuthorizationSha256': digest_hex(b['authorization']),
                          'acceptedAuthorizationSha256': digest_hex(auth)})
        rows.append({'wallet': index, 'claims': len(wallet['receipts']),
                     'payoutSompi': str(sum(int(r['payout']['amount']) for r in wallet['receipts'])),
                     'noWalletOrProvingKey': wallet['noWalletOrProvingKey'],
                     'ownCapabilitiesOnly': wallet['ownCapabilitiesOnly'],
                     'currentStateFromAcceptedRPC': wallet['currentStateFromAcceptedRPC'],
                     'receipts': [{k: r[k] for k in ('confirmed', 'payout', 'terminal',
                                                    'history_transactions', 'native', 'discovery')}
                                  for r in wallet['receipts']]})
        for number, receipt in enumerate(rows[-1]['receipts']):
            receipt['settlementResources'] = (
                root / f'tn10-wallet-{index}/exit-{number}/settlement.resources.txt'
            ).read_text().splitlines()[1:]
        audit = read(root / f'tn10-wallet-{index}/isolation.json')
        paths = [line.split()[1] for line in audit['mounts'].splitlines()]
        assert not audit['host_home_accessible']
        assert all(p not in paths for p in ['/params', '/wallets.json', '/home'])
        isolation.append({'wallet': index, 'hostHomeAccessible': False,
                          'mountTargets': paths,
                          'exit': read(root / f'tn10-wallet-{index}/process-exit.json')})
    summary = {k: v for k, v in result.items() if k != 'wallets'}
    summary['wallets'] = rows
    stopped = read(root / 'prover-stopped.json')
    first = read(root / 'allocation-live/submission.json')
    assert stopped['stopped'] and stopped['at'] < first['at']
    save(target / role / 'result.json', summary)
    save(target / role / 'chain-confirmed.json', chain)
    save(target / role / 'descriptor.json', read(root / 'public/descriptor.json'))
    save(target / role / 'proof-reuse.json', reuse)
    save(target / role / 'isolation.json', isolation)
    save(target / role / 'prover-stopped.json', {'prover': stopped, 'firstBroadcast': first})
    save(target / role / 'node.json', read(root / 'node.json'))
    private = read(root / 'proof-run/result-private.json')
    measurements = []
    for f in ('allocation/0000.metrics.json', 'public/0000.metrics.json'):
        m = read(root / f)
        assert m['txid'] in accepted
        measurements.append(m)
    for row in private['rows'][:7]:
        assert row['tx'] == accepted[row['tx']['id']]
        measurements.append({'txid': row['tx']['id'], 'metrics': row['metrics'],
                             'script_units': row['script_units'], 'native_full': True})
    for wallet in result['wallets']:
        measurements.extend(r['native'] for r in wallet['receipts'])
    assert len(measurements) == 15
    save(target / role / 'measurements.json', measurements)
    save(target / role / 'preflight.json', {
        'offlinePlannedUTXOsNotChainAcceptance': True,
        'elapsedMs': private['elapsed_ms'],
        'privateChangeDecrypted': private['private_change_decrypted'],
        'partialChangeRespent': private['partial_change_respent'],
        'normalAndFallbackMutuallyExclusive': private['normal_and_fallback_mutually_exclusive'],
        'nativeMutationsRejected': sum(len(c['mutations_rejected']) for c in private['native_adversarial_controls']),
        'resources': (root / 'logs/prepare.resources.txt').read_text().splitlines()[1:],
        'proverTimings': [s for s in (root / 'logs/prepare.stderr.log').read_text().splitlines()
                          if s.startswith(('parameters loaded ', 'proof '))],
    })

for index, root in enumerate(funding):
    result = read(root / 'result.json')
    assert result['complete'] and result['network'] == 'testnet-10'
    txs = [read(root / f'{i:04}/transaction.json') for i in range(result['steps'])]
    confirmations = [read(root / f'{i:04}/confirmed.json') for i in range(result['steps'])]
    save(target / f'funding/{index}/result.json', result)
    save(target / f'funding/{index}/transactions.json', txs)
    save(target / f'funding/{index}/confirmations.json', confirmations)

save(target / 'export.json', {'allowlistExport': True, 'acceptedChainBodiesOnly': True,
                             'unusedFallbacksIncluded': False, 'walletKeysIncluded': False,
                             'provingKeyIncluded': False, 'privacyMeasurement': False,
                             'exporterSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
print(json.dumps({'exported': str(target), 'rehearsalAndTrialComplete': True}))

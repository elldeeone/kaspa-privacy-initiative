#!/usr/bin/env python3
"""Check public evidence without wallet secrets, issuer key or network access."""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'

def read(p):
    return json.loads(p.read_text())

def main():
    p = argparse.ArgumentParser()
    p.add_argument('public_evidence', type=pathlib.Path)
    p.add_argument('settlement_program', type=pathlib.Path)
    a = p.parse_args()
    root = a.public_evidence.resolve()
    rows = read(root / 'MANIFEST.json')['files']
    seen = set()
    for row in rows:
        rel = pathlib.PurePosixPath(row['path'])
        assert not rel.is_absolute() and '..' not in rel.parts and row['path'] not in seen
        seen.add(row['path'])
        file = root / rel
        assert file.is_file() and not file.is_symlink()
        raw = file.read_bytes()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    arm = root / 'board'
    view = arm / 'view'
    bundle = read(view / 'bundle.json')
    publication = read(arm / 'BOARD-PUBLICATION.json')
    payload = (view / 'bundle.json').read_bytes()
    assert publication['payloadBytes'] == len(payload) < 24_000
    assert publication['payloadSha256'] == hashlib.sha256(payload).hexdigest()
    assert publication['atomicLocalPublication'] and not publication['nativeTransactionAccepted']
    events = [json.loads(line) for line in (view / 'operator.jsonl').read_text().splitlines()]
    issues = [event for event in events if event['request']['kind'] == 'issue']
    redeems = [event for event in events if event['request']['kind'] == 'redeem']
    assert len(issues) == len(redeems) == len(bundle['entries']) == 3
    assert [entry['issue'] for entry in bundle['entries']] == [event['request'] for event in issues]
    assert all(event['response'] == {'queued': True} for event in issues)
    subprocess.run([HOST, 'board-public-check', view / 'config.json', view / 'bundle.json'], check=True)
    spec = importlib.util.spec_from_file_location('observer', pathlib.Path(__file__).with_name('observe.py'))
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    prediction = observer.observe(view)
    assert prediction == read(arm / 'PREDICTION.json')
    assert hashlib.sha256((arm / 'PREDICTION.json').read_bytes()).hexdigest() == read(arm / 'PREDICTION-SEAL.json')['sha256']
    assert prediction['exactServiceFacts'] == {} and prediction['compatibleMappingCount'] == 6
    controls = read(arm / 'GUARD-CONTROLS.json')
    assert len(controls['checks']) == 9 and controls['payoutKeysDisclosed'] == 0
    assert all(row['rejected'] for row in controls['checks'])
    extra = read(arm / 'EXTRA-CONTROLS.json')
    assert extra['readOnly'] and extra['networkRequests'] == 0 and len(extra['cases']) == 3
    assert all(row['otherReplyInvalid'] and row['rejectedBeforePayoutKey'] for row in extra['cases'])
    result = read(arm / 'RESULT.json')
    assert result['exactCorrectOwnerKeyLinks'] == 0 and result['compatibleMappings'] == 6
    assert result['guardRejections'] == 9 and result['kernel']['payoutSompi'] == 3_000_000_000
    with tempfile.TemporaryDirectory(prefix='kpi-atomic-bundle-check-') as temporary:
        tmp = pathlib.Path(temporary)
        for i in range(4):
            next_state = tmp / f'state-{i+1}.json'
            subprocess.run([HOST, 'apply', arm / f'payments/state-{i}.json',
                            arm / f'payments/payment-{i}.json', next_state], check=True)
            assert read(next_state) == read(arm / f'payments/state-{i+1}.json')
        subprocess.run([HOST, 'replay', view, tmp / 'REPLAY.json'], check=True)
        assert read(tmp / 'REPLAY.json') == read(arm / 'REPLAY.json')
        subprocess.run([HOST, 'check', view / 'state.json', view / 'intent.json',
                        view / 'approvals.json', a.settlement_program, tmp / 'KERNEL.json'], check=True)
        assert read(tmp / 'KERNEL.json') == result['kernel']
        changed = read(view / 'intent.json')
        changed['nonce'][0] ^= 1
        (tmp / 'changed-intent.json').write_text(json.dumps(changed))
        refusal = subprocess.run([HOST, 'check', view / 'state.json', tmp / 'changed-intent.json',
                                  view / 'approvals.json', a.settlement_program, tmp / 'bad.json'],
                                 capture_output=True)
        assert refusal.returncode != 0
        for name, mutated in [('partial', dict(bundle, entries=bundle['entries'][:1])),
                              ('bad-signature', json.loads(payload))]:
            if name == 'bad-signature':
                mutated['entries'][0]['blindSignature'] = '00' * 256
            trial = tmp / f'{name}.json'
            trial.write_text(json.dumps(mutated))
            refusal = subprocess.run([HOST, 'board-public-check', view / 'config.json', trial], capture_output=True)
            assert refusal.returncode != 0
    assert read(root / 'RESULT.json')['localTimingGatePassed']
    print(len(seen), 'public hashes checked; proofs, blinded replies, observer and kernel replayed')

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Replay public proof and accounting evidence; owner truth stays private."""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'
TAG = b'KPI-anonymous-eligibility-v1\0'

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
        f = root / rel
        raw = f.read_bytes()
        assert f.is_file() and not f.is_symlink()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    spec = importlib.util.spec_from_file_location('observer', pathlib.Path(__file__).with_name('observe.py'))
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    with tempfile.TemporaryDirectory(prefix='kpi-round-agreement-replay-') as temporary:
        tmp = pathlib.Path(temporary)
        for mode in ('honest', 'tagged', 'staggered'):
            arm = root / mode
            view = arm / 'view'
            result = read(arm / 'RESULT.json')
            for i in range(4):
                output = tmp / f'{mode}-state-{i+1}.json'
                subprocess.run([HOST, 'apply', arm / f'payments/state-{i}.json',
                                arm / f'payments/payment-{i}.json', output], check=True)
                assert read(output) == read(arm / f'payments/state-{i+1}.json')
            configs = read(view / 'configs.json') if (view / 'configs.json').exists() else [read(view / 'config.json')]
            events = [json.loads(line) for line in (view / 'operator.jsonl').read_text().splitlines()]
            issues = [r for r in events if r['request']['kind'] == 'issue']
            redeems = [r for r in events if r['request']['kind'] == 'redeem']
            assert len(issues) == 3
            nfs = set()
            for i, row in enumerate(issues):
                req = row['request']
                s = req['operation']['statement']
                nf = bytes(s['nullifier'])
                assert nf not in nfs
                nfs.add(nf)
                blind = bytes.fromhex(req['blindMessage'])
                matches = [c for c in configs if list(hashlib.sha256(TAG + bytes(c['round']) +
                           bytes(c['issuer']) + nf + blind).digest()) == s['exit_destination']
                           and c['principalSompi'] == s['exit_value']]
                assert len(matches) == 1
                opfile = tmp / f'{mode}-eligibility-{i}.json'
                opfile.write_text(json.dumps([req['operation']]))
                subprocess.run([HOST, 'apply', view / 'state.json' if (view / 'state.json').exists() else
                                arm / 'payments/state-4.json', opfile,
                                tmp / f'{mode}-eligibility-state-{i}.json'], check=True)
            if mode == 'tagged':
                assert len(redeems) == 0 and result['walletRejections'] == 3
                print(mode, 'three real eligibility proofs; wallet rejection before redemption')
                continue
            assert len(redeems) == 3
            prediction = observer.observe(view)
            assert prediction == read(arm / 'PREDICTION.json')
            seal = read(arm / 'PREDICTION-SEAL.json')
            assert hashlib.sha256((arm / 'PREDICTION.json').read_bytes()).hexdigest() == seal['sha256']
            output = tmp / f'{mode}-kernel.json'
            subprocess.run([HOST, 'check', view / 'state.json', view / 'intent.json',
                            view / 'approvals.json', a.settlement_program, output], check=True)
            assert read(output) == read(arm / 'KERNEL.json')
            changed = read(view / 'intent.json')
            changed['nonce'][0] ^= 1
            mutation = tmp / f'{mode}-changed-intent.json'
            mutation.write_text(json.dumps(changed))
            refused = subprocess.run([HOST, 'check', view / 'state.json', mutation,
                                      view / 'approvals.json', a.settlement_program,
                                      tmp / f'{mode}-must-not-exist.json'], capture_output=True)
            assert refused.returncode != 0
            print(mode, 'proofs, sealed observer, kernel and changed-intent refusal passed')
    summary = read(root / 'RESULT.json')
    assert not summary['privacyGatePassed'] and not summary['costWorkStarted']
    controls = read(root / 'CONTROLS.json')
    assert controls['readOnly'] and controls['networkRequests'] == 0
    assert len(controls['cases']) == 10 and all(c['walletCheckMatchedExpectation'] for c in controls['cases'])
    print(len(seen), 'public hashes checked; owner truth remained private')

if __name__ == '__main__':
    main()

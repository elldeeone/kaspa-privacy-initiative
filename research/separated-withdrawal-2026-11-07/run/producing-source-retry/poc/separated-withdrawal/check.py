#!/usr/bin/env python3
"""Recheck retained public evidence; never creates wallets/proofs or broadcasts."""
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
    manifest = read(root / 'MANIFEST.json')
    seen = set()
    for row in manifest['files']:
        rel = pathlib.PurePosixPath(row['path'])
        assert not rel.is_absolute() and '..' not in rel.parts and row['path'] not in seen
        seen.add(row['path'])
        f = root / rel
        assert f.is_file() and not f.is_symlink()
        raw = f.read_bytes()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    spec = importlib.util.spec_from_file_location('observer', pathlib.Path(__file__).with_name('observe.py'))
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    with tempfile.TemporaryDirectory(prefix='kpi-separated-public-') as temporary:
        out = pathlib.Path(temporary)
        for mode in ('direct', 'honest', 'tagged'):
            arm = root / mode
            view = arm / 'view'
            result = read(arm / 'RESULT.json')
            assert hashlib.sha256((arm / 'PREDICTION.json').read_bytes()).hexdigest() == read(arm / 'PREDICTION-SEAL.json')['sha256'] == result['predictionSha256']
            prediction = observer.observe(view)
            assert prediction == read(arm / 'PREDICTION.json')
            for role in read(arm / 'ISOLATION.json'):
                assert role['uid'] == 1000 and not role['walletHostPathVisible'] and not role['dockerSocketVisible'] and not role['hostHomeVisible']
            for role in read(arm / 'POST-CREATION-ISOLATION.json')['readProbes']:
                assert not any(v['readable'] for v in role['result']['others'].values())
                assert role['result']['own']['readable'] == (role['role'] != 'service')
            subprocess.run([str(HOST), 'replay', str(view), str(out / (mode + '-registration.json'))], check=True)
            # Replay all actual private payments from the supplied deposit state.
            for i in range(4):
                fresh = out / f'{mode}-state-{i}.json'
                subprocess.run([str(HOST), 'apply', str(arm / f'payments/state-{i}.json'), str(arm / f'payments/payment-{i}.json'), str(fresh)], check=True)
                assert read(fresh) == read(arm / f'payments/state-{i+1}.json')
            fresh = out / (mode + '-kernel.json')
            subprocess.run([str(HOST), 'check', str(view / 'state.json'), str(view / 'intent.json'), str(view / 'approvals.json'), str(a.settlement_program), str(fresh)], check=True)
            assert read(fresh) == read(arm / 'KERNEL.json')
            # Reject a changed intent: the service still cannot redirect funds.
            changed = read(view / 'intent.json')
            changed['nonce'][0] ^= 1
            mutation = out / (mode + '-changed-intent.json')
            mutation.write_text(json.dumps(changed))
            refusal = subprocess.run([str(HOST), 'check', str(view / 'state.json'), str(mutation), str(view / 'approvals.json'), str(a.settlement_program), str(out / (mode + '-must-not-exist.json'))], capture_output=True, text=True)
            assert refusal.returncode != 0 and 'complete native effects authorization' in refusal.stderr, refusal.stderr
            print(mode, 'public proofs, payments, kernel, sealed inference and changed-intent refusal passed')
    summary = read(root / 'RESULT.json')
    assert not summary['privacyGatePassed'] and not summary['costWorkStarted']
    print(len(seen), 'public hashes checked; private owner-truth scoring remains a separate retained control')

if __name__ == '__main__':
    main()

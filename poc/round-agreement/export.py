#!/usr/bin/env python3
"""Copy only reviewed public evidence; leave wallet and issuer secrets private."""
import argparse, hashlib, json, pathlib, shutil

def main():
    p = argparse.ArgumentParser()
    p.add_argument('private_run', type=pathlib.Path)
    p.add_argument('new_public_output', type=pathlib.Path)
    a = p.parse_args()
    src, dst = a.private_run.resolve(), a.new_public_output.resolve()
    dst.mkdir()

    def copy(path, rel):
        assert path.is_file() and not path.is_symlink(), path
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

    for name in ('SOURCE-FREEZE.json', 'EXTRA-SOURCE-FREEZE.json', 'IMAGE.json'):
        copy(src / name, name)
    copy(src / 'CONTROLS.json', 'CONTROLS.json')
    for name in ('honest', 'tagged', 'staggered'):
        arm = src / name
        for file in ('RESULT.json', 'ISOLATION.json'):
            copy(arm / file, f'{name}/{file}')
        for file in ('config.json',):
            copy(arm / 'service/round' / file, f'{name}/view/{file}')
        if (arm / 'service/configs.json').exists():
            copy(arm / 'service/configs.json', f'{name}/view/configs.json')
        copy(arm / 'service/operator.jsonl', f'{name}/view/operator.jsonl')
        for i in range(5):
            copy(arm / f'state-{i}.json', f'{name}/payments/state-{i}.json')
        for i in range(4):
            copy(arm / f'payment-{i}.json', f'{name}/payments/payment-{i}.json')
        if name != 'tagged':
            for file in ('KERNEL.json', 'PREDICTION-SEAL.json'):
                copy(arm / file, f'{name}/{file}')
            copy(arm / 'prediction/PREDICTION.json', f'{name}/PREDICTION.json')
            for file in ('operator.jsonl', 'intent.json', 'approvals.json', 'state.json',
                         'service-schedule.json'):
                path = arm / 'observer-view' / file
                if path.exists():
                    copy(path, f'{name}/view/{file}')
    for path in (src / 'producing-source').rglob('*'):
        if path.is_file() and path.suffix in ('.py', '.rs', '.md', '.toml') and path.name != 'run.py':
            copy(path, pathlib.Path('producing-source') / path.relative_to(src / 'producing-source'))
    results = [json.loads((dst / name / 'RESULT.json').read_text()) for name in
               ('honest', 'tagged', 'staggered')]
    assert results[0]['compatibleMappings'] == 6 and results[1]['walletRejections'] == 3
    assert results[2]['exactCorrectOwnerKeyLinks'] == 3
    (dst / 'RESULT.json').write_text(json.dumps({
        'arms': results, 'privacyGatePassed': False, 'costWorkStarted': False,
        'conclusion': 'common-round enforcement blocks round tags but reply timing links all payouts',
        'twoMachineRunCompleted': False
    }, indent=2) + '\n')
    selected = []
    forbidden = ('"blindSecret"', '"nativeSecretKey"', '"wallet":', '"funding":',
                 '"payouts":{')
    for path in sorted(dst.rglob('*')):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if path.suffix in ('.json', '.jsonl') and 'producing-source' not in path.parts:
            assert not any(f in raw.decode() for f in forbidden), path
        selected.append({'path': str(path.relative_to(dst)), 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()})
    (dst / 'MANIFEST.json').write_text(json.dumps({
        'files': selected, 'privateOwnerTruthIncluded': False,
        'walletBackupsBlindingIssuerTorSecretsOrProvingParametersIncluded': False,
        'scope': 'offline same-host role proofs and service wire logs; no accepted native transaction',
        'exactDriverEpochRetainedPrivately': True
    }, indent=2) + '\n')
    print(len(selected), 'public files exported')

if __name__ == '__main__':
    main()

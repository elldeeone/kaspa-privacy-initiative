#!/usr/bin/env python3
"""Export a finite public allowlist; never copy wallet or issuer private files."""
import argparse, hashlib, json, pathlib, shutil

def main():
    p = argparse.ArgumentParser()
    p.add_argument('private_run', type=pathlib.Path)
    p.add_argument('new_public_output', type=pathlib.Path)
    a = p.parse_args()
    src, dst = a.private_run.resolve(), a.new_public_output.resolve()
    dst.mkdir()
    arm = src / 'board'

    def copy(path, rel):
        assert path.is_file() and not path.is_symlink(), path
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

    for name in ('SOURCE-FREEZE.json', 'IMAGE.json', 'RESULT.json'):
        copy(src / name, name)
    for name in ('RESULT.json', 'ISOLATION.json', 'GUARD-CONTROLS.json',
                 'EXTRA-CONTROLS.json', 'BOARD-PUBLICATION.json', 'KERNEL.json',
                 'PREDICTION-SEAL.json', 'REPLAY.json'):
        copy(arm / name, f'board/{name}')
    copy(arm / 'prediction/PREDICTION.json', 'board/PREDICTION.json')
    copy(arm / 'service/round/bundle.json', 'board/view/bundle.json')
    for name in ('config.json', 'operator.jsonl', 'intent.json', 'approvals.json', 'state.json'):
        copy(arm / 'observer-view' / name, f'board/view/{name}')
    for i in range(5):
        copy(arm / f'state-{i}.json', f'board/payments/state-{i}.json')
    for i in range(4):
        copy(arm / f'payment-{i}.json', f'board/payments/payment-{i}.json')
    selected = []
    forbidden = ('"blindSecret"', '"nativeSecretKey"', '"funding":',
                 '"payouts":{', '"private/issuer.der"')
    for path in sorted(dst.rglob('*')):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if path.suffix in ('.json', '.jsonl'):
            assert not any(marker in raw.decode() for marker in forbidden), path
        selected.append({'path': str(path.relative_to(dst)), 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()})
    (dst / 'MANIFEST.json').write_text(json.dumps({
        'files': selected, 'privateOwnerTruthIncluded': False,
        'walletBackupsBlindingIssuerTorSecretsOrProvingParametersIncluded': False,
        'scope': 'same-host offline atomic-publication simulation; no native accepted transaction',
        'originalProducerEpochRetainedPrivately': True
    }, indent=2) + '\n')
    print(len(selected), 'public files exported')

if __name__ == '__main__':
    main()

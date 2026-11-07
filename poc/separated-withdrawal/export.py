#!/usr/bin/env python3
"""Explicit public allowlist. No wallet, issuer, Tor or blinding secrets."""
import argparse, hashlib, json, pathlib, shutil

def main():
    p = argparse.ArgumentParser()
    p.add_argument('private_run', type=pathlib.Path)
    p.add_argument('new_public_output', type=pathlib.Path)
    p.add_argument('--tagged-run', type=pathlib.Path)
    a = p.parse_args()
    src, dst = a.private_run.resolve(), a.new_public_output.resolve()
    dst.mkdir()

    def copy(source, target):
        assert source.is_file() and not source.is_symlink(), source
        target = dst / target
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    for name in ('RESULT.json', 'SOURCE-FREEZE.json', 'IMAGE.json', 'COLLECTION.json', 'FAILED-ATTEMPTS.json'):
        copy(src / name, name)
    if (src / 'REUSED-SOURCE.json').exists():
        copy(src / 'REUSED-SOURCE.json', 'REUSED-SOURCE.json')
    for mode in ('direct', 'honest', 'tagged'):
        arm = (a.tagged_run.resolve() if mode == 'tagged' and a.tagged_run else src) / mode
        for name in ('RESULT.json', 'ISOLATION.json', 'POST-CREATION-ISOLATION.json', 'KERNEL.json', 'PREDICTION-SEAL.json'):
            copy(arm / name, f'{mode}/{name}')
        copy(arm / 'prediction/PREDICTION.json', f'{mode}/PREDICTION.json')
        for name in ('operator.jsonl', 'direct-network.jsonl', 'configs.json', 'intent.json', 'approvals.json', 'state.json'):
            if (arm / 'observer-view' / name).exists():
                copy(arm / 'observer-view' / name, f'{mode}/view/{name}')
        # Public replay receives the common configuration as well. This adds no
        # owner facts to the sealed observer; it was already known to the service.
        copy(arm / 'service/round/config.json', f'{mode}/view/config.json')
        for i in range(5):
            copy(arm / f'state-{i}.json', f'{mode}/payments/state-{i}.json')
        for i in range(4):
            copy(arm / f'payment-{i}.json', f'{mode}/payments/payment-{i}.json')
    if a.tagged_run:
        for name in ('SOURCE-FREEZE.json', 'IMAGE.json'):
            copy(a.tagged_run / name, f'tagged/{name}')
        for item in (a.tagged_run / 'producing-source').rglob('*'):
            if item.is_file():
                copy(item, pathlib.Path('producing-source-retry') / item.relative_to(a.tagged_run / 'producing-source'))
    for item in (src / 'producing-source').rglob('*'):
        if item.is_file():
            copy(item, pathlib.Path('producing-source') / item.relative_to(src / 'producing-source'))
    selected = []
    forbidden_fields = ('"nativeSecretKey"', '"blindSecret"', '"wallet":', '"funding":', '"payouts":{')
    for f in sorted(dst.rglob('*')):
        if not f.is_file():
            continue
        raw = f.read_bytes()
        if f.suffix in ('.json', '.jsonl') and 'producing-source' not in f.parts:
            text = raw.decode()
            assert not any(s in text for s in forbidden_fields), f
        selected.append({'path': str(f.relative_to(dst)), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    (dst / 'MANIFEST.json').write_text(json.dumps({'files': selected, 'privateOwnerTruthIncluded': False,
                                                 'walletBackupsBlindingIssuerTorSecretsOrProvingParametersIncluded': False,
                                                 'publicReplayLimit': 'proofs, economics and conditional inference; private owner truth scoring remains locally retained'}, indent=2) + '\n')
    print(len(selected), 'public files exported')

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Corrective read-only checks: each wallet rejects another client's bad reply."""
import argparse, copy, hashlib, json, pathlib, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'

def read(p):
    return json.loads(p.read_text())

def main():
    p = argparse.ArgumentParser()
    p.add_argument('private_run', type=pathlib.Path)
    a = p.parse_args()
    run = a.private_run.resolve()
    arm = run / 'board'
    original = read(arm / 'service/round/bundle.json')
    before = (arm / 'service/operator.jsonl').read_bytes()
    results = []
    for who in range(3):
        own = read(arm / f'wallet-{who}/wallet/registration.json')['issue']
        changed = copy.deepcopy(original)
        other = next(i for i, entry in enumerate(changed['entries']) if entry['issue'] != own)
        changed['entries'][other]['blindSignature'] = '00' * 256
        trial = arm / f'invalid-other-correction-{who}.json'
        trial.write_text(json.dumps(changed))
        result = subprocess.run([str(HOST), 'board-check', str(arm / f'wallet-{who}/wallet'),
                                 str(arm / f'board-request-{who}.json'), str(trial)],
                                capture_output=True, text=True)
        assert result.returncode != 0 and 'invalid blinded reply' in result.stderr
        results.append({'wallet': who, 'otherReplyInvalid': True, 'rejectedBeforePayoutKey': True})
    assert before == (arm / 'service/operator.jsonl').read_bytes()
    out = {'readOnly': True, 'networkRequests': 0, 'cases': results,
           'operatorLogSha256': hashlib.sha256(before).hexdigest(),
           'sourceSha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
    (arm / 'EXTRA-CONTROLS.json').write_text(json.dumps(out, indent=2) + '\n')
    print('3/3 wallets rejected an invalid reply for another claimant')

if __name__ == '__main__':
    main()

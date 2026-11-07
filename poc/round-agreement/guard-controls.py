#!/usr/bin/env python3
"""Read-only mutation checks against a real wallet's issued claim."""
import copy, json, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'

def read(path):
    return json.loads(path.read_text())

def main():
    arm = pathlib.Path(sys.argv[1]).resolve()
    output = pathlib.Path(sys.argv[2]).resolve()
    wallet = arm / 'wallet-0/wallet'
    registration = read(wallet / 'registration.json')
    response = read(wallet / 'issue-response.json')
    config = read(arm / 'service/round/config.json')
    assert len(response['cohortIssues']) == 3
    base = {'method': 'registration-redeem', 'config': config}
    cases = []
    def add(name, mutation):
        request, reply = copy.deepcopy(base), copy.deepcopy(response)
        mutation(request, reply)
        cases.append((name, request, reply))

    add('genuine complete cohort', lambda _r, _v: None)
    add('missing claim', lambda _r, v: v['cohortIssues'].pop())
    add('duplicate claim', lambda _r, v: v['cohortIssues'].__setitem__(1, v['cohortIssues'][0]))
    add('different round', lambda r, _v: r['config']['round'].__setitem__(0, r['config']['round'][0] ^ 1))
    add('wrong issuer', lambda r, _v: r['config']['issuer'].__setitem__(0, r['config']['issuer'][0] ^ 1))
    add('wrong state', lambda r, _v: r['config'].__setitem__('stateBincodeHex', read(arm / 'state-0.json')['state']))
    add('wrong value', lambda r, _v: r['config'].__setitem__('principalSompi', r['config']['principalSompi'] + 1))
    def change_blind(_r, v):
        original = v['cohortIssues'][1]['blindMessage']
        v['cohortIssues'][1]['blindMessage'] = ('0' if original[0] != '0' else '1') + original[1:]
    add('altered blind request', change_blind)
    def change_proof(_r, v):
        proof = v['cohortIssues'][1]['operation']['proof']
        proof[0] ^= 1
    add('forged proof', change_proof)
    add('malformed cohort', lambda _r, v: v.__setitem__('cohortIssues', {}))

    results = []
    with tempfile.TemporaryDirectory(prefix='kpi-cohort-controls-', dir=ROOT / '.local') as temporary:
        scratch = pathlib.Path(temporary)
        for i, (name, request, reply) in enumerate(cases):
            directory = scratch / str(i)
            directory.mkdir(mode=0o700)
            (directory / 'registration.json').write_text(json.dumps(registration))
            (directory / 'issue-response.json').write_text(json.dumps(reply))
            request_file = directory / 'request.json'
            request_file.write_text(json.dumps(request))
            result = subprocess.run([HOST, 'agreement-check', directory, request_file],
                                    capture_output=True, text=True)
            expected = i == 0
            assert (result.returncode == 0) == expected, (name, result.stderr)
            results.append({'case': name, 'accepted': expected, 'walletCheckMatchedExpectation': True})
    output.write_text(json.dumps({'readOnly': True, 'actualWalletClaim': True,
                                  'networkRequests': 0, 'cases': results}, indent=2) + '\n')
    print(len(results), 'real-wallet cohort checks matched expectation')

if __name__ == '__main__':
    main()

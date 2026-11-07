#!/usr/bin/env python3
"""Service-only predictions. This process receives NO owner-key scoring truth."""
import argparse, hashlib, itertools, json, pathlib

def observe(root):
    rows = [json.loads(s) for s in (root / 'operator.jsonl').read_text().splitlines()]
    good = [r for r in rows if 'error' not in r['response']]
    issues = [r for r in good if r['request']['kind'] == 'issue']
    redeems = [r for r in good if r['request']['kind'] == 'redeem']
    assert len(issues) == len(redeems) == 3
    nf = lambda r: bytes(r['request']['operation']['statement']['nullifier']).hex()
    key = lambda r: r['response']['recipientKey']
    claims, keys = sorted(map(nf, issues)), sorted(map(key, redeems))
    facts = {}
    # Genuine socket-source control, without a driver-provided owner/key map.
    if (root / 'direct-network.jsonl').exists():
        network = [json.loads(l) for l in (root / 'direct-network.jsonl').read_text().splitlines()]
        sources = {nf(r): r['peer'] for r in network if r['request']['kind'] == 'issue'}
        recipients = {r['peer']: key(r) for r in network if r['request']['kind'] == 'redeem'}
        facts.update({c: recipients[s] for c, s in sources.items()})
    # Reconstruct tags from actual wire fields and the issuer's own config,
    # without inserted owner labels or an attack-only response field.
    if (root / 'configs.json').exists():
        configs = json.loads((root / 'configs.json').read_text())
        prefix = b'KPI-anonymous-eligibility-v1\0'
        for issue in issues:
            s = issue['request']['operation']['statement']
            matches = []
            for cfg in configs:
                raw = prefix + bytes(cfg['round']) + bytes(cfg['issuer']) + bytes(s['nullifier']) + bytes.fromhex(issue['request']['blindMessage'])
                if list(hashlib.sha256(raw).digest()) == s['exit_destination']:
                    matches.append(bytes(cfg['round']))
            assert len(matches) == 1
            tag = matches[0]
            matches = [key(r) for r in redeems if bytes.fromhex(r['request']['message'])[len(prefix):len(prefix)+32] == tag]
            assert len(matches) == 1
            facts[nf(issue)] = matches[0]
    candidates = [dict(zip(claims, p)) for p in itertools.permutations(keys)]
    candidates = [p for p in candidates if all(p[c] == k for c, k in facts.items())]
    assert candidates
    # A single timing guess is a hypothesis, not an equality constraint.
    timing = dict(zip(map(nf, issues), map(key, redeems)))
    return {'exactServiceFacts': facts, 'compatibleMappings': candidates,
            'compatibleMappingCount': len(candidates), 'issueRedemptionRankGuess': timing,
            'serviceLogRows': len(rows), 'sourceAddresses': sorted(set(r['peer'].split(':')[0] for r in good)),
            'truthFilesRead': False, 'amountsHidden': False,
            'scope': 'fixed three claimant roles; blindness assumed, no statistical anonymity claim'}

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('service_view', type=pathlib.Path)
    p.add_argument('new_prediction', type=pathlib.Path)
    a = p.parse_args()
    with a.new_prediction.open('x') as f:
        json.dump(observe(a.service_view), f, indent=2)
        f.write('\n')

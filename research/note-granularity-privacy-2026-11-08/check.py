#!/usr/bin/env python3
"""Independent whole-KAS search and public-payload negative controls."""
import json
from pathlib import Path

import attack

HERE = Path(__file__).resolve().parent
U = attack.UNIT


def values(rows):
    return {tuple(row['amountsSompi'][name] for name in attack.LABELS) for row in rows}


def brute(merge):
    # Search every positive whole-KAS transfer consistent with one-input
    # transfers, group note exits, later B/C notes and D's final 3-KAS note.
    found = set()
    for x in range(2, 40):
        for y in range(1, x):
            for z in range(1, 40 - x):
                for w in range(1, z):
                    t = z - w - 7  # D sends B=1 and C=3, then retains 3.
                    if t < 1:
                        continue
                    row = (x * U, y * U, z * U, w * U, U, 3 * U, t * U)
                    for choice in ('old', 'received'):
                        if attack.replay(row, choice, merge):
                            found.add(row)
    return found


def main():
    assert attack.public_audit() == attack.read(HERE / 'PUBLIC-AUDIT.json')
    p = attack.read(HERE / 'PREDICTION.json')
    result = attack.read(HERE / 'RESULT.json')
    assert p['publicAuditSha256'] == attack.sha(HERE / 'PUBLIC-AUDIT.json')
    assert result['predictionSha256'] == attack.sha(HERE / 'PREDICTION.json')
    baseline = values(attack.read(HERE / 'BASELINE-CANDIDATES.json'))
    merged = values(attack.read(HERE / 'MERGE-WHOLE-CANDIDATES.json'))
    assert brute(False) == baseline and brute(True) == merged
    assert len(baseline) == len(merged) == 4
    truth = attack.read(attack.ROOT / 'research/matched-payment-privacy-2026-11-08/TRUTH.json')
    actual = tuple(truth[name] for name in attack.LABELS)
    assert actual in baseline and actual in merged
    assert (actual[0] + 1,) + actual[1:] not in baseline
    main = attack.read(attack.RUN / 'combined/MAIN.json')
    payload = main['records'][1]['transaction']['payload']
    assert attack.packet(payload)['mode'] == 1
    try:
        attack.packet(payload[:-2])
    except ValueError:
        pass
    else:
        raise AssertionError('truncated packet accepted')
    assert result['mergeImplementationGatePassed'] is False
    assert result['completeCostCampaignGatePassed'] is False
    print('public payload audit, exhaustive whole-KAS search, truth and negative controls pass')


if __name__ == '__main__':
    main()

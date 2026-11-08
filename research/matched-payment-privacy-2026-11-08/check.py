#!/usr/bin/env python3
"""Read-only positive and negative checks for the frozen matched screen."""
import copy
import json
import subprocess
import tempfile
from pathlib import Path

import compare

HERE = Path(__file__).resolve().parent


def main():
    assert all(compare.digest(compare.SOURCE / name) == sha
               for name, sha in compare.PINS.items())
    prediction = compare.read(HERE / 'PREDICTION.json')
    result = compare.read(HERE / 'RESULT.json')
    board = compare.read(HERE / 'BOARD.json')
    truth = compare.read(HERE / 'TRUTH.json')
    assert prediction['board']['sha256'] == compare.digest(HERE / 'BOARD.json')
    assert prediction['board']['bytes'] == (HERE / 'BOARD.json').stat().st_size < 24_000
    assert result['predictionSha256'] == compare.digest(HERE / 'PREDICTION.json')
    assert prediction['balanceNecessaryRangesSompi'] == compare.amounts(
        prediction['principalSompi'], prediction['groupPayoutsSompi'],
        prediction['knownOwnerFinalPrincipalSompi'])[0]
    assert compare.model(tuple(truth[name] for name in compare.LABELS),
                         prediction['principalSompi'], prediction['groupPayoutsSompi'],
                         prediction['knownOwnerFinalPrincipalSompi'])
    # The amount calculation above does not read the board or service log.
    assert not compare.model((truth['A_to_B'] + 1,) +
                             tuple(truth[name] for name in compare.LABELS[1:]),
                             prediction['principalSompi'], prediction['groupPayoutsSompi'],
                             prediction['knownOwnerFinalPrincipalSompi'])
    with tempfile.TemporaryDirectory(prefix='kpi-matched-payment-check-') as name:
        trial = Path(name) / 'board.json'
        cmd = [str(compare.HOST), 'board-public-check',
               str(compare.SOURCE / 'registration/config.json'), str(trial)]
        trial.write_text(json.dumps(board, separators=(',', ':')))
        assert subprocess.run(cmd, capture_output=True).returncode == 0
        damaged = copy.deepcopy(board)
        damaged['entries'][0]['blindSignature'] = '00' * 256
        trial.write_text(json.dumps(damaged, separators=(',', ':')))
        assert subprocess.run(cmd, capture_output=True).returncode != 0
        partial = dict(board, entries=board['entries'][:2])
        trial.write_text(json.dumps(partial, separators=(',', ':')))
        assert subprocess.run(cmd, capture_output=True).returncode != 0
    assert result['exactActualAmountsFromNecessaryBalances'] == []
    assert result['exactActualAmountsOnAuxiliaryWholeKASGrid'] == ['D_to_B_after_group']
    assert result['stopBundleEscalationForPaymentPrivacy'] is True
    print('pinned sources, prediction seal, real truth, board verifier and three negative controls pass')


if __name__ == '__main__':
    main()

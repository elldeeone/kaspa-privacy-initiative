#!/usr/bin/env python3
"""Cold one-backup orchestration; unchanged reviewed wallet does all key work.

Position selection comes from the freshly replayed recognized claims, never
from an operator payment map. This wrapper contains no RPC or broadcast API.
"""
from pathlib import Path
import json
import sys

sys.path.insert(0, '/app/poc/independent-recovery')
import wallet
from replay import replay


def run(request):
    wallet.require(type(request) is dict, 'cold-request-object')
    op = request.get('op')
    base = {'op', 'backup_path', 'descriptor_path', 'expected_descriptor_sha256',
            'fetch_path', 'crypto_path'}
    extra = {'disclosure_consent', 'native_helper_path',
             'fee_rate_sompi_per_mass', 'output_dir'}
    wallet.require(op in ('recover', 'prepare-reveal')
                   and set(request) == base | (extra if op == 'prepare-reveal' else set()),
                   'cold-request-fields')
    if op == 'prepare-reveal':
        # Root's explicit research-role disclosure consent is recorded before
        # this process starts. Reject before even looking up private input.
        wallet.require(request['disclosure_consent'] == wallet.DISCLOSURE_CONSENT,
                       'explicit-reveal-consent-required')
    crypto = wallet.runtime_crypto(request['crypto_path'])
    descriptor = wallet.parse_json(Path(request['descriptor_path']).read_bytes())
    selected = wallet.descriptor_identity(descriptor)
    wallet.require(wallet.exact(request['expected_descriptor_sha256'], 32).hex() == selected,
                   'user-selected-descriptor-pin-mismatch')
    fetched = wallet.parse_json(Path(request['fetch_path']).read_bytes())
    public = replay(descriptor, fetched)
    wallet.snapshot_from_replay(descriptor, public)
    seed = wallet.load_backup(request['backup_path'], descriptor)
    summary, receiver, recovered, expected, snapshot = wallet.recognize(
        descriptor, public, seed, crypto)
    actionable = sorted(claim.position for claim in recovered.owned
                        if claim.owner_action_available)
    summary['recognized_actionable_positions'] = actionable
    summary['backup_read_count_by_orchestrator'] = 1
    if op == 'recover':
        return summary
    wallet.require(bool(actionable), 'recognized-unspent-claim-required')
    selected_request = dict(request, position=actionable[0])
    result = wallet.prepare_reveal(selected_request, descriptor, public, receiver,
                                   recovered, expected, snapshot)
    result['position_selected_from_recognized_claims'] = actionable[0]
    result['selection_rule'] = 'First recognized actionable public position in ascending order'
    result['backup_read_count_by_orchestrator'] = 1
    result['recognition'] = summary
    return result


if __name__ == '__main__':
    try:
        request = wallet.parse_json(Path(sys.argv[1]).read_bytes())
        wallet.require(request.get('op') == sys.argv[2], 'cold-mount-operation-mismatch')
        result = run(request)
    except wallet.Invalid as error:
        print(json.dumps({'passed': False, 'error': str(error)}))
        raise SystemExit(1)
    except Exception:
        # No exception value or traceback can accidentally print private data.
        print(json.dumps({'passed': False, 'error': 'cold-client-failed'}))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))

#!/usr/bin/env python3
"""Correct the public schema label on an already sealed active count report.

The original stays immutable. This reads no owner record, prediction capsule or
count leaf and changes no score, inference rule, threshold or evidence class.
"""
import hashlib
from pathlib import Path

from runtime import canonical, parse, read, write_new

ROOT = Path('/var/tmp/kpi-sender-private-lifecycle-01/public/active-retry-03')
WRONG = 'kpx9-active-query-context/v1'
RIGHT = 'kpx9-actual-active-intersection-global-counts/v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    original = read(ROOT / 'final/RESULT.json')
    report = parse(original)
    expected = {'schema', 'stratum', 'experiment_sha256', 'view_sha256',
                'prediction_seal_sha256', 'cases', 'active_candidate_failed',
                'financial_proofs_or_backing_verified', 'privacy_qualified',
                'original_private_contents_read', 'private_owner_or_NF_associations_exported'}
    assert set(report) == expected and report['schema'] == WRONG
    assert report['stratum'] == 'MPC_WIRE_FIXTURE_ACTIVE_INTERSECTION'
    assert report['financial_proofs_or_backing_verified'] is False
    assert report['privacy_qualified'] is False
    assert report['original_private_contents_read'] is False
    assert report['private_owner_or_NF_associations_exported'] is False
    selection = parse(read(ROOT / 'SELECTION.json'))
    assert report['experiment_sha256'] == selection['experiment_sha256']
    for source in selection['source']:
        assert sha(read(Path(source['path']))) == source['sha256']
    closure = parse(read(ROOT / 'QUERY-CLOSED.json'))
    assert closure['prediction_seal_sha256'] == report['prediction_seal_sha256']
    assert len(report['cases']) == 2 and set(report['cases']) == {'overlap', 'same_cohort'}
    for case in report['cases'].values():
        assert set(case) == {'known_colluder_excluded', 'owner_verified_matches',
                             'unique_predictions', 'unknown_eligible'}
        assert all(type(value) is int and value >= 0 for value in case.values())
        assert case['owner_verified_matches'] <= case['unique_predictions'] <= case['unknown_eligible']
    corrected = dict(report, schema=RIGHT)
    assert {key for key in report if report[key] != corrected[key]} == {'schema'}
    raw = canonical(corrected)
    write_new(ROOT / 'final/RESULT-CORRECTED.json', raw)
    receipt = {'schema': 'kpx9-public-schema-label-correction/v1',
               'original_sha256': sha(original), 'corrected_sha256': sha(raw),
               'source_sha256': sha(read(Path(__file__).resolve())),
               'changed_fields': ['schema'], 'original_schema': WRONG,
               'corrected_schema': RIGHT, 'private_material_read': False,
               'scores_or_candidate_decisions_changed': False}
    write_new(ROOT / 'final/CORRECTION.json', canonical(receipt))
    print(canonical(receipt).decode(), end='')


if __name__ == '__main__':
    main()

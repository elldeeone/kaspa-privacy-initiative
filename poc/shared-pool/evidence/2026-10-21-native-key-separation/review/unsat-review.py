#!/usr/bin/env python3
"""Post-run public-only review; never reads backup or private truth files."""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evaluation', type=Path, required=True)
    parser.add_argument('--public-root', type=Path, required=True)
    args = parser.parse_args()
    evaluation, public_root = args.evaluation.resolve(), args.public_root.resolve()
    completion = read(evaluation / 'completion.json')
    assert completion['complete'] is True, 'review requires completed evaluation'
    frozen = read(evaluation / 'freeze.json')
    assert frozen['schema'] == 'kpi-native-key-separation-evaluation-freeze-v1'
    for name, digest in frozen['sources'].items():
        assert sha(evaluation / 'code' / name) == digest, name
    assert frozen['sources']['address_reuse_observer.py'] == 'e157540aef57153909dd2558c853b8381a2bb1260d9e7fdc3ba613618a05a9a9'
    sys.path.insert(0, str(evaluation / 'code'))
    observer = importlib.import_module('address_reuse_observer')
    cases = [('historical-positive', evaluation / 'historical-positive')]
    cases += [(name, public_root / (name + '-03-drained')) for name in
              ('v2-same-index', 'v2-different-index', 'legacy-v1-same-index')]
    checks, boundary_checks = [], []
    for name, inputs in cases:
        prediction_path = evaluation / 'runs' / (name + '-observe') / 'result.json'
        prediction = read(prediction_path)
        raw, directory = observer.load_public(inputs)
        assert prediction['public_sha256'] == observer.full.digest(raw)
        assert prediction['directory_sha256'] == observer.full.digest(directory)
        projection = observer.surface.project(raw)
        relation = observer._relation(projection, directory)
        # Compare actual selected native parent outputs directly, independently
        # of the prediction's comparison booleans and inferred role map.
        parents = {row['id']: row for row in raw['parents']}
        lineage = raw['lineage']
        points = [lineage[0]['inputs'][0]['previousOutpoint']]
        for tx in lineage[1:]:
            if len(tx['inputs']) == 2:
                points.append(tx['inputs'][1]['previousOutpoint'])
        assert len(points) == 2 and len(lineage[-1]['outputs']) == 1
        expected = []
        for point in points:
            selected = parents[point['transactionId']]['outputs'][point['index']]['scriptPublicKey']
            expected.append(selected == lineage[-1]['outputs'][0]['scriptPublicKey'])
        assert expected == ([False, True] if name in ('historical-positive', 'legacy-v1-same-index') else [False, False])
        assert [r['equal'] for r in prediction['boundary']['comparisons']] == expected
        boundary_checks.append(dict(case=name, selected_script_equalities=expected,
                                    prediction_sha256=sha(prediction_path)))
        for row in prediction['rows']:
            selected = observer._prefix(relation, row['through_event'], row['script_association_used'])
            assert row['relation_sha256'] == observer.full.digest(selected)
            forced = [field for field in ('sender', 'recipient', 'amount') if row[field]['forced']]
            if not forced:
                continue
            assert name in ('historical-positive', 'legacy-v1-same-index')
            assert row['horizon'] == 'final' and row['script_association_used'] is True
            model = observer.NativePair(selected)
            for field in forced:
                value = row[field]['candidate']
                cp, smt = model.variables(row['event'], field)
                statuses = {}
                for engine, variable in (('cp_sat', cp), ('z3', smt)):
                    # Unrestricted searches over all hidden variables, with only
                    # this field fixed/excluded. No witness or truth pins.
                    assert model.query(engine, [variable == value]) is not None
                    assert model.query(engine, [variable != value]) is None
                    statuses[engine] = dict(candidate='SAT', different='UNSAT')
                checks.append(dict(case=name, field=field, candidate=value, checked=statuses))
    assert len(checks) == 6
    print(json.dumps(dict(passed=True, scope='Public script comparison and independent rerun of unrestricted original-model candidate/negation queries; no private truth',
        freeze_sha256=sha(evaluation / 'freeze.json'), reviewer_sha256=sha(Path(__file__)),
        cases=boundary_checks, forced_facts=len(checks), unrestricted_solver_queries=4*len(checks), checks=checks), indent=2))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('assertion checks must be enabled')
    main()

#!/usr/bin/env python3
"""Mechanical aggregation only: no generation, attacker or truth-scoring calls.

The original controller saved score.json, then its dict(...,complete=True,
**result) raised because result also contained complete. Reuse its exact frozen
aggregate() on sealed score JSON with a single unambiguous metadata merge.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

PACKET=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/observer/population-01')


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    freeze=json.loads((PACKET/'AGGREGATION-REPAIR-FREEZE.json').read_text())
    for row in freeze['pins']:
        p=Path(row['path'])
        if p.stat().st_size!=row['bytes'] or sha(p)!=row['sha256']:
            raise ValueError('repair immutable input/source mismatch')
    spec=importlib.util.spec_from_file_location('original_frozen_controller',Path(freeze['aggregate_source']))
    original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
    rows=[]
    for item in freeze['cases']:
        score=json.loads(Path(item['score']).read_text())
        status=json.loads(Path(item['status']).read_text())
        # No outcome is recalculated. Preserve actual per-case completeness.
        if score.get('complete') is True:
            rows.append(dict(score,directory=item['directory'],cluster=status['cluster'],
                             score_file_sha256=sha(Path(item['score']))))
        else:
            rows.append(dict(directory=item['directory'],complete=False,
                             failure='sealed per-case score incomplete',original_score=score))
    result=original.aggregate(rows)
    result['aggregation_repair']=dict(original_summary_sha256=freeze['original_summary_sha256'],
        original_failure="dict() got multiple values for keyword argument 'complete'",
        scope='Metadata merge only; original frozen aggregate function and original sealed scores.',
        generation_rerun=False,attacker_rerun=False,truth_scoring_rerun=False)
    target=PACKET/'run/REPAIRED-RESULT.json'
    if target.exists(): raise ValueError('one aggregation repair only; existing result preserved')
    target.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    receipt=dict(schema='kpx3-aggregation-repair-execution/v1',
        original_model_batches=1,aggregation_repairs=1,original_inputs_unchanged=True,
        generated_or_classified_or_scored_cases=0,completed_sealed_scores=result['completed_cases'],
        result_sha256=sha(target),repair_freeze_sha256=sha(PACKET/'AGGREGATION-REPAIR-FREEZE.json'))
    (PACKET/'run/REPAIR-EXECUTION.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')


if __name__=='__main__': main()

#!/usr/bin/env python3
# Explicit public derivative: two original host path constants replaced.
# Original SHA256: dd81c729aaced2aa5fdfdbd9b9ce66846b35617026d5fdab2ea6ccc4aa47bb28
"""Review only public source/input files and safe completed-run metadata."""
import hashlib
import json
from pathlib import Path
from datetime import datetime

NATIVE=Path('/retained-native-trial')
EVAL=Path('/retained-evaluation')
OUT=Path('/tmp/kpi-key-separation-integrity-review.json')

def load(p): return json.loads(p.read_text())
def sha(p):
    with p.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()
def time(s): return datetime.fromisoformat(s)

r=load(NATIVE/'native-result.json'); before=load(NATIVE/'candidate-hashes-before.json'); after=load(NATIVE/'candidate-hashes-after.json')
assert r['complete'] is True and r['proof_count']==len(r['operations'])==10
assert r['genuine_groth16_proofs'] is True and r['chain_acceptance_verified'] is False
assert r['founder_original_backup_unchanged'] is True
assert before['base_commit']=='b62cfd1910d77f9962882b1088d6cc718e7df1b2'
assert 'uncommitted' in before['tested_revision']
assert after['unchanged'] is True and set(before['files'])==set(after['files'])
for name,entry in before['files'].items():
    p=(NATIVE/entry['copy']).resolve()
    assert p.is_relative_to(NATIVE/'software'), 'only copied public source/binary artifacts'
    assert p.stat().st_size==entry['bytes'] and sha(p)==entry['sha256']==after['files'][name]
assert sha(NATIVE/'tracked-source.patch')==before['tracked_patch_sha256']==after['tracked_patch_sha256']
assert before['source_manifest_sha256']==hashlib.sha256(json.dumps(before['files'],sort_keys=True).encode()).hexdigest()
assert before['files']['binary/legacy-wallet']['sha256']=='1b95101d84434d2f8598d6bdd4c2a15964f7fa25fb54da313344dd5cf0d514ed'
assert len(r['isolation'])==45
for row in r['isolation']:
    assert row['host_home_visible'] is False and row['network_interfaces']==['lo'] and row['controller_directory_visible'] is False
# Validate safe rejection reasons; no private process logs are opened.
control_expected={}
for arm in ('v2-same-index','v2-different-index','legacy-v1-same-index'):
    control_expected[arm+'-admission-admit-invalid-request']='funding output is not owned by this wallet/key index'
    control_expected[arm+'-fresh-recovery-exit-exit-invalid-request']='exit key index must equal the lowest selected position'
helper_names={a+'-reject-exit-purpose-funding' for a in ('v2-same-index','v2-different-index')}
assert len(r['controls'])==8 and {x['name'] for x in r['controls']}==set(control_expected)|helper_names
for control in r['controls']:
    assert control['rejected'] is True
    if control['name'] in control_expected:
        assert control['error']==control_expected[control['name']]
    else:
        assert 'error' not in control, 'reason supplied separately for helper rejection'
helper=load(NATIVE/'review-control-reasons.json')
assert helper['both_wrong_purpose_controls_rejected_for_expected_reason'] is True
assert {x['arm'] for x in helper['rows']}=={'v2-same-index','v2-different-index'}
message='two-input offline lifecycle: funding output is not owned by this wallet/key index'
for row in helper['rows']:
    assert row['expected_error']==message and row['exact_message_match'] is True
    assert row['stderr_sha256']==hashlib.sha256((message+'\n').encode()).hexdigest()
# Check every new observer input against its source and seal; never load truth.
prepared=load(EVAL/'preparation.json'); complete=load(EVAL/'completion.json'); batch=load(EVAL/'prediction-batch.json')
assert complete['complete'] is True and complete['privacy_qualification'] is False
assert sha(EVAL/'freeze.json')==r['evaluation_freeze_sha256']==prepared['freeze_sha256']
assert sha(EVAL/'preparation.json')==r['evaluation_preparation_sha256']
assert sha(EVAL/'prediction-batch.json')=='f5ea751e217b0b5a4d3caa5aa15e0e52e5bc83468408dacf21e3a0c8e6d21c69'==complete['prediction_batch_sha256']
assert len(batch['records'])==3 and batch['complete'] is True and batch['scoring_started'] is False
public_names={'descriptor.json','vk.bin','lineage.json','parents.json','funding_owner_directory.json'}
case_reviews=[]; earliest_score=None
for arm,record,scored in zip(r['arms'],batch['records'],complete['scores'],strict=True):
    name=arm['name']; assert record['arm']==arm and scored['arm']==name
    public=(NATIVE/arm['public_dir']).resolve(); assert public.is_relative_to(NATIVE/'public')
    assert set(arm['public_files'])==public_names|{'head.json','checked.json'}
    for filename,digest in arm['public_files'].items(): assert sha(public/filename)==digest
    observed=EVAL/'runs'/(name+'-observe'); scorepath=EVAL/'runs'/(name+'-score')
    seal=load(observed/'prediction-seal.json')
    assert seal==record['seal'] and sha(observed/'prediction-seal.json')==record['seal_sha256']
    assert sha(observed/'result.json')==seal['prediction_sha256'] and seal['public_files']==arm['public_files']
    assert seal['native_result_sha256']==sha(NATIVE/'native-result.json')
    assert seal['freeze_sha256']==prepared['freeze_sha256']
    mounts=load(observed/'inputs.json'); assert set(mounts)=={'/input/'+x for x in public_names}
    assert all(mounts['/input/'+x]==arm['public_files'][x] for x in public_names)
    isolation=load(observed/'isolation.json')
    assert isolation['interfaces']==['lo'] and isolation['home_accessible'] is False
    assert isolation['private_truth_mounted'] is False and isolation['other_arm_mounted'] is False
    obsproc=load(observed/'process.json'); scoreproc=load(scorepath/'process.json')
    assert obsproc['returncode']==scoreproc['returncode']==0
    assert time(obsproc['finished_utc'])<=time(seal['sealed_utc'])<=time(batch['sealed_utc'])<=time(scoreproc['started_utc'])
    earliest_score=min(earliest_score,time(scoreproc['started_utc'])) if earliest_score else time(scoreproc['started_utc'])
    score=load(scorepath/'result.json'); assert sha(scorepath/'result.json')==scored['score_sha256'] and scored['result']==score
    assert score['complete'] is True and score['truth_consistency']=={'cp_sat':True,'z3':True}
    assert score['boundary_matches_setup'] is True and score['qualification_pass'] is False
    sinputs=load(scorepath/'inputs.json')
    assert set(sinputs)==set(mounts)|{'/prediction.json','/truth.json'}
    assert sinputs['/prediction.json']==seal['prediction_sha256'] and sinputs['/truth.json']==seal['truth_sha256']==arm['truth_sha256']
    assert all(sinputs[k]==v for k,v in mounts.items())
    sisolation=load(scorepath/'isolation.json')
    assert sisolation['private_truth_mounted'] is True and sisolation['other_arm_mounted'] is False
    assert sisolation['interfaces']==['lo'] and sisolation['home_accessible'] is False
    for flag in ('original_backup_unchanged','recovery_fresh_process','terminal_payout_spend_native_validated','wrong_owner_script_differs'):
        assert arm[flag] is True
    expected_match=name=='legacy-v1-same-index'
    assert arm['expected_script_match'] is expected_match
    assert arm['native_payout_discovery']=='known index 3 supplied'
    assert arm['legacy_old_new_funding_equal'] is (True if expected_match else None)
    assert arm['exit_purpose_funding_rejected'] is (not expected_match)
    case_reviews.append(dict(case=name,prediction_sha256=seal['prediction_sha256'],score_sha256=scored['score_sha256'],
        input_mounts_public_only=True,prediction_before_batch_before_score=True,actual_truth_sat_reported_by_both_scorer_encodings=True,
        original_backup_unchanged_recorded=True,fresh_process_recovery_recorded=True,known_index_payout_spend_validated_recorded=True))
assert all(time(record['seal']['sealed_utc'])<=time(batch['sealed_utc'])<=earliest_score for record in batch['records'])
manual=load(Path('/tmp/kpi-key-separation-witness-review.json'))
unsat=load(Path('/tmp/kpi-key-separation-unsat-review.json'))
assert unsat['passed'] is True and unsat['forced_facts']==6 and unsat['unrestricted_solver_queries']==24
report=dict(passed=True,scope='Author-team post-run evidence review; private backups/truth/logs not read. Native recovery flags are implementation evidence, not a general cryptographic or privacy guarantee.',
    freeze_sha256=sha(EVAL/'freeze.json'),native_result_sha256=sha(NATIVE/'native-result.json'),prediction_batch_sha256=sha(EVAL/'prediction-batch.json'),
    source_files_verified=len(before['files']),native_proofs_recorded=10,isolation_guards_checked=45,
    worker_rejections_exact_message_checked=6,helper_rejections_safe_message_and_digest_checked=2,
    helper_reasons_sha256=sha(NATIVE/'review-control-reasons.json'),earliest_score_utc=earliest_score.isoformat(),batch_sealed_utc=batch['sealed_utc'],
    cases=case_reviews,manual_witness_report_sha256=sha(Path('/tmp/kpi-key-separation-witness-review.json')),
    unrestricted_solver_report_sha256=sha(Path('/tmp/kpi-key-separation-unsat-review.json')),reviewer_sha256=sha(Path(__file__)))
with OUT.open('x') as f: json.dump(report,f,indent=2); f.write('\n')
print(json.dumps({k:report[k] for k in ('passed','source_files_verified','isolation_guards_checked','worker_rejections_exact_message_checked','helper_rejections_safe_message_and_digest_checked','earliest_score_utc','batch_sealed_utc')},indent=2))

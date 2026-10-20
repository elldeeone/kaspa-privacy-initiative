#!/usr/bin/env python3
"""Allowlisted H14 export; private plans, keys and unused fallback bodies stay private."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from two_input_privacy_native import project, normalized


def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x') as f:json.dump(obj,f,indent=2);f.write('\n')


def export(study,native,out):
    result=read(study/'study-results.json');summary=read(native/'summary.json')
    assert len(result['pairs'])==4 and len(result['executions'])==8
    assert summary['offline_only'] and summary['synthetic_utxos'] and summary['real_groth16_proofs']
    comparisons={}
    for arm in ('fresh','saved'):
        public=project(read(native/f'{arm}-native-private.json'))
        expected=read(study/'a0-s0'/f'{arm}.json')
        if normalized(public)!=normalized(expected):raise ValueError(f'{arm}: native/model projection differs')
        a=summary['arms'][arm]
        assert a['operations']==len(public['events'])==19 and a['reserve_remaining']==0
        assert a['fees_sompi']==sum(e['fee'] for e in public['events'])==760000000
        assert a['payout_sompi']==sum(e['payout'] for e in public['events'])
        assert all(v>0 for v in a['wallet_exit_payouts_sompi']) and len(a['checks'])==7
        assert all(c['unchanged_authorization'] and c['alternate_rejected'] and c['replay_rejected'] and c['isolated'] for c in a['checks'])
        comparisons[arm]=dict(exact_normalized_projection_match=True,transactions=len(public['events']),
            private_native_trace_sha256=sha(native/f'{arm}-native-private.json'))
    # Finish all validation before creating an export directory.
    out.mkdir()
    for case in sorted(study.glob('a*-s*')):
        for arm in ('fresh','saved'):
            dest=out/case.name/arm;dest.mkdir(parents=True)
            shutil.copyfile(case/f'{arm}.json',dest/'public.json')
            src=case/f'{arm}-observation'
            for name in ('predictions.json','score.json','isolation.json','pins.json','observer.log'):
                shutil.copyfile(src/name,dest/name)
    write(out/'summary.json',dict(result,calibration_complete=True,
        completion='frozen screen passed' if result['observer_screen_passes'] else 'frozen screen falsified',
        general_privacy_established=False))
    write(out/'calibration.json',dict(comparisons=comparisons,**summary))
    # Export only the chosen fresh branch's public transaction bodies. The
    # alternate saved-exit authorizations never enter Git, even in this synthetic trial.
    write(out/'fresh-native.json',read(native/'fresh-native-private.json'))
    for name in ('fresh-replay.json','saved-replay.json','public-replay-check.json'):
        write(out/name,read(native/name))
    for name in ('input-continuity.json','controls.log','completed-earlier-crosscheck.json','aggregates.json','retroactive.json'):
        if (study/name).exists():shutil.copyfile(study/name,out/name)
    for source,name in [(study/'execution-pins.json','execution-pins.json'),
                        (native.parent/'native-pins.json','native-pins.json'),
                        (native.parent/'observer-interruption.json','observer-interruption-run-1.json')]:
        if source.exists():shutil.copyfile(source,out/name)
    for number in (2,3,4,5,6,7):
        source=study.parent/f'run-{number}'/'observer-interruption.json'
        if source.exists():shutil.copyfile(source,out/f'observer-interruption-run-{number}.json')
    resource=(native.parent/'native-resource.txt').read_text()
    maximum=next(int(l.split(':')[-1].strip()) for l in resource.splitlines() if 'Maximum resident set size' in l)
    write(out/'resources.json',dict(native_peak_rss_kib=maximum,actual_tkas_spent=0,
        note='Proof process; observer processes ran concurrently and are not included in this peak.'))
    hashes={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    write(out/'SHA256SUMS.json',hashes)
    print(json.dumps(dict(exported_files=len(hashes)+1,projection_matches=2,observer_screen_passes=result['observer_screen_passes'])))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('study',type=Path);p.add_argument('native',type=Path);p.add_argument('out',type=Path)
    a=p.parse_args();export(a.study,a.native,a.out)

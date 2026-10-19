#!/usr/bin/env python3
"""Allowlist H11 aggregate scores and fresh public histories; never old bundles."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


c = module('controller', 'privacy-study.py')
guard = module('export_guard', 'fresh-proof.py')


def forbidden(root):
    values, old_proofs, old_auths = set(), set(), set()
    prepared = root/'native-runtime/prepared'
    for name in ['sparse-00','burst-00']:
        wallet = c.read(prepared/name/'wallets.json')
        for w in wallet['wallets']:
            values.update(bytes(w[k]) for k in ['spending','viewing','native'])
        values.update(bytes(k) for k in wallet['funding_keys'])
        values.update(bytes(note['rho']) for _,note in wallet['notes'])
        old = c.read(prepared/name/'saved-request.json')['bundles']
        new = c.read(prepared/name/'fresh-request.json')['bundles']
        for a,b in zip(old,new,strict=True):
            old_proofs.add(bytes.fromhex(a['proof']))
            if a['authorization'] != b['authorization']:
                old_auths.add(bytes.fromhex(a['authorization']))
    return values,old_proofs,old_auths


def export(root, destination):
    summary = c.read(root/'summary.json'); native = c.read(root/'native-summary.json')
    if not native['complete'] or len(c.read(root/'scores.json')) != 81:
        raise ValueError('study incomplete')
    secrets,proofs,auths = forbidden(root); denied = secrets|proofs|auths
    checked = 0
    for value in [*proofs,*auths,next(iter(secrets))]:
        try:guard.check_bytes(json.dumps({'injection':value.hex()}).encode(),denied)
        except ValueError:checked+=1
        else:raise ValueError('private injection accepted')
    destination.mkdir(parents=True,exist_ok=False)
    manifest = {}
    def put(relative, raw):
        guard.check_bytes(raw,denied)
        target = destination/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);manifest[relative]=c.sha(raw)
    def copy(source,relative):put(relative,source.read_bytes())
    for name in ['summary.json','native-summary.json','freeze.json','source-pins.json']:
        copy(root/name,name)
    for name in ['implementation-note.json','solver-crosscheck.json','flow-crosscheck.json']:
        if (root/name).exists():copy(root/name,name)
    # Per-ledger aggregates support paired intervals without publishing old
    # source assignments or other-arm identifiers for native proof identities.
    scores = c.read(root/'scores.json')
    table = {name:{arm:{h:{attack:{k:v for k,v in row.items() if k!='rows'}
                  for attack,row in attacks.items()} for h,attacks in horizons.items()}
                  for arm,horizons in arms.items()} for name,arms in scores.items()}
    put('ledger-scores.json',(json.dumps(table,indent=2)+'\n').encode())
    projections,observations,isolation,runtimes = [],[],{},{}
    for name,*_ in c.cases():
        projections.append({'case':name,'projection':c.read(root/name/'fresh/input.json')})
        observations.append({'case':name,'observer':c.read(root/name/'fresh/output/result.json')})
        isolation[name] = {arm:c.read(root/name/arm/'isolation.json') for arm in ['saved','fresh','waited','shared']}
        runtimes[name] = c.read(root/name/'fresh/runtime.json')
    for filename,rows in [('fresh-projections.jsonl',projections),('fresh-observations.jsonl',observations)]:
        put('model/'+filename,(''.join(json.dumps(row,separators=(',',':'))+'\n' for row in rows)).encode())
    for filename,value in [('observer-isolation.json',isolation),('observer-runtime.json',runtimes)]:
        put('model/'+filename,(json.dumps(value,indent=2)+'\n').encode())
    for name in ['sparse-00','burst-00']:
        for arm in ['saved','fresh']:
            for filename in ['settlement-isolation.json','observer-isolation.json','settled/result.json','calibration.json']:
                copy(root/'native-analysis'/name/arm/filename,f'native/{name}/{arm}/{filename}')
        for filename in ['settled/chain.json','settled/metrics.json','observer/result.json']:
            copy(root/'native-analysis'/name/'fresh'/filename,f'native/{name}/fresh/{filename}')
    resources = (root/'native-runtime/resources.txt').read_text()
    rss = next(int(line.split(':')[-1]) for line in resources.splitlines() if 'Maximum resident set size' in line)
    elapsed = next(line.split('):',1)[-1].strip() for line in resources.splitlines() if 'Elapsed (wall clock)' in line)
    put('native-resources.json',(json.dumps({'peak_rss_kib':rss,'elapsed_wall_clock':elapsed,
        'rayon_threads':4,'scope':'One CPU prover process, both calibrations; concurrent offline observers'},indent=2)+'\n').encode())
    # Include the exact final analysis/exporter code provenance separately from
    # the source snapshot that preceded generation and proof preparation.
    tooling = {p.name:c.sha(p.read_bytes()) for p in [Path(__file__),HERE/'privacy-study-native.py',
        HERE/'privacy-study-requirements.txt',HERE/'test_privacy_study.py',HERE/'fresh-proof.py']}
    put('tooling-pins.json',(json.dumps(tooling,indent=2)+'\n').encode())
    c.save(destination/'export.json',{'allowlist_only':True,'files_sha256':manifest,
        'known_secret_values_checked':len(secrets),'unused_saved_proofs_checked':len(proofs),
        'distinct_old_authorizations_checked':len(auths),'injection_controls_passed':checked,
        'omitted':['native old arms','private requests','wallets','note openings','private truth'],
        'scope':'Synthetic public fresh traces and aggregate scores; no real-world anonymity claim'})
    for p in destination.rglob('*'):
        if p.is_file():guard.check_bytes(p.read_bytes(),denied)
    print(json.dumps({'exported_files':len(manifest)+1,'secrets_found':0,'unused_saved_proofs_exported':0}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('destination',type=Path)
    a=p.parse_args();export(a.root.resolve(),a.destination.resolve())

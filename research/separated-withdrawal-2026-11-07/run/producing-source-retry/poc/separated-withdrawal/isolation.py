#!/usr/bin/env python3
"""Additive read-only probes AFTER real wallet backup files have been created."""
import argparse, json, pathlib, subprocess, time

def probe(run, mode):
    arm = run / mode
    paths = [str(arm / f'wallet-{i}/wallet/backup.json') for i in range(4)]
    if not all(pathlib.Path(p).exists() for p in paths):
        return False
    prefix = 'kpi-separated-' + mode + '-' + run.name[:8]
    code = '''import json
def attempt(p):
 try:
  with open(p,'rb') as f:f.read(1)
  return {'readable':True}
 except OSError as e:return {'readable':False,'error':type(e).__name__}
print(json.dumps({'own':attempt('/state/wallet/backup.json'),'others':{p:attempt(p) for p in PATHS}}))'''.replace('PATHS', repr(paths))
    rows = []
    for role in ['service', 'wallet-0', 'wallet-1', 'wallet-2', 'wallet-3']:
        result = json.loads(subprocess.check_output(['docker', 'exec', prefix + '-' + role, 'python3', '-c', code], text=True))
        assert not any(v['readable'] for v in result['others'].values())
        assert result['own']['readable'] == (role != 'service')
        rows.append({'role': role, 'result': result})
    with (arm / 'POST-CREATION-ISOLATION.json').open('x') as f:
        json.dump({'actualHostBackupsExist': True, 'readProbes': rows, 'secretContentsExported': False}, f, indent=2)
        f.write('\n')
    print(mode, 'post-creation isolation passed', flush=True)
    return True

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('private_run', type=pathlib.Path)
    a = p.parse_args()
    for mode in ('direct', 'honest', 'tagged'):
        while not probe(a.private_run.resolve(), mode):
            time.sleep(1)

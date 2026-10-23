#!/usr/bin/env python3
"""One generate -> isolated predict -> sealed barrier -> score execution."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
PACKET = ROOT/'research/next-session/privacy-recovery/observer/padding-01'
CODE = PACKET/'source'
BRIDGE = Path('/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def save(p, v):
    p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')


def sandbox(mounts):
    base = ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin']
    for mode, source, target in mounts:
        base += [mode,str(source),target]
    return base


def main():
    freeze = json.loads((PACKET/'PRE-RUN-FREEZE.json').read_text())
    for item in freeze['pins']:
        p = Path(item['path'])
        if p.stat().st_size != item['bytes'] or sha(p) != item['sha256']:
            raise ValueError('pre-run immutable source/binary mismatch')
    run = PACKET/'run'
    run.mkdir(exist_ok=False)
    cgroup = next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                  if line.startswith('0:'))
    cg = Path('/sys/fs/cgroup')/cgroup.lstrip('/')
    caps = {name:(cg/name).read_text().strip() for name in ('cpu.max','memory.max','memory.swap.max')}
    save(run/'LIVE-CGROUP.json',dict(pid=os.getpid(),cgroup=cgroup,actual_limits=caps))
    quota, period = map(int,caps['cpu.max'].split())
    if quota > period or int(caps['memory.max']) != 2*1024**3 or caps['memory.swap.max'] != '0':
        raise ValueError('resource envelope mismatch')
    started = time.monotonic()
    # Generator is a different sandbox; no host home/profile/proving files.
    gen = sandbox([('--ro-bind',CODE/'padding_generate.py','/generate.py'),
        ('--ro-bind',CODE/'recipient.py','/recipient.py'),('--ro-bind',BRIDGE,'/crypto'),
        ('--bind',run,'/out')])
    subprocess.run(gen+['/usr/bin/time','-v','-o','/out/generate-resources.log',
        '/usr/bin/python3','-B','/generate.py','--recipient-module','/recipient.py',
        '--crypto','/crypto','--output','/out/generated'],check=True)
    prediction_dir = run/'prediction'
    prediction_dir.mkdir()
    # The attacker has only its source, public ciphertexts and EMPTY output dir.
    attack = sandbox([('--ro-bind',CODE/'padding_attack.py','/attack.py'),
        ('--ro-bind',run/'generated/public.json','/public.json'),
        ('--bind',prediction_dir,'/out')])
    with (run/'generated/public.json').open('rb') as source, (prediction_dir/'prediction.json').open('wb') as out:
        subprocess.run(attack+['/usr/bin/time','-v','-o','/out/attack-resources.log',
            '/usr/bin/python3','-B','/attack.py'],stdin=source,stdout=out,check=True)
    # Durable prediction barrier BEFORE launching any scorer with truth access.
    with (prediction_dir/'prediction.json').open('rb') as f:
        os.fsync(f.fileno())
    barrier = dict(public_file_sha256=sha(run/'generated/public.json'),
                   prediction_file_sha256=sha(prediction_dir/'prediction.json'),
                   prediction_complete=True,scorer_launched=False)
    save(run/'PREDICTION-BARRIER.json',barrier)
    scorer = sandbox([('--ro-bind',CODE/'padding_score.py','/score.py'),
        ('--ro-bind',run/'generated/public.json','/public.json'),
        ('--ro-bind',prediction_dir/'prediction.json','/prediction.json'),
        ('--ro-bind',run/'generated/truth.json','/truth.json')])
    with (run/'result.json').open('wb') as out:
        subprocess.run(scorer+['/usr/bin/python3','-B','/score.py','/public.json','/prediction.json','/truth.json'],
                       stdout=out,check=True)
    if sha(prediction_dir/'prediction.json') != barrier['prediction_file_sha256']:
        raise ValueError('prediction changed across scorer')
    save(run/'EXECUTION.json',dict(actual_evaluations=1,exit=0,
        wall_seconds=time.monotonic()-started,network='all child namespaces unshared',
        private_profiles_backups_proving_keys_mounted=False,
        live_cgroup_captured_before_generation=True,barrier_before_scorer=True,
        result_file_sha256=sha(run/'result.json')))


if __name__ == '__main__':
    main()

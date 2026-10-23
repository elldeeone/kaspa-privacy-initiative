#!/usr/bin/env python3
"""Fresh role setups and external metadata installation for ADR0058 only.

Caller must obtain implementation/direct-CS review before execution and own a
serialized14-worker resource window. Proving-key bytes stay outside Git. This
is explicit local development authority, never a capsule-driven key selection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def fresh(path):
    path=path.absolute()
    if path.exists() or path.is_relative_to(ROOT) or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('fresh-output-outside-Git-required')
    path.mkdir(parents=True,mode=0o700)
    return path


def run(args):
    output=fresh(args.output);parameters=fresh(args.parameters)
    reports=[]
    for role,fixture in [('compact2','capacity-noappend-continuing'),('wide32','wide32-append')]:
        parameter_dir=parameters/role;parameter_dir.mkdir(mode=0o700)
        setup=output/('setup-'+role)
        command=[str(args.binary.absolute()),'session',role,str((args.fixtures/(fixture+'.json')).absolute()),
                 str(setup),str(parameter_dir/'parameters.pk')]
        result=subprocess.run(command,input='quit\n',capture_output=True,text=True)
        (output/(role+'.stdout.log')).write_text(result.stdout)
        (output/(role+'.stderr.log')).write_text(result.stderr)
        if result.returncode!=0:raise RuntimeError('fresh-setup-failed:'+role)
        selection=[sys.executable,str(HERE/'prover/select_parameters.py'),'--role',role,
            '--setup-report',str(setup/'report.json'),'--shape-report',
            str((args.controls/('shape-'+fixture)/'report.json').absolute()),
            '--setup-binary',str(args.binary.absolute()),'--source-freeze',str(args.source_freeze.absolute()),
            '--output-manifest',str(output/('public-parameters-'+role+'.json')),'--install']
        selected=subprocess.run(selection,capture_output=True,text=True)
        (output/(role+'.selection.stdout.log')).write_text(selected.stdout)
        (output/(role+'.selection.stderr.log')).write_text(selected.stderr)
        if selected.returncode!=0:raise RuntimeError('fresh-parameter-selection-failed:'+role)
        report=json.loads(selected.stdout)
        reports.append(report)
        print(json.dumps({'event':'fresh-role-selected',**report}),flush=True)
    value={'schema':'kpx-capacity-fresh-role-parameters/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_SINGLE_PARTY_DEVELOPMENT_SETUP',
        'fresh_role_count':len(reports),'roles':reports,
        'setup_binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        'source_freeze_sha256':hashlib.sha256(args.source_freeze.read_bytes()).hexdigest(),
        'proving_keys_outside_Git':True,'private_witness_or_assignment_hash':False,'public_parameter_identities_hashed':True,
        'actual_proofs_native_calls_or_chain_backing':False}
    (output/'RESULTS.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','fixtures','controls','source-freeze','output','parameters'):
        parser.add_argument('--'+name,type=Path,required=True)
    run(parser.parse_args())

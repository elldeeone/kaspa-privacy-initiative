#!/usr/bin/env python3
"""Direct constraint checks for public capacity canaries; no parser-as-UNSAT.

Nominal witness secrets are deterministic public fixtures, kept outside Git.
Reports contain finalized public matrix fingerprints/dimensions and outcomes,
never a request, assignment or witness hash.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def dump(path, value):
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')


def replace_auth(row, offset, data):
    raw=bytearray.fromhex(row['auth_hex528']);raw[offset:offset+len(data)]=data
    assert len(raw)==528
    row['auth_hex528']=raw.hex()


def flip(row, offset):
    raw=bytearray.fromhex(row['auth_hex528']);raw[offset]^=1;row['auth_hex528']=raw.hex()


def cases(fixtures):
    base=json.loads((fixtures/'capacity-noappend-continuing.json').read_bytes())
    rows=[]
    def add(label, change, expected=False, native_only=False):
        row=copy.deepcopy(base);change(row)
        rows.append((label,row,expected,native_only))
    def output_rho(row):
        raw=bytearray.fromhex(row['outputs'][1]['note_hex168']);raw[72]=1
        row['outputs'][1]['note_hex168']=raw.hex()
    add('noappend-must-zero-unused-rho',output_rho)
    def coherent_output(row):
        raw=bytearray(168);raw[64:72]=(60_000_000).to_bytes(8,'little')
        row['outputs'][0]['note_hex168']=raw.hex()
        replace_auth(row,484,(920_000_000).to_bytes(8,'little'))
        replace_auth(row,476,(1_060_000_000).to_bytes(8,'little'))
    add('noappend-cannot-hide-coherently-funded-change',coherent_output)
    add('noappend-list-digest-zero',lambda r:flip(r,268))
    add('noappend-start-zero',lambda r:replace_auth(r,304,(2).to_bytes(4,'little')))
    add('noappend-cipher-exact-zero-container',lambda r:replace_auth(r,332,hashlib.sha256(b'').digest()))
    add('noappend-carry-CM-root',lambda r:flip(r,404))
    add('noappend-carry-CM-cursor',lambda r:replace_auth(r,436,(65534).to_bytes(4,'little')))
    add('noappend-exact-two-NFs',lambda r:replace_auth(r,472,(131070).to_bytes(4,'little')))
    add('original-real-NF-preserved',lambda r:flip(r,204))
    def path(row):
        old=bytearray.fromhex(row['inputs'][0]['cm_path_hex'][0]);old[0]^=1
        row['inputs'][0]['cm_path_hex'][0]=old.hex()
    add('wrong-current-CM-membership',path)
    def owner(row):
        old=bytearray.fromhex(row['inputs'][0]['s_hex32']);old[0]^=1
        row['inputs'][0]['s_hex32']=old.hex()
    add('wrong-owner-secret',owner)
    add('wrong-domain',lambda r:flip(r,8))
    add('compact-mode-cannot-select-wide',lambda r:replace_auth(r,300,bytes([32])))
    add('reserved-bytes-remain-zero',lambda r:flip(r,308))
    def floor(row):
        replace_auth(row,188,(1_000_000_001).to_bytes(8,'little'))
        replace_auth(row,476,(1).to_bytes(8,'little'))
    add('noappend-remaining-reserve-floor-still-active',floor)
    def nf_overflow(row):
        replace_auth(row,184,(131070).to_bytes(4,'little'))
        replace_auth(row,472,(131072).to_bytes(4,'little'))
    add('NF-tree-bound-still-active',nf_overflow)
    def no_payout(row):
        replace_auth(row,484,bytes(8));replace_auth(row,492,bytes(36))
        replace_auth(row,476,(1_980_000_000).to_bytes(8,'little'))
    add('noappend-requires-positive-payout',no_payout)
    add('changed-current-outpoint-is-native-obligation',lambda r:flip(r,40),True,True)
    add('NF-absence-is-native-obligation',lambda r:flip(r,152),True,True)
    return rows


def run(binary, fixtures, output):
    output=output.absolute();fixtures=fixtures.absolute();binary=binary.absolute()
    assert not output.is_relative_to(ROOT) and not output.exists()
    output.mkdir(parents=True,mode=0o700)
    requests=output/'requests';requests.mkdir(mode=0o700)
    plans=[]
    for label,row,expected,native_only in cases(fixtures):
        dump(requests/(label+'.json'),row)
        plans.append({'case':label,'expected_relation_satisfied':expected,
                      'native_checks_required':native_only})
    dump(output/'PLAN.json',{'schema':'kpx-capacity-direct-CS-plan/v1','cases':plans,
        'parser_rejection_does_not_count_as_direct_UNSAT':True,
        'private_request_or_assignment_hash':False})
    results=[]
    for item in plans:
        label=item['case'];target=output/label
        result=subprocess.run(['/usr/bin/time','-v','-o',str(output/(label+'.resources.log')),
            str(binary),'check','compact2',str(requests/(label+'.json')),str(target)],
            capture_output=True,text=True)
        (output/(label+'.stdout.log')).write_text(result.stdout)
        (output/(label+'.stderr.log')).write_text(result.stderr)
        if result.returncode != 0:
            raise RuntimeError('direct-CS-case-did-not-complete:'+label)
        report=json.loads((target/'report.json').read_bytes())
        if report['relation_satisfied'] is not item['expected_relation_satisfied']:
            raise RuntimeError('unexpected-direct-CS-result:'+label)
        results.append({**item,'observed_relation_satisfied':report['relation_satisfied'],
                        'finalized':report['finalized'],'seconds':report['seconds'],
                        'compiled_build_identity_sha256':report['compiled_build_identity_sha256']})
    shapes=[]
    for label,role in [('capacity-noappend-continuing','compact2'),
                       ('capacity-noappend-terminal','compact2'),('compact-append','compact2'),
                       ('wide32-append','wide32')]:
        target=output/('shape-'+label)
        result=subprocess.run(['/usr/bin/time','-v','-o',str(output/('shape-'+label+'.resources.log')),
            str(binary),'shape',role,str(fixtures/(label+'.json')),str(target)],capture_output=True,text=True)
        (output/('shape-'+label+'.stdout.log')).write_text(result.stdout)
        (output/('shape-'+label+'.stderr.log')).write_text(result.stderr)
        if result.returncode!=0:raise RuntimeError('shape-did-not-complete:'+label)
        report=json.loads((target/'report.json').read_bytes())
        if report['relation_satisfied'] is not True:raise RuntimeError('positive-unsatisfied:'+label)
        shapes.append({'case':label,**report})
    if not all(row['constraint_shape']==shapes[0]['constraint_shape'] for row in shapes[:3]):
        raise RuntimeError('compact-mode-matrix-mismatch')
    value={'schema':'kpx-capacity-direct-CS-and-shapes/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND', 'cases':results,'shapes':shapes,
        'actual_direct_CS_cases':len(results),'actual_finalized_positive_shapes':len(shapes),
        'all_expected_results':True,'all_compact_modes_identical_matrix':True,
        'request_or_assignment_hash':False,'proof_setup_native_or_network_execution':False,
        'executable_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    dump(output/'RESULTS.json',value)
    print(json.dumps({'direct_CS_cases':len(results),'shapes':len(shapes),
        'all_expected_results':True,'all_compact_modes_identical_matrix':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','fixtures','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();run(args.binary,args.fixtures,args.output)

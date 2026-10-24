#!/usr/bin/env python3
"""Root-only canonical metadata selection after a fresh role setup.

No PK/private-witness reads, decoder, RNG, network or proving. The selected
software release and external authority are trusted; an arbitrary capsule may
never invoke this helper as authority. Owner load authenticates the actual PK.
"""
from pathlib import Path
import argparse
import hashlib
import json

HERE = Path(__file__).resolve().parent

def digest(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def read(path):
    if path.is_symlink(): raise ValueError('metadata_symlink')
    return path.read_bytes()

def select(args):
    raw=read(args.setup_report);report=json.loads(raw);shape=json.loads(read(args.shape_report))
    trial=json.loads(read(HERE/'trial-selection.json'))
    role=args.role;arity={'compact2':2,'wide32':32}[role]
    if (report.get('schema')!='kpx4-compact-batch-setup-result/v1'
        or report.get('role')!=role or report.get('output_arity')!=arity
        or shape.get('role')!=role or shape.get('relation_satisfied') is not True
        or report.get('constraint_shape')!=shape.get('constraint_shape')):
        raise ValueError('setup_shape_role_mismatch')
    for key in ['trial_id','network_id','genesis_hash_hex','domain_hex32','program_label','auth_magic_hex8']:
        if report.get(key)!=trial.get(key):raise ValueError('setup_instance_mismatch')
    cs=report['constraint_shape'];queries=report['queries'];total=cs['witness_variables']+cs['instances_including_one']
    if (cs['instances_including_one']!=3 or cs['constraints']<=0
        or queries!={'a':total,'b_g1':total,'b_g2':total,'l':cs['witness_variables'],
                     'h':cs['fft_domain_size']-1,'instances_including_one':3}):
        raise ValueError('setup_query_dimensions')
    vk=bytes.fromhex(report['vk_hex328'])
    if len(vk)!=328 or digest(vk)!=report['vk_sha256'] or not 0<report['pk_bytes']<=32*1024**3:
        raise ValueError('setup_parameter_metadata')
    fields=['role','output_arity','auth_magic_hex8','program_label','trial_id','network_id',
        'genesis_hash_hex','domain_hex32','format','pk_bytes','pk_sha256','vk_hex328','vk_sha256',
        'core_source_identity','compiled_build_identity_sha256','constraint_shape','queries']
    manifest={'schema':'kpx4-public-proving-parameters/v1',**{key:report[key] for key in fields},
        'setup_provenance':{'executable_sha256':digest(read(args.setup_binary)),
            'source_freeze_sha256':digest(read(args.source_freeze)),'public_setup_report_sha256':digest(raw)}}
    encoded=canonical(manifest)
    with args.output_manifest.open('xb') as file:file.write(encoded)
    if args.install:
        pins=HERE/'pins'/role;prior=json.loads(read(pins/'parameter-selection.json'))
        if prior.get('selected') is not False:raise ValueError('role_already_selected')
        if prior.get('role')!=role:raise ValueError('role_pin_mismatch')
        (pins/'public-parameters.json').write_bytes(encoded)
        (pins/'verification-key.bin').write_bytes(vk)
        (pins/'parameter-selection.json').write_bytes(canonical({'schema':'kpx4-public-parameter-selection/v1',
            'selected':True,'role':role,'manifest_sha256':digest(encoded),'vk_sha256':digest(vk)}))
    return {'role':role,'manifest_sha256':digest(encoded),'vk_sha256':digest(vk),
        'prerequisite_shape_build_identity':shape['compiled_build_identity_sha256'],
        'selected_setup_build_identity':report['compiled_build_identity_sha256'],
        'exact_finalized_matrix_and_dimensions_match_prerequisite':True,
        'pk_bytes':manifest['pk_bytes'],'compiled_pin_selection_installed':args.install,
        'private_input_or_PK_bytes_read':False,'setup_proof_network_or_funding':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--role',choices=['compact2','wide32'],required=True)
    for name in ['setup-report','shape-report','setup-binary','source-freeze','output-manifest']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--install',action='store_true');a=p.parse_args()
    try:print(json.dumps(select(a),sort_keys=True))
    except Exception:raise SystemExit('parameter_selection_refused') from None

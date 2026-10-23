#!/usr/bin/env python3
"""Produce a PUBLIC parameter candidate and a separate cold-client source copy.

This producer does not select authority. Root independently reviews the exact
candidate before compiling it into the cold client. It never opens a witness,
backup, owner seed or prior parameter file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys


ROOT = Path(__file__).resolve().parents[4]
TEMPLATE_FREEZE = ROOT / 'research/next-session/private-service-loss/prover/TEMPLATE-SOURCE-FREEZE-01.json'
TEMPLATE_SHA = 'b207222c4f7dda52a88e8682fed5af8eec521ac1ac678ab1077128ffee74d3ec'
SOURCE_FILES = {'lib_rs_sha256':'src/lib.rs', 'circuit_rs_sha256':'src/circuit.rs',
    'exact_sha256_rs_sha256':'src/exact_sha256.rs', 'request_rs_sha256':'src/request.rs',
    'parameters_rs_sha256':'src/parameters.rs', 'main_rs_sha256':'src/main.rs',
    'setup_rs_sha256':'src/bin/setup.rs', 'build_rs_sha256':'build.rs'}
PKG = Path('poc/private-cashout-prover')


class Failure(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Failure(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_public_field')
        result[key] = value
    return result


def read_json(path):
    raw = path.read_bytes()
    need(len(raw) <= 1024*1024, 'public_input_too_large')
    return raw, json.loads(raw, object_pairs_hook=unique)


def exact(value, keys, code):
    need(type(value) is dict and set(value) == set(keys), code)


def save_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def public_pk(path, size, expected):
    with path.open('rb') as source:
        before = os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size == size, 'new_public_pk_length')
        value, count = hashlib.sha256(), 0
        while chunk := source.read(1024*1024):
            value.update(chunk)
            count += len(chunk)
        after = os.fstat(source.fileno())
    need(count == size and value.hexdigest() == expected, 'new_public_pk_digest')
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
         == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'new_public_pk_changed')


def export(args):
    template_raw, template = read_json(TEMPLATE_FREEZE)
    need(digest(template_raw) == TEMPLATE_SHA, 'template_source_selection')
    source_raw, source = read_json(args.source_workspace / 'SOURCE-MANIFEST.json')
    rows = {row['path']:row for row in source['files']}
    base = {row['path']:row for row in template['files']}
    need(len(rows) == len(source['files']) and set(rows) == set(base), 'source_allowlist')
    package = args.source_workspace / PKG
    for name, row in rows.items():
        path = args.source_workspace / name
        need(not path.is_symlink() and path.is_file(), 'source_file_type')
        raw = path.read_bytes()
        need(len(raw) == row['bytes'] and digest(raw) == row['generated_sha256']
             and row['base_sha256'] == base[name]['sha256'], 'source_file_digest')
        original=(ROOT/name).read_bytes()
        need(digest(original)==base[name]['sha256'],'template_source_changed')
        if name==str(PKG/'src/lib.rs'):
            pattern=rb'(pub const DOMAIN: H = \[)(.*?)(\n\];)'
            matches=list(re.finditer(pattern,original,re.S))
            need(len(matches)==1,'one_template_domain')
            domain=bytes.fromhex(source['domain_hex32'])
            need(len(domain)==32,'fresh_domain_width')
            body=b'\n'+b'\n'.join(b'    '+b', '.join(f'0x{x:02x}'.encode() for x in row)+b','
                                  for row in (domain[:16],domain[16:]))
            expected=re.sub(pattern,lambda match:match.group(1)+body+match.group(3),original,count=1,flags=re.S)
            need(raw==expected,'domain_only_source_delta')
        elif name!=str(PKG/'trial-selection.json'):
            need(raw==original,'unexpected_source_delta')
    _, trial = read_json(package / 'trial-selection.json')
    exact(trial, ['schema','selected','trial_id','network_id','genesis_hash_hex','domain_hex32','program_label'], 'trial_schema')
    need(trial['schema'] == 'kpx3-selected-private-trial-source/v1' and trial['selected'] is True
         and trial['network_id'] == 'testnet-10' and trial['program_label'] == 'AUTH528_PRIVATE_CASHOUT/v1'
         and trial['genesis_hash_hex']=='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
         and trial['domain_hex32'] == source['domain_hex32'] and trial['trial_id'] == source['trial_id'], 'trial_identity')
    raw_report, report = read_json(args.setup_report)
    _, build_result = read_json(args.build_report)
    candidates = [item for item in build_result['binaries'] if item['name'] == 'kpi-private-cashout-setup']
    need(len(candidates) == 1, 'setup_software_selection')
    binary = args.setup_binary.read_bytes()
    need(binary.startswith(b'\x7fELF') and digest(binary) == candidates[0]['sha256']
         and len(binary) == candidates[0]['bytes'], 'setup_software_digest')
    for field in ['trial_id','network_id','genesis_hash_hex','domain_hex32']:
        need(report[field] == trial[field], 'setup_trial_identity')
    identities = {key:digest((package/path).read_bytes()) for key,path in SOURCE_FILES.items()}
    need(report['core_source_identity'] == identities and report['build_identity']['source_identity'] == identities,
         'setup_core_identity')
    build = report['build_identity']
    for field, path in [('cargo_toml_sha256','Cargo.toml'),('cargo_lock_sha256','Cargo.lock'),
                        ('trial_selection_sha256','trial-selection.json')]:
        need(build[field] == digest((package/path).read_bytes()), 'setup_build_source')
    need(digest(canonical(build)) == report['compiled_build_identity_sha256'], 'setup_build_identity')
    vk = bytes.fromhex(report['vk_hex328'])
    need(len(vk) == 328 and vk.hex() == report['vk_hex328'] and digest(vk) == report['vk_sha256'], 'setup_vk_identity')
    need(report['format'] == 'arkworks0.6-bn254-uncompressed' and report['setup_rng'] == 'OsRng', 'setup_format')
    shape, q = report['constraint_shape'], report['queries']
    exact(shape, ['constraints','witness_variables','instances_including_one'], 'setup_shape_fields')
    exact(q, ['a','b_g1','b_g2','l','h','instances_including_one'], 'setup_query_fields')
    need(all(type(v) is int and v > 0 for v in [*shape.values(),*q.values()])
         and shape['instances_including_one'] == q['instances_including_one'] == 3
         and q['a'] == q['b_g1'] == q['b_g2'] == shape['witness_variables']+3
         and q['l'] == shape['witness_variables'], 'setup_dimensions')
    need(type(report['pk_bytes']) is int and report['pk_bytes'] > 0, 'setup_pk_length')
    public_pk(args.public_pk, report['pk_bytes'], report['pk_sha256'])
    manifest = {key:report[key] for key in ['trial_id','network_id','genesis_hash_hex','domain_hex32',
        'format','pk_bytes','pk_sha256','vk_hex328','vk_sha256','core_source_identity',
        'compiled_build_identity_sha256','constraint_shape','queries']}
    manifest.update(schema='kpx3-public-proving-parameters/v1', setup_provenance={
        'executable_sha256':digest(binary),'source_freeze_sha256':digest(source_raw),
        'public_setup_report_sha256':digest(raw_report)})
    raw = canonical(manifest)
    # Preserve the setup source. This NEW source copy changes only three public
    # selection files, and has no witness, profile or parameter blob in it.
    args.cold_source.mkdir(mode=0o700)
    for name in rows:
        destination = args.cold_source/name
        destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        save_new(destination,(args.source_workspace/name).read_bytes())
    changes = {str(PKG/'pins/public-parameters.json'):raw,
        str(PKG/'pins/verification-key.bin'):vk,
        str(PKG/'pins/parameter-selection.json'):canonical({'schema':'kpx3-public-parameter-selection/v1',
            'selected':True,'manifest_sha256':digest(raw),'vk_sha256':digest(vk)})}
    for name, value in changes.items():
        (args.cold_source/name).unlink()
        save_new(args.cold_source/name,value)
    freeze = {'schema':'kpx3-selected-cold-source/v1','trial_id':trial['trial_id'],
        'domain_hex32':trial['domain_hex32'],'base_source_manifest_sha256':digest(source_raw),
        'public_parameter_manifest_sha256':digest(raw),'changed_public_selection_files':sorted(changes),
        'files':[{'path':name,'bytes':(args.cold_source/name).stat().st_size,
                  'sha256':digest((args.cold_source/name).read_bytes())} for name in sorted(rows)]}
    save_new(args.cold_source/'COLD-SOURCE-MANIFEST.json',canonical(freeze))
    save_new(args.output,raw)
    result = {'schema':'kpx3-public-parameter-candidate/v1','candidate_is_not_root_selection':True,
        'trial_id':trial['trial_id'],'domain_hex32':trial['domain_hex32'],
        'manifest_sha256':digest(raw),'manifest_bytes':len(raw),'vk_sha256':digest(vk),
        'pk_sha256':report['pk_sha256'],'pk_bytes':report['pk_bytes'],
        'cold_source_manifest_sha256':digest(canonical(freeze)),
        'compiled_build_identity_sha256':report['compiled_build_identity_sha256'],
        'private_witness_seed_backup_or_prior_parameters_read':False}
    save_new(args.report,canonical(result))
    print(json.dumps(result,sort_keys=True))


def main():
    class Parser(argparse.ArgumentParser):
        def error(self,_message):
            raise Failure('producer_arguments')
    parser = Parser()
    for name in ['setup-report','build-report','setup-binary','source-workspace','public-pk','output','cold-source','report']:
        parser.add_argument('--'+name,type=Path,required=True)
    try:
        export(parser.parse_args())
    except Failure as error:
        print(json.dumps({'event':'error','code':error.args[0]}))
        return 1
    except Exception:
        print('{"event":"error","code":"parameter_candidate_failed"}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

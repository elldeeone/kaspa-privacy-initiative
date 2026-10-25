#!/usr/bin/env python3
"""Public Exit context/quote/finalization from authenticated restored software.

The child has downloaded sources at /work, restored public runtimes and pinned
public inputs only. No original repo/assets, wallet, network or shared prover
is mounted. This supervisor never constructs financial bytes on the host.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

import cold_owner
from cold_owner import closure, selection, stream, write
from run_restore import CLEAN, PublicPolicy, attrs, checked

CODEC_SHA = '8f724750bb4cc849e2e4bde26fc8da2b5bc7f9a7e4ffd09153ee1af15858d208'
PROFILE_SHA = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'

CHILD = r'''from pathlib import Path
import hashlib,json,sys,subprocess
root=Path('/work')
sys.path[:0]=[str(root/'poc/owner-private-lifecycle/integration'),str(root/'poc/owner-private-lifecycle/integration/construction')]
from driver import native_module
import public,quote,exits
from codec import canonical_json,parse_json,sha
from public import fields,hx,need,reconstruct,current_entry_context
for module in (public,quote,exits,native_module()):
    need(Path(module.__file__).is_relative_to(root),'restored-public-helper-only')
for path in ('/home/luke','/var/tmp/kpi-owner-private-lifecycle-01','/input','/private','/var/run/docker.sock'):
    need(not Path(path).exists(),'original-private-or-operator-path-visible')
need(not list(Path('/dev').glob('nvidia*')),'no-cold-public-GPU')
need([line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]==['lo'], 'cold-public-network-isolated')
options=parse_json(Path('/inputs/OPTIONS.json').read_bytes())
def read(name):return parse_json((Path('/inputs')/(name+'.json')).read_bytes())
def save(name,value):
    raw=canonical_json(value) if type(value) is dict else value
    with (Path('/out')/name).open('xb') as target:target.write(raw)
profile_raw=(root/'poc/owner-private-lifecycle/financial-profile.json').read_bytes()
need(sha(profile_raw)=='69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f','restored-fixed-financial-profile')
profile=parse_json(profile_raw);params=read('parameters')
fields(params,('outer_image_hex32','component_profile_sha256','exit_vk_hex328'),'selected-native-parameters')
need(params['outer_image_hex32']==profile['outer_image_hex32'] and params['component_profile_sha256']==profile['component_profile_sha256'] and sha(hx(params['exit_vk_hex328'],328))==profile['roles']['exit']['vk_sha256'],'restored-parameter-profile-join')
module=native_module();codec=module.NativeCodec(Path('/runtime/native-codec'),'8f724750bb4cc849e2e4bde26fc8da2b5bc7f9a7e4ffd09153ee1af15858d208')
identity=(hx(params['outer_image_hex32'],32),hx(params['component_profile_sha256'],32),hx(params['exit_vk_hex328'],328))
history=read('history');state,head=reconstruct(history)
emission=module.emit(codec,hx(head['state_hex112'],112),*identity);tail=emission['immutable_tail_hex']
need(sha(bytes.fromhex(tail))==profile['selected_public_binaries_and_native_policy']['immutable_native_tail']['sha256'],'restored-selected-native-tail')
current=read('current_entry')
if head['outpoint_hex36'] is None:
    need(current is None and options['operation']=='context','terminal-only-read-context')
    daa=None
else:daa=current_entry_context(history,tail,current)
op=options['operation']
if op=='context':
    save('CONTEXT.json',exits.read_context(history,profile['component_profile_sha256'],tail))
elif op=='quote':
    ready=read('ready')
    need(ready['schema']=='kpx8-owner-exit-ready/v1' and ready['history_sha256']==options['history_sha256'] and ready['financial_authorization'] is False,'same-authenticated-owner-ready-history')
    body,case,projection,journal,report,sizing=quote.exit(history,hx(ready['nf_hex32'],32),hx(ready['payout_spk_hex36'],36),ready['gross_claim_sompi'],options['session_hex32'],module,codec,identity,block_daa_score=daa)
    for name,value in [('BODY.bin',body),('CASE.json',case),('PROJECTION.bin',projection),('JOURNAL.bin',journal),('NATIVE-CODEC.json',report),('QUOTE.json',sizing),('CONTEXT.json',exits.read_context(history,profile['component_profile_sha256'],tail,sizing['fee_sompi']))]:save(name,value)
elif op=='finalize':
    body=Path('/inputs/body.bin').read_bytes();projection=Path('/inputs/projection.bin').read_bytes();auth=read('authorization')
    wire=public.load_wire();parsed=wire.parse_exit_projection(projection)
    need(parsed.body.raw==body and parsed.body.point.hex()==head['outpoint_hex36'] and parsed.body.old_state.raw.hex()==head['state_hex112'] and parsed.body.old_reserve==head['reserve_sompi'],'final-exit-current-state-body')
    proof=exits.auth_export(canonical_json(auth),'exit',options['history_sha256'],projection,parsed.body.nf.hex())
    case,actual,journal,report=module.make_case(codec,body,*identity,1800,outer_proof=proof,block_daa_score=daa)
    need(actual==projection and case['entries'][0]==current['entry'],'final-proof-keeps-current-native-context-and-effects')
    quote.exact_final(report,parsed.body.fee)
    for name,value in [('CASE.json',case),('PROJECTION.bin',actual),('JOURNAL.bin',journal),('NATIVE-CODEC.json',report)]:save(name,value)
    done=subprocess.run(['/work/runtime/native-validator','validate-transaction','/out/CASE.json','/out/native'],stdin=subprocess.DEVNULL,capture_output=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'})
    need(done.returncode==0,'restored-native-Full-process-failed')
    native=parse_json(Path('/out/native/native-validation.json').read_bytes());metrics=parse_json(Path('/out/native/metrics.json').read_bytes())
    need(native['isolation']=='PASS' and native['Full']['accepted'] is True and native['all_input_engines_accepted'] is True and len(native['per_input_ScriptEngine'])==1 and native['per_input_ScriptEngine'][0]['accepted'] is True,'restored-native-Full-and-every-input')
    need(metrics['actual_fee_sompi']==parsed.body.fee==metrics['mining_mass']*100,'restored-final-native-fee')
else:need(False,'closed-public-operation')
save('ISOLATION.json',{'schema':'kpx8-restored-public-case-isolation/v1','operation':op,'all_helpers_loaded_from_restored_work':True,'original_repo_cache_assets_absent':True,'private_wallets_mounted':False,'network_unshared':True,'GPU_mounted':False,'shared_prover_used':False,'broadcast_or_chain_acceptance':False})
'''


def run(a):
    policy = PublicPolicy(a.exclude_private_directory)
    closure.need(all(any(p.is_relative_to(root) for root in policy.roots)
                     for p in cold_owner.retained_private_roots()), 'all-private-parents-excluded')
    root, members, assets, identities = selection(a, policy)
    profile = cold_owner.parse_public(policy.read(root / 'poc/owner-private-lifecycle/financial-profile.json', PROFILE_SHA))
    codec_path, codec_info = stream(policy, a.codec, CODEC_SHA)
    validator = root / 'runtime/native-validator'
    validator_pin = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
    identities.extend((stream(policy, validator, validator_pin), (codec_path, codec_info)))
    source_names = ['history', 'current_entry', 'parameters']
    if a.operation == 'quote':
        source_names.append('ready')
    if a.operation == 'finalize':
        source_names += ['body', 'projection', 'authorization']
    source = {}
    for name in source_names:
        selected = getattr(a, name)
        pin = getattr(a, name + '_sha256')
        closure.need(selected is not None and pin is not None, 'complete-public-operation-inputs')
        source[name] = policy.read(selected, pin)
    private = cold_owner.fresh(a.private_run_directory, policy.roots, private=True)
    output = cold_owner.fresh(a.output, policy.roots, private=False)
    inputs = private / 'inputs'
    inputs.mkdir(mode=0o700)
    for name, raw in source.items():
        write(inputs / (name + ('.bin' if name in ('body', 'projection') else '.json')), raw)
    options = {'operation': a.operation, 'history_sha256': a.history_sha256,
               'session_hex32': a.session_hex32 or os.urandom(32).hex()}
    write(inputs / 'OPTIONS.json', closure.encoded(options))
    write(private / 'step.py', CHILD.encode())
    # Copy only the already authenticated public codec bytes. The supervisor
    # never opens/hashes any private staging or wallet leaf afterward.
    write(private / 'native-codec', policy.read(codec_path, CODEC_SHA), 0o500)
    for selected, before in identities:
        closure.need(attrs(selected.lstat()) == attrs(before), 'restored-public-object-changed-before-mount')
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(root), '/work', '--ro-bind', str(inputs), '/inputs',
        '--ro-bind', str(private / 'step.py'), '/control/step.py',
        '--ro-bind', str(private / 'native-codec'), '/runtime/native-codec',
        '--bind', str(output), '/out', '--chdir', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B', '/control/step.py']
    with (private / 'stdout').open('xb') as out, (private / 'stderr').open('xb') as err:
        done = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=CLEAN)
    closure.need(done.returncode == 0, 'closed-restored-public-case-incomplete')
    return {'schema': 'kpx8-cold-public-case-launch/v1', 'operation': a.operation,
            'software_inventory_sha256': a.software_inventory_sha256,
            'original_private_bytes_read': 0, 'broadcast_or_chain_acceptance': False}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('context', 'quote', 'finalize'))
    for name in ('software-root', 'software-inventory', 'assets', 'codec', 'parameters',
                 'history', 'current-entry', 'private-run-directory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('software-inventory', 'assets', 'parameters', 'history', 'current-entry'):
        p.add_argument('--' + name + '-sha256', required=True)
    for name in ('ready', 'body', 'projection', 'authorization'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--' + name + '-sha256')
    p.add_argument('--session-hex32')
    p.add_argument('--exclude-private-directory', action='append', type=Path, required=True)
    return p


if __name__ == '__main__':
    os.umask(0o077)
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('closed restored public case incomplete')

#!/usr/bin/env python3
"""Downloaded full replay/native preflight and once-only replacement relay.

Trusted bootstrap closure: this file plus the separately pinned replay_closed
and relay_registry helpers. No original registry or owner files are mounted.
The public chain observer supplies bytes; the cold namespace rechecks them.
"""
import argparse
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import subprocess

import replay_closed as base


REPLAY_SOURCE_SHA = 'eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863'
# Filled only from the independently reviewed helper's final source freeze.
REGISTRY_SOURCE_SHA = '2e393021757e00b6c6a267e58a2ba6936fa0d2052846435d6a26272692f666e5'
CONFIRM_SOURCE_SHA = '3b6304f211b8a07529266b95ddb0442e242c1c463bb282985a248c36cdd1764d'
REGISTRY_HOST = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/replacement-relay-01')


ENTRY = '''from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/bootstrap')
import replay_closed
assert hashlib.sha256(Path(replay_closed.__file__).read_bytes()).hexdigest()=='eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863'
options=json.loads(Path('/inputs/options.json').read_bytes())
assert all(not Path(p).exists() for p in options['absence']), 'original-path-visible-to-relay'
assert not list(Path('/dev').glob('nvidia*'))
sys.path.insert(0,'/work/poc/owner-private-lifecycle/chain')
import replay
packet=json.loads(Path('/inputs/packet.json').read_bytes());inputs=packet['inputs']
def raw(name):return Path('/data',inputs[name]['path']).read_bytes()
def pin(name):return inputs[name]['sha256']
selected=replay.decode_selection(raw('selection'),pin('selection'))
assert selected.profile_sha256==packet['financial_profile_sha256']==replay_closed.PROFILE_SHA
profile=replay.parse(Path('/work/poc/owner-private-lifecycle/financial-profile.json').read_bytes())
parameters=replay.parse(raw('parameters'))
replay.fields(parameters,{'outer_image_hex32','component_profile_sha256','exit_vk_hex328'},'fixed-native-parameters')
assert parameters['outer_image_hex32']==profile['outer_image_hex32']
assert parameters['component_profile_sha256']==profile['component_profile_sha256']
assert replay.digest(replay.hx(parameters['exit_vk_hex328'],328))==profile['roles']['exit']['vk_sha256']
assert replay.digest(selected.tail)==profile['selected_public_binaries_and_native_policy']['immutable_native_tail']['sha256']
report=replay.replay(raw('selection'),pin('selection'),raw('descriptor'),pin('descriptor'),
 raw('fetch'),pin('fetch'),Path('/data'),raw('parameters'),pin('parameters'),
 Path('/runtime/native-codec'),replay_closed.CODEC_SHA,raw('sessions'),pin('sessions'),
 raw('source-pins'),pin('source-pins'),Path('/scratch/replayed'),
 runtime_paths={name:Path('/work/runtime')/name for name in ('crypto','node','native-validator')},
 sdk_directory=Path('/work/sdk/kaspa'))
assert report['financial_profile_sha256']==replay_closed.PROFILE_SHA
for name,expected in [('HISTORY.json',packet['expected']['history_sha256']),('CHECKPOINT.json',packet['expected']['checkpoint_sha256'])]:
 assert hashlib.sha256(Path('/scratch/replayed',name).read_bytes()).hexdigest()==expected
handover=replay.parse(Path('/inputs/handover.json').read_bytes())
assert replay.digest(Path('/inputs/handover.json').read_bytes())==options['handover_sha256']
assert handover['financial_profile_sha256']==replay_closed.PROFILE_SHA
assert handover['selection_sha256']==pin('selection') and handover['descriptor_sha256']==pin('descriptor')
assert handover['trial_id']==replay.parse(raw('descriptor'))['trial_id']
assert [r['transaction_id'] for r in report['transactions']][:len(handover['accepted_pool_prefix_txids'])]==handover['accepted_pool_prefix_txids']
assert len(handover['accepted_pool_prefix_txids'])==3
public=replay.source_modules(raw('source-pins'),pin('source-pins'))
complete_history=replay.parse(Path('/scratch/replayed/HISTORY.json').read_bytes())
first=complete_history['genesis']
prefix=public.genesis([replay.hx(record,496) for record in first['records_hex496']],first['outpoint_hex36'])
assert len(complete_history['transitions'])>=2 and all(row['kind']=='batch' for row in complete_history['transitions'][:2])
for transition in complete_history['transitions'][:2]:prefix=public.extend(prefix,transition)
_,prefix_checkpoint=public.reconstruct(prefix)
assert replay.digest(replay.encoded(prefix)+b'\\n')==handover['history_sha256'], 'handover-R2-history-membership'
assert replay.digest(replay.encoded(prefix_checkpoint)+b'\\n')==handover['checkpoint_sha256'], 'handover-R2-checkpoint-membership'
import confirm
fetched=replay.parse(raw('fetch'))
assert all(row['kind']=='exit' for row in complete_history['transitions'][2:])
if len(fetched['transactions'])==3:
 point=prefix_checkpoint['outpoint_hex36']
 rows=[q for q in fetched['current_view']['queries'] if confirm.point_key(q['outpoint'])==point]
 assert len(rows)==1 and rows[0]['queried'] is True and rows[0]['entry'] is not None
 historical_entry=confirm.typed_entry(rows[0]['entry'])
else:
 first_exit=replay.native_case(fetched['transactions'][3])
 assert len(first_exit['transaction']['inputs'])==len(first_exit['entries'])==1
 historical_entry={'outpoint':first_exit['transaction']['inputs'][0]['previousOutpoint'],'entry':first_exit['entries'][0]}
public.current_entry_context(prefix,selected.tail.hex(),historical_entry)
assert replay.digest(replay.encoded(historical_entry)+b'\\n')==handover['current_entry_sha256'], 'handover-R2-birthDAA-entry-membership'
raw_case=Path('/inputs/case.json').read_bytes()
assert replay.digest(raw_case)==options['case_sha256']
case=replay.parse(raw_case);replay.fields(case,{'transaction','entries'},'exact-native-exit-case')
body=case['transaction']
assert type(body['version']) is int and body['version']==1 and body['lockTime']==body['gas']==0
assert body['subnetworkId']=='00'*20
runtime=replay.Runtime(paths={name:Path('/work/runtime')/name for name in ('crypto','node','native-validator')},sdk_dir=Path('/work/sdk/kaspa'))
normalized,metrics=runtime.normalize(case,Path('/scratch/candidate-normalization'))
assert normalized==case and metrics['actual_fee_sompi']==100*metrics['mining_mass']
full=replay.verify_native(runtime,case,Path('/scratch/candidate-Full'))
assert full==metrics
parsed=replay.parse(replay.Executable(Path('/runtime/native-codec'),replay_closed.CODEC_SHA).run(request={'operation':'body','case':case,**parameters}).stdout)
assert parsed['case']==case and parsed['mode']=='exit'
checkpoint=report['current_checkpoint'];payload=replay.hx(body['payload'])
assert len(body['inputs'])==len(case['entries'])==1 and body['inputs'][0]['computeBudget']==profile['compute_budget']
point=body['inputs'][0]['previousOutpoint'];previous=point['transactionId']+point['index'].to_bytes(4,'little').hex()
assert previous==checkpoint['outpoint_hex36'] and payload[148:260].hex()==checkpoint['state_hex112']
assert int.from_bytes(payload[260:268],'little')==checkpoint['reserve_sompi']
sdk_body,contexts=runtime.sdk_body(case)
candidate={'schema':'kpx8-replacement-exit-candidate/v1','transaction':sdk_body,'contexts':contexts,
 'case_sha256':options['case_sha256'],'financial_profile_sha256':replay_closed.PROFILE_SHA,
 'trial_id':handover['trial_id'],'stage':options['stage'],'previous_outpoint_hex36':previous,
 'node_pin':replay.GENERIC['node'][1],'actual_native_Full_and_input_engines_passed':True,
 'full_accepted_prefix_replayed':True,'broadcast_performed':False}
candidate_raw=replay.encoded(candidate)+b'\\n'
replay.write_new(Path('/scratch/SDK-CANDIDATE.json'),candidate_raw,0o400)
options['candidate_sha256']=replay.digest(candidate_raw)
Path('/scratch/NODE-OPTIONS.json').write_bytes(replay.encoded(options)+b'\\n')
process=runtime.executables['node'].run([Path('/bootstrap/relay.mjs')],allow_failure=True)
assert Path('/out/RELAY-RESULT.json').exists(), 'replacement-relay-no-typed-outcome'
result=replay.parse(Path('/out/RELAY-RESULT.json').read_bytes())
assert result['transaction_id']==body['id'] and result['stage']==options['stage']
assert result['automatic_resubmission_permitted'] is False
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if result['status'] in ('PREFLIGHT_ONLY_NO_SUBMISSION','SUBMITTED_ACKNOWLEDGED_QUERY_ONLY') else 2)
'''


NODE = '''import fs from 'node:fs';
import {makeTransaction,queryInputs,transmitOnce} from '/work/poc/owner-private-lifecycle/chain/submit.mjs';
import {loadSdk,sha,stringify,need} from '/work/poc/owner-private-lifecycle/chain/wire.mjs';
import {strictJson} from '/work/poc/owner-private-lifecycle/chain/selection.mjs';
import {initialize,reserve} from '/work/poc/owner-private-lifecycle/recovery/relay_registry.mjs';
const options=strictJson(fs.readFileSync('/scratch/NODE-OPTIONS.json'));
const raw=fs.readFileSync('/scratch/SDK-CANDIDATE.json');
need(sha(raw)===options.candidate_sha256,'CANDIDATE','fixed cold preflight candidate changed');
const candidate=strictJson(raw),handoverRaw=fs.readFileSync('/inputs/handover.json');
need(sha(handoverRaw)===options.handover_sha256,'HANDOVER','selected handover changed');
need(candidate.schema==='kpx8-replacement-exit-candidate/v1'&&candidate.actual_native_Full_and_input_engines_passed===true&&candidate.full_accepted_prefix_replayed===true,'CANDIDATE','mandatory native/full-prefix checks');
need(sha(fs.readFileSync(process.execPath))===candidate.node_pin,'NODE','selected downloaded Node required');
const endpoint=new URL(options.rpc);
need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'RPC','public credential-free TLS RPC required');
const k=loadSdk('/work/sdk/kaspa'),tx=makeTransaction(k,candidate.transaction,candidate.contexts);
let intended=false,attempted=false;
let result={schema:'kpx8-replacement-once-relay-result/v1',stage:candidate.stage,
 transaction_id:candidate.transaction.id,case_sha256:candidate.case_sha256,
 automatic_resubmission_permitted:false,confirmation_claimed:false,
 original_registry_repo_cache_or_owner_paths_available:false};
if(options.operation==='check'){
 result={...result,status:'PREFLIGHT_ONLY_NO_SUBMISSION',durable_intent_reserved:false,submission_attempted:false};tx.free();
}else{
 const rpc=new k.RpcClient({url:endpoint.href,networkId:'testnet-10'});
 try{
  const handover=initialize('/work/registry',handoverRaw,options.handover_sha256);
  need(handover.trial_id===candidate.trial_id,'HANDOVER','candidate trial differs');
  await rpc.connect({blockAsyncConnect:true,timeoutDuration:60000,strategy:'fallback'});
  const daa=await queryInputs(k,rpc,candidate.transaction,candidate.contexts);
  reserve('/work/registry',options.handover_sha256,candidate.stage,{trial_id:candidate.trial_id,
   transaction_id:candidate.transaction.id,previous_outpoint_hex36:candidate.previous_outpoint_hex36,
   case_sha256:candidate.case_sha256,candidate_sha256:options.candidate_sha256,last_checked_virtual_daa:daa});
  intended=true;
  await queryInputs(k,rpc,candidate.transaction,candidate.contexts);
  attempted=true;
  const ack=await transmitOnce(rpc,tx,candidate.transaction.id);
  result={...result,status:ack?'SUBMITTED_ACKNOWLEDGED_QUERY_ONLY':'RPC_UNKNOWN_QUERY_ONLY',durable_intent_reserved:true,submission_attempted:true};
 }catch(error){
  result={...result,status:'INCOMPLETE_QUERY_ONLY',durable_intent_reserved:intended,submission_attempted:attempted,
   category:error.code==='EEXIST'?'USED_INTENT_NEVER_RESUBMIT':
    new Set(['INPUT','MATURITY','NETWORK','GENESIS','NODE','INTENT','ENDPOINT']).has(error.category)?error.category:'PUBLIC_RPC_OR_INTENT_UNAVAILABLE'};
 }finally{tx.free();await rpc.disconnect();}
}
fs.writeFileSync('/out/RELAY-RESULT.json',stringify(result)+'\\n',{flag:'wx',mode:0o400});
'''



STATUSES = {'PREFLIGHT_ONLY_NO_SUBMISSION', 'SUBMITTED_ACKNOWLEDGED_QUERY_ONLY',
            'RPC_UNKNOWN_QUERY_ONLY', 'INCOMPLETE_QUERY_ONLY'}
CATEGORIES = {'USED_INTENT_NEVER_RESUBMIT', 'PUBLIC_RPC_OR_INTENT_UNAVAILABLE',
              'INPUT', 'MATURITY', 'NETWORK', 'GENESIS', 'NODE', 'INTENT', 'ENDPOINT'}


def public_result(raw, stage, case_sha256, transaction_id):
    value = base.parse(raw)
    fields = {'schema', 'stage', 'transaction_id', 'case_sha256', 'automatic_resubmission_permitted',
              'confirmation_claimed', 'original_registry_repo_cache_or_owner_paths_available',
              'status', 'durable_intent_reserved', 'submission_attempted'}
    base.need(type(value) is dict and value.get('status') in STATUSES, 'typed-relay-status')
    if value['status'] == 'INCOMPLETE_QUERY_ONLY':
        fields.add('category')
        base.need(type(value.get('category')) is str and value['category'] in CATEGORIES,
                  'typed-relay-category')
    base.need(set(value) == fields and value['schema'] == 'kpx8-replacement-once-relay-result/v1'
              and value['stage'] == stage and value['case_sha256'] == case_sha256
              and value['transaction_id'] == transaction_id and base.SHA.fullmatch(transaction_id)
              and value['automatic_resubmission_permitted'] is False
              and value['confirmation_claimed'] is False
              and value['original_registry_repo_cache_or_owner_paths_available'] is False
              and type(value['durable_intent_reserved']) is bool
              and type(value['submission_attempted']) is bool, 'exact-neutral-relay-outcome')
    base.need(not value['submission_attempted'] or value['durable_intent_reserved'], 'attempt-after-reservation')
    if value['status'] == 'PREFLIGHT_ONLY_NO_SUBMISSION':
        base.need(not value['submission_attempted'] and not value['durable_intent_reserved'], 'check-only-outcome')
    elif value['status'] != 'INCOMPLETE_QUERY_ONLY':
        base.need(value['submission_attempted'] and value['durable_intent_reserved'], 'attempted-once-outcome')
    return {name: value[name] for name in sorted(fields)}


def run(args):
    policy = base.PublicPolicy(args.exclude_private_directory)
    helper = Path(base.__file__).absolute()
    replay_source = policy.read(helper, REPLAY_SOURCE_SHA)
    base.need(type(REGISTRY_SOURCE_SHA) is str and base.SHA.fullmatch(REGISTRY_SOURCE_SHA),
              'reviewed-registry-source-not-yet-selected')
    registry_source = policy.read(args.registry_source, REGISTRY_SOURCE_SHA)
    confirmation_source = policy.read(args.confirmation_source, CONFIRM_SOURCE_SHA)
    base.need(args.operation in ('check', 'submit') and
              re.fullmatch('[a-z][a-z0-9-]{0,63}', args.stage), 'closed-exit-relay-operation')
    endpoint = urlsplit(args.rpc)
    base.need(type(args.rpc) is str and args.rpc.isascii()
              and all(0x20 < ord(c) < 0x7f for c in args.rpc)
              and endpoint.scheme == 'wss' and endpoint.hostname and not endpoint.username
              and not endpoint.password and not endpoint.query and not endpoint.fragment,
              'public-credential-free-TLS-RPC')
    registry = base.checked(REGISTRY_HOST)
    base.need(any(registry.is_relative_to(root) for root in policy.roots), 'replacement-registry-private-coverage')
    selected = base.packet(policy.read(args.packet, args.packet_sha256))
    handover = policy.read(args.handover, args.handover_sha256)
    case = policy.read(args.case, args.case_sha256)
    root = policy.public(args.software_root)
    data_root = policy.public(args.data_root)
    inventory = base.parse(policy.read(args.software_inventory, base.INVENTORY_SHA))
    base.need(inventory['schema'] == 'kpx4-public-software-bundle/v1'
              and len(inventory['files']) == 63, 'exact-downloaded-software-inventory')
    members = [(item, policy.read(root / item['path'], item['sha256'], item['bytes']))
               for item in inventory['files']]
    data = {item['path']: policy.read(data_root / item['path'], item['sha256'], item['bytes'])
            for item in [*selected['inputs'].values(), *selected['pages']]}
    base.selected_profile(data[selected['inputs']['selection']['path']])
    base.need(base.page_paths(base.parse(data[selected['inputs']['fetch']['path']])) ==
              {item['path'] for item in selected['pages']}, 'complete-retained-page-closure')
    codec = policy.read(args.codec, base.CODEC_SHA, base.CODEC_BYTES)
    output = policy.public(args.output)
    base.need(not output.exists() and not output.is_relative_to(root)
              and not output.is_relative_to(data_root)
              and not output.is_relative_to(base.ORIGINAL_REPOSITORY), 'fresh-public-relay-output')
    controller = base.checked(args.private_run_directory)
    base.need(not controller.exists() and controller.is_relative_to(base.RESERVED)
              and any(controller.is_relative_to(root) for root in policy.roots)
              and not controller.is_relative_to(REGISTRY_HOST)
              and not REGISTRY_HOST.is_relative_to(controller), 'fresh-private-relay-controller')
    controller.mkdir(parents=True, mode=0o700)
    scratch = controller / 'scratch'
    scratch.mkdir(mode=0o700)
    output.mkdir(parents=True, mode=0o700)
    for item, raw in members:
        base.write(controller / 'stage/software' / item['path'], raw,
                   0o500 if item['kind'] == 'selected-executable' else 0o400)
    (controller / 'stage/software/registry').mkdir(mode=0o700)
    for name, raw in data.items():
        base.write(controller / 'stage/data' / name, raw)
    base.write(controller / 'stage/software/poc/owner-private-lifecycle/recovery/relay_registry.mjs', registry_source)
    base.write(controller / 'stage/software/poc/owner-private-lifecycle/chain/confirm.py', confirmation_source)
    for name, raw in [('replay_closed.py', replay_source),
                      ('relay.mjs', NODE.encode()), ('entry.py', ENTRY.encode())]:
        base.write(controller / 'stage/bootstrap' / name, raw)
    base.write(controller / 'stage/native-codec', codec, 0o500)
    base.write(controller / 'stage/packet.json', base.encoded(selected))
    base.write(controller / 'stage/case.json', case)
    base.write(controller / 'stage/handover.json', handover)
    absence = ['/home/luke', str(base.ORIGINAL_REPOSITORY), '/home/luke/.cargo',
               '/var/tmp/kpi-owner-private-lifecycle-01',
               '/home/luke/.cache/kpi-sdk', '/var/tmp/kpi-owner-private-lifecycle-01/private/submission-intents']
    absence.extend(str(root) for root in policy.roots)
    options = {'absence': absence, 'codec_sha256': base.CODEC_SHA,
               'case_sha256': args.case_sha256, 'handover_sha256': args.handover_sha256,
               'operation': args.operation, 'stage': args.stage, 'rpc': args.rpc}
    base.write(controller / 'stage/options.json', base.encoded(options))
    public = output / 'public'
    public.mkdir(mode=0o700)
    if args.operation == 'submit':
        if not registry.exists():
            registry.mkdir(mode=0o700)
            fd = os.open(registry.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        base.need(registry.is_dir() and not registry.is_symlink(), 'replacement-registry-directory')
    command = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-uts',
               '--unshare-ipc', '--die-with-parent', '--new-session', '--clearenv']
    for system in ('/usr', '/lib', '/lib64'):
        if Path(system).exists():
            command.extend(('--ro-bind', system, system))
    command.extend(('--dir', '/etc', '--ro-bind', '/etc/ssl', '/etc/ssl'))
    for name in ('resolv.conf', 'nsswitch.conf', 'hosts', 'ld.so.cache'):
        source = Path('/etc') / name
        if source.exists():
            command.extend(('--ro-bind', str(source), str(source)))
    command.extend(('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
        '--ro-bind', str(controller / 'stage/software'), '/work',
        '--ro-bind', str(controller / 'stage/data'), '/data', '--dir', '/runtime',
        '--ro-bind', str(controller / 'stage/native-codec'), '/runtime/native-codec',
        '--ro-bind', str(controller / 'stage/bootstrap'), '/bootstrap', '--dir', '/inputs'))
    if args.operation == 'submit':
        command.extend(('--bind', str(registry), '/work/registry'))
    for name in ('packet', 'options', 'case', 'handover'):
        command.extend(('--ro-bind', str(controller / ('stage/' + name + '.json')), '/inputs/' + name + '.json'))
    command.extend(('--bind', str(scratch), '/scratch', '--bind', str(public), '/out', '--setenv', 'PATH', '/usr/bin:/bin',
                    '--setenv', 'LANG', 'C.UTF-8', '--chdir', '/work',
                    '/usr/bin/python3', '-B', '/bootstrap/entry.py'))
    # Source plans and raw streams remain private. The supervisor reads only
    # the separately mounted allowlisted public outcome after the worker ends.
    base.write(controller / 'COMMAND.json', base.encoded(command))
    log_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    stdout_fd = os.open(controller / 'stdout.log', log_flags, 0o400)
    stderr_fd = os.open(controller / 'stderr.log', log_flags, 0o400)
    try:
        process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout_fd,
                                 stderr=stderr_fd, env=base.CLEAN)
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    result_path = public / 'RELAY-RESULT.json'
    base.need(result_path.exists(), 'replacement-relay-incomplete-before-typed-result')
    result = public_result(policy.read(result_path, None), args.stage, args.case_sha256,
                           base.parse(case)['transaction']['id'])
    receipt = {'schema': 'kpx8-closed-replacement-relay-run/v1', 'returncode': process.returncode,
               'packet_sha256': args.packet_sha256, 'handover_sha256': args.handover_sha256,
               'case_sha256': args.case_sha256, 'source_dependencies': {
                   'replay_closed.py': REPLAY_SOURCE_SHA, 'relay_registry.mjs': REGISTRY_SOURCE_SHA,
                   'confirm.py': CONFIRM_SOURCE_SHA},
               'original_backup_seed_or_registry_read': False,
               'same_physical_host_separate_namespace': True,
               'replacement_registry_mounted': args.operation == 'submit',
               'network_unshared': False,
               'network_scope': 'downloaded SDK exact public TLS input queries and at most one submit RPC',
               'confirmation_claimed': False, 'result': result}
    base.write(output / 'RESULT.json', base.encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('check', 'submit'))
    for name in ('software-root', 'software-inventory', 'data-root', 'packet', 'handover',
                 'case', 'codec', 'registry-source', 'confirmation-source', 'private-run-directory', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('packet-sha256', 'handover-sha256', 'case-sha256', 'stage', 'rpc'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--exclude-private-directory', type=Path, action='append', required=True)
    try:
        value = run(parser.parse_args())
        print(json.dumps(value, sort_keys=True))
        if value['returncode']:
            raise SystemExit(2)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(2, 'replacement relay incomplete; reconcile the same TXID read-only, never resend\n')


if __name__ == '__main__':
    main()

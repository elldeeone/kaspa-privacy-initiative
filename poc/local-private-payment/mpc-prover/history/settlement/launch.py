#!/usr/bin/env python3
"""Direct fresh public-only settlement verifier for ADR-0077.

This process never clears a journal. The C++ owner must authenticate and launch
it, bind its fresh result, and construct its private settlement capability.
There is no imported-report or retained-bundle success command.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

HERE = Path(__file__).resolve().parent
BOOTSTRAP = Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
STANDARD_ENDPOINTS = {
    'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
    'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
}
PUBLIC_PHASE = 'bootstrap'


def stage(name):
    global PUBLIC_PHASE
    PUBLIC_PHASE = name


def require(value, reason):
    if not value:
        raise ValueError(reason)


def basic_json(raw):
    def pairs(values):
        result = {}
        for name, value in values:
            require(name not in result, 'duplicate-json-field')
            result[name] = value
        return result
    def reject(_):
        raise ValueError('noninteger-json-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)


def load_guard(exclusions):
    require(exclusions, 'explicit-whole-private-roots-required')
    roots, inodes = [], set()
    for value in exclusions:
        root = Path(value).absolute()
        require(root.is_dir() and '..' not in root.parts
                and not any(p.is_symlink() for p in (root, *root.parents)), 'private-root-metadata')
        roots.append(root)
        def failed(error):
            raise ValueError('private-metadata-incomplete') from error
        for current, directories, files in os.walk(root, followlinks=False, onerror=failed):
            directories[:] = [name for name in directories if not (Path(current)/name).is_symlink()]
            for name in files:
                info = (Path(current)/name).lstat()
                if stat.S_ISREG(info.st_mode):
                    inodes.add((info.st_dev, info.st_ino))
    require(not any(p.is_symlink() for p in (BOOTSTRAP, *BOOTSTRAP.parents))
            and all(not BOOTSTRAP.is_relative_to(root) for root in roots), 'public-bootstrap-path')
    before = BOOTSTRAP.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and (before.st_dev,before.st_ino) not in inodes, 'public-bootstrap-metadata')
    keys = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
    fd = os.open(BOOTSTRAP, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        opened = os.fstat(handle.fileno());require(all(getattr(before,key)==getattr(opened,key) for key in keys),'bootstrap-open-race')
        raw = handle.read();after = os.fstat(handle.fileno())
    require(all(getattr(before,key)==getattr(after,key) for key in keys)
            and hashlib.sha256(raw).hexdigest()==BOOTSTRAP_SHA,'bootstrap-source-pin')
    guard = {'__file__':str(BOOTSTRAP),'__name__':'settlement_guard09'}
    exec(compile(raw,str(BOOTSTRAP),'exec'),guard)
    guard['m'].GUARD.directories = tuple(dict.fromkeys((*guard['m'].GUARD.directories,*roots)))
    guard['m'].GUARD.inodes.update(inodes)
    return guard


def load_protocol(selection, reader):
    path = HERE/'protocol.py'
    rows = {row['path']:row for row in selection['source_members']}
    require(len(rows)==len(selection['source_members']) and str(path) in rows, 'selected-protocol-source')
    raw = reader(rows[str(path)])
    namespace = {'__file__':str(path),'__name__':'kpb_settlement_protocol'}
    exec(compile(raw,str(path),'exec'),namespace)
    return types.SimpleNamespace(**namespace)


def selection_rows(P, value):
    P.fields(value, ('schema','selected','classification','source_members','tools',
        'component_profile','outer_selection','parameters','sdk_directory','rpc_url'))
    P.need(value['schema']=='kpb-live-settlement-selection/v1'
           and value['selected'] is True and value['classification']==P.CLASS,
           'selected-settlement-adapter-required')
    P.need(value['rpc_url'] in STANDARD_ENDPOINTS, 'selected-Tor-testnet-endpoint')
    P.fields(value['tools'], ('node','native_validator','codec','host'))
    P.need(type(value['source_members']) is list and value['source_members'], 'complete-public-source-closure')
    rows = {}
    for row in [*value['source_members'],*value['tools'].values(),
                value['component_profile'],value['outer_selection'],value['parameters']]:
        P.record(row)
        path=Path(row['path'])
        P.need(not any(path.is_relative_to(root) for root in
               ('/usr','/etc','/proc','/tmp','/out','/bin','/lib','/lib64'))
               and (not path.is_relative_to('/dev') or path.is_relative_to('/dev/shm')),
               'selected-file-not-hidden-by-base-mount')
        P.need(not row['path'].endswith('.pyc') and '__pycache__' not in Path(row['path']).parts,
               'no-unselected-python-bytecode')
        P.need(row['path'] not in rows or rows[row['path']]==row, 'one-identity-per-public-path')
        rows[row['path']] = row
    P.need(str(HERE/'launch.py') in rows and str(HERE/'protocol.py') in rows
           and str(HERE/'acquire.mjs') in rows, 'complete-adapter-source-members')
    return rows


def selected_profile(P, selection, reader, request):
    raw = reader(selection['component_profile']);profile=P.parse(raw)
    P.need(profile.get('schema')=='private-batch-component-profile/v1'
           and profile.get('selected') is True and profile.get('classification')==P.CLASS,
           'financial-component-profile-unselected')
    outer=P.parse(reader(selection['outer_selection']))
    P.need(outer.get('schema')=='private-batch-outer-selection/v1' and outer.get('selected') is True
           and outer.get('classification')==P.CLASS
           and outer.get('component_profile_sha256')==P.sha(raw), 'financial-outer-profile-unselected')
    P.digest(outer['image_id_hex32']);P.digest(outer['program_sha256'])
    params_raw=reader(selection['parameters']);params=P.parse(params_raw)
    P.fields(params, ('domain_hex32','chain_hex32','pool_hex32','profile_hex32','service_hex32',
                     'outer_image_hex32','component_profile_sha256','exit_vk_hex328','component_manifest_hex'))
    P.need(params['component_manifest_hex']==raw.hex() and params['component_profile_sha256']==P.sha(raw)
           and params['outer_image_hex32']==outer['image_id_hex32']
           and params['exit_vk_hex328']==profile['auth_exit']['vk_hex328'], 'actual-selected-parameter-manifest')
    P.need(P.sha(params_raw)==request['native_policy']['native_parameters_sha256']
           ==request['final_candidate']['selection_sha256']==selection['parameters']['sha256']
           and outer['image_id_hex32']==request['final_candidate']['image_hex32'],
           'exact-durable-final-parameter-selection-and-image')
    for context_key, profile_key in (('chain_hex32','chain_genesis_hex32'),('pool_hex32','pool_lineage_hex32'),
        ('profile_hex32','profile_id_hex32'),('domain_hex32','domain_hex32'),('service_hex32','service_policy_hex32')):
        P.need(params[context_key]==profile[profile_key]==request['context'][context_key], 'selected-context-lineage')
    return profile,outer,params


def run_tool(P, command, output, *, input_bytes=None):
    # The outer launcher creates sibling namespaces: preflight/verify have no
    # network; acquire alone shares the existing Tor proxy network. Nested
    # user namespaces are deliberately unnecessary.
    result = subprocess.run(command,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    output.mkdir(parents=True,exist_ok=False)
    (output/'stdout.log').write_bytes(result.stdout);(output/'stderr.log').write_bytes(result.stderr)
    P.need(result.returncode==0,'selected-public-verifier-refused')
    return result.stdout


def save(P, path, value):
    raw=P.encoded(value)+b'\n'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as handle:
        handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return {'path':str(path),'sha256':P.sha(raw)}


def sync_evidence(root):
    """Durably retain this fresh public observation before exporting its hash."""
    directories=[]
    def failed(error):
        raise ValueError('evidence-traversal-incomplete') from error
    for current,names,files in os.walk(root,followlinks=False,onerror=failed):
        directory=Path(current)
        if directory==root:names.remove('shadow')
        info=directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid(),'owned-evidence-directory')
        directories.append(directory)
        for name in names:
            child=(directory/name).lstat()
            require(stat.S_ISDIR(child.st_mode) and child.st_uid==os.getuid(),'no-evidence-symlinks')
        for name in files:
            path=directory/name;before=path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                    and before.st_uid==os.getuid(),'owned-regular-evidence')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
            try:
                opened=os.fstat(fd)
                keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
                require(all(getattr(before,key)==getattr(opened,key) for key in keys),'evidence-open-race')
                os.fsync(fd)
                after=os.fstat(fd)
                require(all(getattr(before,key)==getattr(after,key) for key in keys),'evidence-sync-race')
            finally:os.close(fd)
    for directory in [*reversed(directories),root.parent]:
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)


def inside(arguments):
    stage('public-namespace')
    require(Path('/kpb-public-only').is_file() and arguments.output=='/out', 'isolated-public-role-required')
    # The outer launcher already authenticated/snapshotted this selected source.
    selection_raw=Path(arguments.selection).read_bytes()
    require(hashlib.sha256(selection_raw).hexdigest()==arguments.selection_sha256,'selected-inner-selection')
    selection=basic_json(selection_raw)
    P=load_protocol(selection, lambda row: finite_bootstrap_read(row))
    rows=selection_rows(P,selection)
    for row in rows.values():P.read_finite(row)
    request_raw=P.read_finite({'path':arguments.request,'sha256':arguments.request_sha256})
    request=P.validate_request(P.parse(request_raw))
    stage('financial-selection')
    profile,outer,parameters=selected_profile(P,selection,P.read_finite,request)
    tools=selection['tools'];output=Path('/out')/arguments.inside_mode
    output.mkdir(mode=0o700)
    if arguments.inside_mode=='acquire':
        stage('fresh-live-acquisition')
        P.digest(arguments.network_request_sha256)
        network_path=Path('/out/preflight/NETWORK-REQUEST.json')
        network_request=P.parse(P.read_finite({'path':str(network_path),'sha256':arguments.network_request_sha256}))
        P.need(network_request['nonce_hex32']==request['nonce_hex32']
               and network_request['request_sha256']==arguments.request_sha256
               and network_request['selection_sha256']==arguments.selection_sha256,'direct-network-request-binding')
        acquisition_path=output/'acquisition'
        acquired=P.parse(run_tool(P,[tools['node']['path'],str(HERE/'acquire.mjs'),
            '--selection',arguments.selection,'--selection-sha256',arguments.selection_sha256,
            '--request',str(network_path),'--request-sha256',arguments.network_request_sha256,
            '--output',str(acquisition_path)],output/'network-process'))
        acquisition_raw=(acquisition_path/'ACQUISITION.json').read_bytes()
        P.need(acquired['schema']=='kpb-live-acquisition-complete/v1'
               and acquired['request_sha256']==arguments.request_sha256
               and acquired['acquisition_sha256']==P.sha(acquisition_raw)
               and acquired['retained_replay_performed'] is True,'direct-fresh-acquisition-provenance')
        print('KPB_LIVE_ACQUISITION_V1 '+' '.join([request['nonce_hex32'],arguments.request_sha256,
            arguments.selection_sha256,P.sha(acquisition_raw)]))
        return
    stage('compiled-host-selection')
    embedded=P.parse(run_tool(P,[tools['host']['path'],'key-check'],output/'host-selection-process'))
    P.need(embedded['component_profile_sha256']==selection['component_profile']['sha256']
           and embedded['aggregate_vk_sha256']==profile['aggregate']['vk_sha256']
           and embedded['output_vk_sha256']==profile['output']['vk_sha256']
           and embedded['auth_exit_vk_sha256']==profile['auth_exit']['vk_sha256']
           and embedded['domain_hex32']==request['context']['domain_hex32'],
           'actual-compiled-host-profile-selected')
    raw_case=P.read_finite(request['final_candidate']['case'])
    stage('candidate-binding')
    candidate=P.parse(raw_case);P.validate_case(candidate)
    codec_input=P.encoded({'operation':'body','parameters':parameters,'case':candidate})
    codec=P.parse(run_tool(P,[tools['codec']['path']],output/'candidate-codec',input_bytes=codec_input))
    candidate,projection,journal=P.verify_candidate(request,raw_case,codec)
    P.need(codec['component_profile_sha256']==selection['component_profile']['sha256']
           and codec['outer_image_hex32']==outer['image_id_hex32'], 'actual-candidate-selected-policy')
    expected_journal=b'KPBAJR01'+P.hx(request['context']['domain_hex32'],32)+P.hx(selection['component_profile']['sha256'],32)+hashlib.sha256(projection).digest()
    P.need(journal==expected_journal,'actual-selected-journal')
    frame=P.hx(candidate['transaction']['inputs'][0]['signatureScript'])
    P.need(len(frame)>247 and frame[:2]==b'\x4c\x80' and frame[130]==0x4d
           and len(frame)==133+int.from_bytes(frame[131:133],'little'),'candidate-native-witness')
    network_request={'schema':'kpb-settlement-acquisition-request/v1','nonce_hex32':request['nonce_hex32'],
        'request_sha256':arguments.request_sha256,'selection_sha256':arguments.selection_sha256,
        'birth_start_hash':request['birth_start_hash'],'head':request['head'],'context':request['context'],
        'immutable_tail_hex':frame[247:].hex(),'candidate_transaction_id':candidate['transaction']['id']}
    network_row=save(P,output/'NETWORK-REQUEST.json',network_request)
    if arguments.inside_mode=='preflight':
        print('KPB_PREFLIGHT_EVIDENCE_V1 '+' '.join([request['nonce_hex32'],arguments.request_sha256,
            arguments.selection_sha256,network_row['sha256']]))
        return
    P.need(arguments.inside_mode=='verify','closed-offline-evidence-mode')
    P.digest(arguments.acquisition_sha256)
    acquisition_path=Path('/out/acquire/acquisition')
    acquisition_raw=P.read_finite({'path':str(acquisition_path/'ACQUISITION.json'),'sha256':arguments.acquisition_sha256})
    acquisition=P.parse(acquisition_raw)
    P.need(acquisition['nonce_hex32']==request['nonce_hex32']
           and acquisition['request_sha256']==arguments.request_sha256
           and acquisition['selection_sha256']==arguments.selection_sha256,'fresh-live-binding')
    retained=P.parse(run_tool(P,[tools['node']['path'],str(HERE/'acquire.mjs'),'--verify-retained',
        '--selection',arguments.selection,'--selection-sha256',arguments.selection_sha256,
        '--request',network_row['path'],'--request-sha256',network_row['sha256'],
        '--output',str(acquisition_path),'--acquisition-sha256',P.sha(acquisition_raw)],
        output/'retained-offline-process'))
    P.need(retained['schema']=='kpb-retained-settlement-evidence-check/v1'
           and retained['acquisition_sha256']==P.sha(acquisition_raw)
           and retained['financial_settlement_authority'] is False,'independent-offline-retained-evidence-check')
    accepted=[P.rpc_case(row) for row in acquisition['transactions']]
    P.need(accepted and accepted[0]==candidate,'fresh-accepted-whole-CASE-equals-FINAL-CANDIDATE')
    producer=P.rpc_producer_case(acquisition['locked_head_producer'])
    head=request['head'];point=head['outpoint'];outputs=producer['transaction']['outputs']
    P.need(producer['transaction']['id']==point['transactionId'] and point['index']<len(outputs)
           and outputs[point['index']]['value']==P.decimal(head['reserve_sompi'])
           and outputs[point['index']]['scriptPublicKey']==candidate['entries'][0]['scriptPublicKey'],
           'accepted-locked-head-producer-output')
    producer_base=Path('/out/locked-head-producer');producer_case=save(P,producer_base/'CASE.json',producer)
    run_tool(P,[tools['native_validator']['path'],'validate-transaction',producer_case['path'],str(producer_base/'native')],producer_base/'native-process')
    producer_report=P.parse((producer_base/'native/native-validation.json').read_bytes())
    producer_scripts=producer_report.get('per_input_ScriptEngine')
    P.need(producer_report.get('isolation')=='PASS' and producer_report['Full']['accepted'] is True
           and producer_report.get('all_input_engines_accepted') is True
           and type(producer_scripts) is list and len(producer_scripts)==len(producer['transaction']['inputs'])
           and all(row.get('accepted') is True for row in producer_scripts),'actual-head-producer-native-Full')
    reports=[]
    stage('accepted-cryptographic-replay')
    for index,(case,row) in enumerate(zip(accepted,acquisition['transactions'])):
        base=Path('/out/accepted-cases')/f'{index:05d}';base.mkdir(parents=True)
        case_row=save(P,base/'CASE.json',case)
        actual_codec=P.parse(run_tool(P,[tools['codec']['path']],base/'codec-process',
            input_bytes=P.encoded({'operation':'body','parameters':parameters,'case':case})))
        P.need(actual_codec['case']==case and actual_codec['mode']==row['mode']
               and actual_codec['component_profile_sha256']==selection['component_profile']['sha256']
               and actual_codec['outer_image_hex32']==outer['image_id_hex32'],'accepted-selected-native-projection')
        actual_projection=P.hx(actual_codec['financial_projection_hex'])
        projection_file=base/'PROJECTION.bin';projection_file.write_bytes(actual_projection)
        if row['mode']=='payment':
            run_tool(P,[tools['host']['path'],'cross-check',str(projection_file),str(base/'host-cross-check')],base/'host-process')
            host=P.parse((base/'host-cross-check/report.json').read_bytes())
            P.need(host['aggregate_and_six_Output_G16_verified'] is True
                   and host['independent_arkworks_reference_checked'] is True
                   and host['public_state_and_global_balance_verified'] is True
                   and host['projection_sha256']==P.sha(actual_projection)
                   and host['journal_hex104']==actual_codec['journal_hex104'],'actual-seven-proof-composition')
        run_tool(P,[tools['native_validator']['path'],'validate-transaction',case_row['path'],str(base/'native')],base/'native-process')
        native=P.parse((base/'native/native-validation.json').read_bytes())
        scripts=native.get('per_input_ScriptEngine')
        P.need(native.get('isolation')=='PASS' and native['Full']['accepted'] is True
               and native.get('all_input_engines_accepted') is True
               and type(scripts) is list and len(scripts)==len(case['transaction']['inputs'])
               and all(item.get('accepted') is True for item in scripts)
               and native['Full']['fee_sompi']==actual_codec['metrics']['actual_fee_sompi'],
               'actual-native-Full-and-all-input-engines')
        reports.append({'case':case_row,'mode':row['mode'],'projection_sha256':P.sha(actual_projection),
            'native_report_sha256':P.sha((base/'native/native-validation.json').read_bytes()),
            'accepting_block_hash':row['accepting_block_header']['hash']})
    # A valid receipt for the same claim but a different native witness is not
    # the exact final candidate: encode and compare all actual native proof128.
    receipt_raw=P.read_finite(request['final_candidate']['r0_receipt'])
    stage('exact-candidate-R0-witness')
    receipt_path=output/'candidate-r0-receipt.bin';receipt_path.write_bytes(receipt_raw)
    journal_path=output/'candidate-journal.bin';journal_path.write_bytes(journal)
    run_tool(P,[tools['host']['path'],'native-proof',str(receipt_path),str(journal_path),str(output/'candidate-r0-verified')],output/'candidate-r0-process')
    native_proof=(output/'candidate-r0-verified/native-proof.bin').read_bytes()
    receipt_report=P.parse((output/'candidate-r0-verified/report.json').read_bytes())
    P.need(receipt_report['genuine_new_image_Groth16_receipt_verified'] is True
           and receipt_report['image_id_hex32']==outer['image_id_hex32']
           and receipt_report['journal_sha256']==P.sha(journal)
           and receipt_report['native_proof_bytes']==128
           and receipt_report['native_proof_sha256']==P.sha(native_proof)
           and (output/'candidate-r0-verified/journal.bin').read_bytes()==journal,
           'direct-R0-verifier-selected-image-journal-and-native-proof')
    P.need(len(native_proof)==128 and native_proof==frame[2:130],'genuine-R0-receipt-equals-accepted-native-witness')
    P.need(P.sha(native_proof)==request['final_candidate']['native_proof_sha256']
           and P.sha(journal)==request['final_candidate']['journal_sha256'],
           'genuine-R0-equals-durable-FINAL-CANDIDATE')
    claim={'schema':'kpb-settlement-acceptance-identity/v1','history_key_hex32':request['history_key_hex32'],
        'attempt_id_hex32':request['attempt_id_hex32'],'locked_binding_sha256':request['locked_binding_sha256'],
        'prepared_core_sha256':request['prepared_core_sha256'],'egress':request['egress'],
        'final_case_sha256':request['final_candidate']['case']['sha256'],
        'canonical_case_sha256':request['final_candidate']['canonical_case_sha256'],
        'component_profile_sha256':selection['component_profile']['sha256'],
        'outer_image_hex32':outer['image_id_hex32'],'selection_sha256':arguments.selection_sha256,
        'context':request['context'],'locked_head':request['head'],
        'native_policy':request['native_policy'],
        'final_candidate_policy':{key:request['final_candidate'][key] for key in
            ('selection_sha256','image_hex32','journal_sha256','native_proof_sha256')},
        'birth_start_hash':request['birth_start_hash'],
        'accepting_block_hash':acquisition['transactions'][0]['accepting_block_header']['hash']}
    result={'schema':'kpb-public-settlement-replay-result/v1','status':'VERIFIED_PUBLIC_REPLAY_EVIDENCE_ONLY',
        'nonce_hex32':request['nonce_hex32'],'request_sha256':arguments.request_sha256,
        'selection_sha256':arguments.selection_sha256,'acceptance_identity':claim,
        'acceptance_identity_sha256':P.sha(P.encoded(claim)),
        'acquisition_sha256':P.sha(acquisition_raw),'accepted_CASE_reports':reports,
        'locked_head_producer_case':producer_case,
        'locked_head_producer_native_report_sha256':P.sha((producer_base/'native/native-validation.json').read_bytes()),
        'locked_head_genesis_Output_admission_independently_required':True,
        'genuine_R0_receipt_sha256':P.sha(receipt_raw),'native_proof_sha256':P.sha(native_proof),
        'current_head':acquisition['head'],'current_state_hex112':acquisition['state_hex112'],
        'current_reserve_sompi':acquisition['reserve_sompi'],'selected_node_finite_prefix_assumption':True,
        'independent_consensus_or_continuous_currentness':False,'funding_or_broadcast':False,
        'journal_modified':False,'financial_authority_qualified':False}
    selected=save(P,output/'REPLAY-RESULT.json',result)
    stage('verified-export')
    tokens=[request['nonce_hex32'],arguments.request_sha256,arguments.selection_sha256,
        request['locked_binding_sha256'],request['final_candidate']['case']['sha256'],
        request['egress']['projection_sha256'],selected['sha256'],result['acceptance_identity_sha256']]
    # Retained bytes alone can yield only this evidence prefix. The outer
    # launcher emits financial settlement provenance after its actual live run.
    print('KPB_VERIFIED_EVIDENCE_V1 '+' '.join(tokens))


def finite_bootstrap_read(row):
    path=Path(row['path']);require(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'finite-source-path')
    before=path.lstat();require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'finite-source-file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        opened=os.fstat(handle.fileno());raw=handle.read();after=os.fstat(handle.fileno())
    keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
    require(all(getattr(before,key)==getattr(opened,key)==getattr(after,key) for key in keys)
            and hashlib.sha256(raw).hexdigest()==row['sha256'],'finite-source-pin-or-race')
    return raw


def namespace_command(shadow, output, network, argv):
    command=['/usr/bin/bwrap','--unshare-all']
    if network:command.append('--share-net')
    return [*command,'--die-with-parent','--new-session','--clearenv',
        '--ro-bind',str(shadow),'/', '--ro-bind','/usr','/usr','--proc','/proc','--dev','/dev',
        '--ro-bind',str(shadow/'dev/shm'),'/dev/shm','--tmpfs','/tmp','--bind',str(output),'/out',
        '--tmpfs','/out/shadow','--ro-bind','/etc/ssl/certs','/etc/ssl/certs',
        '--ro-bind','/etc/alternatives','/etc/alternatives','--setenv','PATH','/usr/bin:/bin',
        '--setenv','LANG','C.UTF-8','--setenv','PYTHONDONTWRITEBYTECODE','1','--chdir','/',*argv]


def outside(arguments):
    stage('private-metadata-and-guard')
    guard=load_guard(arguments.exclude_private_directory)
    reader=lambda row:guard['read'](Path(row['path']),row['sha256'])
    selection_raw=reader({'path':arguments.selection,'sha256':arguments.selection_sha256});selection=basic_json(selection_raw)
    # Refuse the template before executing any selected auxiliary source/tool.
    stage('adapter-selection')
    require(selection.get('schema')=='kpb-live-settlement-selection/v1'
            and selection.get('selected') is True,'selected-settlement-adapter-required')
    P=load_protocol(selection,reader);rows=selection_rows(P,selection)
    request_raw=reader({'path':arguments.request,'sha256':arguments.request_sha256})
    request=P.validate_request(P.parse(request_raw));stage('financial-selection');selected_profile(P,selection,reader,request)
    for row in (request['final_candidate']['case'],request['final_candidate']['r0_receipt'],
                {'path':arguments.selection,'sha256':arguments.selection_sha256},
                {'path':arguments.request,'sha256':arguments.request_sha256}):
        P.record(row);P.need(row['path'] not in rows or rows[row['path']]==row,'one-identity-per-public-path');rows[row['path']]=row
        P.need(not any(Path(row['path']).is_relative_to(root) for root in
               ('/usr','/etc','/proc','/tmp','/out','/bin','/lib','/lib64','/dev')),
               'selected-data-not-hidden-by-base-mount')
    output=Path(arguments.output).absolute()
    P.need('..' not in output.parts and output.parent.is_dir() and output.parent.stat().st_uid==os.getuid()
           and not any(p.is_symlink() for p in (output,*output.parents))
           and all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in guard['m'].GUARD.directories)
           and all(not Path(row['path']).is_relative_to(output) for row in rows.values()),'fresh-disjoint-public-output')
    stage('public-snapshot');output.mkdir(mode=0o700);shadow=output/'shadow';shadow.mkdir(mode=0o700)
    executable_paths={row['path'] for row in selection['tools'].values()}
    for row in rows.values():
        raw=reader(row);target=shadow/row['path'].lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as handle:handle.write(raw)
        target.chmod(0o500 if row['path'] in executable_paths else 0o400)
    # A readonly complete public tree prevents import-path/bytecode injection.
    # The original private filesystem and the writable snapshot alias never
    # appear inside this role; only the existing Tor proxy network is shared.
    for name in ('usr','proc','dev','dev/shm','tmp','out','out/shadow','etc/ssl/certs','etc/alternatives'):
        (shadow/name).mkdir(parents=True,exist_ok=True)
    (shadow/'kpb-public-only').write_bytes(b'ADR0077 PUBLIC FILESYSTEM ONLY\n')
    for name,target in (('bin','usr/bin'),('lib','usr/lib'),('lib64','usr/lib64')):
        (shadow/name).symlink_to(target)
    for directory in sorted((p for p in shadow.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):directory.chmod(0o555)
    shadow.chmod(0o555)
    def role(mode,extra=()):
        command=namespace_command(shadow,output,mode=='acquire',
            [sys.executable,'-I','-B',str(HERE/'launch.py'),'--inside-mode',mode,
            '--selection',arguments.selection,'--selection-sha256',arguments.selection_sha256,
            '--request',arguments.request,'--request-sha256',arguments.request_sha256,
            '--output','/out',*extra])
        stage('isolated-'+mode+'-role')
        process=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        (output/(mode+'-launcher-stderr.log')).write_bytes(process.stderr)
        P.need(process.returncode==0,'direct-public-role-incomplete')
        return process.stdout.decode('ascii').strip().split(' ')
    preflight=role('preflight')
    P.need(len(preflight)==5 and preflight[0]=='KPB_PREFLIGHT_EVIDENCE_V1'
           and preflight[1:4]==[request['nonce_hex32'],arguments.request_sha256,arguments.selection_sha256],
           'direct-preflight-binding')
    P.digest(preflight[4])
    live=role('acquire',('--network-request-sha256',preflight[4]))
    P.need(len(live)==5 and live[0]=='KPB_LIVE_ACQUISITION_V1'
           and live[1:4]==[request['nonce_hex32'],arguments.request_sha256,arguments.selection_sha256],
           'direct-live-acquisition-binding')
    P.digest(live[4])
    tokens=role('verify',('--acquisition-sha256',live[4]))
    P.need(len(tokens)==9 and tokens[0]=='KPB_VERIFIED_EVIDENCE_V1','closed-evidence-result-line')
    for token in tokens[1:]:P.digest(token)
    P.need(tokens[1:7]==[request['nonce_hex32'],arguments.request_sha256,arguments.selection_sha256,
        request['locked_binding_sha256'],request['final_candidate']['case']['sha256'],request['egress']['projection_sha256']], 'direct-live-result-binding')
    result_raw=reader({'path':str(output/'verify/REPLAY-RESULT.json'),'sha256':tokens[7]});result=P.parse(result_raw)
    P.need(result['acceptance_identity_sha256']==tokens[8]
           and result['request_sha256']==arguments.request_sha256 and result['nonce_hex32']==request['nonce_hex32']
           and result['acquisition_sha256']==live[4], 'direct-live-export-file-binding')
    # Reauthenticate the original selected source/data identities after child
    # execution. The role itself used immutable independent snapshots.
    for row in rows.values():reader(row)
    # Only this direct outer flow has fresh acquisition provenance. Offline
    # replay cannot write this final result or emit its financial prefix.
    result.update(schema='kpb-direct-live-settlement-result/v1',
                  status='VERIFIED_FRESH_ACCEPTED_PRIVATE_BATCH',
                  financial_authority_qualified=True,
                  direct_live_acquisition_and_exact_replay=True,
                  replay_result_sha256=tokens[7])
    final=save(P,output/'SETTLEMENT.json',result)
    sync_evidence(output)
    exported=[*tokens[1:7],final['sha256'],tokens[8]]
    sys.stdout.write('KPB_SETTLEMENT_VERIFIED_V1 '+' '.join(exported)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','selection-sha256','request','request-sha256','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--exclude-private-directory',action='append',default=[])
    parser.add_argument('--inside-mode',choices=('preflight','acquire','verify'),help=argparse.SUPPRESS)
    parser.add_argument('--network-request-sha256',help=argparse.SUPPRESS)
    parser.add_argument('--acquisition-sha256',help=argparse.SUPPRESS)
    arguments=parser.parse_args()
    try:
        (inside if arguments.inside_mode else outside)(arguments)
    except Exception:
        # Inputs and SDK views are public, but keep the launcher's contract
        # narrow. Detailed selected subprocess evidence remains in its output.
        sys.stderr.write('kpb-settlement: incomplete:'+PUBLIC_PHASE+'\n');raise SystemExit(2)


if __name__=='__main__':main()

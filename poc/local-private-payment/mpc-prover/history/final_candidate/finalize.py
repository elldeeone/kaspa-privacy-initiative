#!/usr/bin/env python3
"""Offline public EGRESS -> FINAL verifier. No chain, submit or unlock authority."""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

HERE=Path(__file__).resolve().parent
SHARED=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment/mpc-prover/history/settlement')
SHARED_SHA='9a9d8cb0dd978e2c9265dc187dd24a92f1696e6de668a9d2997039e56fedc4c5'
PROTOCOL_SHA='cae9c1c46a425c780b5545254203251cd72a4e96188cfd8998779b3febe2c8c0'
BOOTSTRAP=Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA='0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
PHASE='bootstrap'


def require(value,reason):
    if not value:raise ValueError(reason)


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


def finite(row):
    path=Path(row['path'])
    require(path.is_absolute() and '..' not in path.parts
            and not any(p.is_symlink() for p in (path,*path.parents)),'finite-public-path')
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'finite-public-file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        opened=os.fstat(handle.fileno());raw=handle.read();after=os.fstat(handle.fileno())
    require(all(getattr(before,k)==getattr(opened,k)==getattr(after,k) for k in
            ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink'))
            and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==row['sha256'],
            'finite-public-pin-or-race')
    return raw


def shared(reader):
    path=SHARED/'launch.py';raw=reader({'path':str(path),'sha256':SHARED_SHA})
    namespace={'__file__':str(path),'__name__':'offline_final_shared'}
    exec(compile(raw,str(path),'exec'),namespace)
    return types.SimpleNamespace(**namespace)


def selected(L, selection, reader):
    P=L.load_protocol(selection,reader)
    P.fields(selection,('schema','selected','classification','registered_history_sha256',
        'source_members','tools','component_profile','outer_selection','parameters'))
    P.need(selection['schema']=='kpb-offline-final-selection/v1'
           and selection['selected'] is True and selection['classification']==P.CLASS,
           'selected-offline-finalizer-required')
    P.digest(selection['registered_history_sha256'])
    P.fields(selection['tools'],('codec','host','native_validator'))
    P.need(type(selection['source_members']) is list and selection['source_members'],'complete-offline-source-closure')
    rows={}
    for row in [*selection['source_members'],*selection['tools'].values(),
                selection['component_profile'],selection['outer_selection'],selection['parameters']]:
        P.record(row);path=Path(row['path'])
        P.need(not any(path.is_relative_to(root) for root in
            ('/usr','/etc','/proc','/tmp','/out','/bin','/lib','/lib64','/dev'))
            and not row['path'].endswith('.pyc') and '__pycache__' not in path.parts,
            'visible-offline-source-path')
        P.need(row['path'] not in rows or rows[row['path']]==row,'one-public-path-identity')
        rows[row['path']]=row
    for path,pin in ((SHARED/'launch.py',SHARED_SHA),(SHARED/'protocol.py',PROTOCOL_SHA)):
        P.need(rows.get(str(path))=={'path':str(path),'sha256':pin},'exact-frozen-shared-source')
    for path in (HERE/'finalize.py',HERE/'offline_protocol.py'):
        P.need(str(path) in rows,'complete-offline-final-source')
    path=HERE/'offline_protocol.py';namespace={'__file__':str(path),'__name__':'offline_final_protocol'}
    exec(compile(reader(rows[str(path)]),str(path),'exec'),namespace)
    Q=types.SimpleNamespace(**namespace)
    return P,Q,rows


def inside(args):
    global PHASE
    PHASE='offline-public-role'
    require(Path('/kpb-public-only').is_file() and args.output=='/out','isolated-offline-role')
    L=shared(finite);selection=L.basic_json(finite({'path':args.selection,'sha256':args.selection_sha256}))
    P,Q,rows=selected(L,selection,finite)
    for row in rows.values():P.read_finite(row)
    request=Q.validate(P,P.parse(P.read_finite({'path':args.request,'sha256':args.request_sha256})))
    P.need(request['registered_history_sha256']==selection['registered_history_sha256'],'registered-history-selection')
    # These temporary expected values come from selected public metadata, not
    # caller FINAL fields; the request intentionally contains no prior FINAL.
    outer_raw=P.parse(P.read_finite(selection['outer_selection']))
    joined={**request,'final_candidate':{'selection_sha256':selection['parameters']['sha256'],
                                       'image_hex32':outer_raw['image_id_hex32']}}
    PHASE='selected-financial-profile'
    profile,outer,parameters=L.selected_profile(P,selection,P.read_finite,joined)
    output=Path('/out/verify');output.mkdir(mode=0o700);tools=selection['tools']
    PHASE='actual-CASE-and-EGRESS'
    raw_case=P.read_finite(request['candidate']['case']);case=P.parse(raw_case);P.validate_case(case)
    codec=P.parse(L.run_tool(P,[tools['codec']['path']],output/'codec-process',
        input_bytes=P.encoded({'operation':'body','parameters':parameters,'case':case})))
    case,projection,journal,fields=Q.candidate(P,request,raw_case,codec,selection,outer)
    P.need(codec['component_profile_sha256']==selection['component_profile']['sha256']
           and codec['outer_image_hex32']==outer['image_id_hex32'],'actual-selected-codec-policy')
    expected=b'KPBAJR01'+P.hx(request['context']['domain_hex32'],32)+P.hx(selection['component_profile']['sha256'],32)+hashlib.sha256(projection).digest()
    P.need(journal==expected,'actual-selected-journal')
    projection_path=output/'PROJECTION.bin';projection_path.write_bytes(projection)
    journal_path=output/'JOURNAL.bin';journal_path.write_bytes(journal)
    PHASE='actual-seven-proof-composition'
    embedded=P.parse(L.run_tool(P,[tools['host']['path'],'key-check'],output/'host-selection-process'))
    P.need(embedded['component_profile_sha256']==selection['component_profile']['sha256']
           and embedded['aggregate_vk_sha256']==profile['aggregate']['vk_sha256']
           and embedded['output_vk_sha256']==profile['output']['vk_sha256']
           and embedded['auth_exit_vk_sha256']==profile['auth_exit']['vk_sha256']
           and embedded['domain_hex32']==request['context']['domain_hex32'],'actual-host-profile')
    L.run_tool(P,[tools['host']['path'],'cross-check',str(projection_path),str(output/'host-cross-check')],output/'host-process')
    host=P.parse((output/'host-cross-check/report.json').read_bytes())
    P.need(host['aggregate_and_six_Output_G16_verified'] is True
           and host['independent_arkworks_reference_checked'] is True
           and host['public_state_and_global_balance_verified'] is True
           and host['projection_sha256']==P.sha(projection)
           and host['journal_hex104']==journal.hex(),'actual-seven-proof-composition')
    PHASE='actual-genuine-R0-and-exact-witness'
    receipt_raw=P.read_finite(request['candidate']['r0_receipt'])
    receipt_path=output/'RECEIPT.bin';receipt_path.write_bytes(receipt_raw)
    L.run_tool(P,[tools['host']['path'],'native-proof',str(receipt_path),str(journal_path),str(output/'r0')],output/'r0-process')
    proof=(output/'r0/native-proof.bin').read_bytes();r0=P.parse((output/'r0/report.json').read_bytes())
    frame=P.hx(case['transaction']['inputs'][0]['signatureScript'])
    P.need(len(proof)==128 and proof==frame[2:130] and P.sha(proof)==fields['native_proof']
           and (output/'r0/journal.bin').read_bytes()==journal
           and r0['genuine_new_image_Groth16_receipt_verified'] is True
           and r0['image_id_hex32']==fields['image'] and r0['journal_sha256']==fields['journal']
           and r0['native_proof_bytes']==128 and r0['native_proof_sha256']==fields['native_proof'],
           'genuine-selected-R0-equals-exact-CASE-witness')
    P.need(P.sha(receipt_raw)==fields['outer_receipt'],'actual-outer-receipt-bytes')
    PHASE='actual-NativeFull-and-every-input'
    case_path=L.save(P,output/'CASE.json',case)
    L.run_tool(P,[tools['native_validator']['path'],'validate-transaction',case_path['path'],str(output/'native')],output/'native-process')
    native=P.parse((output/'native/native-validation.json').read_bytes());engines=native.get('per_input_ScriptEngine')
    P.need(native.get('isolation')=='PASS' and native['Full']['accepted'] is True
           and native.get('all_input_engines_accepted') is True
           and type(engines) is list and len(engines)==len(case['transaction']['inputs'])
           and all(row.get('accepted') is True for row in engines)
           and native['Full']['fee_sompi']==codec['metrics']['actual_fee_sompi'],
           'actual-NativeFull-and-every-input')
    result={'schema':'kpb-offline-final-replay/v1','classification':'OFFLINE_FINAL_CANDIDATE_NOT_CHAIN_ACCEPTANCE',
        'nonce_hex32':request['nonce_hex32'],'request_sha256':args.request_sha256,
        'adapter_selection_sha256':args.selection_sha256,'locked_binding_sha256':request['locked_binding_sha256'],
        'egress_record':request['egress_record'],'final_candidate':fields,
        'candidate_sha256':P.sha(Q.encoded_candidate(P,fields)),
        'network_or_chain_acceptance':False,'settlement_or_unlock_authority':False,
        'funding_or_broadcast':False,'journal_modified':False}
    report=L.save(P,output/'REPLAY-RESULT.json',result)
    print('KPB_OFFLINE_FINAL_EVIDENCE_V1 '+' '.join(Q.tokens(P,request,args.request_sha256,args.selection_sha256,fields,report['sha256'])))


def outside(args):
    global PHASE
    PHASE='private-metadata-and-guard'
    guard=load_guard(args.exclude_private_directory)
    reader=lambda row:guard['read'](Path(row['path']),row['sha256'])
    L=shared(reader)
    selection=L.basic_json(reader({'path':args.selection,'sha256':args.selection_sha256}))
    PHASE='offline-final-selection'
    require(selection.get('schema')=='kpb-offline-final-selection/v1' and selection.get('selected') is True,
            'selected-offline-finalizer-required')
    P,Q,rows=selected(L,selection,reader)
    request=Q.validate(P,P.parse(reader({'path':args.request,'sha256':args.request_sha256})))
    P.need(request['registered_history_sha256']==selection['registered_history_sha256'],'registered-history-selection')
    # Reject an unselected real outer before creating the public namespace.
    outer=P.parse(reader(selection['outer_selection']))
    joined={**request,'final_candidate':{'selection_sha256':selection['parameters']['sha256'],
                                       'image_hex32':outer['image_id_hex32']}}
    L.selected_profile(P,selection,reader,joined)
    for row in (request['candidate']['case'],request['candidate']['r0_receipt'],
                {'path':args.selection,'sha256':args.selection_sha256},
                {'path':args.request,'sha256':args.request_sha256}):
        P.record(row);P.need(row['path'] not in rows or rows[row['path']]==row,'one-public-path-identity')
        P.need(not any(Path(row['path']).is_relative_to(root) for root in
            ('/usr','/etc','/proc','/tmp','/out','/bin','/lib','/lib64','/dev')),'visible-public-input')
        rows[row['path']]=row
    output=Path(args.output).absolute()
    P.need('..' not in output.parts and output.parent.is_dir() and output.parent.stat().st_uid==os.getuid()
           and not any(p.is_symlink() for p in (output,*output.parents))
           and all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in guard['m'].GUARD.directories)
           and all(not Path(row['path']).is_relative_to(output) for row in rows.values()),'fresh-disjoint-output')
    PHASE='readonly-public-snapshot'
    output.mkdir(mode=0o700);shadow=output/'shadow';shadow.mkdir(mode=0o700)
    executable={row['path'] for row in selection['tools'].values()}
    for row in rows.values():
        raw=reader(row);target=shadow/row['path'].lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as handle:handle.write(raw)
        target.chmod(0o500 if row['path'] in executable else 0o400)
    for name in ('usr','proc','dev/shm','tmp','out/shadow','etc/ssl/certs','etc/alternatives'):
        (shadow/name).mkdir(parents=True,exist_ok=True)
    (shadow/'kpb-public-only').write_bytes(b'OFFLINE FINAL PUBLIC ONLY\n')
    for name,target in (('bin','usr/bin'),('lib','usr/lib'),('lib64','usr/lib64')):(shadow/name).symlink_to(target)
    for directory in sorted((p for p in shadow.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):directory.chmod(0o555)
    shadow.chmod(0o555)
    PHASE='direct-offline-verifier'
    command=L.namespace_command(shadow,output,False,[sys.executable,'-I','-B',str(HERE/'finalize.py'),
        '--inside','--selection',args.selection,'--selection-sha256',args.selection_sha256,
        '--request',args.request,'--request-sha256',args.request_sha256,'--output','/out'])
    process=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,close_fds=True)
    (output/'verifier-stderr.log').write_bytes(process.stderr)
    P.need(process.returncode==0,'actual-offline-final-verifier-refused')
    tokens=process.stdout.decode('ascii').strip().split(' ')
    P.need(len(tokens)==17 and tokens[0]=='KPB_OFFLINE_FINAL_EVIDENCE_V1','closed-offline-result-line')
    for item in tokens[1:]:P.digest(item)
    fields=dict(zip(Q.FIELDS,tokens[9:]))
    expected=Q.tokens(P,request,args.request_sha256,args.selection_sha256,fields,tokens[8])
    P.need(tokens[1:]==expected and fields['raw_case']==request['candidate']['case']['sha256']
           and fields['outer_receipt']==request['candidate']['r0_receipt']['sha256']
           and fields['selection']==request['native_policy']['native_parameters_sha256'],
           'exact-direct-request-and-candidate-binding')
    report_raw=reader({'path':str(output/'verify/REPLAY-RESULT.json'),'sha256':tokens[8]})
    report=P.parse(report_raw)
    P.need(report['final_candidate']==fields and report['candidate_sha256']==tokens[7]
           and report['egress_record']==request['egress_record'],'exact-direct-evidence-file')
    for row in rows.values():reader(row)
    report.update(schema='kpb-direct-offline-final-result/v1',replay_result_sha256=tokens[8])
    final=L.save(P,output/'FINAL-CANDIDATE.json',report)
    L.sync_evidence(output)
    exported=Q.tokens(P,request,args.request_sha256,args.selection_sha256,fields,final['sha256'])
    print('KPB_OFFLINE_FINAL_VERIFIED_V1 '+' '.join(exported))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','selection-sha256','request','request-sha256','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--exclude-private-directory',action='append',default=[])
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    try:(inside if args.inside else outside)(args)
    except Exception:
        sys.stderr.write('kpb-offline-final: incomplete:'+PHASE+'\n');raise SystemExit(2)


if __name__=='__main__':main()


"""Public encoding/control tests only; no proof or live settlement fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
P=runpy.run_path(str(HERE/'protocol.py'))


def h(text):return hashlib.sha256(text.encode()).hexdigest()


def fixture():
    context={'chain_hex32':P['GENESIS'],'pool_hex32':h('synthetic pool'),
        'profile_hex32':h('synthetic profile'),'domain_hex32':h('synthetic D'),
        'service_hex32':h('synthetic service'),'epoch_hex32':h('synthetic epoch')}
    point={'transactionId':h('synthetic old point'),'index':7}
    core=bytearray(10364);core[:8]=b'KPBAEF01'
    for at,key in ((8,'chain_hex32'),(40,'pool_hex32'),(72,'profile_hex32'),(104,'domain_hex32'),(136,'service_hex32')):
        core[at:at+32]=bytes.fromhex(context[key])
    core[168:204]=bytes.fromhex(point['transactionId'])+(7).to_bytes(4,'little')
    core[204:236]=bytes.fromhex(h('synthetic CM'));core[236:268]=bytes.fromhex(h('synthetic NFroot'))
    core[268:272]=(3).to_bytes(4,'little');core[272:276]=(1).to_bytes(4,'little')
    core[276:284]=(600000000).to_bytes(8,'little');core[356:364]=(580000000).to_bytes(8,'little')
    core[364:372]=(20000000).to_bytes(8,'little')
    for at,label in ((404,'A'),(500,'B'),(596,'C')):core[at:at+32]=bytes.fromhex(h('synthetic NF '+label))
    payload=bytes(core)+bytes(128)  # Deliberately not a valid proof.
    state=b'KPBAST01'+core[104:136]+core[204:236]+core[268:272]+core[236:268]+core[272:276]
    tail=b'PUBLIC SYNTHETIC UNSELECTED POLICY'
    redeem=b'\x4c\x70'+state+tail
    frame=b'\x4c\x80'+bytes(128)+b'\x4d'+len(redeem).to_bytes(2,'little')+redeem
    case={'transaction':{'version':1,'id':h('synthetic candidate'),'inputs':[{
        'previousOutpoint':point,'signatureScript':frame.hex(),
        'sequence':2**64-1,'computeBudget':1800}],
        'outputs':[{'value':580000000,'scriptPublicKey':'0000aa20'+h('synthetic successor')+'87','covenant':None}],
        'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':payload.hex(),'mass':1},
        'entries':[{'amount':600000000,'scriptPublicKey':'0000aa20'+h('synthetic input')+'87',
            'blockDaaScore':987654321012345678,'isCoinbase':False,'covenantId':None}]}
    raw=P['encoded'](case)+b'\n';projection=b'KPBAFX01'+bytes(185)+payload
    journal=b'KPBAJR01'+bytes(96)
    request={'schema':'kpb-live-settlement-request/v2','nonce_hex32':h('synthetic nonce'),
        'history_key_hex32':h('synthetic history'),'attempt_id_hex32':h('synthetic attempt'),
        'locked_binding_sha256':h('synthetic lock'),'prepared_core_sha256':P['sha'](bytes(core)),
        'context':context,'head':{'outpoint':point,'state_hex112':state.hex(),'reserve_sompi':'600000000'},
        'native_policy':{'old_script_public_key_hex37':case['entries'][0]['scriptPublicKey'],
            'immutable_tail_sha256':P['sha'](tail),'native_parameters_sha256':h('synthetic native parameters')},
        'egress':{'core_sha256':P['sha'](bytes(core)),'aggregate_proof_sha256':P['sha'](bytes(128)),
            'projection_sha256':P['sha'](projection),'nfs_hex32':sorted(core[at:at+32].hex() for at in (404,500,596))},
        'final_candidate':{'case':{'path':'/synthetic/CASE.json','sha256':P['sha'](raw)},
            'canonical_case_sha256':P['canonical_case_sha256'](case),
            'selection_sha256':h('synthetic native parameters'),'image_hex32':h('synthetic guest image'),
            'journal_sha256':P['sha'](journal),'native_proof_sha256':P['sha'](bytes(128)),
            'r0_receipt':{'path':'/synthetic/receipt.bin','sha256':h('not an actual receipt')}},
        'birth_start_hash':h('synthetic birth')}
    codec={'mode':'payment','case':case,'financial_projection_hex':projection.hex(),
        'effects_digest_hex32':P['sha'](bytes(core)),'journal_hex104':journal.hex(),
        'outer_image_hex32':h('synthetic guest image')}
    return request,case,raw,codec


class PublicProtocolControls(unittest.TestCase):
    def test_public_framing_has_no_financial_authority(self):
        request,case,raw,codec=fixture();P['validate_request'](request)
        actual,projection,journal=P['verify_candidate'](request,raw,codec)
        self.assertEqual(actual,case);self.assertEqual(len(projection),10685);self.assertEqual(len(journal),104)
        self.assertNotIn('settled',P);self.assertNotIn('resolve',P)

    def test_witness_change_same_txid_is_not_same_candidate(self):
        request,case,raw,codec=fixture();changed=copy.deepcopy(case)
        changed['transaction']['inputs'][0]['signatureScript']='01'+changed['transaction']['inputs'][0]['signatureScript'][2:]
        self.assertEqual(changed['transaction']['id'],case['transaction']['id'])
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,P['encoded'](changed),codec)

    def test_budget_change_same_txid_is_not_same_candidate(self):
        request,case,raw,codec=fixture();changed=copy.deepcopy(case)
        changed['transaction']['inputs'][0]['computeBudget']+=1
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,P['encoded'](changed),codec)

    def test_context_change_is_refused(self):
        request,case,raw,codec=fixture();request['context']['pool_hex32']=h('another pool')
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)

    def test_head_reserve_change_is_refused(self):
        request,case,raw,codec=fixture();request['head']['reserve_sompi']='600000001'
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)

    def test_nf_high_bit_change_is_not_fr_alias(self):
        request,case,raw,codec=fixture();nf=bytearray.fromhex(request['egress']['nfs_hex32'][0]);nf[31]^=0x80
        request['egress']['nfs_hex32'][0]=nf.hex();request['egress']['nfs_hex32'].sort()
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)

    def test_duplicate_nf_refuses(self):
        request,*_=fixture();request['egress']['nfs_hex32'][1]=request['egress']['nfs_hex32'][0]
        with self.assertRaises(P['Refused']):P['validate_request'](request)

    def test_changed_projection_refuses(self):
        request,case,raw,codec=fixture();codec['financial_projection_hex']='00'+codec['financial_projection_hex'][2:]
        with self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)

    def test_durable_final_policy_pins_match_actual_artifacts(self):
        for field in ('image_hex32','journal_sha256','native_proof_sha256'):
            request,case,raw,codec=fixture();request['final_candidate'][field]=h('wrong '+field)
            with self.subTest(field=field),self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)
        for field in ('old_script_public_key_hex37','immutable_tail_sha256'):
            request,case,raw,codec=fixture()
            request['native_policy'][field]=('0000aa20'+h('wrong policy')+'87') if field.endswith('hex37') else h('wrong policy')
            with self.subTest(field=field),self.assertRaises(P['Refused']):P['verify_candidate'](request,raw,codec)
        request,*_=fixture();request['final_candidate']['selection_sha256']=h('wrong native parameters')
        with self.assertRaises(P['Refused']):P['validate_request'](request)

    def test_request_v1_never_upgrades_to_v2(self):
        request,*_=fixture();request['schema']='kpb-live-settlement-request/v1'
        with self.assertRaises(P['Refused']):P['validate_request'](request)

    def test_duplicate_json_and_float_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":1.0}',b'{"x":NaN}',b'\xff'):
            with self.assertRaises((P['Refused'],UnicodeError,json.JSONDecodeError)):P['parse'](raw)

    def test_bool_not_integer(self):
        _,case,_,_=fixture();case['transaction']['version']=True
        with self.assertRaises(P['Refused']):P['validate_case'](case)

    def test_decimal_boundaries(self):
        self.assertEqual(P['decimal']('18446744073709551615'),2**64-1)
        for value in ('18446744073709551616','01','1.0',1,True,'-1'):
            with self.assertRaises(P['Refused']):P['decimal'](value)

    def test_Full_decimal_conversion_preserves_wide_integers(self):
        _,case,_,_=fixture();tx=copy.deepcopy(case['transaction']);entry=case['entries'][0]
        tx['inputs'][0]['sequence']=str(tx['inputs'][0]['sequence'])
        for output in tx['outputs']:output['value']=str(output['value'])
        tx['lockTime']=str(tx['lockTime']);tx['gas']=str(tx['gas']);tx['storageMass']=str(tx.pop('mass'))
        row={'transaction':tx,'accepted_input_contexts':[{'outpoint':tx['inputs'][0]['previousOutpoint'],
            'amount_sompi':str(entry['amount']),'script_public_key':entry['scriptPublicKey'],
            'block_daa_score':str(entry['blockDaaScore']),'is_coinbase':False,'covenant_id':None}]}
        self.assertEqual(P['rpc_case'](row),case)

    def test_unselected_launcher_refuses_before_namespace_or_network(self):
        with tempfile.TemporaryDirectory(prefix='kpb-settlement-public-control-') as directory:
            root=Path(directory);private=root/'empty-private';private.mkdir()
            selection=root/'SELECTION.json';raw=b'{"schema":"kpb-live-settlement-selection/v1","selected":false}\n';selection.write_bytes(raw)
            process=subprocess.run(['/usr/bin/python3','-I',str(HERE/'launch.py'),
                '--selection',str(selection),'--selection-sha256',P['sha'](raw),
                '--request',str(root/'never-read-request'),'--request-sha256',h('unused request'),
                '--output',str(root/'never-created-output'),'--exclude-private-directory',str(private)],
                stdin=subprocess.DEVNULL,capture_output=True,close_fds=True)
            self.assertEqual(process.returncode,2);self.assertEqual(process.stdout,b'')
            self.assertEqual(process.stderr,b'kpb-settlement: incomplete:adapter-selection\n')
            self.assertFalse((root/'never-created-output').exists())

    def test_real_public_namespace_hides_private_path_fd_and_writable_snapshot_alias(self):
        launch=runpy.run_path(str(HERE/'launch.py'))
        with tempfile.TemporaryDirectory(prefix='kpb-settlement-namespace-control-') as directory:
            root=Path(directory);output=root/'out';output.mkdir();shadow=output/'shadow';shadow.mkdir()
            canary=root/'NONFINANCIAL-CANARY';canary.write_text('PUBLIC SYNTHETIC CANARY; NO WALLET DATA')
            probe="""import json,os,pathlib
assert not pathlib.Path(CANARY).exists()
assert not pathlib.Path('/out/shadow/probe.py').exists()
try:os.fstat(99)
except OSError:pass
else:raise AssertionError('inherited descriptor')
try:os.chmod('/probe.py',0o600)
except OSError:pass
else:raise AssertionError('readonly source')
print(json.dumps({'net':os.readlink('/proc/self/ns/net'),'public_only':True}))
""".replace('CANARY',repr(str(canary)))
            (shadow/'probe.py').write_text(probe)
            for name in ('usr','proc','dev/shm','tmp','out/shadow','etc/ssl/certs','etc/alternatives'):
                (shadow/name).mkdir(parents=True,exist_ok=True)
            for name,target in (('bin','usr/bin'),('lib','usr/lib'),('lib64','usr/lib64')):(shadow/name).symlink_to(target)
            fd=os.open(canary,os.O_RDONLY);os.dup2(fd,99)
            try:
                parent_net=os.readlink('/proc/self/ns/net')
                for shared in (False,True):
                    result=subprocess.run(launch['namespace_command'](shadow,output,shared,
                        ['/usr/bin/python3','-I','-B','/probe.py']),stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
                    self.assertEqual(result.returncode,0,result.stderr.decode())
                    value=P['parse'](result.stdout);self.assertTrue(value['public_only'])
                    self.assertEqual(value['net']==parent_net,shared)
            finally:os.close(fd);os.close(99)

    def test_evidence_fsync_admits_owned_files_and_refuses_aliases(self):
        launch=runpy.run_path(str(HERE/'launch.py'))
        with tempfile.TemporaryDirectory(prefix='kpb-settlement-durability-control-') as directory:
            root=Path(directory)/'out';root.mkdir();(root/'shadow').mkdir()
            (root/'public-evidence.json').write_text('{"synthetic":true}\n')
            launch['sync_evidence'](root)
            # Public fixture only: an alias must not be admitted as durable
            # evidence. No excluded or real private file is opened here.
            (root/'alias').symlink_to(root/'public-evidence.json')
            with self.assertRaises(ValueError):launch['sync_evidence'](root)
            (root/'alias').unlink()
            os.link(root/'public-evidence.json',root/'hardlink')
            with self.assertRaises(ValueError):launch['sync_evidence'](root)


if __name__=='__main__':unittest.main()

"""Synthetic public framing/refusal controls; no financial proof or journal."""
import copy
import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import types
import unittest

HERE=Path(__file__).resolve().parent
ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
SHARED=ROOT/'poc/local-private-payment/mpc-prover/history/settlement'
P=types.SimpleNamespace(**runpy.run_path(str(SHARED/'protocol.py')))
Q=types.SimpleNamespace(**runpy.run_path(str(HERE/'offline_protocol.py')))
L=runpy.run_path(str(HERE/'finalize.py'))
FIXTURE=runpy.run_path(str(SHARED/'test_protocol.py'))['fixture']


def h(label):return hashlib.sha256(label.encode()).hexdigest()


def fixture():
    old,case,raw,codec=FIXTURE()
    certs=[h('synthetic cert '+str(i)) for i in range(3)]
    key=b'KPBHKEY1'+b''.join(bytes.fromhex(old['context'][name]) for name in
        ('chain_hex32','pool_hex32','domain_hex32','profile_hex32','service_hex32','epoch_hex32'))
    key+=b''.join(bytes.fromhex(item) for item in certs)
    request={key:copy.deepcopy(old[key]) for key in ('nonce_hex32','attempt_id_hex32',
        'locked_binding_sha256','prepared_core_sha256','context','head','native_policy','egress')}
    request.update(schema='kpb-offline-final-request/v1',history_key_hex32=P.sha(key),
        registered_history_sha256=h('synthetic registration'),server_certificates_hex32=certs,
        egress_record={'sequence':4,'checkpoint_sha256':h('synthetic checkpoint')},
        candidate={key:old['final_candidate'][key] for key in ('case','r0_receipt')})
    selection={'parameters':{'sha256':request['native_policy']['native_parameters_sha256']}}
    outer={'image_id_hex32':codec['outer_image_hex32']}
    return request,case,raw,codec,selection,outer


class OfflineFinalControls(unittest.TestCase):
    def test_public_encoding_is_not_verification_authority(self):
        request,case,raw,codec,selection,outer=fixture();Q.validate(P,request)
        actual,projection,journal,fields=Q.candidate(P,request,raw,codec,selection,outer)
        self.assertEqual(actual,case);self.assertEqual(len(projection),10685)
        self.assertEqual(fields['journal'],P.sha(journal))
        encoded=Q.encoded_candidate(P,fields)
        self.assertEqual(encoded[:8],b'KPBHFIN1');self.assertEqual(len(encoded),264)
        tokens=Q.tokens(P,request,h('request'),h('selection'),fields,h('evidence'))
        self.assertEqual(len(tokens),16);self.assertEqual(tokens[5],fields['projection'])
        self.assertEqual(tokens[6],P.sha(encoded));self.assertEqual(tokens[8:],list(fields.values()))
        self.assertFalse(hasattr(Q,'resolve'));self.assertFalse(hasattr(Q,'verify_financial_proof'))

    def test_no_prefilled_FINAL_or_accepted_fields(self):
        for key in ('final_candidate','accepted','qualified'):
            request,*_=fixture();request[key]=True
            with self.subTest(key=key),self.assertRaises(P.Refused):Q.validate(P,request)

    def test_wrong_roster_or_history_key(self):
        request,*_=fixture();request['server_certificates_hex32'].reverse()
        with self.assertRaises(P.Refused):Q.validate(P,request)
        request,*_=fixture();request['server_certificates_hex32'][1]=request['server_certificates_hex32'][0]
        with self.assertRaises(P.Refused):Q.validate(P,request)

    def test_strict_checkpoint_sequence(self):
        for value in (0,True,-1,2**64,'4'):
            request,*_=fixture();request['egress_record']['sequence']=value
            with self.subTest(value=value),self.assertRaises(P.Refused):Q.validate(P,request)

    def test_exact_EGRESS_hashes_and_full_NFs(self):
        for key in ('core_sha256','aggregate_proof_sha256','projection_sha256'):
            request,case,raw,codec,selection,outer=fixture();request['egress'][key]=h('wrong '+key)
            with self.subTest(key=key),self.assertRaises(P.Refused):Q.candidate(P,request,raw,codec,selection,outer)
        request,case,raw,codec,selection,outer=fixture()
        nf=bytearray.fromhex(request['egress']['nfs_hex32'][0]);nf[31]^=128
        request['egress']['nfs_hex32'][0]=nf.hex();request['egress']['nfs_hex32'].sort()
        with self.assertRaises(P.Refused):Q.candidate(P,request,raw,codec,selection,outer)

    def test_actual_native_policy_and_selection(self):
        for key in ('immutable_tail_sha256','native_parameters_sha256'):
            request,case,raw,codec,selection,outer=fixture();request['native_policy'][key]=h('wrong '+key)
            with self.subTest(key=key),self.assertRaises(P.Refused):Q.candidate(P,request,raw,codec,selection,outer)
        request,case,raw,codec,selection,outer=fixture();request['native_policy']['old_script_public_key_hex37']='00'*37
        with self.assertRaises(P.Refused):Q.candidate(P,request,raw,codec,selection,outer)

    def test_same_txid_changed_CASE_cannot_join_original(self):
        request,case,raw,codec,selection,outer=fixture();changed=copy.deepcopy(case)
        changed['transaction']['inputs'][0]['computeBudget']+=1
        self.assertEqual(changed['transaction']['id'],case['transaction']['id'])
        with self.assertRaises(P.Refused):Q.candidate(P,request,P.encoded(changed)+b'\n',codec,selection,outer)

    def test_candidate_identity_binds_every_field(self):
        request,case,raw,codec,selection,outer=fixture()
        fields=Q.candidate(P,request,raw,codec,selection,outer)[3];prior=P.sha(Q.encoded_candidate(P,fields))
        for key in Q.FIELDS:
            changed={**fields,key:h('wrong '+key)}
            with self.subTest(key=key):self.assertNotEqual(P.sha(Q.encoded_candidate(P,changed)),prior)

    def test_unselected_direct_launcher_refuses_before_inputs_or_namespace(self):
        with tempfile.TemporaryDirectory(prefix='kpb-offline-final-public-control-') as directory:
            root=Path(directory);private=root/'empty-private';private.mkdir()
            raw=b'{"schema":"kpb-offline-final-selection/v1","selected":false}\n'
            source=root/'SELECTION.json';source.write_bytes(raw)
            result=subprocess.run(['/usr/bin/python3','-I','-B',str(HERE/'finalize.py'),
                '--selection',str(source),'--selection-sha256',P.sha(raw),
                '--request',str(root/'not-read'),'--request-sha256',h('unused'),
                '--output',str(root/'not-created'),'--exclude-private-directory',str(private)],
                stdin=subprocess.DEVNULL,capture_output=True,close_fds=True)
            self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,b'')
            self.assertEqual(result.stderr,b'kpb-offline-final: incomplete:offline-final-selection\n')
            self.assertFalse((root/'not-created').exists())

    def test_real_offline_namespace_has_no_host_network_or_private_FD(self):
        shared=runpy.run_path(str(SHARED/'launch.py'))
        with tempfile.TemporaryDirectory(prefix='kpb-offline-final-namespace-control-') as directory:
            root=Path(directory);out=root/'out';out.mkdir();shadow=out/'shadow';shadow.mkdir()
            canary=root/'PUBLIC-SYNTHETIC-CANARY';canary.write_text('not private data')
            code="import os,pathlib;assert not pathlib.Path(%r).exists();assert os.readlink('/proc/self/ns/net')!=%r\ntry:os.fstat(99)\nexcept OSError:pass\nelse:raise AssertionError('inherited descriptor')\nprint('offline namespace PASS')\n"%(str(canary),os.readlink('/proc/self/ns/net'))
            (shadow/'probe.py').write_text(code)
            for name in ('usr','proc','dev/shm','tmp','out/shadow','etc/ssl/certs','etc/alternatives'):(shadow/name).mkdir(parents=True,exist_ok=True)
            for name,target in (('bin','usr/bin'),('lib','usr/lib'),('lib64','usr/lib64')):(shadow/name).symlink_to(target)
            fd=os.open(canary,os.O_RDONLY);os.dup2(fd,99)
            try:
                result=subprocess.run(shared['namespace_command'](shadow,out,False,
                    ['/usr/bin/python3','-I','-B','/probe.py']),stdin=subprocess.DEVNULL,capture_output=True,close_fds=True)
                self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stdout,b'offline namespace PASS\n')
            finally:os.close(fd);os.close(99)


if __name__=='__main__':unittest.main()

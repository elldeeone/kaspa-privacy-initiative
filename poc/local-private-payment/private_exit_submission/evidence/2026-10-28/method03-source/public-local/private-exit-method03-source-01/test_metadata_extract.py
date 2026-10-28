"""Invented PUBLIC source-record fixtures; no real packets/proofs/keys/IO."""
import copy
import unittest

import metadata_attack as attack
import metadata_extract as extract
from test_metadata_attack import fixture as model_fixture, hx


def fixture():
    plan, old, _ = model_fixture()
    plan['sources'].update({str(i):hx(i) for i in range(4,12)})
    plan['native_source_pins']=dict(zip(('adapter','codec','engine','verifier','parameters','manifest','tail'),
                                      [hx(i)for i in range(4,11)]))
    plan['transport_source_pins']={k:v for k,v in old['transport_parameters']['A'].items()
                                  if k.endswith('_sha256')}
    binding=plan['binding']; events=[]
    def event(kind,**fields):
        row={'schema':'kpb-method03-controller-event/v1','binding':copy.deepcopy(binding),
             'sequence':len(events)+1,'recorded_monotonic_ns':2000,'kind':kind}
        row.update(fields);events.append(row);return row
    early=copy.deepcopy(old['clocks'][0]);early['sample']['monotonic_before_ns']=5
    early['sample']['monotonic_after_ns']=8
    event('controller-clock',value=early,source_event_ref={'path':'PUBLIC/EARLY-CONTROLLER-CLOCK.json','sha256':hx(15)})
    event('controller-clock-followup',value=old['clocks'][0])
    event('session-parameters',value=old['transport_parameters']['A'])
    heads=[];raw=[];parsed=[];exposures=[];contacts={'A':{},'B':{}}
    ctx_by_arm={}
    for ai,arm in enumerate(attack.ARMS):
        ctx=bytearray(276);ctx[64:96]=bytes.fromhex(hx(70));ctx[96:128]=bytes.fromhex(hx(71))
        ctx[160:196]=bytes.fromhex(hx(201+ai,36));ctx[196:228]=bytes.fromhex(hx(80+ai))
        ctx[228:260]=bytes.fromhex(hx(90+ai));ctx[260:264]=(3).to_bytes(4,'little')
        ctx[264:268]=(1).to_bytes(4,'little');ctx[268:276]=(6000000000).to_bytes(8,'little')
        ctx_by_arm[arm]=bytes(ctx);heads.append({'arm':arm,'context_hex276':ctx.hex(),'evidence_ref':'PUBLIC/head/'+arm})
    def status(role,value):
        envelope={'schema':'kpb-method03-status-observation/v1','reader_id':'controller/'+role,
                  'role':role,'reader_pid':100,'reader_observed_monotonic_ns':1000,
                  'reader_observed_realtime_ns':2000,'reader_observed_boottime_ns':1500,
                  'value':copy.deepcopy(value)}
        return event('status',role=role,observation=envelope,consumed_monotonic_ns=1500)
    status('receiver/0',old['clocks'][1])
    for ai,arm in enumerate(attack.ARMS):
        for owner in attack.OWNERS:
            slot=ai*3+owner;r=attack.role(arm,owner);clock=copy.deepcopy(old['clocks'][2+slot])
            event('pipe-created',slot=slot,arm=arm,owner_slot=owner,pipe_inode=5000+slot,
                  parent_read_fd=10+slot*2,parent_write_fd=11+slot*2,child_mapping={'owner_stdout':1,'transport_stdin':0})
            event('candidate-metadata',slot=slot,arm=arm,owner_slot=owner,candidate_ref={'path':'/PRIVATE/selected/'+str(slot)},
                  body_read=False,body_hash=False,handle_mode='O_PATH',setup_fd=50+slot)
            event('launch',role=r,host_pid=1000+slot,controller_pid=100,controller_ppid=99,
                  popen_started_monotonic_ns=100,popen_returned_monotonic_ns=110,
                  argv=['/public/bwrap','--ro-bind','/PRIVATE/selected/'+str(slot),'/in/candidate'],
                  passed_setup_fds=[50+slot],stdio={'stdin':10+slot*2,'stdout':'PIPE','stderr':'DEVNULL'})
            status(r,clock)
            common={'schema':'kpb-method03-role-subprocess-event/v1','actor_role':r,'clock_role':r,
                    'subprocess_index':1,'actual_local_pid':10,'actual_local_ppid':1,
                    'pid_namespace':{'link':'pid:[1000]','inode':1000},'operation':'curl'}
            status(r,{**common,'kind':'role-subprocess-launch','pre_Popen_monotonic_ns':150,
                      'post_Popen_monotonic_ns':160,'argv':['/public/curl','--config','/proc/self/fd/8'],
                      'pass_fds':[8,9],'stdio':{'stdin':'DEVNULL','stdout':'PIPE','stderr':'DEVNULL'},
                      'close_fds':True,'env_mode':'inherited'})
            status(r,{**common,'kind':'role-subprocess-exit','observed_wait_monotonic_ns':600,
                      'returncode':0,'observation':'communicate'})
            status(r,{'schema':'kpb-exit-transport-status/v1','transport_receipt':True,'financial_or_chain_acceptance':False})
            event('role-exit',role=r,host_pid=1000+slot,returncode=0,wait_returned_monotonic_ns=1100)
            event('parent-pipe-ends-closed',slot=slot,parent_fds=[10+slot*2,11+slot*2])
            event('submission-finished',slot=slot,arm=arm,owner_slot=owner,owner_returncode=0,
                  transport_returncode=0,receipt_seen=True,owner_fixed_status='FRAME_WRITTEN',possibly_arrived=True)
            projection=bytes([40+slot])*1844;proof=bytes([60+slot])*128
            frame=b'KPBXNET1'+(1844).to_bytes(2,'little')+projection+proof
            frame+=bytes([80+slot])*(4096-len(frame))
            aid=extract.sha(projection);ctx=ctx_by_arm[arm]
            raw.append({'schema':'kpb-exit-transport-arrival/v1','scope':'UNTRUSTED_PUBLIC_TRANSPORT_ONLY',
                'arrival_sequence':slot+1,'accepted_monotonic_ns':490+owner,'handler_monotonic_ns':495+owner,
                'post_handler_monotonic_ns':500+owner,'recorded_monotonic_ns':3000+owner,
                'peer':['127.0.0.1',40000+slot],'request_line':'POST /exit HTTP/1.0',
                'headers':[['Host','public-fixture.invalid.onion'],['User-Agent','kpb-exit-transport/1'],
                           ['Accept','application/octet-stream'],['Content-Type','application/octet-stream'],
                           ['Content-Length','4096']],'path':'/exit','http_status':202,'received_body_bytes':4096,
                'frame_sha256':extract.sha(frame),'framing':'PASS','projection_hex':projection.hex(),
                'proof_hex128':proof.hex(),'exit_id':aid,'financial_validation':'NOT_RUN','broadcast':False})
            native=copy.deepcopy(old['arrivals'][arm][owner]['native'])
            native.update(context_hex276=ctx.hex(),context_sha256=extract.sha(ctx),**extract._context(ctx))
            native['destination_spk_hex36']=(b'\0\0\x20'+bytes.fromhex(hx(300+slot))+b'\xac').hex()
            parsed.append({'ordinal':slot+1,'arrival_id':aid,'projection_hex':projection.hex(),
                           'proof_hex128':proof.hex(),'native':native})
            if arm=='A':
                event('A-exposure',slot=slot,arm='A',owner_slot=owner,artifact_path='/PUBLIC/A/'+str(owner))
                exposures.append({'schema':'kpb-method03-controller-A-exposure/v1','binding':copy.deepcopy(binding),
                    'arm':'A','owner_slot':owner,'owner_role':'owner/'+str(owner),'transport_role':r,
                    'owner_returncode':0,'owner_fixed_status':'FRAME_WRITTEN','frame_hex':frame.hex(),
                    'frame_sha256':extract.sha(frame),'framing_valid':True,'projection_hex':projection.hex(),
                    'projection_sha256':aid,'proof_hex128':proof.hex(),'packet_source_sha256':hx(8),
                    'owner_source_sha256':hx(9)})
    status('receiver/0',{'schema':'kpb-probe-listener-summary/v1','accepted':6,'completed':6,'monotonic_ns':1600})
    event('receiver-stop-control',bytes=5)
    for ai,arm in enumerate(attack.ARMS):
        rows=[]
        for owner in attack.OWNERS:
            for idx in (11,13):
                rows.append({'owner':owner,'native_pk_hex32':hx(400+owner*2+(idx==13)),
                    'delivery_pk_hex32':hx(500+owner),'invoice_index':idx,
                    'domain_hex32':hx(71),'profile_hex32':hx(70)})
        own=parsed[ai*3+1]['native']
        contacts[arm]={'contacts':rows,'own_payouts':[{'owner':1,'nf_hex32':own['nf_hex32'],
                           'spk_hex36':own['destination_spk_hex36']}],
            'known_receipts':[{'owner':0,'rho_hex32':hx(600+ai),'cm_hex32':hx(610+ai),
                'value':200000000,'known_consumed':True,'invoice_hex208':hx(620+ai,208),
                'receipt_hex216':hx(630+ai,216),'blind_hex32':hx(640+ai),'tuple_hex520':hx(650+ai,520)}],
            'unmodeled':[{'scope':attack.VIEW,'category':'PUBLIC-fixture-opaque-semantics',
                          'evidence_refs':['PUBLIC/contact/'+arm]}]}
    journal={'schema':'kpb-method03-controller-journal/v1','binding':copy.deepcopy(binding),'records':events}
    index={'schema':'kpb-method03-receiver-index/v1','binding':copy.deepcopy(binding),
           'records':raw,'public_heads':heads,'native_reports':[],
           'transport_parameters':copy.deepcopy(old['transport_parameters'])}
    parsed={'schema':'kpb-method03-parsed-arrivals/v1','binding':copy.deepcopy(binding),'records':parsed}
    contact={'schema':'kpb-method03-private-contact-view/v1','binding':copy.deepcopy(binding),'arms':contacts}
    baseline={'schema':'kpb-method03-controller-A-exposures/v1','binding':copy.deepcopy(binding),'records':exposures}
    return plan,journal,index,parsed,contact,baseline


def observe(args):
    return extract.extract(*args)


class PublicExtractorControls(unittest.TestCase):
    def test_actual_source_shapes_derive_facts_no_caller_pass_and_unqualified(self):
        args=fixture();obs=observe(args);pred=attack.predict(args[0],obs)
        self.assertEqual(pred['candidate_counts'],{'A':[1,1,1],'B':[2,1,2]})
        self.assertFalse(pred['finite_primary_view_complete'])
        self.assertFalse(obs['coverage']['traffic_metadata']['complete'])
        self.assertFalse(obs['coverage']['native_verification']['complete'])
        self.assertTrue(any(x['category']=='missing-full-terminal-packet' for x in obs['unmodeled']))
        self.assertTrue(any(x['category']=='opaque-corrupt-receipt-invoice-blind-tuple-semantics' for x in obs['unmodeled']))
        self.assertEqual(obs['retained_contact_facts'],args[4])
        self.assertEqual(len(obs['contact_applicability']['A']),6)

    def test_actual_curl_wait_tightens_late_reader_without_backdating(self):
        args=fixture()
        for event in args[1]['records']:
            if event['kind']=='status' and event['role']=='transport/3':
                value=event['observation']['value']
                if value.get('kind')=='role-subprocess-exit':value['observed_wait_monotonic_ns']=500
        obs=observe(args);pred=attack.predict(args[0],obs)
        self.assertEqual(pred['candidate_counts']['B'],[1,1,1])
        status=[x for x in obs['statuses'] if x['arm']=='B' and x['owner']==0][0]
        self.assertEqual(status['reader_observed_monotonic_ns'],1000)
        self.assertEqual(obs['launches'][3]['started_ns'],100)
        self.assertEqual(obs['launches'][3]['post_popen_ns'],110)

    def test_curlrc0_without_actual_typed202_has_no_completion_upper(self):
        args=fixture()
        for event in args[1]['records']:
            if event['kind']=='status' and event['role']=='transport/3':
                value=event['observation']['value']
                if value.get('kind')=='role-subprocess-exit':value['observed_wait_monotonic_ns']=500
        args[1]['records'][:]=[e for e in args[1]['records'] if not(e['kind']=='status'
            and e['role']=='transport/3' and e['observation']['value'].get('schema')=='kpb-exit-transport-status/v1')]
        renumber(args[1])
        obs=observe(args);pred=attack.predict(args[0],obs)
        self.assertEqual(pred['candidate_counts']['B'],[2,1,2])
        self.assertFalse(obs['coverage']['reader_status']['complete'])

    def test_later_failure_does_not_erase_observed202_or_curl_upper(self):
        args=fixture()
        for event in args[1]['records']:
            if event['kind']=='role-exit' and event['role']=='transport/3':event['returncode']=-15
            if event['kind']=='status' and event['role']=='transport/3':
                value=event['observation']['value']
                if value.get('kind')=='role-subprocess-exit':value['observed_wait_monotonic_ns']=500
        obs=observe(args);pred=attack.predict(args[0],obs)
        self.assertEqual(pred['candidate_counts']['B'],[1,1,1])
        self.assertFalse(pred['all_transports_ack_and_exit0'])

    def test_globalordinal_rawindex_order_preserved_no_arm_renumber(self):
        args=fixture();args[2]['records'].reverse()
        obs=observe(args)
        self.assertEqual([r['ordinal']for r in obs['arrivals']['B']],[6,5,4])
        self.assertEqual(attack.predict(args[0],obs)['candidate_counts']['B'],[2,1,2])

    def test_raw_parsed_byte_hash_or_globalordinal_mismatch_refuses(self):
        for mutate in (lambda a:a[3]['records'][0].update(projection_hex='00'*1844),
                       lambda a:a[3]['records'][0].update(proof_hex128='00'*128),
                       lambda a:a[3]['records'][0].update(arrival_id=hx(999)),
                       lambda a:a[3]['records'][0].update(ordinal=6)):
            args=fixture();mutate(args)
            with self.assertRaises(ValueError):observe(args)

    def test_public_context_partition_not_private_owner_or_arrival_order(self):
        args=fixture();args[3]['records'].reverse();obs=observe(args)
        self.assertEqual([r['ordinal']for r in obs['arrivals']['A']],[1,2,3])
        bad=copy.deepcopy(args);bad[2]['public_heads'][1]['context_hex276']=bad[2]['public_heads'][0]['context_hex276']
        with self.assertRaises(ValueError):observe(bad)
        bad=copy.deepcopy(args);bad[3]['records'][0]['native']['domain_hex32']=hx(999)
        with self.assertRaises(ValueError):observe(bad)

    def test_A_actual_packet_map_crossbinds_receiver_not_asserted_owner(self):
        args=fixture();args[5]['records'][0]['frame_sha256']=hx(999)
        with self.assertRaises(ValueError):observe(args)
        args=fixture();args[5]['records'][0]['projection_sha256']=hx(999)
        with self.assertRaises(ValueError):observe(args)
        args=fixture();args[5]['records'][0]['arm']='B'
        with self.assertRaises(ValueError):observe(args)

    def test_root_allowed_edges_or_complete_flags_not_admission(self):
        for key in ('allowed_edges','coverage','facts','qualified','complete'):
            args=fixture();args[1][key]=True
            with self.assertRaises(ValueError):observe(args)

    def test_partial_journal_lifetime_clock_or_unknown_event_cannot_hide(self):
        args=fixture();args[1]['records'][1]['sequence']=999
        with self.assertRaises(ValueError):observe(args)
        args=fixture()
        launch=next(e for e in args[1]['records']if e['kind']=='launch')
        launch['host_pid']=999
        with self.assertRaises(ValueError):observe(args)
        args=fixture();e=copy.deepcopy(args[1]['records'][-1]);e.update(kind='UNMODELED_ACTUAL_METADATA')
        args[1]['records'].append(e);renumber(args[1]);obs=observe(args)
        self.assertTrue(any(m['category']=='unmodeled-controller-event-kind'for m in obs['unmodeled']))

    def test_clock_offset_normalization_uses_actual_role_not_zero_fit(self):
        args=fixture()
        for event in args[1]['records']:
            if event['kind']=='status' and event['role']=='transport/3':
                v=event['observation']['value']
                if v.get('schema')=='kpb-method03-clock-snapshot/v1':
                    v['time_namespace']=v['time_for_children_namespace']={'link':'time:[51]','inode':51}
                    v['timens_offsets']['monotonic_ns']=10000
                elif v.get('kind')=='role-subprocess-launch':
                    v['pre_Popen_monotonic_ns']+=10000;v['post_Popen_monotonic_ns']+=10000
                elif v.get('kind')=='role-subprocess-exit':v['observed_wait_monotonic_ns']+=10000
        self.assertEqual(attack.predict(args[0],observe(args))['candidate_counts']['B'],[2,1,2])

    def test_corrupt_own_nf_and_spk_must_both_match_same_actual_record(self):
        args=fixture();args[4]['arms']['B']['own_payouts'][0]['spk_hex36']=hx(999,36)
        with self.assertRaises(ValueError):observe(args)
        args=fixture();args[4]['arms']['B']['own_payouts'][0]['owner']=0
        with self.assertRaises(ValueError):observe(args)

    def test_all_legitimate_contact_alternatives_retained_and_equality_used(self):
        args=fixture()
        target=args[3]['records'][3]['native']['destination_spk_hex36'][6:-2]
        for contact in args[4]['arms']['B']['contacts']:
            if contact['owner']==0 and contact['invoice_index']==11:contact['native_pk_hex32']=target
        obs=observe(args);pred=attack.predict(args[0],obs)
        self.assertEqual(pred['candidate_counts']['B'],[1,1,1])
        self.assertTrue(any(f['category']=='legitimate-contact-native-payout-equality' for f in obs['facts']))
        self.assertEqual(len(obs['contact_applicability']['B']),6)

    def test_missing_native_report_never_inherits_receiver202_as_acceptance(self):
        args=fixture();obs=observe(args)
        self.assertFalse(obs['coverage']['native_verification']['complete'])
        args[2]['native_reports']=[{'schema':'PASS','complete':True}]
        obs=observe(args)
        self.assertFalse(obs['coverage']['native_verification']['complete'])

    def test_strict_actual_source_report_binding_is_not_bare_pass(self):
        args=fixture()
        def reports(a):
            return [{'schema':'kpb-method03-received-native-check/v1','binding':copy.deepcopy(a[0]['binding']),
                'ordinal':r['arrival_sequence'],'receiver_row_sha256':extract.sha((
                    __import__('json').dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode()),
                'projection_sha256':r['exit_id'],'proof_sha256':extract.sha(bytes.fromhex(r['proof_hex128'])),
                'source_pins':dict(zip(('adapter','codec','engine','verifier','parameters','manifest','tail'),
                                     [hx(i) for i in range(4,11)])),
                'actual_native_returncode':0,'native_full_accepted':True,'all_scripts_passed':True,
                'actual_public_proof_verified':True,'isolation':{'network':'none',
                    'input_scope':'unlabelled-public-received-exits','originals_mounted':False},
                'artifact_refs':{k:{'path':'PUBLIC/'+str(r['arrival_sequence'])+'/'+k+'.json','sha256':hx(12)}
                                 for k in ('case','normalization','native_report','proof_result')}}
                for r in a[2]['records']]
        args[2]['native_reports']=reports(args)
        obs=observe(args)
        self.assertTrue(obs['coverage']['native_verification']['complete'])
        self.assertFalse(attack.predict(args[0],obs)['finite_primary_view_complete'])
        for mutate in (
            lambda q:q[0].update(receiver_row_sha256=hx(999)),
            lambda q:q[0].update(proof_sha256=hx(999)),
            lambda q:q[0]['source_pins'].update(tail=hx(999)),
            lambda q:q[0]['source_pins'].update(tail=hx(4)),
            lambda q:q[0]['artifact_refs']['case'].update(path='../owner.json'),
            lambda q:q[0]['isolation'].update(originals_mounted=True)):
            bad=copy.deepcopy(args);mutate(bad[2]['native_reports'])
            with self.assertRaises(ValueError):observe(bad)
        bad=copy.deepcopy(args);bad[2]['native_reports'][0]['native_full_accepted']=False
        self.assertFalse(observe(bad)['coverage']['native_verification']['complete'])

    def test_exact_named_transport_map_rejects_role_hash_swaps(self):
        args=fixture();session=next(e for e in args[1]['records']if e['kind']=='session-parameters')
        p=session['value'];p['tor_binary_sha256'],p['curl_binary_sha256']=p['curl_binary_sha256'],p['tor_binary_sha256']
        args[2]['transport_parameters']={'A':copy.deepcopy(p),'B':copy.deepcopy(p)}
        with self.assertRaises(ValueError):observe(args)

    def test_early_controller_clock_preserved_and_late_identity_cannot_substitute(self):
        args=fixture();obs=observe(args)
        early=next(c for c in obs['clocks']if c['role']=='controller')
        self.assertEqual(early['sample']['monotonic_after_ns'],8)
        follow=next(e for e in args[1]['records']if e['kind']=='controller-clock-followup')
        follow['value']['pid']=999
        with self.assertRaises(ValueError):observe(args)

    def test_publication_clock_missing_or_pre_shutdown_stays_primary_unmodeled(self):
        args=fixture();obs=observe(args)
        self.assertTrue(any(m['category']=='missing-public-Native-publication-timing'for m in obs['unmodeled']))
        clock=copy.deepcopy(args[1]['records'][0]['value'])
        snapshot={k:copy.deepcopy(clock[k])for k in ('boot_id','time_namespace','time_for_children_namespace','timens_offsets')}
        metadata={'schema':'kpb-method03-native-publication/v1','pid':999,
            'clock_evidence':{'boot_id':clock['boot_id'],
                'kernel_clock_ids':{'monotonic':extract.time.CLOCK_MONOTONIC,'realtime':extract.time.CLOCK_REALTIME,
                                    'boottime':extract.time.CLOCK_BOOTTIME},
                'before':copy.deepcopy(snapshot),'after':copy.deepcopy(snapshot),'stable':True},
            'before_public_write':{'monotonic_ns':2000,'unix_ns':3000,'boottime_ns':2000},
            'after_public_fsync':{'monotonic_ns':2010,'unix_ns':3010,'boottime_ns':2010},
            'public_artifacts':{k:{'path':'PUBLIC/'+k+'.json','sha256':hx(20)}for k in ('exits','native_result')}}
        args[2]['publication_metadata']=metadata;obs=observe(args)
        self.assertFalse(any('publication' in m['category']for m in obs['unmodeled']))
        metadata['before_public_write']['monotonic_ns']=100
        obs=observe(args)
        self.assertTrue(any(m['category']=='public-Native-publication-before-network-shutdown'for m in obs['unmodeled']))

    def test_terminal_bytes_cannot_be_relabelled_continuing_shape(self):
        args=fixture();r=args[2]['records'][0]
        r['projection_hex']='00'*1796;r['exit_id']=extract.sha(bytes.fromhex(r['projection_hex']))
        p=args[3]['records'][0];p.update(projection_hex=r['projection_hex'],arrival_id=r['exit_id'])
        with self.assertRaises(ValueError):observe(args)

    def test_secondary_coverage_no_prediction_relabel_or_private_declassification(self):
        binding=fixture()[0]['binding']
        for label in extract.SECONDARIES:
            capsule=extract.secondary_coverage(binding,label,hx(1),hx(2),[],
                [{'category':'COMPLETE_DECLARED_SECONDARY_VIEW_NOT_CAPTURED','evidence_refs':['PRIVATE/ref']}])
            pub=extract.public_secondary_status(capsule)
            self.assertEqual(pub['status'],'MISSING');self.assertFalse(pub['scored']);self.assertFalse(pub['gain_claimed'])
            self.assertNotIn('PRIVATE/ref',str(pub));self.assertNotIn('capture_refs',pub)
            bad=copy.deepcopy(capsule);bad['joint_models']=[]
            with self.assertRaises(ValueError):extract.public_secondary_status(bad)
            bad=copy.deepcopy(capsule);bad['status']='PASS'
            with self.assertRaises(ValueError):extract.public_secondary_status(bad)
        with self.assertRaises(ValueError):extract.secondary_coverage(binding,'PRIMARY',hx(1),hx(2),[],[])

    def test_pure_truth_free_immutable_inputs_and_no_secondary_primary_facts(self):
        args=fixture();before=copy.deepcopy(args);obs=observe(args)
        self.assertEqual(args,before)
        self.assertNotIn('truth',extract.extract.__code__.co_varnames)
        with self.assertRaises(ValueError):extract.extract(*args,view='TERMINAL+CONTACT')


def renumber(journal):
    for i,e in enumerate(journal['records']):e['sequence']=i+1


if __name__=='__main__':unittest.main()

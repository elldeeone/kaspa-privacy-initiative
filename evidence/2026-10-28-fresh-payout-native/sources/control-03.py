#!/usr/bin/env python3
"""PUBLIC-SYNTHETIC existing-key fresh-destination Exit controls; never funded."""
import argparse
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types

ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
HERE=Path(__file__).resolve().parent
WALLET=ROOT/'poc/local-private-payment/private_batch_trial'
BOOTSTRAP=Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA='0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
CLASS='PUBLIC_SYNTHETIC_UNFUNDED_FRESH_DESTINATION_NO_ACCEPTED_LEDGER'
PRIVATE_ROOTS=tuple([ROOT/'.local/mpc-prover-financial-runs'/name for name in (
    '767159332ffa15d5a2dd4447237c78fb02d54165c1193cf313df8a35032824db',
    '581f4a3324649fe22b204919a57105849fea0d87032ce1b6bf225b83d53fe317',
    '0b1f968077d9d4308457b7137f9bcd95c19721340c9acef398e47505276f7d38')]
    +[ROOT/'.local/owner-wait-toy-runs/fbb5efdf5519eafff4cb775801f80e5be4a414573c4b1d116e2367e7af2875c0',
      Path('/run/user/1000/kpb-unfunded-batch-components-20261028-05/owners'),
      Path('/dev/shm/kpb-public-driver-preparation-Px0Y9O/tls-controls-01/private')])

def require(value,reason):
    if not value:raise ValueError(reason)

def load_guard(exclusions):
    # Pre-admit the qualified builder itself before executing its fixed-nine
    # bootstrap. No guard helper is loaded until every new private root has
    # already contributed its paths/inodes.
    roots=[];inodes=set()
    def failed(error):raise ValueError('private-metadata-incomplete') from error
    for value in exclusions:
        path=Path(value).absolute()
        require(path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)),'private-root-metadata')
        roots.append(path)
        for current,dirs,files in os.walk(path,followlinks=False,onerror=failed):
            dirs[:]=[n for n in dirs if not (Path(current)/n).is_symlink()]
            for name in files:
                info=(Path(current)/name).lstat()
                if stat.S_ISREG(info.st_mode):inodes.add((info.st_dev,info.st_ino))
    path=ROOT/'.local/private-batch-history-settlement-candidate-01/public-driver-preparation/build_driver.py'
    require(not any(p.is_symlink() for p in (path,*path.parents))
        and all(not path.is_relative_to(p) for p in roots),'qualified-bootstrap-path')
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
        and (before.st_dev,before.st_ino) not in inodes,'qualified-bootstrap-metadata')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        opened=os.fstat(f.fileno())
        keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
        require(all(getattr(before,k)==getattr(opened,k) for k in keys),'qualified-bootstrap-open-race')
        raw=f.read();after=os.fstat(f.fileno())
    require(all(getattr(before,k)==getattr(after,k) for k in keys)
        and hashlib.sha256(raw).hexdigest()=='d8de7262599c0723813486c1cffa4b226052faa5b86886ae2c2a89e54ce39be4',
        'qualified-bootstrap-source-pin')
    module=types.ModuleType('_fresh_exit_qualified_builder');module.__file__=str(path)
    sys.modules[module.__name__]=module;exec(compile(raw,str(path),'exec'),module.__dict__)
    return module.load_guard(roots)


def main(args):
    # This is the reviewed guard bootstrap: all six whole private roots are
    # inventoried before the guard helper body, plan or public source is read.
    guard=load_guard(PRIVATE_ROOTS)
    read=lambda path,pin=None:guard['read'](Path(path),pin)
    plan_raw=read(args.plan,args.plan_sha256);plan=json.loads(plan_raw)
    require(set(plan)=={'schema','classification','source_members','tools','profile','auth_exit_manifest',
        'proving_key','native_parameters','immutable_tail','fresh_payout_module','wallet_candidate','virtual_source_map',
        'reference_fee_rate_sompi_per_mass','compute_budget','public_seed_hex32','js_internal_aliases','js_auxiliary_bookkeeping'},'exact-control-plan')
    require(plan['schema']=='kpb-public-synthetic-fresh-exit-control/v1' and plan['classification']==CLASS
        and plan['public_seed_hex32']==bytes(range(32)).hex()
        and plan['reference_fee_rate_sompi_per_mass']==100 and plan['compute_budget']==1800,
        'frozen-public-synthetic-control-only')
    require(set(plan['tools'])=={'relation','codec','native_validator'},'actual-selected-tools')
    for row in [*plan['source_members'],*plan['tools'].values(),plan['profile'],plan['auth_exit_manifest'],
                plan['native_parameters'],plan['immutable_tail'],plan['fresh_payout_module'],plan['wallet_candidate']]:
        require(set(row)=={'path','sha256'},'exact-public-selection-row');read(row['path'],row['sha256'])
    require(set(plan['proving_key'])=={'path','sha256'},'exact-existing-public-proving-parameter-row')
    guard['m'].GUARD.metadata(Path(plan['proving_key']['path']))
    manifest=json.loads(read(plan['auth_exit_manifest']['path'],plan['auth_exit_manifest']['sha256']))
    require(plan['auth_exit_manifest']['sha256']=='bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f'
        and manifest['role']=='new-auth-exit'
        and manifest['vk_sha256']=='e6a49ac7ece8aa501300f24c1ec4602745df6e8d38cd4eed8b1222b36f1e0414'
        and manifest['matrix_sha256']=='9fbedc0628a6afb592f03a0ceda9825924f7d8bd76fe49785b6252237affc149'
        and manifest['pk_sha256']==plan['proving_key']['sha256']
        and Path(plan['proving_key']['path']).stat().st_size==manifest['pk_bytes'],
        'same-existing-AuthExit-key-and-matrix-no-setup')
    # Standard imports are definition-only and all their selected public source
    # bytes were admitted above. No Original is opened or supplied to this run.
    require(plan['wallet_candidate']['sha256']=='4991baef65d13a91a7944f21bc7750b77c5776dc6f7c4d2c6844ca5b8f39e289'
        and plan['fresh_payout_module']['sha256']=='886fed167f177fd1781bddf090ca2b5fd01dd2df7d10f5a664016f6aee46d456',
        'exact-reviewed-fresh-wallet-policy')
    require(plan['virtual_source_map']==[
        {'virtual_path':str(WALLET/'wallet_profile.py'),'source':plan['wallet_candidate']},
        {'virtual_path':str(WALLET/'fresh_self_payout.py'),'source':plan['fresh_payout_module']}],
        'frozen-candidate-wallet-at-canonical-virtual-paths')
    sys.dont_write_bytecode=True;sys.pycache_prefix=tempfile.mkdtemp(prefix='empty-pyc-',dir=HERE)
    sys.path.insert(0,str(WALLET))
    members={row['path']:row for row in plan['source_members']}
    def initialize(name,virtual,row):
        require(name not in sys.modules,'wallet-policy-must-load-before-dependent-modules')
        module=types.ModuleType(name);module.__file__=str(virtual);sys.modules[name]=module
        exec(compile(read(row['path'],row['sha256']),str(virtual),'exec'),module.__dict__)
        return module
    exit_wire=initialize('exit_wire',WALLET/'exit_wire.py',members[str(WALLET/'exit_wire.py')])
    wallet=initialize('wallet_profile',WALLET/'wallet_profile.py',plan['wallet_candidate'])
    fresh=initialize('fresh_self_payout',WALLET/'fresh_self_payout.py',plan['fresh_payout_module'])
    component_run=initialize('component_run',WALLET/'component_run.py',members[str(WALLET/'component_run.py')])
    require({row['path']:row['sha256'] for row in plan['source_members']}[str(WALLET/'component_run.py')]
        =='77730831655c37745a4fef9bab683a266605af28c4a8282f6e549e7acc267149','exact-reused-public-fixture-and-witness-tools')

    class PublicRun(component_run.Run):
        def __init__(self):
            # Preserve qualified component methods while replacing its bootstrap
            # with the six-root guard above. Its setup entry is never called.
            self.output=Path(args.output).absolute();require(not self.output.exists(),'fresh-control-identity')
            require(not any(p.is_symlink() for p in (self.output,*self.output.parents))
                and all(not self.output.is_relative_to(p) and not p.is_relative_to(self.output)
                        for p in guard['m'].GUARD.directories),
                'public-control-output-disjoint-from-private-roots')
            self.output.mkdir(mode=0o700)
            self.read=read;self.binary=Path(plan['tools']['relation']['path'])
            self.profile_raw=read(plan['profile']['path'],plan['profile']['sha256'])
            selected=json.loads(self.profile_raw);self.descriptor=selected['profile_descriptor']
            require(component_run.sha(json.dumps(self.descriptor,sort_keys=True,separators=(',',':')).encode())
                    ==selected['profile_id_hex32'],'unchanged-profile-descriptor')
            self.profile=wallet.Profile(bytes.fromhex(self.descriptor['domain_hex32']),bytes.fromhex(selected['profile_id_hex32']))
            require(manifest['domain_hex32']==self.profile.domain.hex()
                and manifest['profile_id_hex32']==self.profile.profile_id.hex(),'unchanged-D-and-ProfileID')
            self.serial=0;self.events=[];self.artifacts={}
            read(component_run.NODE,wallet.NODE_SHA256);read(component_run.CRYPTO,wallet.CRYPTO_SHA256)
            leaf_raw=read(component_run.LEAF_MAP,component_run.LEAF_MAP_SHA);leaf=json.loads(leaf_raw)
            require(leaf['installedFileMapSha256']=='25737bfa889a940d41db50612f3a99dffd5c673dedd62288224c4bec80b91b02'
                and len(leaf['files'])==3567,'same-already-admitted-mature-JS-cache')
            modules=component_run.JS_ROOT/'node_modules';before={};aliases=[];alias_metadata={}
            require(all(not modules.is_relative_to(p) and not p.is_relative_to(modules)
                for p in guard['m'].GUARD.directories),'JS-cache-disjoint-from-private-prefixes')
            def js_failed(error):raise ValueError('public-JS-metadata-incomplete') from error
            for current,dirs,files in os.walk(modules,followlinks=False,onerror=js_failed):
                for name in dirs:require(not (Path(current)/name).is_symlink(),'no-JS-directory-alias')
                for name in files:
                    path=Path(current)/name;info=path.lstat()
                    if stat.S_ISLNK(info.st_mode):
                        text=os.readlink(path);resolved=(path.parent/text).resolve(strict=True)
                        require(resolved.is_relative_to(modules)
                            and resolved!=modules,'JS-alias-target-strictly-inside-public-cache')
                        relative=str(path.relative_to(component_run.JS_ROOT))
                        target_relative=str(resolved.relative_to(component_run.JS_ROOT))
                        require(target_relative in leaf['files'],'JS-alias-target-is-an-exact-selected-leaf')
                        _,target_info=guard['m'].GUARD.metadata(resolved)
                        require(target_info.st_nlink==1,'JS-alias-target-single-link-public-leaf')
                        aliases.append({'relative':relative,'link_text':text,'target_relative':target_relative})
                        alias_metadata[relative]=((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns),text)
                        continue
                    path,info=guard['m'].GUARD.metadata(path)
                    require(info.st_nlink==1,'single-link-public-JS-cache')
                    before[str(path.relative_to(component_run.JS_ROOT))]=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            require(plan['js_auxiliary_bookkeeping']=={'relative':'node_modules/.package-lock.json','sha256':'e52d29a883e7f4b80d79ee1b7bdc29d3b96f65ea5905daf203241b158c6b02cb'},'only-fixed-public-cache-bookkeeping')
            require(set(before)==set(leaf['files'])|{'node_modules/.package-lock.json'},'exact-whole-bound-JS-cache-leaf-set')
            require(sorted(aliases,key=lambda r:r['relative'])==plan['js_internal_aliases'],
                'only-frozen-internal-JS-aliases')
            argv=self.isolation()+['--ro-bind',str(modules),'/public/node_modules',
                '--ro-bind',str(component_run.LEAF_MAP),'/public/LEAF-MAP.json',
                '--ro-bind',str(HERE/'js_cache_check-03.py'),'/public/check.py',
                '/usr/bin/python3','-I','-B','/public/check.py']
            checked=json.loads(self.call('unchanged-public-JS-cache-in-closed-namespace',argv))
            require(checked=={'schema':'kpb-public-mature-JS-cache-check/v1','leaves':3567,
                'map_sha256':component_run.LEAF_MAP_SHA,'auxiliary_metadata_leaves':1},'actual-public-namespace-leaf-body-hashes')
            for relative,identity in before.items():
                _,info=guard['m'].GUARD.metadata(component_run.JS_ROOT/relative)
                require(identity==(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns),
                    'admitted-JS-cache-changed')
            for relative,(identity,text) in alias_metadata.items():
                path=component_run.JS_ROOT/relative;info=path.lstat()
                require(stat.S_ISLNK(info.st_mode)
                    and identity==(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
                    and os.readlink(path)==text,'admitted-internal-JS-alias-changed')
            self.modules=modules
            self.signature_artifacts={name:read(component_run.BUILD/name,pin) for name,pin in component_run.PINS.items()}
            self.matrix_request={'mode':'matrix',
                'ordinaryR1csHex':self.signature_artifacts['ordinary/private_authorization.r1cs'].hex(),
                'cpp0R1csHex':self.signature_artifacts['cpp0/private_authorization.r1cs'].hex(),
                'symHex':self.signature_artifacts['ordinary/private_authorization.sym'].hex()}
            self.crypto=wallet.Crypto(component_run.CRYPTO)
            self.parameters=json.loads(read(plan['native_parameters']['path'],plan['native_parameters']['sha256']))
            self.tail=read(plan['immutable_tail']['path'],plan['immutable_tail']['sha256'])
            require(plan['native_parameters']['sha256']=='3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751'
                and plan['immutable_tail']['sha256']=='4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
                and self.parameters['pool_hex32']=='d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf'
                and hashlib.sha256(bytes.fromhex(self.parameters['exit_vk_hex328'])).hexdigest()==manifest['vk_sha256'],
                'actual-final-policy-and-existing-ExitVK')
            self.save('FROZEN-PLAN.json',plan_raw)
            self.authority=wallet.Authority(component_run.NODE,self.modules)
            self.receiver=wallet.Receiver(bytes(range(32)),self.profile,self.crypto,self.authority)

        def native(self,label,request):
            require(request['operation'] in ('check-joined','prove','verify'),'no-setup-operation')
            argv=self.isolation()+['--ro-bind',str(self.binary),'/public/relation',
                '--ro-bind',str(self.output),str(self.output),
                '--ro-bind',plan['auth_exit_manifest']['path'],'/parameters/MANIFEST.json']
            if request['operation']=='prove':argv+=['--ro-bind',plan['proving_key']['path'],'/parameters/parameters.pk']
            return json.loads(self.call(label,argv+['/public/relation'],request))

        def codec(self,label,operation,case=None,state=None):
            require(operation in ('emit','body','normalize','canonicalize-control'),'fixed-public-codec-operations')
            request={'operation':operation,'parameters':self.parameters}
            request.update({'state_hex112':state.hex()} if operation=='emit' else {'case':case})
            argv=self.isolation()+['--ro-bind',plan['tools']['codec']['path'],'/public/codec','/public/codec']
            return json.loads(self.call(label,argv,request))

        def vm(self,label,case,positive):
            source=self.save(label+'.CASE.json',component_run.encoded(case))
            out=self.output/(label+'-vm');out.mkdir(mode=0o700)
            argv=self.isolation()+['--ro-bind',plan['tools']['native_validator']['path'],'/public/native',
                '--ro-bind',source['path'],'/public/CASE.json','--bind',str(out),'/out',
                '/public/native','validate-transaction','/public/CASE.json','/out/native']
            self.call(label+'-actual-NativeFull',argv)
            report=json.loads(read(out/'native/native-validation.json'))
            engines=report.get('per_input_ScriptEngine')
            require(report.get('isolation')=='PASS' and type(engines) is list
                and len(engines)==len(case['transaction']['inputs']) and engines,
                'actual-isolation-and-all-input-engines-required')
            if positive:
                require(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
                    and all(row.get('accepted') is True for row in engines),'actual-positive-NativeFull-and-engines')
            else:
                require(report['Full']['accepted'] is False and report['all_input_engines_accepted'] is False
                    and any(row.get('accepted') is False for row in engines),'actual-negative-ScriptEngine-rejection')
            return {'case':source,'report_sha256':component_run.sha(read(out/'native/native-validation.json')),
                    'Full':report['Full'],'per_input_ScriptEngine':engines}

        def case(self,context,body,proof):
            effect=exit_wire.parse_body(body);state=context.state()
            emission=self.codec('emit-policy-'+str(self.serial),'emit',state=state)
            require(bytes.fromhex(emission['immutable_tail_hex'])==self.tail,'same-final-immutable-tail')
            redeem=bytes.fromhex(emission['redeem_hex'])
            frame=b'\x4c\x80'+proof+b'\x4d'+len(redeem).to_bytes(2,'little')+redeem
            outputs=([(effect.new_reserve,exit_wire.state_spk(effect.next_state(),self.tail))]
                     if effect.new_reserve else [])+[(effect.payout,effect.payout_spk)]
            return {'transaction':{'version':1,'id':'00'*32,'inputs':[{
                'previousOutpoint':{'transactionId':context.point[:32].hex(),'index':int.from_bytes(context.point[32:],'little')},
                'signatureScript':frame.hex(),'sequence':(1<<64)-1,'computeBudget':1800}],
                'outputs':[{'value':amount,'scriptPublicKey':spk.hex(),'covenant':None} for amount,spk in outputs],
                'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':body.hex(),'mass':0},
                'entries':[{'amount':context.reserve,'scriptPublicKey':emission['script_public_key'],
                            'blockDaaScore':0,'isCoinbase':False,'covenantId':None}]}

        def execute(self):
            tree_spec=importlib.util.spec_from_file_location('_fresh_exit_public_trees',WALLET.parent/'integration/trees.py')
            trees=importlib.util.module_from_spec(tree_spec);sys.modules[tree_spec.name]=trees
            exec(compile(read(tree_spec.origin),tree_spec.origin,'exec'),trees.__dict__)
            delivery=wallet.deliver(self.crypto,self.receiver.invoice(7),200_000_000,bytes([11])*32,0)
            receipt=self.receiver.open(delivery.ciphertext);state=trees.PublicState([delivery.cm])
            nf=self.receiver.nullifier(receipt,0)
            claim=wallet.RecoveredOpening(0,receipt,nf,tuple(state.cm.path(0)[at:at+32] for at in range(0,512,32)),False)
            old_nf_root=state.nf.root();nf_witness=state.insert(nf);new_nf_root=state.nf.root()
            results=[]
            for mode,reserve,index in (('terminal',200_000_000,3),('continuing',260_000_000,7)):
                # Separate hypothetical UTXOs; this is not a double-funded note
                # or accepted GEN3 ledger. The only seed is the public00..1f.
                context=exit_wire.HeadContext(bytes.fromhex(self.parameters['chain_hex32']),
                    bytes.fromhex(self.parameters['pool_hex32']),self.profile.profile_id,self.profile.domain,
                    bytes.fromhex(self.parameters['service_hex32']),hashlib.sha256(('PUBLIC FRESH DESTINATION '+mode).encode()).digest()+index.to_bytes(4,'little'),
                    state.cm.root(),old_nf_root,1,1,reserve)
                action=hashlib.sha256(('PUBLIC FRESH DESTINATION ACTION '+mode).encode()).digest()
                payout=fresh.derive(self.receiver,context,nf,action)
                require(payout.public_key!=receipt.native_pk and payout.script_public_key==b'\0\0\x20'+payout.public_key+b'\xac',
                    'fresh-owner-derived-destination-differs-from-invoice')
                def body(fee):
                    return exit_wire.body(context,action,new_nf_root,2,reserve-200_000_000,
                        fee,200_000_000-fee,payout.script_public_key,nf,nf_witness)
                quoted=self.codec(mode+'-quote-source-native-mass','normalize',self.case(context,body(1_000_000),bytes(128)))
                fee=quoted['metrics']['mining_mass']*100
                require(type(fee) is int and 0<fee<=190_000_000,'actual-native-fee-quote')
                raw_body=body(fee);pre=self.codec(mode+'-quote-exact-effects','normalize',self.case(context,raw_body,bytes(128)))
                require(pre['metrics']['mining_mass']*100==fee,'stable-exact-positive-native-fee-quote')
                projection=bytes.fromhex(pre['financial_projection_hex'])
                approved=wallet.authorize_exit(self.receiver,claim,projection,context,self.tail,approved_fee_sompi=fee)
                require(approved.statement==exit_wire.statement(projection),'fresh-AK-consent-exact-full-statement')
                signature_input=self.authority.signature_inputs(approved.statement,approved.authorization)
                signature=self.normalize(mode+'-fresh-owner-authorization',signature_input)
                request={**approved.private_request,'signature':signature}
                check=self.native(mode+'-actual-joined-matrix',{**request,'operation':'check-joined'})
                require(check['matrix_sha256']==manifest['matrix_sha256']
                    and all(check['counts'][key]==0 for key in ('native_residual_failures','signature_residual_failures','link_residual_failures')),
                    'same-actual-matrix-with-independent-fresh-destination-SAT')
                selected={'manifest':'/parameters/MANIFEST.json','manifest_sha256':plan['auth_exit_manifest']['sha256']}
                proof=self.native(mode+'-genuine-existing-key-proof',{**request,'operation':'prove',
                    'parameters':{**selected,'pk':'/parameters/parameters.pk','pk_sha256':manifest['pk_sha256']}})
                proof_bytes=bytes.fromhex(proof['proof_hex128']);require(len(proof_bytes)==128,'canonical-proof128')
                verifier={'operation':'verify','role':'new-auth-exit','profile':request['profile'],
                    'statement_hex':approved.statement.hex(),'proof_hex128':proof_bytes.hex(),'parameters':selected}
                require(self.native(mode+'-independent-public-proof-verify',verifier)['accepted'] is True,'genuine-fresh-destination-proof')
                positive=self.codec(mode+'-positive-native-case','normalize',self.case(context,raw_body,proof_bytes))
                require(bytes.fromhex(positive['financial_projection_hex'])==projection,'same-signed-and-proved-native-projection')
                native_positive=self.vm(mode+'-fresh-destination',positive['case'],True)
                controls=[]
                for change in ('destination','fee','head'):
                    changed=copy.deepcopy(positive['case']);payload=bytearray.fromhex(changed['transaction']['payload'])
                    if change=='destination':
                        destination=b'\0\0\x20'+receipt.native_pk+b'\xac'
                        payload[376:412]=destination;changed['transaction']['outputs'][-1]['scriptPublicKey']=destination.hex()
                    elif change=='fee':
                        payload[360:368]=(fee+1).to_bytes(8,'little');payload[368:376]=(199_999_999-fee).to_bytes(8,'little')
                        changed['transaction']['outputs'][-1]['value']-=1
                    else:
                        point=hashlib.sha256(('PUBLIC WRONG FRESH EXIT HEAD '+mode).encode()).digest()+(index+1).to_bytes(4,'little')
                        payload[168:204]=point
                        changed['transaction']['inputs'][0]['previousOutpoint']={'transactionId':point[:32].hex(),'index':index+1}
                    changed['transaction']['payload']=payload.hex()
                    normalized=self.codec(mode+'-'+change+'-cache-only-normalization','canonicalize-control',changed)
                    normalized=normalized['case']
                    before=copy.deepcopy(changed);after=copy.deepcopy(normalized)
                    for value in (before,after):value['transaction'].pop('id');value['transaction'].pop('mass')
                    require(before==after,'negative-normalizer-only-cached-ID-and-mass')
                    actual=self.codec(mode+'-'+change+'-actual-statement','body',normalized)
                    require(actual['exit_statement_hex152']!=approved.statement.hex(),'tamper-changes-owner-signed-statement')
                    require(self.native(mode+'-'+change+'-stale-proof-public-refusal',
                        {**verifier,'statement_hex':actual['exit_statement_hex152']})['accepted'] is False,
                        'old-proof-cannot-authorize-destination-fee-or-head-change')
                    controls.append({'change':change,'native':self.vm(mode+'-'+change+'-old-proof',normalized,False)})
                    if change=='destination':
                        stale=copy.deepcopy(signature_input);digest=hashlib.sha256(bytes.fromhex(actual['exit_statement_hex152'])).digest()
                        stale['digestLimbs']=[str(int.from_bytes(digest[at:at+16],'little')) for at in (0,16)]
                        stale_request={**request,'statement_hex':actual['exit_statement_hex152'],
                            'signature':self.normalize(mode+'-destination-old-signature',stale)}
                        bad=self.native(mode+'-destination-actual-old-signature-matrix',{**stale_request,'operation':'check-joined'})
                        require(bad['counts']['native_residual_failures']==0 and bad['counts']['signature_residual_failures']>0
                            and bad['counts']['link_residual_failures']==0,'actual-AK-signature-reconsent-required-for-destination')
                results.append({'mode':mode,'note_native_pk_hex32':receipt.native_pk.hex(),
                    'fresh_payout_pk_hex32':payout.public_key.hex(),'note_cm_hex32':receipt.commitment().hex(),
                    'public_known_seed_used':True,'fee_sompi':fee,'fresh_statement_hex152':approved.statement.hex(),
                    'proof_hex128':proof_bytes.hex(),'actual_matrix':check,'positive_native':native_positive,'negative_controls':controls})
            result={'schema':'kpb-public-synthetic-fresh-destination-result/v1','classification':CLASS,
                'plan_sha256':args.plan_sha256,'cases':results,'fresh_setup':False,'D_Profile_or_VK_changed':False,
                'actual_original_or_old_private_input_read':False,'accepted_GEN3_chain_or_privacy_qualification':False,
                'funding_or_broadcast':False}
            self.save('EVENTS.json',component_run.encoded(self.events));self.save('RESULT.json',component_run.encoded(result))
            return result

    run=None
    try:
        run=PublicRun();result=run.execute()
        print(json.dumps({'status':'PUBLIC_SYNTHETIC_FRESH_DESTINATION_CONTROLS_PASSED','case_count':len(result['cases']),
            'same_existing_AuthExit_parameters':True,'accepted_backing_or_chain_confirmation':False}))
    except BaseException as error:
        if run is not None:
            run.save('FIRST-FAILURE.json',component_run.encoded({'classification':CLASS,
                'error_type':type(error).__name__,'category':str(error),'events':run.events}))
            if not (run.output/'EVENTS.json').exists():run.save('EVENTS.json',component_run.encoded(run.events))
        raise
    finally:
        if run is not None:run.authority.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--output',required=True)
    main(parser.parse_args())


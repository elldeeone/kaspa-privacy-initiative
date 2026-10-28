// Public offline fixtures only. No RPC, mining, wallet, key or submission.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {IDS,MAX,identityDocument,checkAddresses,matureObservation,reservePhase,sha} from './funding_network_common.mjs';
import {nativeGate,submitOnce} from './funding_network.mjs';

function fixture() {
  return {schema:'kpb-three-owner-funding-identity/v1',...IDS,
    trial_id:'7abaee02-63ab-4b1e-817e-28bc7e63d169',label:'public-network-control',
    bootstrap_trial_sha256:'01'.repeat(32),component_profile_sha256:'02'.repeat(32),native_tail_sha256:'03'.repeat(32),
    owners:[0,1,2].map(i=>({owner_component:i,funding_spk_hex36:'000020'+String(i+1).padStart(2,'0').repeat(32)+'ac',address:'kaspatest:PUBLIC_FIXTURE_'+i})),
    financial_readiness:false};
}
const encode=value=>Buffer.from(JSON.stringify(value));
const entry=(id='11'.repeat(32),amount='2100000000',score='0')=>({outpoint:{transactionId:id,index:0},
  amount,scriptPublicKey:fixture().owners[0].funding_spk_hex36,blockDaaScore:score,isCoinbase:true,covenantId:null});

test('new identity exact five IDs, distinct owners and no old-schema relabel',()=>{
  assert.deepEqual(identityDocument(encode(fixture())),fixture());
  for(const key of ['genesis_hash_hex','domain_hex32','profile_id_hex32','pool_lineage_hex32','service_policy_hex32']) {
    const value=fixture();value[key]='ff'.repeat(32);assert.throws(()=>identityDocument(encode(value)));
  }
  for(const change of [x=>x.schema='kpxa-three-owner-funding-identity/v1',x=>x.financial_readiness=true,
    x=>x.owners[0].owner_component=true,x=>x.owners[1].funding_spk_hex36=x.owners[0].funding_spk_hex36,
    x=>x.owners[1].address=x.owners[0].address,x=>x.extra='private']) {
    const value=fixture();change(value);assert.throws(()=>identityDocument(encode(value)));
  }
});

test('SDK address/script equality mandatory',()=>{
  const value=fixture();
  const sdk={addressFromScriptPublicKey:spk=>({toString:()=>value.owners.find(row=>row.funding_spk_hex36===spk).address,free(){}})};
  checkAddresses(sdk,value);
  assert.throws(()=>checkAddresses({addressFromScriptPublicKey:()=>({toString:()=> 'kaspatest:WRONG',free(){}})},value));
});

test('coinbase maturity exact1000 and canonical RPC decimal boundary',()=>{
  const identity=fixture();
  assert.equal(matureObservation(identity,0,[entry()],999n).observation.sources.length,0);
  const mature=matureObservation(identity,0,[entry()],1000n);
  assert.equal(mature.total,2100000000n);
  assert.deepEqual(Object.keys(mature.observation).sort(),['schema',...Object.keys(IDS),'trial_id','owner_component',
    'funding_script_public_key','virtual_daa_score','sources'].sort());
  assert.equal(mature.observation.schema,'kpb-own-mature-coinbase-observation/v1');
  assert.equal(mature.observation.sources[0].entry.amount,'2100000000');
  for(const amount of [true,'02100000000','-1','2.1',MAX+1n]) assert.throws(()=>matureObservation(identity,0,[entry(undefined,amount)],1000n));
  assert.equal(matureObservation(identity,0,[entry(undefined,MAX)],1000n).total,MAX);
});

test('duplicate, foreign and immature/ordinary funding inputs cannot become mature coinbase sources',()=>{
  assert.throws(()=>matureObservation(fixture(),0,[entry(),entry()],1000n));
  assert.throws(()=>matureObservation(fixture(),0,[{...entry(),scriptPublicKey:fixture().owners[1].funding_spk_hex36}],1000n));
  assert.throws(()=>matureObservation(fixture(),0,[{...entry(),covenantId:'01'.repeat(32)}],1000n));
  assert.equal(matureObservation(fixture(),0,[{...entry(),isCoinbase:false}],1000n).observation.sources.length,0);
});

test('durable trial/stage and transaction reservations refuse replay across fresh controller paths/trial IDs',()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'kpb-public-registry-control-'));
  try {
    const identity=fixture(),record={transaction_id:'44'.repeat(32),case_sha256:'55'.repeat(32)};
    reservePhase(root,identity,'consolidate-0',record);
    assert.throws(()=>reservePhase(root,identity,'consolidate-0',record),{code:'EEXIST'});
    assert.throws(()=>reservePhase(root,{...identity,trial_id:'43d6bdc2-d709-4f4c-9ea3-941b20c79c9c'},'consolidate-0',record),{code:'EEXIST'});
    assert.throws(()=>reservePhase(root,identity,'../reset',record));
    assert.equal(fs.statSync(path.join(root,'transactions','44'.repeat(32)+'.json')).mode&0o777,0o400);
  } finally {fs.rmSync(root,{recursive:true,force:true});}
});

test('network gate is reexecuted; imported acceptance flags are not candidates',()=>{
  let calls=0;
  const job={identity_sha256:'01'.repeat(32),case_sha256:'02'.repeat(32),case_mode:'consolidation',owner_component:0};
  const candidate={schema:'kpb-network-native-candidate/v1',...job,network_or_broadcast:false};
  const result=nativeGate(job,(program,args)=>{calls++;assert.equal(program,'/usr/bin/python3');
    assert.ok(args.at(-1).endsWith('funding_network_gate.py'));return{status:0,stdout:JSON.stringify(candidate)};});
  assert.equal(calls,1);assert.equal(result.case_sha256,job.case_sha256);
  assert.throws(()=>nativeGate(job,()=>({status:0,stdout:JSON.stringify({accepted:true,actual_native_Full_passed:true})})));
  assert.throws(()=>nativeGate(job,()=>({status:2,stdout:JSON.stringify(candidate)})));
});

function rpcFixture() {
  let submissions=0;
  const identity=fixture(),own=identity.owners[0];
  const candidate={transaction:{id:'22'.repeat(32),inputs:[{previousOutpoint:{transactionId:'11'.repeat(32),index:0}}],
      outputs:[{value:'2090000000',scriptPublicKey:own.funding_spk_hex36}]},
    contexts:[{amount_sompi:'2100000000',script_public_key:own.funding_spk_hex36,block_daa_score:'0',is_coinbase:true,covenant_id:null}]};
  let after=false;
  const rpc={getServerInfo:async()=>({networkId:'testnet-10',serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true}),
    getBlockDagInfo:async()=>({network:'testnet-10',virtualDaaScore:2000n}),
    getUtxosByAddresses:async()=>({entries:after?[]:[entry()]}),
    submitTransaction:async()=>{submissions++;after=true;throw Error('PUBLIC FIXTURE UNKNOWN WRITE');}};
  const k={addressFromScriptPublicKey:()=>({toString:()=>own.address,free(){}})};
  return {rpc,k,identity,candidate,get submissions(){return submissions;}};
}
test('unknown submission invokes exactlyone network write and only requery afterward',async()=>{
  const fixture=rpcFixture();
  const result=await submitOnce({...fixture,job:{operation:'submit-consolidation',owner_component:0,case_sha256:'03'.repeat(32),identity_sha256:'04'.repeat(32)},transaction:{}});
  assert.equal(fixture.submissions,1);assert.equal(result.status,'RPC_UNKNOWN_QUERY_ONLY');
  assert.equal(result.automatic_resubmission_permitted,false);assert.equal(result.confirmation_claimed,false);
});
test('current source substitution refuses before the sole submit call',async()=>{
  const fixture=rpcFixture();fixture.rpc.getUtxosByAddresses=async()=>({entries:[entry(undefined,'2100000001')]});
  await assert.rejects(submitOnce({...fixture,job:{operation:'submit-consolidation',owner_component:0},transaction:{}}));
  assert.equal(fixture.submissions,0);
});

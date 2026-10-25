// SDK/once-only controls only. Synthetic source contexts; no network or secrets.
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {test} from 'node:test';
import {queryInputs,reserveIntent,transmitOnce} from './submit.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const spk='000020'+'01'.repeat(32)+'ac',point={transactionId:hash('synthetic-input'),index:0};
const body={inputs:[{previousOutpoint:point}]};
const expected=[{amount_sompi:'2000000000',script_public_key:spk,block_daa_score:'1234',is_coinbase:false,covenant_id:null}];
const k={addressFromScriptPublicKey:()=>({toString:()=> 'kaspatest:synthetic',free(){}})};
function rpc(modify=()=>{}){
 const raw={outpoint:point,amount:2000000000n,scriptPublicKey:spk,blockDaaScore:1234n,isCoinbase:false,covenantId:null};modify(raw);
 return {getServerInfo:async()=>({networkId:'testnet-10',serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true}),
 getBlockDagInfo:async()=>({network:'testnet-10',virtualDaaScore:9999n}),getUtxosByAddresses:async()=>({entries:[raw]})};
}
test('exact whole populated input includes amount,DAA,script,point,coinbase,covenant',async()=>assert.equal(await queryInputs(k,rpc(),body,expected),'9999'));
for(const [name,change] of Object.entries({amount:r=>{r.amount=2000000001n;},DAA:r=>{r.blockDaaScore=1235n;},script:r=>{r.scriptPublicKey='000020'+'02'.repeat(32)+'ac';},point:r=>{r.outpoint={...point,index:1};},coinbase:r=>{r.isCoinbase=true;},covenant:r=>{r.covenantId='01'.repeat(32);}}))
 test('reject changed live input '+name,async()=>assert.rejects(queryInputs(k,rpc(change),body,expected)));
test('one acknowledged submit RPC',async()=>{let calls=0;const id=hash('submit-ack');assert.equal(await transmitOnce({submitTransaction:async()=>{calls++;return {transactionId:id};}}, {},id),true);assert.equal(calls,1);});
test('unknown submit response never triggers retry',async()=>{let calls=0;assert.equal(await transmitOnce({submitTransaction:async()=>{calls++;throw Error('synthetic unknown');}}, {},hash('unknown')),false);assert.equal(calls,1);});
test('immutable stage and transaction reservations block repeated attempts without reading private files',()=>{
 const trial=randomUUID(),tx=hash(randomUUID()),root='/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01/test/controller';
 const record={trial_id:trial,transaction_id:tx};reserveIntent(root,'synthetic-test',record);
 assert.throws(()=>reserveIntent(root,'synthetic-test',{...record,transaction_id:hash(randomUUID())}),{code:'EEXIST'});
 assert.throws(()=>reserveIntent(root,'another-stage',record),{code:'EEXIST'});
});

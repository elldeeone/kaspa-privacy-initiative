// Public mocks and dummy intent metadata only; never contact a live endpoint.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {loadSdk} from './wire.mjs';
import {queryInputs,reserveIntent,transmitOnce} from './submit.mjs';

test('one RPC call after unknown, rejected, or unexpected response; no automatic retry',async()=>{
 for(const mode of ['unknown','wrong','accepted']){
  let count=0;
  const rpc={async submitTransaction(){count++;if(mode==='unknown')throw Error('injected loss');
   return{transactionId:mode==='accepted'?'11'.repeat(32):'22'.repeat(32)};}};
  assert.equal(await transmitOnce(rpc,{},'11'.repeat(32)),mode==='accepted');assert.equal(count,1);
 }
});

test('fresh source context and 1000 DAA coinbase maturity required immediately before intent',async()=>{
 const k=loadSdk(),at={transactionId:'33'.repeat(32),index:0},spk='000020'+'44'.repeat(32)+'ac';
 const body={inputs:[{previousOutpoint:at}]};
 const context={amount_sompi:'3000000000',script_public_key:spk,block_daa_score:'100',is_coinbase:true,covenant_id:null};
 const make=(daa,amount='3000000000')=>({async getServerInfo(){return{networkId:'testnet-10',serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true};},
  async getBlockDagInfo(){return{network:'testnet-10',virtualDaaScore:daa};},
  async getUtxosByAddresses(){return{entries:[{outpoint:at,amount,scriptPublicKey:spk,blockDaaScore:'100',isCoinbase:true,covenantId:null}]};}});
 await assert.rejects(()=>queryInputs(k,make('1099'),body,[context]));
 assert.equal(await queryInputs(k,make('1100'),body,[context]),'1100');
 await assert.rejects(()=>queryInputs(k,make('1100','3000000001'),body,[context]));
});

test('new controller or stage cannot erase a consumed trial transaction intent',()=>{
 const trial=crypto.randomUUID();
 const a='/var/tmp/kpi-owner-private-lifecycle-01/private/submit-public-controls/controller/a';
 const b='/var/tmp/kpi-owner-private-lifecycle-01/private/submit-public-controls/controller/b';
 const record={trial_id:trial,transaction_id:crypto.randomBytes(32).toString('hex'),case_sha256:'66'.repeat(32)};
 reserveIntent(a,'public-test-stage',record);
 assert.throws(()=>reserveIntent(b,'public-test-stage',record),/EEXIST/);
 assert.throws(()=>reserveIntent(b,'different-stage-same-tx',record),/EEXIST/);
 assert.equal(reserveIntent(b,'fresh-stage-new-tx',{...record,transaction_id:crypto.randomBytes(32).toString('hex')}).length,2);
 assert.throws(()=>reserveIntent(b,'another-trial-same-tx',{...record,trial_id:crypto.randomUUID()}),/EEXIST/);
});

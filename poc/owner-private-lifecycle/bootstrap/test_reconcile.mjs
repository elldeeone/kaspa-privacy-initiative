// Synthetic observations only; no network, signatures, funds or accepted prefix.
import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalTransaction, GENESIS, loadSdk} from '../chain/wire.mjs';
import {reconcile} from './reconcile_ordinary.mjs';

const real=loadSdk(),clone=value=>JSON.parse(JSON.stringify(value));
const source={transactionId:'11'.repeat(32),index:0};
const spk='000020'+'22'.repeat(32)+'ac';
const amount='9007199254740993'; // Deliberately above JavaScript's exact Number range.
const contexts=[{amount_sompi:'9007199254741993',script_public_key:spk,
  block_daa_score:'100',is_coinbase:true,covenant_id:null}];
const tx=new real.Transaction({version:1,inputs:[{previousOutpoint:source,signatureScript:'',
  sequence:18446744073709551615n,computeBudget:10,sigOpCount:0,
  utxo:{outpoint:source,amount:9007199254741993n,scriptPublicKey:spk,
    blockDaaScore:100n,isCoinbase:true}}],outputs:[{value:BigInt(amount),scriptPublicKey:spk}],
  lockTime:0n,subnetworkId:'00'.repeat(20),gas:0n,payload:'',storageMass:0n});
tx.finalize();const body=canonicalTransaction(tx);tx.free();
const candidate={schema:'kpx8-public-submit-candidate/v1',mode:'consolidate',
  network_id:'testnet-10',genesis_hash_hex:GENESIS,trial_id:'cfec7af9-5614-4af0-bf30-de1d24de7595',
  case_sha256:'33'.repeat(32),transaction:body,contexts};
const output={outpoint:{transactionId:body.id,index:0},amount,scriptPublicKey:spk,
  blockDaaScore:'1000',isCoinbase:false,covenantId:null};
function mocked(entries,daa='1020',network='testnet-10'){
 return {...real,RpcClient:class {
  async connect(){}async disconnect(){}
  async getServerInfo(){return{networkId:network,serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true};}
  async getBlockDagInfo(){return{network,virtualDaaScore:daa};}
  async getUtxosByAddresses(){return{entries};}
 }};
}
const observe=(entries,daa='1020',input=candidate,network='testnet-10')=>
 reconcile(input,'unused','wss://synthetic.invalid',mocked(entries,daa,network));

test('exact ordinary output and depth20 retain integer precision and narrow scope',async()=>{
 const result=await observe([clone(output)]);
 assert.equal(result.status,'EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20');
 assert.equal(result.output.amount_sompi,amount);
 assert.equal(result.observed_daa_depth,'20');
 assert.equal(result.full_accepted_prefix_or_independent_consensus_proved,false);
 assert.equal(result.signing_or_broadcast_performed,false);
 assert.equal((await observe([clone(output)],'1019')).status,'INCOMPLETE_WAIT_FOR_DAA_DEPTH');
 assert.equal((await observe([])).status,'INCOMPLETE_QUERY_ONLY');
});

test('amount, script, native metadata, duplicate and old-input substitutions reject',async()=>{
 for(const change of [{amount:'9007199254740992'},{scriptPublicKey:'000020'+'44'.repeat(32)+'ac'},
                     {isCoinbase:true},{covenantId:'55'.repeat(32)}])
  await assert.rejects(()=>observe([{...clone(output),...change}]));
 await assert.rejects(()=>observe([clone(output),clone(output)]));
 await assert.rejects(()=>observe([clone(output),{...clone(output),outpoint:source}]));
});

test('SDK body ID and selected TN10 identity are checked before an observation',async()=>{
 const wrong=clone(candidate);wrong.transaction.id='66'.repeat(32);
 await assert.rejects(()=>observe([clone(output)],'1020',wrong));
 await assert.rejects(()=>observe([clone(output)],'1020',candidate,'mainnet'));
});

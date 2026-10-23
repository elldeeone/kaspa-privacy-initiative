// Offline SDK codec and ordinary funding signature only. No RPC/broadcast API.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const SDK='/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const PINS={'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'};
const G='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const stringify=x=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?v.toString():v);
function sdk(){
  for(const [name,hash] of Object.entries(PINS))assert.equal(digest(fs.readFileSync(SDK+'/'+name)),hash);
  return createRequire(import.meta.url)(SDK+'/kaspa.js');
}
function spk(s){return typeof s==='string'?s:s.version.toString(16).padStart(4,'0')+s.script;}
function canonical(t){return{version:t.version,id:t.id,inputs:t.inputs.map(i=>({
  previousOutpoint:{transactionId:i.previousOutpoint.transactionId,index:i.previousOutpoint.index},
  signatureScript:i.signatureScript,sequence:i.sequence.toString(),computeBudget:i.computeBudget})),
  outputs:t.outputs.map(o=>{assert.equal(o.covenant??null,null);return{value:o.value.toString(),
    scriptPublicKey:spk(o.scriptPublicKey),covenant:null};}),lockTime:t.lockTime.toString(),
  subnetworkId:t.subnetworkId,gas:t.gas.toString(),payload:t.payload,
  storageMass:(t.storageMass??t.mass).toString()};}
function integer(s){assert.equal(typeof s,'string');assert.match(s,/^(0|[1-9][0-9]*)$/);
  const x=BigInt(s);assert.ok(x<=0xffffffffffffffffn);return x;}
export function run(request){
  assert.equal(request.schema,'kpx3-offline-sdk-body/v1');assert.equal(request.network_id,'testnet-10');
  assert.equal(request.genesis_hash_hex,G);assert.ok(['roundtrip','sign-founding'].includes(request.mode));
  assert.deepEqual(Object.keys(request).sort(),['schema','network_id','genesis_hash_hex','mode',
    'transaction','contexts',...(request.mode==='sign-founding'?['funding_secret_hex32']:[])].sort());
  const k=sdk(),raw=request.transaction,contexts=request.contexts;
  assert.equal(raw.version,1);assert.equal(contexts.length,raw.inputs.length);
  const inputs=raw.inputs.map((i,n)=>{assert.equal(i.sequence,'18446744073709551615');
    assert.equal(contexts[n].is_coinbase,false);assert.equal(contexts[n].covenant_id,null);
    return{...i,sequence:integer(i.sequence),sigOpCount:0,utxo:{outpoint:i.previousOutpoint,
      amount:integer(contexts[n].amount_sompi),scriptPublicKey:contexts[n].script_public_key,
      blockDaaScore:integer(contexts[n].block_daa_score),isCoinbase:false}};});
  let tx,signed,key;
  try{
    tx=new k.Transaction({...raw,inputs,outputs:raw.outputs.map(o=>({value:integer(o.value),
      scriptPublicKey:o.scriptPublicKey})),lockTime:integer(raw.lockTime),gas:integer(raw.gas),
      storageMass:integer(raw.storageMass)});tx.finalize();
    if(request.mode==='sign-founding'){
      assert.equal(inputs.length,1);assert.equal(inputs[0].computeBudget,10);
      assert.equal(raw.payload.length,1072);assert.equal(raw.payload.slice(0,16),'4b505832474e3031');
      assert.match(request.funding_secret_hex32,/^[0-9a-f]{64}$/);
      key=new k.PrivateKey(request.funding_secret_hex32);
      const address=key.toAddress('testnet-10'),source=k.payToAddressScript(address);
      try{assert.equal(spk(source),contexts[0].script_public_key);}finally{source.free();address.free();}
      signed=k.signTransaction(tx,[key],true);signed.finalize();
      assert.match(signed.inputs[0].signatureScript,/^41[0-9a-f]{128}01$/);
    }else{assert.deepEqual(canonical(tx),raw,'SDK native body/id mismatch');}
    const result=canonical(signed??tx);
    const safe=k.Transaction.deserializeFromSafeJSON((signed??tx).serializeToSafeJSON());
    try{safe.finalize();assert.deepEqual(canonical(safe),result);}finally{safe.free();}
    return{schema:'kpx3-offline-sdk-result/v1',transaction:result,
      lossless_safe_roundtrip:true,network_or_broadcast:false,secret_material_emitted:false};
  }finally{key?.free();if(signed&&signed!==tx)signed.free();tx?.free();}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{process.stdout.write(stringify(run(JSON.parse(fs.readFileSync(0,'utf8'))))+'\n');}
  catch{process.stderr.write('offline SDK body refused\n');process.exitCode=1;}
}

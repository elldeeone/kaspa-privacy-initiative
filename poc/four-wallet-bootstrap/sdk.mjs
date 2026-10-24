// Selected offline SDK21 helper. No RPC, submit API, wallet state or key store.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const SDK = process.argv[2] ?? '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const PINS = {
  'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'};
const G='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
function fields(x,names){assert.deepEqual(Object.keys(x).sort(),names.slice().sort());}
function sdk(){
  for(const [name,hash] of Object.entries(PINS))
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(SDK+'/'+name)).digest('hex'),hash);
  return createRequire(import.meta.url)(SDK+'/kaspa.js');
}
function spk(s){return typeof s==='string'?s:s.version.toString(16).padStart(4,'0')+s.script;}
function integer(s){assert.equal(typeof s,'string');assert.match(s,/^(0|[1-9][0-9]*)$/);
  const n=BigInt(s);assert.ok(n<=0xffffffffffffffffn);return n;}
function canonical(t){return {version:t.version,id:t.id,inputs:t.inputs.map(i=>({
  previousOutpoint:{transactionId:i.previousOutpoint.transactionId,index:i.previousOutpoint.index},
  signatureScript:i.signatureScript,sequence:i.sequence.toString(),computeBudget:i.computeBudget})),
  outputs:t.outputs.map(o=>{assert.equal(o.covenant??null,null);return{value:o.value.toString(),
    scriptPublicKey:spk(o.scriptPublicKey),covenant:null};}),lockTime:t.lockTime.toString(),
  subnetworkId:t.subnetworkId,gas:t.gas.toString(),payload:t.payload,
  storageMass:(t.storageMass??t.mass).toString()};}
export function run(request){
  assert.equal(request.schema,'kpx6-offline-GN2-sdk/v1');
  assert.equal(request.network_id,'testnet-10');assert.equal(request.genesis_hash_hex,G);
  const k=sdk();
  if(request.operation==='address'){
    fields(request,['schema','network_id','genesis_hash_hex','operation','xonly_hex32']);
    assert.match(request.xonly_hex32,/^[0-9a-f]{64}$/);
    const key=new k.XOnlyPublicKey(request.xonly_hex32),address=key.toAddress('testnet-10');
    const script=k.payToAddressScript(address);
    try{assert.equal(spk(script),'000020'+request.xonly_hex32+'ac');return{
      xonly_hex32:request.xonly_hex32,address:address.toString(),script_public_key:spk(script)};}
    finally{script.free();address.free();key.free();}
  }
  assert.ok(['roundtrip','sign-input'].includes(request.operation));
  fields(request,['schema','network_id','genesis_hash_hex','operation','transaction','contexts',
    ...(request.operation==='sign-input'?['input_index','funding_secret_hex32']:[])]);
  const raw=request.transaction,contexts=request.contexts;
  assert.equal(raw.version,1);assert.equal(raw.inputs.length,2);assert.equal(contexts.length,2);
  const inputs=raw.inputs.map((i,n)=>{
    assert.equal(i.sequence,'18446744073709551615');assert.equal(i.computeBudget,10);
    assert.equal(contexts[n].is_coinbase,false);assert.equal(contexts[n].covenant_id,null);
    return{...i,sequence:integer(i.sequence),sigOpCount:0,utxo:{outpoint:i.previousOutpoint,
      amount:integer(contexts[n].amount_sompi),scriptPublicKey:contexts[n].script_public_key,
      blockDaaScore:integer(contexts[n].block_daa_score),isCoinbase:false}};});
  let tx,key;
  try{
    tx=new k.Transaction({...raw,inputs,outputs:raw.outputs.map(o=>{
      assert.equal(o.covenant,null);return{value:integer(o.value),scriptPublicKey:o.scriptPublicKey};}),
      lockTime:integer(raw.lockTime),gas:integer(raw.gas),storageMass:integer(raw.storageMass)});
    tx.finalize();assert.deepEqual(canonical(tx),raw,'GN2 SDK body/ID mismatch');
    if(request.operation==='sign-input'){
      assert.ok(Number.isInteger(request.input_index)&&request.input_index>=0&&request.input_index<2);
      assert.match(request.funding_secret_hex32,/^[0-9a-f]{64}$/);
      key=new k.PrivateKey(request.funding_secret_hex32);
      const address=key.toAddress('testnet-10'),source=k.payToAddressScript(address);
      try{assert.equal(spk(source),contexts[request.input_index].script_public_key);}
      finally{source.free();address.free();}
      const signature=k.createInputSignature(tx,request.input_index,key,k.SighashType.All);
      assert.match(signature,/^41[0-9a-f]{128}01$/);
      // Signature-only export; never mutate or sign another owner's input.
      assert.deepEqual(canonical(tx),raw);
      return{input_index:request.input_index,signature_script_hex66:signature,
        network_or_broadcast:false,secret_material_emitted:false};
    }
    const safe=k.Transaction.deserializeFromSafeJSON(tx.serializeToSafeJSON());
    try{safe.finalize();assert.deepEqual(canonical(safe),raw);}finally{safe.free();}
    return{transaction:canonical(tx),lossless_safe_roundtrip:true,network_or_broadcast:false};
  }finally{key?.free();tx?.free();}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{process.stdout.write(JSON.stringify(run(JSON.parse(fs.readFileSync(0,'utf8'))))+'\n');}
  catch{process.stderr.write('offline GN2 SDK refused\n');process.exitCode=1;}
}

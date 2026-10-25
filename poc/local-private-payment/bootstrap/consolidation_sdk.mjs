// Offline ordinary own-coinbase consolidation only. Private scalar is stdin-only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {loadSdk,canonicalTransaction,GENESIS} from '../chain/wire.mjs';

const MAX=2870000000000000000n,P2PK=/^000020[0-9a-f]{64}ac$/;
function exact(value,names){assert.deepEqual(Object.keys(value).sort(),[...names].sort());}
function dec(value){assert.equal(typeof value,'string');assert.match(value,/^(0|[1-9][0-9]*)$/);
 const result=BigInt(value);assert(result<=0xffffffffffffffffn);return result;}
export function run(request,sdkDirectory){
 assert.equal(request.schema,'kpxa-offline-own-mined-consolidation/v1');
 assert.equal(request.network_id,'testnet-10');assert.equal(request.genesis_hash_hex,GENESIS);
 assert(['roundtrip','sign-all'].includes(request.operation));
 exact(request,['schema','network_id','genesis_hash_hex','operation','transaction','contexts',
  ...(request.operation==='sign-all'?['funding_secret_hex32']:[])]);
 const body=request.transaction,contexts=request.contexts;
 exact(body,['version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','storageMass']);
 assert.equal(body.version,1);assert.match(body.id,/^[0-9a-f]{64}$/);
 assert.equal(body.lockTime,'0');assert.equal(body.gas,'0');assert.equal(body.subnetworkId,'00'.repeat(20));
 assert.match(body.payload,/^4b5058414d463031[0-9a-f]{160}$/);
 assert(Array.isArray(body.inputs)&&body.inputs.length>0&&contexts.length===body.inputs.length);
 assert.equal(body.outputs.length,1);const output=body.outputs[0];
 exact(output,['value','scriptPublicKey','covenant']);assert.equal(output.covenant,null);
 assert.match(output.scriptPublicKey,P2PK);assert(dec(output.value)>0n&&dec(output.value)<=MAX);
 const points=new Set();let source=0n;
 const inputs=body.inputs.map((item,index)=>{
  exact(item,['previousOutpoint','signatureScript','sequence','computeBudget']);
  exact(item.previousOutpoint,['transactionId','index']);assert.match(item.previousOutpoint.transactionId,/^[0-9a-f]{64}$/);
  assert(Number.isInteger(item.previousOutpoint.index)&&item.previousOutpoint.index>=0&&item.previousOutpoint.index<2**32);
  const identity=item.previousOutpoint.transactionId+':'+item.previousOutpoint.index;
  assert(!points.has(identity));points.add(identity);
  assert.equal(item.sequence,'18446744073709551615');assert.equal(item.computeBudget,10);
  assert.match(item.signatureScript,/^41[0-9a-f]{128}01$/);
  const entry=contexts[index];exact(entry,['amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id']);
  assert.equal(entry.script_public_key,output.scriptPublicKey);assert.equal(entry.is_coinbase,true);
  assert.equal(entry.covenant_id,null);const amount=dec(entry.amount_sompi);assert(amount>0n&&amount<=MAX);source+=amount;
  return {...item,sequence:dec(item.sequence),sigOpCount:0,utxo:{outpoint:item.previousOutpoint,
   amount,scriptPublicKey:entry.script_public_key,blockDaaScore:dec(entry.block_daa_score),isCoinbase:true}};
 });
 assert(source<=MAX&&source>dec(output.value));
 const k=loadSdk(sdkDirectory);let tx,key;
 try{
  tx=new k.Transaction({...body,inputs,outputs:[{value:dec(output.value),scriptPublicKey:output.scriptPublicKey}],
   lockTime:0n,gas:0n,storageMass:dec(body.storageMass)});
  tx.finalize();assert.deepEqual(canonicalTransaction(tx),body);
  if(request.operation==='sign-all'){
   assert.match(request.funding_secret_hex32,/^[0-9a-f]{64}$/);key=new k.PrivateKey(request.funding_secret_hex32);
   const address=key.toAddress('testnet-10'),script=k.payToAddressScript(address);
   try{assert.equal('0000'+script.script,output.scriptPublicKey);}finally{script.free();address.free();}
   const signatures=inputs.map((_,index)=>{
    const value=k.createInputSignature(tx,index,key,k.SighashType.All);assert.match(value,/^41[0-9a-f]{128}01$/);return value;
   });
   assert.deepEqual(canonicalTransaction(tx),body);
   return {signature_scripts_hex66:signatures,secret_material_emitted:false,network_or_broadcast:false};
  }
  const restored=k.Transaction.deserializeFromSafeJSON(tx.serializeToSafeJSON());
  try{restored.finalize();assert.deepEqual(canonicalTransaction(restored),body);}finally{restored.free();}
  return {lossless_safe_roundtrip:true,network_or_broadcast:false};
 }finally{key?.free();tx?.free();}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{process.stdout.write(JSON.stringify(run(JSON.parse(fs.readFileSync(0,'utf8')),process.argv[2]))+'\n');}
 catch{process.stderr.write('own ordinary consolidation SDK refused\n');process.exitCode=1;}
}

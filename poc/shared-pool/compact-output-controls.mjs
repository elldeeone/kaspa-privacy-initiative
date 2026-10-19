#!/usr/bin/env node
// Actual output mutations with an unchanged valid private authorization/proof.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {read,save,k,canonical,binary,number,fileHash} from './runtime.mjs';
import {outputUtxo} from './chain.mjs';
const [publicDir,stepText,out]=process.argv.slice(2),step=Number(stepText);
fs.mkdirSync(out,{mode:0o700});
const original=read(path.join(publicDir,number(step)+'.json'));
assert.equal(original.outputs.length,2);
assert.equal(Buffer.from(original.payload,'hex')[8+172],2);
const prior=read(path.join(publicDir,number(step-1)+'.json'));
save(path.join(out,'context.json'),[outputUtxo(prior,0)]);
function execute(raw,label){
  const tx=new k.Transaction({...raw,
    inputs:raw.inputs.map(i=>({...i,sequence:BigInt(i.sequence)})),
    outputs:raw.outputs.map(o=>{const r={...o,value:BigInt(o.value)};delete r.covenant;return r;}),
    lockTime:BigInt(raw.lockTime),gas:BigInt(raw.gas),storageMass:BigInt(raw.storageMass)});
  let exact;try{exact=canonical(tx);}finally{tx.free();}
  assert.equal(exact.inputs[0].signatureScript,original.inputs[0].signatureScript);
  assert.equal(exact.payload,original.payload);
  save(path.join(out,label+'.json'),exact);
  const result=spawnSync(binary,['validate',path.join(out,label+'.json'),path.join(out,'context.json')],{encoding:'utf8'});
  return {code:result.status,error:result.stderr.trim(),stdout:result.stdout};
}
assert.equal(execute(original,'positive').code,0);
const r=Buffer.from(original.inputs[0].signatureScript,'hex').subarray(133);
const next=Buffer.concat([r.subarray(0,36),Buffer.from(original.payload,'hex').subarray(643,748),r.subarray(141)]);
const vk=fs.readFileSync(path.join(publicDir,'vk.bin')),vkIndex=next.indexOf(vk);assert.ok(vkIndex>=0);
const results=[];
for(const [label,offset] of [['changed-verification-key',vkIndex],['changed-domain',1],['changed-rule',next.length-1]]){
  const mutated=Buffer.from(next);mutated[offset]^=1;
  // Python's standard library computes the same unkeyed 32-byte BLAKE2b as
  // the native P2SH opcode; it does not receive any private material.
  const hash=spawnSync('python3',['-c','import hashlib,sys; print(hashlib.blake2b(bytes.fromhex(sys.argv[1]),digest_size=32).hexdigest())',mutated.toString('hex')],{encoding:'utf8'});
  assert.equal(hash.status,0,hash.stderr);
  const tx=structuredClone(original);tx.outputs[0].scriptPublicKey='0000aa20'+hash.stdout.trim()+'87';
  const checked=execute(tx,label);assert.notEqual(checked.code,0);assert.match(checked.error,/signature script|script validation/i);
  results.push({control:label,rejected:true,native_error:checked.error,privateProofUnchanged:true});
}
const redirected=structuredClone(original),spk=Buffer.from(redirected.outputs[1].scriptPublicKey,'hex');spk[3]^=1;
redirected.outputs[1].scriptPublicKey=spk.toString('hex');
const checked=execute(redirected,'redirected-payout');assert.notEqual(checked.code,0);assert.match(checked.error,/signature script|script validation/i);
results.push({control:'redirected-payout',rejected:true,native_error:checked.error,privateProofUnchanged:true});
save(path.join(out,'result.json'),{nativeRejections:results.length,positiveNativeFull:true,results,
  binarySha256:fileHash(binary),proofSha256:crypto.createHash('sha256').update(Buffer.from(original.inputs[0].signatureScript,'hex').subarray(2,130)).digest('hex')});
console.log(JSON.stringify({nativeRejections:results.length,positiveNativeFull:true}));

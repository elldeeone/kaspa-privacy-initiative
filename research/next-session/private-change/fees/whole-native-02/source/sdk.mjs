// Public offline native-fixture ID calculation. No RPC, keys or signing API.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const SDK='/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const PINS={'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
 'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
 'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'};
for(const [name,pin] of Object.entries(PINS))assert.equal(crypto.createHash('sha256').update(fs.readFileSync(SDK+'/'+name)).digest('hex'),pin);
const k=createRequire(import.meta.url)(SDK+'/kaspa.js');
const batch=JSON.parse(fs.readFileSync(0,'utf8'));
for(const row of batch){
 const raw=row.transaction;
 assert.equal(raw.inputs[0].sequence,'18446744073709551615');
 const tx=new k.Transaction({...raw,inputs:raw.inputs.map(i=>({...i,sequence:BigInt(i.sequence),sigOpCount:0})),
  outputs:raw.outputs.map(o=>({value:BigInt(o.value),scriptPublicKey:o.scriptPublicKey})),
  lockTime:BigInt(raw.lockTime),gas:BigInt(raw.gas),storageMass:BigInt(raw.mass)});
 try{tx.finalize();raw.id=tx.id;}finally{tx.free();}
}
process.stdout.write(JSON.stringify(batch)+'\n');

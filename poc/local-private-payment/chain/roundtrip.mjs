// Public arbitrary-input SDK roundtrip only. No key, RPC client or signing call.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {GENESIS,loadSdk,stringify,canonicalTransaction} from './wire.mjs';
import {strictJson} from './selection.mjs';
import {makeTransaction} from './submit.mjs';
try {
  const value=strictJson(fs.readFileSync(0));
  assert.deepEqual(Object.keys(value).sort(),['contexts','genesis_hash_hex','network_id','transaction']);
  assert.equal(value.network_id,'testnet-10');assert.equal(value.genesis_hash_hex,GENESIS);
  assert(Array.isArray(value.contexts)&&value.contexts.length===value.transaction.inputs.length);
  const tx=makeTransaction(loadSdk(process.argv[2]),value.transaction,value.contexts);
  try {process.stdout.write(stringify({transaction:canonicalTransaction(tx),contexts:value.contexts,
    lossless_safe_roundtrip:true,network_or_broadcast:false})+'\n');}
  finally {tx.free();}
}catch {process.stderr.write('public SDK roundtrip refused\n');process.exitCode=1;}

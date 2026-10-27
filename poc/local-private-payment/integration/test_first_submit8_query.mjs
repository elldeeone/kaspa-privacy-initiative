import assert from 'node:assert/strict';
import {readOnlyRpc,publicError,ENDPOINT} from './first_submit8_query.mjs';

const calls=[];
const rpc=readOnlyRpc({
 getServerInfo:async()=>{calls.push('server');return {networkId:'testnet-10'};},
 getBlockDagInfo:async()=>{calls.push('dag');return {network:'testnet-10'};},
 getUtxosByAddresses:async()=>{calls.push('utxo');return {entries:[]};},
 submitTransaction:()=>assert.fail('submit must be inaccessible'),
});
await rpc.getServerInfo();await rpc.getBlockDagInfo();await rpc.getUtxosByAddresses({addresses:[]});
assert.deepEqual(calls,['server','dag','utxo']);
for(const name of ['submitTransaction','sign','reserveIntent','getBlock','disconnect'])
 assert.throws(()=>rpc[name],/NON_READ_RPC_BLOCKED/);
assert.deepEqual(publicError(new Error('WebSocket disconnected: KNOWN PUBLIC DETAIL')),
 {category:'WEBSOCKET_DISCONNECTED',code:null});
assert.deepEqual(publicError({message:'unknown PRIVATE-LIKE-CONTROL-MARKER',code:'ECONNRESET'}),
 {category:'UNCLASSIFIED_PUBLIC_QUERY_ERROR',code:'ECONNRESET'});
assert.equal(JSON.stringify(publicError({message:'DO-NOT-EXPORT',code:'/not-a-code'})).includes('DO-NOT-EXPORT'),false);
assert.deepEqual(publicError({category:'INPUT'}),{category:'EXACT_INPUT_MISMATCH',code:null});
assert.equal(ENDPOINT,'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh');
console.log('READ_ONLY_RPC_ALLOWLIST_AND_SAFE_ERROR_CONTROLS_PASS');

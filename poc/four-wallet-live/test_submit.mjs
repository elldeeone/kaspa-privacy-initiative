// Public/synthetic only: no node connection, private key, Native or proof run.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {makeTransaction, queryInputs, stablePublic, transmitOnce} from './submit.mjs';
import {roundtrip} from './offline_sdk.mjs';
import {canonicalTransaction, loadSdk} from '../four-wallet-chain/wire.mjs';

const k = loadSdk(), spk = '000020' + '22'.repeat(32) + 'ac';
const source = {transactionId: '11'.repeat(32), index: 0};
const contexts = [{amount_sompi: '2000', script_public_key: spk,
  block_daa_score: '18446744073709551614', is_coinbase: false, covenant_id: null}];
const draft = new k.Transaction({version: 1, id: '00'.repeat(32), inputs: [{previousOutpoint: source,
  signatureScript: '', sequence: 18446744073709551615n, computeBudget: 10, sigOpCount: 0,
  utxo: {outpoint: source, amount: 2000n, scriptPublicKey: spk,
    blockDaaScore: 18446744073709551614n, isCoinbase: false}}],
  outputs: [{value: 1000n, scriptPublicKey: spk}], lockTime: 0n,
  subnetworkId: '00'.repeat(20), gas: 0n, payload: '', storageMass: 0n});
draft.finalize(); const body = canonicalTransaction(draft); draft.free();
const rebuilt = makeTransaction(k, body, contexts);
assert.equal(canonicalTransaction(rebuilt).inputs[0].sequence, '18446744073709551615'); rebuilt.free();
const publicRequest = {schema: 'kpx6-four-wallet-public-offline-SDK/v1', network_id: 'testnet-10',
  genesis_hash_hex: 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
  transaction: body, contexts};
const sdkDirectory = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
assert.deepEqual(roundtrip(publicRequest, sdkDirectory).transaction, body);
assert.throws(() => roundtrip({...publicRequest, funding_secret_hex32: 'PUBLIC_SENTINEL'}, sdkDirectory));
assert.throws(() => roundtrip({...publicRequest, network_id: 'mainnet'}, sdkDirectory));

let freed = 0;
const querySdk = {addressFromScriptPublicKey: () => ({toString: () => 'PUBLIC_TEST_ADDRESS', free: () => freed++})};
const live = {outpoint: source, amount: 2000n, scriptPublicKey: spk,
  blockDaaScore: 18446744073709551614n, isCoinbase: false, covenantId: null};
const rpc = {getServerInfo: async () => ({networkId: 'testnet-10', serverVersion: '2.1.0', isSynced: true, hasUtxoIndex: true}),
  getBlockDagInfo: async () => ({network: 'testnet-10'}), getUtxosByAddresses: async () => ({entries: [live]})};
await queryInputs(querySdk, rpc, body, contexts); assert.equal(freed, 1);
await assert.rejects(queryInputs(querySdk, {...rpc, getUtxosByAddresses: async () => ({entries: [{...live, blockDaaScore: 1n}]})}, body, contexts));
await assert.rejects(queryInputs(querySdk, {...rpc, getUtxosByAddresses: async () => ({entries: [live, live]})}, body, contexts));
await assert.rejects(queryInputs(querySdk, {...rpc, getUtxosByAddresses: async () => ({entries: []})}, body, contexts));
await assert.rejects(queryInputs(querySdk, {...rpc, getServerInfo: async () => ({networkId: 'mainnet'})}, body, contexts));

for (const outcome of ['ACK', 'UNKNOWN', 'WRONG_ID']) {
  let calls = 0;
  const peer = {submitTransaction: async request => {
    calls++; assert.equal(request.allowOrphan, false);
    if (outcome === 'UNKNOWN') throw Error('PUBLIC_UNKNOWN');
    return {transactionId: outcome === 'ACK' ? body.id : 'ff'.repeat(32)};
  }};
  assert.equal(await transmitOnce(peer, {}, body.id), outcome === 'ACK'); assert.equal(calls, 1);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kpx6-public-submit-controls-'));
try {
  for (const role of ['A', 'B', 'C', 'D']) {
    const folder = path.join(root, 'owners', role); fs.mkdirSync(folder, {recursive: true});
    fs.writeFileSync(path.join(folder, 'backup.json'), 'PUBLIC_SYNTHETIC_SENTINEL_' + role);
  }
  const publicFile = path.join(root, 'public.json'), forbidden = path.join(root, 'owners', 'D', 'backup.json');
  fs.writeFileSync(publicFile, '{}');
  const originalOpen = fs.openSync, originalRead = fs.readFileSync; let forbiddenReads = 0;
  fs.openSync = function(file, ...args) {
    if (file === publicFile) { fs.unlinkSync(publicFile); fs.linkSync(forbidden, publicFile); }
    return originalOpen.call(fs, file, ...args);
  };
  fs.readFileSync = function(file, ...args) {
    if (typeof file === 'number') {
      const a = fs.fstatSync(file), b = fs.statSync(forbidden);
      if (a.dev === b.dev && a.ino === b.ino) forbiddenReads++;
    }
    return originalRead.call(fs, file, ...args);
  };
  try { assert.throws(() => stablePublic(publicFile, root)); assert.equal(forbiddenReads, 0); }
  finally { fs.openSync = originalOpen; fs.readFileSync = originalRead; }
} finally { fs.rmSync(root, {recursive: true}); }
console.log(JSON.stringify({status: 'PASS', groups: 9, scope: 'PUBLIC_SYNTHETIC_SDK_AND_MOCK_RPC_ONLY', live_submission: false}));

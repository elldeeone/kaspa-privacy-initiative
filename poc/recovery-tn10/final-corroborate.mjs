#!/usr/bin/env node
// Read-only terminal UTXO corroboration across two independently operated,
// synchronized public TN10 endpoints. No private truth or wallet file is read.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const k = createRequire(import.meta.url)(path.join(repo, '.local/sdk/kaspa-wasm32-sdk/nodejs/kaspa'));
const run = path.resolve(process.argv[2]);
assert.equal(fs.statSync(run).mode & 0o077, 0, 'private run directory required');
const urls = [
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
  'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
];
const read = name => JSON.parse(fs.readFileSync(path.join(run, name), 'utf8'));
const stringify = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2);
const spk = value => value.version.toString(16).padStart(4, '0') + value.script;
function address(record, index) {
  const encoded = record.transaction.outputs[index].scriptPublicKey;
  return k.addressFromScriptPublicKey(
    new k.ScriptPublicKey(Number.parseInt(encoded.slice(0, 4), 16), encoded.slice(4)),
    'testnet',
  ).toString();
}
function entry(raw) {
  const value = raw.entry ?? raw;
  return {
    address: raw.address?.toString() ?? null,
    outpoint: {transactionId: value.outpoint.transactionId, index: value.outpoint.index},
    amount: value.amount.toString(),
    scriptPublicKey: spk(value.scriptPublicKey),
    covenantId: value.covenantId?.toString() ?? null,
  };
}
const ordinal = value => String(value).padStart(2, '0');
const payoutRecords = Array.from({length: 5}, (_, index) => read(`payout-${ordinal(index + 1)}-build/transaction.json`));
const operations = Array.from({length: 5}, (_, index) => read(`wallet-public/operation-${ordinal(index + 6)}.json`));
const payouts = payoutRecords.map((record, index) => {
  const amount = BigInt(operations[index].statement.exit_value) + 50_000_000n;
  assert.equal(BigInt(record.transaction.outputs[0].value), amount);
  return {
    address: address(record, 0),
    outpoint: {transactionId: record.transactionId, index: 0},
    amount: amount.toString(),
  };
});
const permissionRecords = Array.from({length: 5}, (_, index) => read(`batch-${ordinal(index + 2)}-settlement-build/transaction.json`));
const permissions = permissionRecords.map(record => ({
  address: address(record, 1),
  outpoint: {transactionId: record.transactionId, index: 1},
}));
const reserveRecord = read('deposit-a-build/transaction.json');
const reserveAddress = address(reserveRecord, 0);
const stateRecord = read('batch-07-settlement-build/transaction.json');
const state = {
  address: address(stateRecord, 0),
  outpoint: {transactionId: stateRecord.transactionId, index: 0},
  amount: '100000000',
};
const trial = read('trial/trial.json');
const addresses = [...new Set([
  ...payouts.map(value => value.address),
  ...permissions.map(value => value.address),
  reserveAddress,
  state.address,
  trial.sponsorNative.address,
])];
const observations = [];
for (const url of urls) {
  const rpc = new k.RpcClient({url, networkId: 'testnet-10'});
  await rpc.connect({timeoutDuration: 15_000});
  try {
    const info = await rpc.getServerInfo();
    assert.equal(info.networkId, 'testnet-10');
    assert.equal(info.isSynced, true);
    const entries = (await rpc.getUtxosByAddresses({addresses})).entries.map(entry);
    for (const expected of payouts) {
      const found = entries.filter(value => value.outpoint.transactionId === expected.outpoint.transactionId
        && value.outpoint.index === expected.outpoint.index
        && value.amount === expected.amount);
      assert.equal(found.length, 1, `${url}: payout missing`);
    }
    for (const expected of permissions) {
      assert(!entries.some(value => value.outpoint.transactionId === expected.outpoint.transactionId
        && value.outpoint.index === expected.outpoint.index), `${url}: permission remains unspent`);
    }
    assert(!entries.some(value => value.address === reserveAddress), `${url}: reserve principal remains`);
    assert(entries.some(value => value.outpoint.transactionId === state.outpoint.transactionId
      && value.outpoint.index === state.outpoint.index
      && value.amount === state.amount), `${url}: terminal state rent missing`);
    const sponsor = entries.filter(value => value.address === trial.sponsorNative.address);
    assert.equal(sponsor.length, 1, `${url}: sponsor change shape`);
    observations.push({url, info, payouts: payouts.map(value => value.outpoint), permissionsSpent: true,
      reserveEntries: 0, state, sponsor: sponsor[0]});
  } finally {
    await rpc.disconnect();
  }
}
const result = {
  schema: 'KPI_FULL_DRAINAGE_TERMINAL_CORROBORATION_V1',
  trial: trial.trial,
  endpoints: observations,
  confirmedNativeOwnerOutputs: 5,
  permissionsSpent: 5,
  reservePrincipalSompi: 0,
  stateRentSompi: 100_000_000,
  userPrincipalAccountingZero: true,
};
const output = path.join(run, 'final-corroboration.json');
fs.writeFileSync(output, `${stringify(result)}\n`, {flag: 'wx', mode: 0o600});
console.log(JSON.stringify({corroborated: true, endpoints: urls.length, payouts: 5}));

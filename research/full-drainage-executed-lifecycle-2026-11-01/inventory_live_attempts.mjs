#!/usr/bin/env node
// Read-only inventory of retained TN10 attempt outputs. Never reads a key.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const k = createRequire(import.meta.url)(path.join(repo, '.local/sdk/kaspa-wasm32-sdk/nodejs/kaspa'));
const output = path.resolve(process.argv[2]);
assert(!fs.existsSync(output), 'output exists');
const base = '/var/tmp/kpi-tn10-full-drainage-live-20261102-attempt-';
const urls = [
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
  'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
];
const stringify = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2);
const spk = value => value.version.toString(16).padStart(4, '0') + value.script;
const point = value => `${value.transactionId}:${value.index}`;
function address(script) {
  return k.addressFromScriptPublicKey(
    new k.ScriptPublicKey(Number.parseInt(script.slice(0, 4), 16), script.slice(4)),
    'testnet',
  ).toString();
}
function walk(directory) {
  const values = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    const target = path.join(directory, item.name);
    if (item.isDirectory()) values.push(...walk(target));
    else values.push(target);
  }
  return values;
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
function canonical(values) {
  return values.map(entry).sort((a, b) => point(a.outpoint).localeCompare(point(b.outpoint)));
}
async function query(url, addresses) {
  const rpc = new k.RpcClient({url, networkId: 'testnet-10'});
  await rpc.connect({timeoutDuration: 15_000});
  try {
    const info = await rpc.getServerInfo();
    assert.equal(info.networkId, 'testnet-10');
    assert.equal(info.serverVersion, '2.1.0');
    assert.equal(info.isSynced, true);
    assert.equal(info.hasUtxoIndex, true);
    const entries = [];
    for (let index = 0; index < addresses.length; index += 50) {
      entries.push(...(await rpc.getUtxosByAddresses({addresses: addresses.slice(index, index + 50)})).entries);
    }
    return {url, info, entries: canonical(entries)};
  } finally { await rpc.disconnect(); }
}
function latestCheckpoint(run) {
  const paths = walk(run).filter(value => /(?:initialize|batch-\d\d)-checkpoint\/checkpoint\.json$/.test(value));
  if (!paths.length) return null;
  const rows = paths.map(value => ({path: value, value: JSON.parse(fs.readFileSync(value, 'utf8'))}));
  rows.sort((a, b) => {
    const stage = row => row.value.completed === 'initialize' ? 0 : Number(row.value.completed?.split('-')[1] ?? -1);
    return stage(a) - stage(b);
  });
  const row = rows.at(-1);
  return {completed: row.value.completed, accounting: row.value.accounting, stateOutpoint: row.value.stateOutpoint};
}

const attempts = [];
for (let number = 1; number <= 6; number++) {
  const run = `${base}${String(number).padStart(2, '0')}`;
  assert.equal(fs.statSync(run).mode & 0o077, 0, 'attempt directory must remain private');
  const trial = JSON.parse(fs.readFileSync(path.join(run, 'trial/trial.json'), 'utf8'));
  const transactionFiles = walk(run).filter(value => /-build\/transaction\.json$/.test(value));
  const outputs = new Map();
  const addresses = new Set([trial.sponsorNative.address]);
  const payoutPoints = new Set();
  const permissionPoints = new Set();
  const statePoints = new Set();
  let reserveScript = null;
  for (const file of transactionFiles) {
    const record = JSON.parse(fs.readFileSync(file, 'utf8'));
    const label = path.basename(path.dirname(file)).replace(/-build$/, '');
    for (let index = 0; index < record.transaction.outputs.length; index++) {
      const value = record.transaction.outputs[index];
      const outpoint = `${record.transactionId}:${index}`;
      const outputAddress = address(value.scriptPublicKey);
      addresses.add(outputAddress);
      outputs.set(outpoint, {label, index, value: String(value.value), address: outputAddress, covenant: value.covenant});
      if (/^payout-\d\d$/.test(label) && index === 0) payoutPoints.add(outpoint);
      if ((label === 'initialize' || /^batch-\d\d-settlement$/.test(label)) && index === 0) statePoints.add(outpoint);
      if (/^batch-\d\d-settlement$/.test(label) && index === 1) permissionPoints.add(outpoint);
      if (label === 'deposit-a' && index === 0) reserveScript = value.scriptPublicKey;
    }
  }
  const observations = [];
  for (const url of urls) observations.push(await query(url, [...addresses]));
  assert.deepEqual(observations[0].entries, observations[1].entries, `attempt ${number} routes disagree`);
  // Owner addresses were reused across attempts. Attribute only outputs built by
  // this attempt, plus its unique sponsor address, to avoid cross-attempt counts.
  const current = observations[0].entries.filter(value =>
    outputs.has(point(value.outpoint)) || value.address === trial.sponsorNative.address
  );
  const sums = {sponsorOrdinarySompi: 0n, reservePrincipalSompi: 0n, stateRentSompi: 0n, permissionRentSompi: 0n, ownerPayoutOutputsSompi: 0n, otherSompi: 0n};
  const classified = [];
  for (const value of current) {
    const outpoint = point(value.outpoint);
    const produced = outputs.get(outpoint);
    let category = 'otherSompi';
    if (value.address === trial.sponsorNative.address && value.covenantId === null) category = 'sponsorOrdinarySompi';
    else if (produced && reserveScript && produced.address === address(reserveScript)) category = 'reservePrincipalSompi';
    else if (statePoints.has(outpoint)) category = 'stateRentSompi';
    else if (permissionPoints.has(outpoint)) category = 'permissionRentSompi';
    else if (payoutPoints.has(outpoint)) category = 'ownerPayoutOutputsSompi';
    sums[category] += BigInt(value.amount);
    classified.push({outpoint, amountSompi: value.amount, category, producedBy: produced?.label ?? null});
  }
  const files = fs.readdirSync(run);
  const acceptedLabels = files.filter(value => value.endsWith('-accepted.json')).map(value => value.slice(0, -'-accepted.json'.length));
  attempts.push({
    attempt: number,
    trial: trial.trial,
    sponsorAddress: trial.sponsorNative.address,
    fundingTransactionId: fs.existsSync(path.join(run, 'funding-plan.json')) ? JSON.parse(fs.readFileSync(path.join(run, 'funding-plan.json'), 'utf8')).transaction.id : null,
    acceptedTransactionRecords: acceptedLabels.length,
    confirmedPayouts: acceptedLabels.filter(value => /^payout-\d\d$/.test(value)).length,
    confirmedSettlements: acceptedLabels.filter(value => /^batch-\d\d-settlement$/.test(value)).length,
    latestCheckpoint: latestCheckpoint(run),
    currentUtxos: classified,
    currentBalances: Object.fromEntries(Object.entries(sums).map(([key, value]) => [key, value.toString()])),
    recoveryBoundary: {
      sponsorKeyPresentMode0600: fs.existsSync(path.join(run, 'trial/sponsor/native.key')) && (fs.statSync(path.join(run, 'trial/sponsor/native.key')).mode & 0o077) === 0,
      sponsorOrdinaryRecoveryNotExecuted: true,
      covenantOrReserveRecoveryNotExecuted: true,
      ownerPayoutsAreOutsideSponsorRecovery: true,
    },
  });
}
const result = {
  schema: 'full-drainage-live-attempt-inventory-v1',
  observedAt: new Date().toISOString(),
  network: 'testnet-10',
  endpoints: urls,
  readsPrivateKeysOrTruth: false,
  performsMutation: false,
  attempts,
  boundary: 'Current UTXOs only; recovery capability was not exercised. Attempt 06 does not account for attempts 01-05.',
};
fs.writeFileSync(output, `${stringify(result)}\n`, {flag: 'wx', mode: 0o600});
console.log(JSON.stringify({attempts: attempts.length, earlierAttemptsWithReservePrincipal: attempts.slice(0, 5).filter(value => BigInt(value.currentBalances.reservePrincipalSompi) > 0n).length}));

#!/usr/bin/env node
// One fresh ordinary TN10 funding transaction. Preparation and submission are
// separate commands; submission is single-shot and durably records intent.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const k = createRequire(import.meta.url)(path.join(repo, '.local/sdk/kaspa-wasm32-sdk/nodejs/kaspa'));
const PRIMARY = 'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh';
const WITNESS = 'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh';
const REMOTES = [
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
  'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
];
const [action, runText, keyFile, destination, amountText] = process.argv.slice(2);
assert(['prepare', 'submit', 'corroborate'].includes(action));
const run = path.resolve(runText);
assert(fs.statSync(run).isDirectory(), 'private run directory required');
assert.equal(fs.statSync(run).mode & 0o077, 0, 'run directory must be mode 0700');
const stringify = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2);
const read = name => JSON.parse(fs.readFileSync(path.join(run, name), 'utf8'));
const trial = JSON.parse(fs.readFileSync(path.join(run, 'trial/trial.json'), 'utf8'));
function save(name, value) {
  const target = path.join(run, name);
  const handle = fs.openSync(target, 'wx', 0o600);
  fs.writeFileSync(handle, `${stringify(value)}\n`);
  fs.fsyncSync(handle);
  fs.closeSync(handle);
  const directory = fs.openSync(run, 'r');
  fs.fsyncSync(directory);
  fs.closeSync(directory);
}
function spk(value) { return value.version.toString(16).padStart(4, '0') + value.script; }
function canonical(transaction) {
  transaction.finalize();
  return {
    version: transaction.version,
    id: transaction.id,
    inputs: transaction.inputs.map(input => ({
      previousOutpoint: {transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index},
      signatureScript: input.signatureScript ?? '',
      sequence: input.sequence.toString(),
      sigOpCount: input.sigOpCount,
      computeBudget: input.computeBudget,
    })),
    outputs: transaction.outputs.map(output => ({
      value: output.value.toString(),
      scriptPublicKey: spk(output.scriptPublicKey),
      covenant: output.covenant ? {
        authorizingInput: output.covenant.authorizingInput,
        covenantId: output.covenant.covenantId.toString(),
      } : null,
    })),
    lockTime: transaction.lockTime.toString(),
    subnetworkId: transaction.subnetworkId,
    gas: transaction.gas.toString(),
    payload: transaction.payload,
    storageMass: transaction.storageMass.toString(),
  };
}
function transaction(raw) {
  const outputs = raw.outputs.map(output => {
    const restored = {...output, value: BigInt(output.value)};
    if (output.covenant === null) delete restored.covenant;
    return restored;
  });
  const restored = new k.Transaction({
    ...raw,
    inputs: raw.inputs.map(input => ({...input, sequence: BigInt(input.sequence)})),
    outputs,
    lockTime: BigInt(raw.lockTime),
    gas: BigInt(raw.gas),
    storageMass: BigInt(raw.storageMass),
  });
  assert.deepEqual(canonical(restored), raw, 'SDK transaction roundtrip changed a field');
  return restored;
}
function entry(raw) {
  const value = raw.entry ?? raw;
  return {
    outpoint: {transactionId: value.outpoint.transactionId, index: value.outpoint.index},
    amount: value.amount.toString(),
    scriptPublicKeyHex: spk(value.scriptPublicKey),
    blockDaaScore: value.blockDaaScore.toString(),
    isCoinbase: value.isCoinbase,
    covenantId: value.covenantId?.toString() ?? null,
  };
}
function canonicalEntries(values) {
  return values.map(entry).sort((left, right) => {
    const a = `${left.outpoint.transactionId}:${left.outpoint.index}`;
    const b = `${right.outpoint.transactionId}:${right.outpoint.index}`;
    return a.localeCompare(b);
  });
}
async function connect(url) {
  const rpc = new k.RpcClient({url, networkId: 'testnet-10'});
  await rpc.connect({timeoutDuration: 15_000});
  const info = await rpc.getServerInfo();
  assert.equal(info.networkId, 'testnet-10');
  assert.equal(info.serverVersion, '2.1.0');
  assert.equal(info.isSynced, true);
  assert.equal(info.hasUtxoIndex, true);
  return {rpc, info};
}
async function observe(rpc, intent, address, expectedScript, expectedAmount) {
  for (let attempt = 0; attempt < 240; attempt++) {
    const chain = await rpc.getVirtualChainFromBlock({
      startHash: intent.before,
      includeAcceptedTransactionIds: true,
      minConfirmationCount: 10,
    });
    assert.equal(chain.removedChainBlockHashes.length, 0, 'reorg; halt and inspect');
    const accepted = chain.acceptedTransactionIds.find(item => item.acceptedTransactionIds.includes(intent.transactionId));
    const outputs = (await rpc.getUtxosByAddresses({addresses: [address]})).entries
      .map(entry)
      .filter(output => output.outpoint.transactionId === intent.transactionId
        && output.scriptPublicKeyHex === expectedScript
        && BigInt(output.amount) === expectedAmount
        && output.covenantId === null);
    if (accepted && outputs.length === 1) return {accepted, recipientUtxo: outputs[0], observedAt: new Date().toISOString()};
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('funding acceptance unresolved; do not resubmit');
}

if (action === 'prepare') {
  assert(keyFile && destination?.startsWith('kaspatest:') && /^\d+$/.test(amountText));
  assert.equal(fs.statSync(keyFile).mode & 0o077, 0, 'source key must be private');
  const keyHex = fs.readFileSync(keyFile, 'utf8').trim();
  const key = new k.PrivateKey(keyHex);
  const source = key.toKeypair().toAddress('testnet-10').toString();
  assert.notEqual(source, destination);
  const amount = BigInt(amountText);
  assert.equal(destination, trial.sponsorNative.address, 'destination must be this fresh trial sponsor');
  assert.equal(amount, 1_000_000_000n, 'reviewed sponsor funding is exactly 10 test KAS');
  const {rpc, info} = await connect(PRIMARY);
  const {rpc: witnessRpc, info: witnessInfo} = await connect(WITNESS);
  try {
    const destinationEntries = (await rpc.getUtxosByAddresses({addresses: [destination]})).entries;
    assert.equal(destinationEntries.length, 0, 'fresh sponsor already has a UTXO');
    const available = (await rpc.getUtxosByAddresses({addresses: [source]})).entries;
    const witnessDestination = (await witnessRpc.getUtxosByAddresses({addresses: [destination]})).entries;
    const witnessAvailable = (await witnessRpc.getUtxosByAddresses({addresses: [source]})).entries;
    assert.deepEqual(canonicalEntries(witnessDestination), canonicalEntries(destinationEntries),
      'routes disagree on fresh sponsor state');
    assert.deepEqual(canonicalEntries(witnessAvailable), canonicalEntries(available),
      'routes disagree on funding source UTXOs');
    const spendable = available.filter(value => {
      const normalized = entry(value);
      return !normalized.isCoinbase && normalized.covenantId === null;
    });
    assert.ok(spendable.length > 0, 'funding source has no ordinary non-coinbase UTXO');
    const generator = new k.Generator({
      entries: spendable,
      outputs: [{address: destination, amount}],
      changeAddress: source,
      priorityFee: 500_000n,
      networkId: 'testnet-10',
    });
    const pending = await generator.next();
    assert(pending, 'no funding transaction generated');
    assert.ok(!(await generator.next()), 'funding must be one transaction');
    pending.sign([key]);
    const built = pending.transaction;
    let raw = canonical(built);
    const availableMap = new Map(spendable.map(value => {
      const normalized = entry(value);
      return [`${normalized.outpoint.transactionId}:${normalized.outpoint.index}`, normalized];
    }));
    const entries = raw.inputs.map(input => availableMap.get(`${input.previousOutpoint.transactionId}:${input.previousOutpoint.index}`));
    assert(entries.every(Boolean));
    const exactNumber = value => {
      const integer = BigInt(value);
      assert(integer >= 0n && integer <= BigInt(Number.MAX_SAFE_INTEGER), 'mass value exceeds exact JS integer range');
      return Number(integer);
    };
    const masses = k.calculateStorageMass(
      'testnet-10',
      entries.map(value => exactNumber(value.amount)),
      raw.outputs.map(output => exactNumber(output.value)),
    );
    assert.notEqual(masses, undefined, 'storage mass unavailable');
    built.storageMass = masses;
    raw = canonical(built);
    const targetScript = spk(k.payToAddressScript(destination));
    const changeScript = spk(k.payToAddressScript(source));
    assert.equal(raw.outputs.filter(output => output.scriptPublicKey === targetScript && BigInt(output.value) === amount).length, 1);
    assert(raw.outputs.every(output => output.covenant === null && [targetScript, changeScript].includes(output.scriptPublicKey)));
    const total = entries.reduce((sum, value) => sum + BigInt(value.amount), 0n);
    const outputTotal = raw.outputs.reduce((sum, value) => sum + BigInt(value.value), 0n);
    const fee = total - outputTotal;
    assert(fee > 0n && fee <= 10_000_000n, 'funding fee outside 0.1 test KAS cap');
    save('funding-plan.json', {
      schema: 'KPI_FULL_DRAINAGE_SPONSOR_FUNDING_V1',
      source,
      destination,
      amountSompi: amount,
      feeSompi: fee,
      transaction: raw,
      entries,
      primaryServer: info,
      witnessServer: witnessInfo,
      broadcast: false,
    });
    console.log(stringify({prepared: true, transactionId: raw.id, amountSompi: amount, feeSompi: fee, broadcast: false}));
  } finally { await rpc.disconnect(); await witnessRpc.disconnect(); }
} else if (action === 'submit') {
  const plan = read('funding-plan.json');
  const {rpc} = await connect(PRIMARY);
  const {rpc: witnessRpc} = await connect(WITNESS);
  try {
    const available = (await rpc.getUtxosByAddresses({addresses: [plan.source]})).entries.map(entry);
    const witnessAvailable = (await witnessRpc.getUtxosByAddresses({addresses: [plan.source]})).entries.map(entry);
    assert.deepEqual(witnessAvailable.sort((a, b) => `${a.outpoint.transactionId}:${a.outpoint.index}`.localeCompare(`${b.outpoint.transactionId}:${b.outpoint.index}`)),
      available.sort((a, b) => `${a.outpoint.transactionId}:${a.outpoint.index}`.localeCompare(`${b.outpoint.transactionId}:${b.outpoint.index}`)),
      'routes disagree immediately before funding');
    for (const expected of plan.entries) {
      const actual = available.find(value => value.outpoint.transactionId === expected.outpoint.transactionId && value.outpoint.index === expected.outpoint.index);
      assert.deepEqual(actual, expected, 'funding input changed or spent');
    }
    const dag = await rpc.getBlockDagInfo();
    let before = dag.sink;
    for (let index = 0; index < 20; index++) {
      before = (await rpc.getBlock({hash: before, includeTransactions: false})).block.verboseData.selectedParentHash;
    }
    const intent = {transactionId: plan.transaction.id, before, at: new Date().toISOString(), allowOrphan: false};
    save('funding-submission-intent.json', intent);
    const response = await rpc.submitTransaction({transaction: transaction(plan.transaction), allowOrphan: false});
    assert.equal(response.transactionId, plan.transaction.id);
    save('funding-admission.json', response);
    const target = plan.transaction.outputs.find(output => output.scriptPublicKey === spk(k.payToAddressScript(plan.destination)) && output.value === String(plan.amountSompi));
    assert(target);
    const accepted = await observe(rpc, intent, plan.destination, target.scriptPublicKey, BigInt(plan.amountSompi));
    save('funding-acceptance.json', accepted);
    console.log(stringify({accepted: true, transactionId: plan.transaction.id, acceptance: accepted}));
  } finally { await rpc.disconnect(); await witnessRpc.disconnect(); }
} else {
  const plan = read('funding-plan.json');
  const local = read('funding-acceptance.json');
  const observations = [];
  for (const url of REMOTES) {
    const {rpc, info} = await connect(url);
    try {
      const outputs = (await rpc.getUtxosByAddresses({addresses: [plan.destination]})).entries.map(entry)
        .filter(value => value.outpoint.transactionId === plan.transaction.id && BigInt(value.amount) === BigInt(plan.amountSompi));
      assert.equal(outputs.length, 1, `remote ${url} missing exact sponsor UTXO`);
      observations.push({url, info, output: outputs[0]});
    } finally { await rpc.disconnect(); }
  }
  save('funding-corroboration.json', {transactionId: plan.transaction.id, local, observations});
  console.log(stringify({corroborated: true, transactionId: plan.transaction.id, endpoints: observations.map(value => value.url)}));
}

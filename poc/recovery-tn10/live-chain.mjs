#!/usr/bin/env node
// Finite TN10 JSON-RPC mutations over two independently operated TLS routes.
// Each label can be submitted once; an ambiguous response is an inspection
// boundary. The locally owned node remains an additional asynchronous witness.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as E from '../lane-completeness/integration/exact-json.mjs';

const [action, runText, label, argument] = process.argv.slice(2);
assert(['query', 'block', 'submit', 'wait'].includes(action));
assert(/^[a-z0-9-]+$/.test(label ?? ''));
const run = path.resolve(runText);
assert(fs.statSync(run).isDirectory(), 'run directory required');
assert.equal(fs.statSync(run).mode & 0o077, 0, 'run directory must be private');

function read(file) { return E.parse(fs.readFileSync(file, 'utf8')); }
function save(suffix, value) {
  const file = path.join(run, `${label}-${suffix}.json`);
  const handle = fs.openSync(file, 'wx', 0o600);
  fs.writeFileSync(handle, `${E.stringify(value, null, 2)}\n`);
  fs.fsyncSync(handle);
  fs.closeSync(handle);
  const directory = fs.openSync(run, 'r');
  fs.fsyncSync(directory);
  fs.closeSync(directory);
  return file;
}

const PRIMARY = 'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/json';
const WITNESS = 'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/json';
const records = [];
async function connect(url, role) {
  const socket = new WebSocket(url);
  const pending = new Map();
  let sequence = 0;
  socket.onmessage = event => {
    const raw = String(event.data);
    const response = E.parse(raw);
    const request = pending.get(response.id);
    if (!request) return;
    pending.delete(response.id);
    clearTimeout(request.timer);
    records.push({role, method: request.method, request: request.params, raw});
    if (response.error) request.reject(new Error(E.stringify(response.error)));
    else request.resolve(response.params);
  };
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  function call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`RPC timeout for ${role}.${method}; reconcile without resubmitting`));
      }, 60_000);
      pending.set(id, {resolve, reject, timer, method, params});
      socket.send(E.stringify({id, method, params}));
    });
  }
  return {call, close: () => socket.close()};
}
const primary = await connect(PRIMARY, 'primary');
const witness = await connect(WITNESS, 'witness');
const call = primary.call;

function canonicalUtxos(value) {
  return [...value.entries].sort((left, right) => {
    const a = `${left.outpoint.transactionId}:${left.outpoint.index}`;
    const b = `${right.outpoint.transactionId}:${right.outpoint.index}`;
    return a.localeCompare(b);
  });
}

async function context(addresses) {
  const server = await call('getServerInfo');
  assert.equal(server.networkId, 'testnet-10');
  assert.equal(server.isSynced, true);
  assert.equal(server.hasUtxoIndex, true);
  const fees = await call('getFeeEstimate');
  assert.ok(fees.estimate.priorityBucket.feerate <= 100, 'fee quote exceeds reviewed rate');
  const utxos = await call('getUtxosByAddresses', {addresses});
  const witnessServer = await witness.call('getServerInfo');
  assert.equal(witnessServer.networkId, 'testnet-10');
  assert.equal(witnessServer.isSynced, true);
  assert.equal(witnessServer.hasUtxoIndex, true);
  const witnessUtxos = await witness.call('getUtxosByAddresses', {addresses});
  assert.deepEqual(canonicalUtxos(witnessUtxos), canonicalUtxos(utxos),
    'independent TN10 routes disagree on relevant UTXOs');
  const {sink} = await call('getSink');
  let sinkBlock = await call('getBlock', {hash: sink, includeTransactions: false});
  for (let depth = 0; !sinkBlock.block.verboseData.isChainBlock && depth < 50; depth++) {
    sinkBlock = await call('getBlock', {
      hash: sinkBlock.block.verboseData.selectedParentHash,
      includeTransactions: false,
    });
  }
  assert.equal(sinkBlock.block.verboseData.isChainBlock, true, 'no stable chain block within 50 selected parents');
  return {server, witnessServer, routes: {primary: PRIMARY, witness: WITNESS}, fees, utxos, sinkBlock};
}

async function confirmed(intent) {
  for (let attempt = 0; attempt < 240; attempt++) {
    const result = await call('getVirtualChainFromBlockV2', {
      startHash: intent.before,
      dataVerbosityLevel: 'Full',
      minConfirmationCount: 10,
    });
    assert.equal(result.removedChainBlockHashes.length, 0, 'reorg; halt and inspect');
    for (const block of result.chainBlockAcceptedTransactions) {
      const transaction = block.acceptedTransactions.find(
        candidate => candidate.verboseData.transactionId === intent.transactionId,
      );
      if (transaction) {
        const accepted = {
          transactionId: intent.transactionId,
          header: block.chainBlockHeader,
          transaction,
          confirmed: 10,
          observedAt: new Date().toISOString(),
        };
        save('accepted', accepted);
        return accepted;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('acceptance unresolved; inspect intent and chain before any retry');
}

async function stableChainAnchor(startHash) {
  let start = startHash;
  for (let attempt = 0; attempt < 5; attempt++) {
    let before = start;
    for (let depth = 0; depth < 100; depth++) {
      const block = await call('getBlock', {hash: before, includeTransactions: false});
      before = block.block.verboseData.selectedParentHash;
    }
    const recheck = await call('getBlock', {hash: before, includeTransactions: false});
    if (recheck.block.verboseData.isChainBlock) return before;
    start = (await call('getSink')).sink;
  }
  throw new Error('no stable chain anchor after five deep read-only attempts');
}

let failure;
try {
  if (action === 'query') {
    const addresses = E.parse(argument);
    assert(Array.isArray(addresses) && addresses.every(value => value.startsWith('kaspatest:')));
    const snapshot = await context(addresses);
    save('snapshot', snapshot);
    console.log(E.stringify(snapshot));
  } else if (action === 'block') {
    assert(/^[0-9a-f]{64}$/.test(argument));
    const server = await call('getServerInfo');
    assert.equal(server.networkId, 'testnet-10');
    assert.equal(server.isSynced, true);
    const block = await call('getBlock', {hash: argument, includeTransactions: false});
    assert.equal(block.block.header.hash, argument);
    assert.equal(block.block.verboseData.isChainBlock, true);
    save('block', block);
    console.log(E.stringify(block));
  } else if (action === 'wait') {
    const accepted = await confirmed(read(path.resolve(argument)));
    console.log(E.stringify({accepted: true, transactionId: accepted.transactionId, block: accepted.header.hash}));
  } else {
    const envelope = read(path.resolve(argument));
    const {record, entries, qualification} = envelope;
    assert(record?.transaction && /^[0-9a-f]{64}$/.test(record.transactionId));
    assert.equal(record.transaction.inputs.length, entries.length);
    assert.equal(qualification.transactionId, record.transactionId);
    assert.equal(qualification.allInputScriptsExecuted, true);
    assert.ok(qualification.feeSompi > 0);
    const addresses = [...new Set(entries.map(entry => entry.address))];
    assert(addresses.every(value => value.startsWith('kaspatest:')));
    const fresh = await context(addresses);
    save('fresh', fresh);
    for (let index = 0; index < entries.length; index++) {
      const expected = entries[index];
      const point = record.transaction.inputs[index].previousOutpoint;
      assert.deepEqual(point, expected.outpoint);
      const actual = fresh.utxos.entries.find(
        entry => entry.outpoint.transactionId === point.transactionId && entry.outpoint.index === point.index,
      );
      assert(actual, `input ${index} absent or spent`);
      assert.deepEqual(actual, expected, `input ${index} changed`);
    }
    const before = await stableChainAnchor(fresh.sinkBlock.block.header.hash);
    const intent = {
      transactionId: record.transactionId,
      before,
      at: new Date().toISOString(),
      allowOrphan: false,
    };
    const intentPath = save('submission-intent', intent);
    const admission = await call('submitTransaction', {transaction: record.transaction, allowOrphan: false});
    assert.equal(admission.transactionId, record.transactionId);
    save('admission', admission);
    const accepted = await confirmed(read(intentPath));
    console.log(E.stringify({accepted: true, transactionId: accepted.transactionId, block: accepted.header.hash}));
  }
} catch (error) {
  failure = error;
  try { save('failure', {error: error.message, at: new Date().toISOString(), noAutomaticRetry: true}); }
  catch {}
  console.error(error.message);
  process.exitCode = 1;
} finally {
  try { save(`${action}-rpc`, records); } catch {}
  primary.close();
  witness.close();
}
if (failure) process.exitCode = 1;

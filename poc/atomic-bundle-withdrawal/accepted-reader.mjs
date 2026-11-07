#!/usr/bin/env node
// One wallet's independent TN10 read. The issuer never supplies this file.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as E from '../lane-completeness/integration/exact-json.mjs';
import {acceptedExactBundle} from './reader-core.mjs';

const [trialText, walletText, route] = process.argv.slice(2);
assert(['blue', 'green'].includes(route), 'reviewed public TN10 route required');
const trial = path.resolve(trialText);
const wallet = path.resolve(walletText);
assert(wallet.startsWith(`${trial}${path.sep}private${path.sep}wallet-`));
assert.equal(fs.statSync(wallet).mode & 0o077, 0, 'private wallet directory required');
const intent = E.parse(fs.readFileSync(path.join(trial, 'bundle-submission-intent.json'), 'utf8'));
const envelope = E.parse(fs.readFileSync(path.join(trial, 'bundle-envelope.json'), 'utf8'));
const expected = fs.readFileSync(path.join(trial, 'registration', 'bundle.json'));
assert.equal(envelope.record.transactionId, intent.transactionId);
assert.equal(envelope.record.transaction.payload, expected.toString('hex'));
const url = route === 'blue'
  ? 'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/json'
  : 'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/json';
const socket = new WebSocket(url);
const pending = new Map();
let sequence = 0;
socket.onmessage = event => {
  const response = E.parse(String(event.data));
  const p = pending.get(response.id);
  if (!p) return;
  pending.delete(response.id);
  clearTimeout(p.timer);
  response.error ? p.reject(new Error(E.stringify(response.error))) : p.resolve(response.params);
};
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
function call(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 60_000);
    pending.set(id, {resolve, reject, timer});
    socket.send(E.stringify({id, method, params}));
  });
}
try {
  const server = await call('getServerInfo');
  assert.equal(server.networkId, 'testnet-10');
  assert.equal(server.isSynced, true);
  let found = false;
  for (let attempt = 0; attempt < 240; attempt++) {
    const chain = await call('getVirtualChainFromBlockV2', {
      startHash: intent.before, dataVerbosityLevel: 'Full', minConfirmationCount: 10,
    });
    found = acceptedExactBundle(chain, intent, envelope, expected);
    if (found) break;
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  assert(found, 'ten-confirmation acceptance unresolved');
  // Create exactly once after the wallet's own route observed the accepted bytes.
  const output = path.join(wallet, 'accepted-bundle.json');
  const handle = fs.openSync(output, 'wx', 0o600);
  fs.writeFileSync(handle, expected);
  fs.fsyncSync(handle);
  fs.closeSync(handle);
  const receipt = path.join(wallet, 'accepted-bundle-receipt.json');
  fs.writeFileSync(receipt, E.stringify({route, transactionId: intent.transactionId, confirmations: 10}) + '\n', {flag: 'wx', mode: 0o600});
  console.log(E.stringify({wallet: path.basename(wallet), route, accepted: true}));
} finally {
  socket.close();
}

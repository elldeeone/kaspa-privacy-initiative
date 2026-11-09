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
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function connect() {
  const socket = new WebSocket(url);
  const pending = new Map();
  let sequence = 0;
  const failPending = error => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    pending.clear();
  };
  socket.onmessage = event => {
    const response = E.parse(String(event.data));
    const request = pending.get(response.id);
    if (!request) return;
    pending.delete(response.id);
    clearTimeout(request.timer);
    response.error
      ? request.reject(new Error(E.stringify(response.error)))
      : request.resolve(response.params);
  };
  try {
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = () => reject(new Error('public RPC connection failed'));
    });
  } catch (error) {
    socket.close();
    throw error;
  }
  socket.onerror = () => failPending(new Error('public RPC connection failed'));
  socket.onclose = () => failPending(new Error('public RPC connection closed'));
  return {
    socket,
    call(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`${method} timed out`));
        }, 60_000);
        pending.set(id, {resolve, reject, timer});
        socket.send(E.stringify({id, method, params}));
      });
    },
  };
}

let found = false;
while (!found) {
  let rpc;
  try {
    rpc = await connect();
  } catch (error) {
    console.error(`Waiting for ${route} public RPC: ${error.message}`);
    await wait(5_000);
    continue;
  }
  try {
    let server;
    try {
      server = await rpc.call('getServerInfo');
    } catch (error) {
      console.error(`Retrying ${route} public RPC: ${error.message}`);
      await wait(5_000);
      continue;
    }
    assert.equal(server.networkId, 'testnet-10');
    if (!server.isSynced) {
      console.error(`Waiting for ${route} public RPC to synchronize`);
      await wait(5_000);
      continue;
    }
    while (!found) {
      let chain;
      try {
        chain = await rpc.call('getVirtualChainFromBlockV2', {
          startHash: intent.before, dataVerbosityLevel: 'Full', minConfirmationCount: 10,
        });
      } catch (error) {
        console.error(`Retrying ${route} public RPC: ${error.message}`);
        break;
      }
      // Safety failures from the accepted-body/reorg checks remain fatal.
      found = acceptedExactBundle(chain, intent, envelope, expected);
      if (!found) await wait(500);
    }
  } finally {
    rpc.socket.close();
  }
}

// Create exactly once after the wallet's own route observed the accepted bytes.
const output = path.join(wallet, 'accepted-bundle.json');
const handle = fs.openSync(output, 'wx', 0o600);
fs.writeFileSync(handle, expected);
fs.fsyncSync(handle);
fs.closeSync(handle);
const receipt = path.join(wallet, 'accepted-bundle-receipt.json');
fs.writeFileSync(receipt, E.stringify({route, transactionId: intent.transactionId, confirmations: 10}) + '\n', {flag: 'wx', mode: 0o600});
console.log(E.stringify({wallet: path.basename(wallet), route, accepted: true}));

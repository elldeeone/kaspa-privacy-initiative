// Read-only TN10 capability probe. No wallet, signing or submission method.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import * as exact from '../lane-completeness/integration/exact-json.mjs';

const [url, output] = process.argv.slice(2);
assert(url && output, 'usage: node probe_node.mjs WS_URL NEW_OUTPUT_DIRECTORY');
const endpoint = new URL(url);
assert(['ws:', 'wss:'].includes(endpoint.protocol), 'WebSocket URL required');
assert(!endpoint.username && !endpoint.password, 'credentials in URLs are forbidden');
fs.mkdirSync(output, {mode: 0o700});
const records = []; let id = 0;
const save = (name, value) => fs.writeFileSync(`${output}/${name}`, exact.stringify(value, null, 2) + '\n', {flag: 'wx'});
const allowed = new Set(['getServerInfo', 'getInfo', 'getBlockDagInfo', 'getBlock', 'getFeeEstimate',
  'getSeqCommitLaneProof', 'getVirtualChainFromBlockV2']);
const call = (method, params = {}) => new Promise((resolve, reject) => {
  assert(allowed.has(method), 'read-only method required');
  // Older servers may close a connection on an unknown RPC operation. Isolate
  // each probe so that cannot turn later known-good calls into false failures.
  const n = ++id, ws = new WebSocket(url); let settled = false;
  const finish = (error, response) => {
    if (settled) return;
    settled = true; clearTimeout(timer); ws.close();
    if (error) {records.push({method, request: params, error: error.message}); reject(error);}
    else resolve(response);
  };
  const timer = setTimeout(() => finish(Error(`${method}: unavailable after timeout`)), 20000);
  ws.onopen = () => ws.send(exact.stringify({id: n, method, params}));
  ws.onmessage = e => {
    try {
      const raw = String(e.data), response = exact.parse(raw);
      records.push({method, request: params, raw});
      if (response.id === n) finish(null, response);
    } catch (error) {finish(error);}
  };
  ws.onerror = () => finish(Error(`${method}: WebSocket error`));
  ws.onclose = e => finish(Error(`${method}: connection closed (${e.code})`));
});
try {
  const server = await call('getServerInfo');
  save('server.json', server);
  assert(!server.error && server.params.networkId === 'testnet-10', 'TN10 only');
  assert(server.params.isSynced === true && server.params.hasUtxoIndex === true, 'synced UTXO-indexed node required');
  const dag = await call('getBlockDagInfo');
  assert(!dag.error && dag.params.network === 'testnet-10', 'TN10 DAG required');
  const hash = dag.params.sink;
  assert(typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash), 'canonical sink hash required');
  // Allow the selected chain to advance so Full can return actual accepted
  // transaction bodies rather than only an empty response at the same sink.
  await new Promise(resolve => setTimeout(resolve, 1500));
  const lane = crypto.createHash('sha256').update('KPI/P1/read-only-probe/v1').digest('hex');
  const observations = {};
  for (const [method, params] of [
    ['getInfo', {}], ['getFeeEstimate', {}], ['getBlock', {hash, includeTransactions: false}],
    ['getSeqCommitLaneProof', {blockHash: hash, laneKey: lane}],
    ['getVirtualChainFromBlockV2', {startHash: hash, dataVerbosityLevel: 'Full', minConfirmationCount: 0}],
  ]) {
    try {
      const response = await call(method, params);
      const observation = {responded: true, error: response.error ?? null};
      if (method === 'getVirtualChainFromBlockV2' && !response.error) {
        const rows = response.params.chainBlockAcceptedTransactions;
        assert(Array.isArray(rows), 'accepted transaction groups missing');
        observation.addedChainBlocks = response.params.addedChainBlockHashes.length;
        observation.acceptedGroups = rows.length;
        observation.acceptedTransactions = rows.reduce((n, row) => n + row.acceptedTransactions.length, 0);
        // Count observations only; no body/header/ordering verification claim.
      }
      observations[method] = observation;
    }
    catch (error) {observations[method] = {responded: false, error: error.message};}
  }
  const after = await call('getServerInfo');
  assert(!after.error && after.params.networkId === 'testnet-10', 'post-probe node identity unavailable');
  const result = {scope: 'READ_ONLY_SINGLE_NODE_RPC_PREFLIGHT_NOT_NATIVE_TRIAL', endpoint: url,
    observedAt: new Date().toISOString(), server: server.params, observations,
    serverAfter: after.params, nativeTransactions: 0, walletCreated: false, fundingRequiredNow: false};
  save('result.json', result);
  console.log(exact.stringify(result));
} finally {
  save('rpc-records.json', records);
}

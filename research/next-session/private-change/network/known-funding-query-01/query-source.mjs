// Root-authorized exact known-SPK query only; no signer/wallet/submit API.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
const SOURCE = '/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/private-network-recovery/fetch.mjs';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
if (sha(fs.readFileSync(SOURCE)) !== '7584d3b15fd3e4f98db2f0ce07093729dbdfded1d03d50a51b62294fd7917ffc')
  throw Error('frozen-public-SDK-loader-source');
const {loadSdk, script, integer, SDK_PINS} = await import(pathToFileURL(SOURCE));
const [inputPath, outputPath] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(inputPath)), k = loadSdk();
if (config.schema !== 'kpx3-known-public-funding-query/v1' || config.network_id !== 'testnet-10') throw Error('public-query-schema');
const expected = new Map(config.scripts.map(row => [row.script_public_key, row]));
for (const value of expected.keys()) if (!/^000020[0-9a-f]{64}ac$/.test(value)) throw Error('known-public-P2PK-only');
const addresses = [...expected.keys()].map(value => {
  const address = k.addressFromScriptPublicKey(value, 'testnet-10');
  if (!address) throw Error('known-script-address');
  try { return address.toString(); } finally { address.free(); }
});
const endpoint = 'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh';
const rpc = new k.RpcClient({url: endpoint, networkId: 'testnet-10'});
try {
  await rpc.connect({blockAsyncConnect: true, timeoutDuration: 60000, strategy: 'fallback'});
  const server = await rpc.getServerInfo(), dag = await rpc.getBlockDagInfo();
  if (server.networkId !== 'testnet-10' || dag.network !== 'testnet-10' || server.serverVersion !== '2.1.0'
      || server.isSynced !== true || server.hasUtxoIndex !== true) throw Error('selected-node-identity');
  const result = await rpc.getUtxosByAddresses({addresses});
  const entries = [], seen = new Set();
  for (const raw of result.entries) {
    const value = raw.entry ?? raw, spk = script(value.scriptPublicKey);
    if (!expected.has(spk)) throw Error('unexpected-entry-outside-known-public-scripts');
    const point = value.outpoint.toJSON ? value.outpoint.toJSON() : value.outpoint;
    if (!/^[0-9a-f]{64}$/.test(point.transactionId) || !Number.isSafeInteger(point.index) || point.index < 0) throw Error('outpoint-encoding');
    const key = point.transactionId + ':' + point.index;
    if (seen.has(key)) throw Error('duplicate-current-outpoint'); seen.add(key);
    entries.push({outpoint: point, amount_sompi: integer(value.amount).toString(), script_public_key: spk,
      block_daa_score: integer(value.blockDaaScore).toString(), is_coinbase: value.isCoinbase,
      covenant_id: value.covenantId?.toString() ?? null});
  }
  const total = entries.reduce((sum, entry) => sum + BigInt(entry.amount_sompi), 0n);
  const output = {schema: 'kpx3-known-public-funding-observation/v1', observed_at: new Date().toISOString(),
    input_file_sha256: sha(fs.readFileSync(inputPath)), source: endpoint, network: 'testnet-10',
    expected_genesis: config.expected_genesis, server, observed_sink: dag.sink,
    sdk_pins: SDK_PINS, queried_known_script_count: expected.size, entries,
    total_on_queried_known_scripts_sompi: total.toString(), target_sompi: config.target_sompi,
    single_coin_at_least_target: entries.filter(entry => BigInt(entry.amount_sompi) >= BigInt(config.target_sompi)),
    observed_total_meets_target: total >= BigInt(config.target_sompi),
    selected_validating_node_assumption: true, confirmations_and_private_control_not_verified: true,
    no_empty_wallet_or_broad_discovery_claim: true, private_material_or_faucet_or_submission_used: false,
    rpc_methods: ['getServerInfo', 'getBlockDagInfo', 'getUtxosByAddresses']};
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  process.stdout.write(JSON.stringify({status: 'KNOWN_PUBLIC_SCRIPT_QUERY_COMPLETE', scripts: expected.size,
    entries: entries.length, total_sompi: total.toString(), meets_target: output.observed_total_meets_target}) + '\n');
} finally { await rpc.disconnect(); }

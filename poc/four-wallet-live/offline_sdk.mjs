// Public offline roundtrip only. No key, signature or RPC interface.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS, loadSdk, need, verifyTransactionId} from '../four-wallet-chain/wire.mjs';
import {strictJson} from '../four-wallet-chain/json.mjs';

export function roundtrip(request, sdkDirectory) {
  need(typeof sdkDirectory === 'string' && path.isAbsolute(sdkDirectory),
    'ARGUMENT', 'explicit selected SDK directory required');
  need(Object.keys(request).sort().join(',') === 'contexts,genesis_hash_hex,network_id,schema,transaction'
    && request.schema === 'kpx6-four-wallet-public-offline-SDK/v1'
    && request.network_id === 'testnet-10' && request.genesis_hash_hex === GENESIS,
    'REQUEST', 'fixed public roundtrip request required');
  verifyTransactionId(loadSdk(sdkDirectory), request.transaction, request.contexts);
  return {schema: 'kpx6-four-wallet-public-offline-SDK-result/v1',
    transaction: request.transaction, exact_SDK_roundtrip: true,
    network_signing_or_broadcast: false};
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    need(process.argv.length === 3, 'ARGUMENT', 'one fixed staged SDK directory required');
    process.stdout.write(JSON.stringify(roundtrip(strictJson(fs.readFileSync(0)), process.argv[2])) + '\n');
  } catch {
    process.stderr.write('public offline SDK roundtrip refused\n'); process.exitCode = 2;
  }
}

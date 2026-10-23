// Public offline SDK verification; never creates an RpcClient or reads a key.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {descriptor, loadSdk, headerHash, canonicalDescriptor, canonicalTransaction,
  verifyTransactionId, sha, SDK_PINS} from './fetch.mjs';
import {strictJson, validateManifest} from './parameter_manifest.mjs';

const [descriptorPath, manifestPath, bundlePath, output] = process.argv.slice(2);
try {
  const d = descriptor(strictJson(fs.readFileSync(descriptorPath)));
  validateManifest(fs.readFileSync(manifestPath), d);
  const bundle = strictJson(fs.readFileSync(bundlePath)), k = loadSdk();
  assert.equal(bundle.schema, 'kpx3-private-network-fetch/v1');
  assert.equal(bundle.descriptor_sha256, sha(canonicalDescriptor(d)));
  assert.equal(canonicalDescriptor(bundle.descriptor), canonicalDescriptor(d));
  const headers = [bundle.coverage.anchor_header, bundle.coverage.initial_sink,
    bundle.coverage.frontier, bundle.current_view.post_query_delta.frontier,
    ...bundle.transactions.map(row => row.accepting_block_header)];
  const seen = new Map();
  for (const header of headers) {
    assert.equal(headerHash(k, header), header.hash, 'actual SDK header hash');
    const encoding = canonicalDescriptor(header);
    if (seen.has(header.hash)) assert.equal(seen.get(header.hash), encoding, 'conflicting header fields');
    seen.set(header.hash, encoding);
  }
  const ids = new Set();
  for (const row of bundle.transactions) {
    assert.deepEqual(canonicalTransaction(row.transaction), row.transaction);
    assert(!ids.has(row.transaction.id), 'duplicate selected transaction'); ids.add(row.transaction.id);
    verifyTransactionId(k, row.transaction, row.accepted_input_contexts);
  }
  const receipt = {schema: 'kpx3-public-sdk-verification/v1', descriptor_sha256: bundle.descriptor_sha256,
    canonical_bundle_sha256: sha(canonicalDescriptor(bundle)), sdk_pins: SDK_PINS,
    selected_transaction_ids: [...ids], verified_headers: [...seen.keys()],
    transaction_ids_recomputed: true, header_hashes_recomputed: true,
    chain_inclusion_or_pow_verified: false, public_parameter_blob_read: false};
  fs.writeFileSync(output, JSON.stringify(receipt) + '\n', {flag: 'wx', mode: 0o600});
  process.stdout.write(JSON.stringify({status: 'PUBLIC_SDK_CHECKS_PASS', transactions: ids.size, headers: seen.size}) + '\n');
} catch (error) {
  process.stderr.write(`public-sdk-verification:${error.message}\n`); process.exitCode = 2;
}

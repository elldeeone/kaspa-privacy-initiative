#!/usr/bin/env node
// Falsify the exact accepted-body, withholding, and reorg reader decisions
// against this trial's real confirmed bundle. No broadcast or wallet secrets.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import * as E from '../lane-completeness/integration/exact-json.mjs';
import {acceptedExactBundle} from './reader-core.mjs';

const trial = path.resolve(process.argv[2]);
const read = name => E.parse(fs.readFileSync(path.join(trial, name), 'utf8'));
const intent = read('bundle-submission-intent.json');
const envelope = read('bundle-envelope.json');
const receipt = read('bundle-accepted.json');
const bytes = fs.readFileSync(path.join(trial, 'registration/bundle.json'));
const chain = transaction => ({removedChainBlockHashes: [],
  chainBlockAcceptedTransactions: [{acceptedTransactions: [transaction]}]});
assert.equal(receipt.confirmed, 10);
assert(acceptedExactBundle(chain(receipt.transaction), intent, envelope, bytes));
assert.equal(acceptedExactBundle({removedChainBlockHashes: [],
  chainBlockAcceptedTransactions: []}, intent, envelope, bytes), false);
assert.throws(() => acceptedExactBundle({removedChainBlockHashes: ['a'.repeat(64)],
  chainBlockAcceptedTransactions: []}, intent, envelope, bytes), /reorg/);
const changed = structuredClone(receipt.transaction);
changed.payload = `${changed.payload.slice(0, -1)}${changed.payload.endsWith('0') ? '1' : '0'}`;
assert.throws(() => acceptedExactBundle(chain(changed), intent, envelope, bytes), /accepted payload differs/);
const changedOutput = structuredClone(receipt.transaction);
changedOutput.outputs[0].value = Number(changedOutput.outputs[0].value) + 1;
assert.throws(() => acceptedExactBundle(chain(changedOutput), intent, envelope, bytes), /accepted transaction body differs/);
const issuerRoute = spawnSync(process.execPath, [path.join(import.meta.dirname, 'accepted-reader.mjs'),
  trial, path.join(trial, 'private/wallet-0'), 'issuer'], {encoding: 'utf8'});
assert.notEqual(issuerRoute.status, 0);
assert.match(issuerRoute.stderr, /reviewed public TN10 route required/);
const result = {realAcceptedPass: true, withholdingRefused: true,
  reorgRefused: true, alteredPayloadRefused: true, alteredOutputRefused: true,
  issuerProvidedRouteRefused: true, forcedLiveReorgTested: false};
if (process.argv[3]) fs.writeFileSync(path.resolve(process.argv[3]), `${E.stringify(result, null, 2)}\n`,
  {flag: 'wx', mode: 0o600});
console.log(E.stringify(result));

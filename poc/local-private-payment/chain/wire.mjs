import {guardedRead} from './public.mjs';
// Adapted immutable b7b41ab0 public SDK codecs; no old financial profile is inherited.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
export const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
export const SDK_PINS = {
  'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
};
const SDK_DIRECTORY = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
export const stringify = value => JSON.stringify(value, (_, x) => typeof x === 'bigint' ? x.toString() : x);
export const sha = value => crypto.createHash('sha256').update(value).digest('hex');
export const pointKey = point => `${point.transactionId}:${point.index}`;
export class Incomplete extends Error {
  constructor(category, message) { super(message); this.category = category; }
}
export function need(ok, category, message) { if (!ok) throw new Incomplete(category, message); }
export function canonicalDescriptor(value) {
  const ordered = x => Array.isArray(x) ? x.map(ordered) : x && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map(key => [key, ordered(x[key])])) : x;
  return stringify(ordered(value));
}
export function hex(value, bytes) {
  need(typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value)
    && (bytes === undefined || value.length === bytes * 2), 'MALFORMED', 'noncanonical hex');
  return value;
}
export function integer(value, bits = 64) {
  need((typeof value === 'bigint' || typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
    || typeof value === 'number' && Number.isSafeInteger(value)), 'MALFORMED', 'integer encoding');
  const result = BigInt(value);
  need(result >= 0n && result < (1n << BigInt(bits)), 'MALFORMED', 'integer range');
  return result;
}
export function script(value) {
  const result = typeof value === 'string' ? value
    : Number(integer(value.version, 16)).toString(16).padStart(4, '0') + value.script;
  hex(result);
  need(result.startsWith('0000'), 'UNSUPPORTED_SCRIPT_VERSION', 'script version must be zero');
  return result;
}
export function point(value) {
  // Pinned SDK classes store fields behind WASM getters; their explicit
  // serializer returns the same two canonical public fields as plain RPC JSON.
  if (value && typeof value.toJSON === 'function') value = value.toJSON();
  need(value && Object.keys(value).sort().join(',') === 'index,transactionId', 'MALFORMED', 'outpoint fields');
  return {transactionId: hex(value.transactionId, 32), index: Number(integer(value.index, 32))};
}
export function loadSdk(directory = SDK_DIRECTORY) {
  for (const [name, hash] of Object.entries(SDK_PINS))
    need(sha(guardedRead(path.join(directory,name),hash)) === hash, 'SDK_IDENTITY', `SDK pin ${name}`);
  return createRequire(import.meta.url)(path.join(directory, 'kaspa.js'));
}
export function plainHeader(raw) {
  const parents = raw.parentsByLevel;
  let expanded;
  if (Array.isArray(parents)) expanded = parents;
  else if (parents && typeof parents.toExpanded === 'function') {
    try { expanded = parents.toExpanded(); } finally { parents.free(); }
  }
  need(Array.isArray(expanded) && expanded.every(Array.isArray), 'HEADER_ENCODING',
    'full expanded header parents required; lossy historical {} is not reconstructible');
  const work = typeof raw.blueWork === 'bigint' ? integer(raw.blueWork, 192)
    : typeof raw.blueWork === 'string' && /^[0-9a-f]{48}$/.test(raw.blueWork)
      ? BigInt('0x' + raw.blueWork) : null;
  need(work !== null, 'HEADER_ENCODING', 'blue work must be SDK bigint or native fixed-width hex');
  return {hash: hex(raw.hash, 32), version: Number(integer(raw.version, 16)),
    parentsByLevel: expanded.map(level => level.map(hash => hex(hash, 32))),
    hashMerkleRoot: hex(raw.hashMerkleRoot, 32), acceptedIdMerkleRoot: hex(raw.acceptedIdMerkleRoot, 32),
    utxoCommitment: hex(raw.utxoCommitment, 32), timestamp: integer(raw.timestamp).toString(),
    bits: Number(integer(raw.bits, 32)), nonce: integer(raw.nonce).toString(),
    daaScore: integer(raw.daaScore).toString(), blueScore: integer(raw.blueScore).toString(),
    blueWork: work.toString(16).padStart(48, '0'), pruningPoint: hex(raw.pruningPoint, 32)};
}
export function headerHash(k, raw) {
  const restored = plainHeader(raw);
  // Deliberately discard the RPC's cached identity before official finalize.
  restored.hash = '00'.repeat(32);
  for (const name of ['timestamp', 'nonce', 'daaScore', 'blueScore']) restored[name] = integer(raw[name]);
  restored.blueWork = BigInt('0x' + restored.blueWork);
  const header = new k.Header(restored);
  try { return header.finalize(); } finally { header.free(); }
}
export function validateHeader(k, raw, expected) {
  hex(raw.hash, 32);
  need(raw.hash === expected && headerHash(k, raw) === expected, 'HEADER', 'header hash mismatch');
  integer(raw.blueScore);
}
export function canonicalTransaction(t) {
  need(t.version === 1, 'UNSUPPORTED_TRANSACTION', 'pool transaction version must be one');
  if (t.mass !== undefined && t.storageMass !== undefined)
    need(integer(t.mass) === integer(t.storageMass), 'MALFORMED', 'mass aliases differ');
  return {version: 1, id: hex(t.verboseData?.transactionId ?? t.id, 32),
    inputs: t.inputs.map(input => {
      need(input.computeBudget !== undefined, 'MALFORMED', 'missing compute budget');
      if (input.sigOpCount !== undefined && input.sigOpCount !== null)
        need(input.sigOpCount === 0, 'MALFORMED', 'version-one sigOpCount');
      return {previousOutpoint: point(input.previousOutpoint), signatureScript: hex(input.signatureScript),
        sequence: integer(input.sequence).toString(), computeBudget: Number(integer(input.computeBudget, 16))};
    }),
    outputs: t.outputs.map(output => {
      need((output.covenant ?? null) === null, 'UNSUPPORTED_COVENANT', 'KPXA output covenant must be absent');
      return {value: integer(output.value).toString(), scriptPublicKey: script(output.scriptPublicKey), covenant: null};
    }),
    lockTime: integer(t.lockTime).toString(), subnetworkId: hex(t.subnetworkId, 20),
    gas: integer(t.gas).toString(), payload: hex(t.payload), storageMass: integer(t.storageMass ?? t.mass).toString()};
}
export function contexts(raw, transaction) {
  need(raw.inputs.length === transaction.inputs.length, 'MALFORMED', 'input context count');
  return raw.inputs.map((input, index) => {
    const entry = input.verboseData?.utxoEntry;
    need(entry && entry.isCoinbase === false && (entry.covenantId ?? null) === null,
      'INPUT_CONTEXT', 'Full populated noncoinbase input context required');
    return {outpoint: transaction.inputs[index].previousOutpoint,
      amount_sompi: integer(entry.amount).toString(), script_public_key: script(entry.scriptPublicKey),
      block_daa_score: integer(entry.blockDaaScore).toString(), is_coinbase: false, covenant_id: null};
  });
}
export function verifyTransactionId(k, transaction, entries) {
  const tx = new k.Transaction({...transaction,
    inputs: transaction.inputs.map((input, index) => ({...input, sequence: BigInt(input.sequence), sigOpCount: 0,
      utxo: {outpoint: input.previousOutpoint, amount: BigInt(entries[index].amount_sompi),
        scriptPublicKey: entries[index].script_public_key, blockDaaScore: BigInt(entries[index].block_daa_score),
        isCoinbase: false}})),
    outputs: transaction.outputs.map(output => ({value: BigInt(output.value), scriptPublicKey: output.scriptPublicKey})),
    lockTime: BigInt(transaction.lockTime), gas: BigInt(transaction.gas), storageMass: BigInt(transaction.storageMass)});
  try { tx.finalize(); assert.deepEqual(canonicalTransaction(tx), transaction, 'SDK body/ID mismatch'); }
  finally { tx.free(); }
}

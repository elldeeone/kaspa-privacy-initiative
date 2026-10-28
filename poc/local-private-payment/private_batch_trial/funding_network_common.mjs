// Explicit new-profile public network envelopes; established SDK/coinbase rules.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {strictJson, canonical} from '../chain/json.mjs';
import {canonicalTransaction, integer, point, pointKey, script} from '../chain/wire.mjs';

export {canonicalTransaction, integer, point, pointKey, script, strictJson, canonical};
export const IDS = Object.freeze({network_id:'testnet-10',
  genesis_hash_hex:'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
  domain_hex32:'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0',
  profile_id_hex32:'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700',
  pool_lineage_hex32:'d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf',
  service_policy_hex32:'ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5'});
export const SDK_PINS = Object.freeze({
  'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'});
export const NODE_PIN = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c';
export const RPCS = ['wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh'];
export const MAX = 2870000000000000000n;
export const need = (value, code) => { if (!value) throw new Error(code); };
export const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const stringify = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item);
export function exact(value, names) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...names].sort().join(','), 'NEW_FUNDING_EXACT_FIELDS');
}
export function hash(value) { need(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'NEW_FUNDING_HASH'); return value; }
export function checkedPath(value) {
  need(typeof value === 'string' && value.length && !value.split(/[\\/]/).includes('..'), 'NEW_FUNDING_PATH');
  const result = path.resolve(value); let current = result;
  for (;;) {
    if (fs.existsSync(current)) need(!fs.lstatSync(current).isSymbolicLink(), 'NEW_FUNDING_SYMLINK');
    const parent = path.dirname(current); if (parent === current) break; current = parent;
  }
  return result;
}
export function readPinned(file, expected) {
  file = checkedPath(file);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, {bigint:true});
    need(before.isFile() && before.nlink === 1n, 'NEW_FUNDING_REGULAR_SINGLE_LINK');
    const raw = fs.readFileSync(fd), after = fs.fstatSync(fd, {bigint:true});
    need(['dev','ino','size','mtimeNs','ctimeNs'].every(name => before[name] === after[name]), 'NEW_FUNDING_CHANGED_FILE');
    if (expected !== undefined) need(sha(raw) === hash(expected), 'NEW_FUNDING_PUBLIC_PIN');
    return raw;
  } finally { fs.closeSync(fd); }
}
export function loadSdk(directory='/sdk') {
  for (const [name, pin] of Object.entries(SDK_PINS)) readPinned(path.join(directory,name),pin);
  return createRequire(import.meta.url)(path.join(directory,'kaspa.js'));
}
export function identityDocument(raw) {
  const value = strictJson(raw);
  exact(value,['schema',...Object.keys(IDS),'trial_id','label','bootstrap_trial_sha256',
    'component_profile_sha256','native_tail_sha256','owners','financial_readiness']);
  need(value.schema === 'kpb-three-owner-funding-identity/v1'
    && Object.entries(IDS).every(([name, expected]) => value[name] === expected)
    && value.financial_readiness === false, 'EXPLICIT_NEW_FUNDING_IDENTITY');
  need(typeof value.trial_id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.trial_id)
    && typeof value.label === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(value.label), 'FRESH_NEW_FUNDING_TRIAL');
  for (const key of ['bootstrap_trial_sha256','component_profile_sha256','native_tail_sha256']) hash(value[key]);
  need(Array.isArray(value.owners) && value.owners.length === 3, 'THREE_NEW_FUNDING_OWNERS');
  value.owners.forEach((owner,index) => {
    exact(owner,['owner_component','funding_spk_hex36','address']);
    need(Number.isSafeInteger(owner.owner_component) && owner.owner_component === index
      && /^000020[0-9a-f]{64}ac$/.test(owner.funding_spk_hex36)
      && typeof owner.address === 'string' && owner.address.startsWith('kaspatest:'), 'NEW_OWNER_P2PK');
  });
  need(new Set(value.owners.map(owner => owner.funding_spk_hex36)).size === 3
    && new Set(value.owners.map(owner => owner.address)).size === 3, 'NEW_DISTINCT_FUNDING_OWNERS');
  return value;
}
export function checkAddresses(k,value) {
  for (const owner of value.owners) {
    const address = k.addressFromScriptPublicKey(owner.funding_spk_hex36,'testnet-10');
    try { need(address && address.toString() === owner.address,'NEW_SDK_ADDRESS_SCRIPT_BINDING'); }
    finally { address?.free(); }
  }
}
export function matureObservation(identity, component, values, virtualDaa) {
  need(Number.isSafeInteger(component) && component >= 0 && component < 3 && Array.isArray(values), 'NEW_OWN_UTXO_SCOPE');
  const owner = identity.owners[component], current = integer(virtualDaa), sources=[], seen=new Set();
  let total=0n, immature=0n;
  for (const raw of values) {
    const entry=raw.entry??raw, at=point(entry.outpoint), key=pointKey(at);
    need(!seen.has(key),'DUPLICATE_OWN_COINBASE'); seen.add(key);
    need(script(entry.scriptPublicKey) === owner.funding_spk_hex36 && (entry.covenantId??null) === null,
      'EXACT_NEW_OWNER_FUNDING_SCRIPT');
    if (entry.isCoinbase !== true) continue;
    const amount=integer(entry.amount), born=integer(entry.blockDaaScore);
    need(amount>0n && amount<=MAX,'NEW_COINBASE_AMOUNT');
    if (current < born+1000n) { immature+=amount; continue; }
    total+=amount;
    sources.push({outpoint:at,entry:{amount:amount.toString(),scriptPublicKey:owner.funding_spk_hex36,
      blockDaaScore:born.toString(),isCoinbase:true,covenantId:null}});
  }
  need(total<=MAX,'NEW_COINBASE_TOTAL_RANGE');
  sources.sort((a,b)=>a.outpoint.transactionId.localeCompare(b.outpoint.transactionId)||a.outpoint.index-b.outpoint.index);
  return {observation:{schema:'kpb-own-mature-coinbase-observation/v1',...IDS,
    trial_id:identity.trial_id,owner_component:component,funding_script_public_key:owner.funding_spk_hex36,
    virtual_daa_score:current.toString(),sources},total,immature};
}
export function makeTransaction(k,body,contexts) {
  need(body.inputs.length === contexts.length,'NEW_COMPLETE_INPUT_CONTEXTS');
  const tx=new k.Transaction({...body,inputs:body.inputs.map((input,index)=>({...input,
    sequence:integer(input.sequence),sigOpCount:0,utxo:{outpoint:input.previousOutpoint,
      amount:integer(contexts[index].amount_sompi),scriptPublicKey:contexts[index].script_public_key,
      blockDaaScore:integer(contexts[index].block_daa_score),isCoinbase:contexts[index].is_coinbase}})),
    outputs:body.outputs.map(output=>({value:integer(output.value),scriptPublicKey:output.scriptPublicKey})),
    lockTime:integer(body.lockTime),gas:integer(body.gas),storageMass:integer(body.storageMass)});
  try {
    tx.finalize(); assert.deepEqual(canonicalTransaction(tx),body);
    const restored=k.Transaction.deserializeFromSafeJSON(tx.serializeToSafeJSON());
    try {restored.finalize();assert.deepEqual(canonicalTransaction(restored),body);} finally {restored.free();}
    return tx;
  }
  catch (error) { tx.free(); throw error; }
}
export function durable(file,value) {
  file=checkedPath(file);
  const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
  try { fs.writeFileSync(fd,stringify(value)+'\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const directory=fs.openSync(path.dirname(file),fs.constants.O_RDONLY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
export function directory(value) {
  value=checkedPath(value);
  if (!fs.existsSync(value)) {
    directory(path.dirname(value)); fs.mkdirSync(value,{mode:0o700});
    const fd=fs.openSync(path.dirname(value),fs.constants.O_RDONLY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  need(fs.lstatSync(value).isDirectory(),'NEW_REGISTRY_DIRECTORY'); return value;
}
export function reservePhase(root,identity,stage,record) {
  need(/^(mine-[012]|consolidate-[012]|genesis)$/.test(stage),'NEW_FIXED_NETWORK_STAGE');
  root=directory(root);
  const trial=directory(path.join(root,'trials',identity.trial_id));
  durable(path.join(trial,stage+'.json'),{schema:'kpb-consumed-public-network-phase/v1',...IDS,
    trial_id:identity.trial_id,stage,...record,automatic_resubmission_permitted:false});
  if (record.transaction_id) {
    hash(record.transaction_id);
    const txs=directory(path.join(root,'transactions'));
    durable(path.join(txs,record.transaction_id+'.json'),{trial_id:identity.trial_id,stage,...record,
      automatic_resubmission_permitted:false});
  }
  return trial;
}

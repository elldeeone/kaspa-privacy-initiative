import {guardedRead} from './public.mjs';
// ADR0066 public GN3 selection. External whole-file SHA is the caller's authority.
import fs from 'node:fs';
import path from 'node:path';
import {canonical, strictJson} from './json.mjs';
import {GENESIS, hex, need, point, sha} from './wire.mjs';

export const CHILD_DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c';
export const DESCRIPTOR_FIELDS = ['schema','network_id','genesis_hash_hex',
  'financial_profile_sha256','trial_id','founding_outpoint','birth_start_hash',
  'initial_redeem_hex','initial_redeem_sha256'];

export function exact(value, names, code) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...names].sort().join(','), code,
    'exact public fields required');
}

export function checkedPath(value) {
  need(typeof value === 'string' && value.length > 0 && !value.split(/[\\/]/).includes('..'),
    'PATH', 'canonical public path required');
  const resolved=path.resolve(value);
  let current=resolved;
  for (;;) {
    if(fs.existsSync(current))need(!fs.lstatSync(current).isSymbolicLink(),'PATH','symlink path');
    const parent=path.dirname(current);if(parent===current)break;current=parent;
  }
  return resolved;
}

export function readPublic(file,expected) {
  hex(expected,32);return guardedRead(checkedPath(file),expected);
}

// The profile parameter is the exact bootstrap selector; its pinned financial
// profile identity remains distinct from this selector file's SHA.
export function profile(raw, expected) {
  hex(expected,32);need(sha(raw)===expected,'PROFILE','external GN3 selection SHA differs');
  const value=strictJson(raw);
  exact(value,['schema','network_id','genesis_hash_hex','domain_hex32','state_magic_hex8',
    'financial_profile_sha256','native_tail_hex','native_tail_sha256','output_relation','output_vk_hex328','initial_cv_hex64'],'PROFILE');
  need(value.schema==='kpxa-GN3-selection/v1'&&value.network_id==='testnet-10'
    &&value.genesis_hash_hex===GENESIS&&value.domain_hex32===CHILD_DOMAIN
    &&value.state_magic_hex8===Buffer.from('KPXAST01').toString('hex'),
    'PROFILE','selected new testnet lifecycle identity required');
  hex(value.financial_profile_sha256,32);hex(value.native_tail_hex);hex(value.native_tail_sha256,32);
  need(value.native_tail_hex.length>0&&sha(Buffer.from(value.native_tail_hex,'hex'))===value.native_tail_sha256,
    'PROFILE','selected native policy tail differs');
  return value;
}

export function descriptor(raw,expected,selected,_selectionSha) {
  hex(expected,32);need(sha(raw)===expected,'DESCRIPTOR','external descriptor SHA differs');
  const value=strictJson(raw);exact(value,DESCRIPTOR_FIELDS,'DESCRIPTOR');
  need(value.schema==='kpxa-gn3-network-descriptor/v1'&&value.network_id==='testnet-10'
    &&value.genesis_hash_hex===GENESIS
    &&value.financial_profile_sha256===selected.financial_profile_sha256,
    'DESCRIPTOR','selected financial identity required');
  need(typeof value.trial_id==='string'
    &&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.trial_id),
    'DESCRIPTOR','canonical fresh trial UUID required');
  hex(value.birth_start_hash,32);need(value.birth_start_hash!=='00'.repeat(32),'DESCRIPTOR','real birth anchor required');
  const at=point(value.founding_outpoint);need(at.index===0&&at.transactionId!=='00'.repeat(32),
    'DESCRIPTOR','founding output zero required');
  hex(value.initial_redeem_hex);hex(value.initial_redeem_sha256,32);
  const redeem=Buffer.from(value.initial_redeem_hex,'hex');
  need(redeem.length>114&&sha(redeem)===value.initial_redeem_sha256
    &&redeem.subarray(0,10).toString('hex')==='4c704b50584153543031'
    &&redeem.subarray(10,42).toString('hex')===CHILD_DOMAIN
    &&redeem.readUInt32LE(74)===3&&redeem.readUInt32LE(110)===1
    &&redeem.subarray(114).toString('hex')===selected.native_tail_hex,
    'DESCRIPTOR','selected exact initial state and immutable tail required');
  return value;
}

export {canonical,strictJson};

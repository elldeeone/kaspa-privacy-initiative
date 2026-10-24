// ADR0060 public identity parsing. Profile authority is an external raw SHA.
import fs from 'node:fs';
import path from 'node:path';
import {canonical, strictJson} from './json.mjs';
import {GENESIS, hex, integer, need, point, sha} from './wire.mjs';

export const PROFILE_ID = '68312927-f203-4317-9816-c47c020eed16';
export const CHILD_DOMAIN = '2630ed4a338afa60d3e1747a0d8875ba05f4b6694eefc345a977def800c4b89e';
export const WRAPPER_DOMAIN = 'de8ccd620d2957ec9df7ddc45c5acb0222322a4539aa7f2437cc9effccc52734';
export const DESCRIPTOR_FIELDS = ['schema', 'network_id', 'genesis_hash_hex',
  'financial_profile_sha256', 'trial_id', 'founding_outpoint', 'birth_start_hash',
  'initial_redeem_hex', 'initial_redeem_sha256'];

export function exact(value, fields, code) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(','), code, 'exact fields required');
}
function small(value, positive = false, bits = 53) {
  need(typeof value === 'number' && Number.isSafeInteger(value)
    && (!positive || value > 0), 'PROFILE', 'safe integer metadata required');
  return integer(value, bits);
}
export function checkedPath(value) {
  need(typeof value === 'string' && value.length > 0 && !value.split(/[\\/]/).includes('..'),
    'PATH', 'parent traversal is not permitted');
  const resolved = path.resolve(value);
  let current = resolved;
  for (;;) {
    if (fs.existsSync(current)) need(!fs.lstatSync(current).isSymbolicLink(), 'PATH', 'symlink path');
    const parent = path.dirname(current); if (parent === current) break; current = parent;
  }
  return resolved;
}
export function readPublic(file, expected) {
  hex(expected, 32);
  const resolved = checkedPath(file), before = fs.statSync(resolved);
  need(before.isFile(), 'PATH', 'regular public file required');
  const raw = fs.readFileSync(resolved), after = fs.statSync(resolved);
  need(before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs,
    'SOURCE_CHANGED', 'public file changed while reading');
  need(sha(raw) === expected, 'SOURCE_IDENTITY', 'external whole-file SHA mismatch');
  return raw;
}
export function profile(raw, expected) {
  hex(expected, 32); need(sha(raw) === expected, 'PROFILE', 'external profile SHA mismatch');
  const value = strictJson(raw);
  exact(value, ['schema', 'financial_profile_id', 'classification', 'network_id',
    'genesis_hash_hex', 'child_domain_hex32', 'wrapper_domain_hex32', 'compact',
    'settlement', 'W', 'private', 'executables'], 'PROFILE');
  need(value.schema === 'kpx6-four-wallet-financial-profile/v1'
    && value.financial_profile_id === PROFILE_ID
    && value.classification === 'TESTNET_REHEARSAL_ONLY_ADR0060'
    && value.network_id === 'testnet-10' && value.genesis_hash_hex === GENESIS
    && value.child_domain_hex32 === CHILD_DOMAIN
    && value.wrapper_domain_hex32 === WRAPPER_DOMAIN, 'PROFILE', 'selected financial identity required');
  exact(value.compact, ['role', 'output_arity', 'parameter_manifest_sha256', 'vk_hex328',
    'vk_sha256', 'pk_sha256', 'pk_bytes', 'compiled_build_identity_sha256'], 'PROFILE');
  need(value.compact.role === 'compact2' && value.compact.output_arity === 2,
    'PROFILE', 'selected compact role required');
  hex(value.compact.vk_hex328, 328);
  for (const key of ['parameter_manifest_sha256', 'vk_sha256', 'pk_sha256', 'compiled_build_identity_sha256'])
    hex(value.compact[key], 32);
  need(sha(Buffer.from(value.compact.vk_hex328, 'hex')) === value.compact.vk_sha256,
    'PROFILE', 'VK hash mismatch');
  small(value.compact.pk_bytes, true);
  exact(value.settlement, ['child_profile_sha256', 'child_template_tail_hex',
    'child_template_tail_sha256', 'image_id_hex32', 'program_sha256', 'child_count',
    'child_mode', 'journal_bytes', 'payload_bytes', 'aggregate_budget'], 'PROFILE');
  for (const key of ['child_profile_sha256', 'child_template_tail_sha256', 'image_id_hex32', 'program_sha256'])
    hex(value.settlement[key], 32);
  hex(value.settlement.child_template_tail_hex);
  need(sha(Buffer.from(value.settlement.child_template_tail_hex, 'hex'))
    === value.settlement.child_template_tail_sha256, 'PROFILE', 'virtual tail hash mismatch');
  need(value.settlement.child_count === 2 && value.settlement.child_mode === 2
    && value.settlement.journal_bytes === 424 && value.settlement.payload_bytes === 8108
    && value.settlement.aggregate_budget === 1600, 'PROFILE', 'exact two-child format required');
  exact(value.W, ['immutable_tail_hex', 'immutable_tail_sha256'], 'PROFILE');
  hex(value.W.immutable_tail_hex); hex(value.W.immutable_tail_sha256, 32);
  need(value.W.immutable_tail_hex.length > 0
    && sha(Buffer.from(value.W.immutable_tail_hex, 'hex')) === value.W.immutable_tail_sha256,
    'PROFILE', 'actual W tail hash mismatch');
  const metadata=Buffer.concat([Buffer.from('7520','hex'),Buffer.from(value.wrapper_domain_hex32,'hex'),
    Buffer.from('7520','hex'),Buffer.from(value.settlement.child_template_tail_sha256,'hex'),
    Buffer.from('7520','hex'),Buffer.from(value.settlement.image_id_hex32,'hex'),
    Buffer.from('75084b5058355753303175','hex')]);
  const actualTail=Buffer.from(value.W.immutable_tail_hex,'hex');
  need(actualTail.length>113&&actualTail.length<=65535-114&&actualTail.subarray(0,113).equals(metadata),
    'PROFILE','actual W metadata/domain/template/image/kind differs');
  const vk=Buffer.from(value.compact.vk_hex328,'hex'),virtualTail=Buffer.from(value.settlement.child_template_tail_hex,'hex');
  const count=(hay,needle)=>{let result=0,at=0;while((at=hay.indexOf(needle,at))>=0){result++;at++;}return result;};
  need(!vk.equals(Buffer.alloc(328))&&virtualTail.length<=65535-114
    &&count(virtualTail,vk)===1&&count(virtualTail,Buffer.alloc(328))===1,
    'PROFILE','selected compact VK/unselected wide sentinel differs');
  exact(value.private, ['budget', 'complete_input_bound_units', 'bound_result_sha256'], 'PROFILE');
  need(value.private.budget===1500,'PROFILE','selected private budget required');
  small(value.private.budget, true, 16); small(value.private.complete_input_bound_units, true);
  hex(value.private.bound_result_sha256, 32);
  need(value.private.complete_input_bound_units <= value.private.budget * 10000 + 9999,
    'PROFILE', 'private bound exceeds selected allowance');
  exact(value.executables, ['prover', 'w-codec', 'native-validator', 'node', 'crypto'], 'PROFILE');
  for (const [role,entry] of Object.entries(value.executables)) {
    exact(entry, ['basename', 'bytes', 'sha256'], 'PROFILE');
    need(entry.basename===role,
      'PROFILE', 'plain selected executable basename required');
    small(entry.bytes, true); hex(entry.sha256, 32);
  }
  return value;
}
export function descriptor(raw, expected, selected, selectedSha) {
  hex(expected, 32); need(sha(raw) === expected, 'DESCRIPTOR', 'external descriptor SHA mismatch');
  const value = strictJson(raw); exact(value, DESCRIPTOR_FIELDS, 'DESCRIPTOR');
  need(value.schema === 'kpx5-gn2-network-descriptor/v1' && value.network_id === 'testnet-10'
    && value.genesis_hash_hex === GENESIS && value.financial_profile_sha256 === selectedSha,
    'DESCRIPTOR', 'selected GN2 financial profile required');
  need(typeof value.trial_id === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.trial_id),
    'DESCRIPTOR', 'canonical trial UUID required');
  hex(value.birth_start_hash, 32); need(value.birth_start_hash !== '00'.repeat(32),
    'DESCRIPTOR', 'real recent birth anchor required');
  const at = point(value.founding_outpoint);
  need(at.index === 0 && at.transactionId !== '00'.repeat(32), 'DESCRIPTOR', 'actual founding output zero required');
  hex(value.initial_redeem_hex); hex(value.initial_redeem_sha256, 32);
  const redeem = Buffer.from(value.initial_redeem_hex, 'hex');
  need(redeem.length > 114 && sha(redeem) === value.initial_redeem_sha256
    && redeem.subarray(0, 10).toString('hex') === '4c704b50583253543031'
    && redeem.subarray(10, 42).toString('hex') === selected.child_domain_hex32
    && redeem.readUInt32LE(74) === 2 && redeem.readUInt32LE(110) === 1
    && redeem.subarray(114).toString('hex') === selected.W.immutable_tail_hex,
    'DESCRIPTOR', 'selected W initial prefix/tail required');
  return value;
}
export {canonical, strictJson};

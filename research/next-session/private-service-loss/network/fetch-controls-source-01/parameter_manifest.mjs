// Small public identity only. Never opens or locates the public parameter blob.
import crypto from 'node:crypto';
const hash = raw => crypto.createHash('sha256').update(raw).digest('hex');
const need = (ok, message) => { if (!ok) throw new Error(`public-manifest:${message}`); };
export function canonical(value) {
  const sort = x => Array.isArray(x) ? x.map(sort) : x && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sort(x[k])])) : x;
  return JSON.stringify(sort(value));
}
export function strictJson(raw) {
  // JSON.parse alone silently accepts duplicate names. Tokenize names before
  // parsing so every object, including nested parameter identities, is strict.
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : raw;
  let at = 0;
  const space = () => { while (/[ \r\n\t]/.test(text[at] ?? '\0')) at++; };
  function string() {
    space(); const match = /^"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(at));
    need(match, 'json-string'); at += match[0].length; return JSON.parse(match[0]);
  }
  function value() {
    space();
    if (text[at] === '{') {
      at++; space(); const seen = new Set(); if (text[at] === '}') { at++; return; }
      for (;;) {
        const key = string(); need(!seen.has(key), 'duplicate-field'); seen.add(key); space();
        need(text[at++] === ':', 'json-colon'); value(); space();
        const end = text[at++]; if (end === '}') return; need(end === ',', 'json-object');
      }
    }
    if (text[at] === '[') {
      at++; space(); if (text[at] === ']') { at++; return; }
      for (;;) { value(); space(); const end = text[at++]; if (end === ']') return; need(end === ',', 'json-array'); }
    }
    if (text[at] === '"') { string(); return; }
    const match = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    need(match, 'json-value'); at += match[0].length;
  }
  value(); space(); need(at === text.length, 'json-trailing'); return JSON.parse(text);
}
const exact = (x, names) => need(x && typeof x === 'object' && !Array.isArray(x)
  && Object.keys(x).sort().join(',') === [...names].sort().join(','), 'fields');
const hex = (x, bytes) => need(typeof x === 'string' && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(x), 'hex');
const positive = x => need(Number.isSafeInteger(x) && x > 0, 'positive-integer');
export function validateManifest(raw, descriptor) {
  const value = strictJson(raw), bytes = Buffer.from(raw);
  need(bytes.equals(Buffer.from(canonical(value))), 'canonical-bytes-no-newline');
  need(hash(bytes) === descriptor.public_params_manifest_sha256, 'descriptor-digest');
  exact(value, ['schema', 'trial_id', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'format', 'pk_bytes', 'pk_sha256',
    'vk_hex328', 'vk_sha256', 'core_source_identity', 'compiled_build_identity_sha256', 'constraint_shape', 'queries', 'setup_provenance']);
  need(value.schema === 'kpx3-public-proving-parameters/v1' && value.format === 'arkworks0.6-bn254-uncompressed', 'schema-format');
  need(typeof value.trial_id === 'string' && value.trial_id.length > 0, 'trial-id');
  for (const key of ['network_id', 'genesis_hash_hex', 'domain_hex32', 'vk_hex328'])
    need(value[key] === descriptor[key], `descriptor-${key}`);
  hex(value.genesis_hash_hex, 32); hex(value.domain_hex32, 32); hex(value.vk_hex328, 328);
  hex(value.pk_sha256, 32); hex(value.vk_sha256, 32); hex(value.compiled_build_identity_sha256, 32);
  need(hash(Buffer.from(value.vk_hex328, 'hex')) === value.vk_sha256, 'vk-digest'); positive(value.pk_bytes);
  exact(value.core_source_identity, ['lib_rs_sha256', 'circuit_rs_sha256', 'exact_sha256_rs_sha256',
    'request_rs_sha256', 'parameters_rs_sha256', 'main_rs_sha256', 'setup_rs_sha256', 'build_rs_sha256']);
  for (const x of Object.values(value.core_source_identity)) hex(x, 32);
  exact(value.constraint_shape, ['constraints', 'witness_variables', 'instances_including_one']);
  exact(value.queries, ['a', 'b_g1', 'b_g2', 'l', 'h', 'instances_including_one']);
  for (const x of [...Object.values(value.constraint_shape), ...Object.values(value.queries)]) positive(x);
  need(value.constraint_shape.instances_including_one === 3 && value.queries.instances_including_one === 3, 'instances');
  exact(value.setup_provenance, ['executable_sha256', 'source_freeze_sha256', 'public_setup_report_sha256']);
  for (const x of Object.values(value.setup_provenance)) hex(x, 32);
  // These are authenticated manifest claims. Actual PK query lengths/VK/full
  // bytes are checked by the separate cold loader before any private witness.
  return value;
}

// SOURCE PREPARATION ONLY: not imported, syntax-checked, built or executed.
// Buffer-only format bridge. No path API, file I/O, generator, predicate or proof.
// Callers admit every input body through unchanged helper09 before this module.
import { createHash } from 'node:crypto';

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const PUBLIC_NAMES = Object.freeze([
  'main.digestLimbs[0]', 'main.digestLimbs[1]',
  ...Array.from({ length: 64 }, (_, i) => `main.ownerKeyBytes[${i}]`),
]);
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const HEADER_FIELDS = ['nVars', 'nOutputs', 'nPubInputs', 'nPrvInputs'];
const PREPARED = new WeakMap(); // component state cannot be supplied/altered by a caller.

export class BridgeRefusal extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.name = 'BridgeRefusal'; this.code = code;
    this.kind = 'FORMAT_OR_INTERFACE_REFUSAL_NOT_R1CS_UNSAT';
  }
}
function need(ok, code, detail) { if (!ok) throw new BridgeRefusal(code, detail); }
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function json(value) {
  if (Array.isArray(value)) return `[${value.map(json).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${json(value[k])}`).join(',')}}`;
  }
  need(value !== undefined && typeof value !== 'bigint', 'JSON_TYPE', 'use explicit decimal strings');
  return JSON.stringify(value);
}
function artifact(value) {
  const bytes = Buffer.from(`${json(value)}\n`, 'utf8');
  return Object.freeze({ bytes, byteLength: bytes.length, sha256: sha(bytes) });
}
function admitted(value, pin, label) {
  need(value instanceof Uint8Array, 'BUFFER_ONLY', label);
  need(pin && /^[0-9a-f]{64}$/.test(pin.sha256) && Number.isSafeInteger(pin.byteLength), 'PIN_REQUIRED', label);
  const b = Buffer.from(value); // private snapshot; no later caller mutation.
  need(b.length === pin.byteLength && sha(b) === pin.sha256, 'BODY_PIN', label);
  return b;
}
function identity(pin) { return { sha256: pin.sha256, byteLength: pin.byteLength }; }
async function libraryCall(fn, label) {
  try { return await fn(); }
  catch (cause) {
    const e = new BridgeRefusal('LIBRARY_REFUSAL', label);
    e.cause = cause; throw e; // preserve original error; never substitute a witness.
  }
}
function cursor(b, label) {
  let p = 0;
  function take(n) {
    need(Number.isSafeInteger(n) && n >= 0 && n <= b.length - p, 'TRUNCATION', label);
    const q = b.subarray(p, p + n); p += n; return q;
  }
  return {
    take, u32: () => take(4).readUInt32LE(0), u64: () => take(8).readBigUInt64LE(0),
    done: () => need(p === b.length, 'SECTION_LENGTH', label),
    remaining: () => b.length - p,
  };
}
function uintLE(b) {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}
function rawFr(c, label) {
  const n = uintLE(c.take(32));
  need(n < FIELD, 'NONCANONICAL_FIELD', label); // never reduce malformed input.
  return n.toString();
}
function sections(b, magic, version, ids) {
  const c = cursor(b, magic);
  need(c.take(4).equals(Buffer.from(magic, 'ascii')), 'MAGIC', magic);
  need(c.u32() === version, 'EXACT_VERSION', magic);
  need(c.u32() === ids.length, 'SECTION_COUNT', magic);
  const out = new Map();
  for (let i = 0; i < ids.length; i++) {
    const id = c.u32(), len = c.u64();
    need(ids.includes(id), 'UNSUPPORTED_SECTION', `${magic}/${id}; custom/unknown predicates prohibited`);
    need(!out.has(id), 'DUPLICATE_SECTION', `${magic}/${id}`);
    need(len <= MAX_SAFE, 'UNSUPPORTED_U64_LENGTH', magic);
    out.set(id, c.take(Number(len)));
  }
  c.done();
  need(ids.every(id => out.has(id)), 'MISSING_SECTION', magic);
  return out;
}
function preflightR1cs(b) {
  const s = sections(b, 'r1cs', 1, [1, 2, 3]);
  const c = cursor(s.get(1), 'r1cs/header');
  need(c.u32() === 32 && uintLE(c.take(32)) === FIELD, 'FIELD_HEADER', 'r1cs');
  const h = {};
  for (const k of HEADER_FIELDS) h[k] = c.u32();
  const labels = c.u64(); h.nLabels = labels.toString(); h.nConstraints = c.u32(); c.done();
  need(h.nOutputs === 0 && h.nPubInputs === 66 && h.nVars >= 67, 'PUBLIC_PREFIX', 'ONE+66 public inputs; no outputs');
  need(h.nConstraints > 0, 'EMPTY_RELATION', 'a signature predicate must contain actual rows');
  // The pinned library uses JS Numbers for uint64 labels: refuse rather than round.
  need(labels <= MAX_SAFE, 'UNSUPPORTED_U64_LABELS', 'r1csfile Number boundary');
  need(s.get(3).length === h.nVars * 8, 'MAP_LENGTH', 'wire-to-label map');
  const mc = cursor(s.get(3), 'r1cs/map'), map = [], seenLabels = new Set();
  for (let i = 0; i < h.nVars; i++) {
    const label = mc.u64();
    need(label < labels && label <= MAX_SAFE, 'LABEL_RANGE', `wire ${i}`);
    need(!seenLabels.has(label.toString()), 'DUPLICATE_LABEL', `wire ${i}`);
    seenLabels.add(label.toString()); map.push(label.toString());
  }
  mc.done(); need(map[0] === '0', 'ONE_LABEL', 'wire0 must retain label0');
  const rc = cursor(s.get(2), 'r1cs/constraints'), rows = [];
  need(h.nConstraints * 12 <= rc.remaining(), 'ROW_LENGTH', 'at least three LC counts per row');
  for (let r = 0; r < h.nConstraints; r++) {
    const row = [];
    for (let k = 0; k < 3; k++) {
      const n = rc.u32(), lc = [], used = new Set();
      need(n * 36 <= rc.remaining(), 'TERM_LENGTH', `row ${r}/${k}`);
      for (let j = 0; j < n; j++) {
        const wire = rc.u32();
        need(wire < h.nVars, 'WIRE_RANGE', `row ${r}/${k}`);
        need(!used.has(wire), 'DUPLICATE_TERM', `row ${r}/${k}/wire ${wire}`);
        used.add(wire); lc.push([wire, rawFr(rc, `row ${r}/${k}/wire ${wire}`)]);
      }
      row.push(lc);
    }
    rows.push(row);
  }
  rc.done();
  return { h, rows, map };
}
function preflightWitness(b, nVars) {
  const s = sections(b, 'wtns', 2, [1, 2]), c = cursor(s.get(1), 'wtns/header');
  need(c.u32() === 32 && uintLE(c.take(32)) === FIELD, 'FIELD_HEADER', 'wtns');
  need(c.u32() === nVars, 'WITNESS_COUNT', 'complete nVars including all auxiliaries'); c.done();
  need(s.get(2).length === nVars * 32, 'WITNESS_LENGTH', 'full canonical vector');
  const v = cursor(s.get(2), 'wtns/values'), values = [];
  for (let i = 0; i < nVars; i++) values.push(rawFr(v, `witness ${i}`));
  v.done(); need(values[0] === '1', 'ONE_ASSIGNMENT', 'raw integer ONE, not reduced equivalence');
  return values;
}
function publicPermutation(sym, raw) {
  need(sym.every(x => x === 10 || (x >= 32 && x <= 126)), 'UNSUPPORTED_SYM_ENCODING', 'ASCII LF only');
  const lines = sym.toString('ascii').split('\n');
  if (lines.at(-1) === '') lines.pop();
  const named = new Map(), physical = new Set(), ids = new Set();
  for (const line of lines) {
    const v = line.split(',');
    need(v.length === 4 && /^(0|[1-9][0-9]*)$/.test(v[0]) && /^(0|[1-9][0-9]*)$/.test(v[2]), 'SYM_RECORD', line);
    need(v[1] === '-1' || /^(0|[1-9][0-9]*)$/.test(v[1]), 'SYM_WIRE', line);
    const label = BigInt(v[0]), wire = BigInt(v[1]);
    need(label < BigInt(raw.h.nLabels) && !ids.has(v[0]) && v[3].length > 0 && !named.has(v[3]), 'SYM_DUPLICATE_OR_LABEL', line);
    ids.add(v[0]); named.set(v[3], wire);
    if (wire !== -1n) {
      need(wire > 0n && wire < BigInt(raw.h.nVars), 'SYM_WIRE_RANGE', line);
      const w = Number(wire);
      need(!physical.has(w) && raw.map[w] === v[0], 'SYM_MAP_MISMATCH', line);
      physical.add(w);
    }
  }
  need(physical.size === raw.h.nVars - 1, 'SYM_FULL_COVERAGE', 'every nonzero physical wire once');
  const rawToCanonical = Array.from({ length: raw.h.nVars }, (_, i) => i);
  const canonicalToRaw = rawToCanonical.slice(), publicMap = [], selected = new Set();
  for (let i = 0; i < PUBLIC_NAMES.length; i++) {
    const name = PUBLIC_NAMES[i], w = named.get(name);
    need(w !== undefined && w >= 1n && w <= 66n, 'SELECTED_PUBLIC_NAME', name);
    const r = Number(w), canonical = i + 1;
    need(!selected.has(r), 'SELECTED_PUBLIC_BIJECTION', name);
    selected.add(r); rawToCanonical[r] = canonical; canonicalToRaw[canonical] = r;
    publicMap.push({ name, raw: r, canonical });
  }
  need(selected.size === 66, 'SELECTED_PUBLIC_COVERAGE', 'precisely raw wires1..66');
  for (let i = 0; i < raw.h.nVars; i++) {
    need(canonicalToRaw[rawToCanonical[i]] === i && rawToCanonical[canonicalToRaw[i]] === i, 'PERMUTATION_INVERSE', `${i}`);
    need(i < 67 || rawToCanonical[i] === i, 'PRIVATE_SUFFIX_CHANGED', `${i}`);
  }
  need(rawToCanonical[0] === 0, 'ONE_MAP', 'ONE0 fixed');
  return { rawToCanonical, canonicalToRaw, publicMap };
}
function libraryParity(lib, F, raw) {
  need(lib.F === F && !lib.useCustomGates && lib.n8 === 32 && lib.prime === FIELD, 'LIBRARY_FIELD', 'explicit pure-BigInt F1Field');
  for (const k of [...HEADER_FIELDS, 'nConstraints']) need(lib[k] === raw.h[k], 'LIBRARY_HEADER', k);
  need(BigInt(lib.nLabels).toString() === raw.h.nLabels, 'LIBRARY_LABEL_COUNT', 'exact safe integer');
  need(lib.map.length === raw.map.length && lib.constraints.length === raw.rows.length, 'LIBRARY_SHAPE', 'map/rows');
  for (let i = 0; i < raw.map.length; i++) need(BigInt(lib.map[i]).toString() === raw.map[i], 'LIBRARY_MAP', `${i}`);
  for (let r = 0; r < raw.rows.length; r++) {
    need(lib.constraints[r].length === 3, 'LIBRARY_ROW', `${r}`);
    for (let k = 0; k < 3; k++) {
      const lc = lib.constraints[r][k], terms = raw.rows[r][k];
      need(Object.keys(lc).length === terms.length, 'LIBRARY_TERMS', `${r}/${k}`);
      for (const [w, v] of terms) {
        need(Object.hasOwn(lc, w) && typeof lc[w] === 'bigint' && lc[w].toString() === v, 'LIBRARY_COEFFICIENT', `${r}/${k}/${w}`);
      }
    }
  }
}

// deps must be authenticated, selected existing APIs, injected by reviewed runner:
// r1csfile0.0.48 readR1cs; its ffjavascript0.3.0 F1Field.
// No bare dependency import, path input, dynamic resolution, downloads or curve setup.
export async function prepareSignatureMatrix(input, deps) {
  need(input && input.pins && deps, 'INPUT_SHAPE', 'matrix bodies/pins and selected APIs required');
  const ordinary = admitted(input.ordinaryR1cs, input.pins.ordinaryR1cs, 'ordinary R1CS');
  const cpp0 = admitted(input.cpp0R1cs, input.pins.cpp0R1cs, 'CPP0 R1CS');
  const sym = admitted(input.symBytes, input.pins.symBytes, 'ordinary sym');
  need(ordinary.equals(cpp0), 'ORDINARY_CPP0_BYTE_IDENTITY', 'before any common normalization');
  const raw = preflightR1cs(ordinary), permutation = publicPermutation(sym, raw);
  need(typeof deps.readR1cs === 'function' && typeof deps.F1Field === 'function', 'DEPENDENCY_API', 'reviewed API injection required');
  const F = await libraryCall(() => new deps.F1Field(FIELD), 'F1Field construction');
  // fastfile0.0.20 accepts Uint8Array as a memory file. No library body read.
  const lib = await libraryCall(() => deps.readR1cs(Uint8Array.from(ordinary), {
    F, loadConstraints: true, loadMap: true, loadCustomGates: false, singleThread: true,
  }), 'r1csfile memory import');
  libraryParity(lib, F, raw);
  const { rawToCanonical: forward, canonicalToRaw: inverse, publicMap } = permutation;
  const rows = raw.rows.map(row => row.map(lc => lc.map(([w, v]) => [forward[w], v])));
  const labels = inverse.map(w => raw.map[w]);
  for (let r = 0; r < raw.rows.length; r++) for (let k = 0; k < 3; k++) {
    need(rows[r][k].length === raw.rows[r][k].length, 'ROW_INVERSE_LENGTH', `${r}/${k}`);
    for (let j = 0; j < rows[r][k].length; j++) {
      const [w, v] = rows[r][k][j], [oldWire, oldValue] = raw.rows[r][k][j];
      need(inverse[w] === oldWire && v === oldValue, 'ROW_INVERSE', `${r}/${k}/${j}`);
    }
  }
  for (let i = 0; i < labels.length; i++) need(labels[forward[i]] === raw.map[i], 'LABEL_INVERSE', `${i}`);
  const mapping = artifact({ schema: 'kpi-signature-public-permutation/v1', one: 0, publicMap, privateSuffixStart: 67, privateSuffixPolicy: 'identity' });
  const matrix = artifact({
    schema: 'kpi-signature-normalized-r1cs/v1', field: FIELD.toString(), n8: 32,
    nVars: raw.h.nVars, nInstances: 67, nWitnesses: raw.h.nVars - 67,
    nOutputs: 0, nPublicInputs: 66, nDeclaredPrivateInputs: raw.h.nPrvInputs,
    nLabels: raw.h.nLabels, nConstraints: raw.h.nConstraints,
    // Each row is [A,B,C]; each LC is ordered [wire,canonical-Fr-decimal] terms.
    rows, wireToLabel: labels, mappingSha256: mapping.sha256,
  });
  const metadata = artifact({
    schema: 'kpi-signature-matrix-admission/v1', status: 'FORMAT_ONLY_NOT_SAT_CHECKED',
    sourcePins: { ordinaryR1cs: identity(input.pins.ordinaryR1cs), cpp0R1cs: identity(input.pins.cpp0R1cs), symBytes: identity(input.pins.symBytes) }, ordinaryCpp0ByteIdentical: true,
    versions: { r1cs: 1, wtns: 2, r1csfile: '0.0.48', fastfile: '0.0.20', parserField: 'ffjavascript0.3.0 F1Field' },
    shape: raw.h, mappingSha256: mapping.sha256, normalizedMatrixSha256: matrix.sha256,
    rawPreflight: 'exact sections/canonical fields/unique terms/full rows/map',
    libraryParity: 'every header/map/row/term/coefficient',
    inverseChecks: 'every permutation/row/term/coefficient/label; ONE0/private suffix fixed',
    unsupported: 'custom or unknown sections; non-exact versions; unsafe u64 labels; non-ASCII/LF sym',
    scope: 'synthetic signature-component format; no R1CS evaluation/proof/setup/MPC/privacy/fee claim',
  });
  const prepared = Object.freeze({ matrix, mapping, metadata });
  PREPARED.set(prepared, {
    nVars: raw.h.nVars, forward, inverse,
    mappingSha256: mapping.sha256, normalizedMatrixSha256: matrix.sha256,
  });
  return prepared;
}

// The caller freezes both hashes after matrix-only preparation and before controls.
// deps.exportWitnessJson is authenticated snarkjs0.7.6 wtns.exportJson.
export async function prepareSignatureWitness(input, prepared, deps) {
  const state = PREPARED.get(prepared);
  need(state && input && deps, 'PREPARED_CONTEXT', 'same-process successful matrix preparation required');
  need(sha(prepared.matrix.bytes) === state.normalizedMatrixSha256 && sha(prepared.mapping.bytes) === state.mappingSha256, 'PREPARED_ARTIFACT_MUTATION', 'do not change exported buffers');
  need(input.frozen && input.frozen.mappingSha256 === state.mappingSha256 &&
    input.frozen.normalizedMatrixSha256 === state.normalizedMatrixSha256, 'FROZEN_MAPPING_REQUIRED', 'freeze matrix+symbol permutation before any witness/control');
  const bytes = admitted(input.wtns, input.pin, 'candidate WTNS');
  const raw = preflightWitness(bytes, state.nVars);
  need(typeof deps.exportWitnessJson === 'function', 'DEPENDENCY_API', 'snarkjs wtns.exportJson required');
  const lib = await libraryCall(() => deps.exportWitnessJson(Uint8Array.from(bytes)), 'snarkjs memory WTNS export');
  need(Array.isArray(lib) && lib.length === raw.length, 'LIBRARY_WITNESS_SHAPE', 'full nVars, not nPrvInputs');
  const { forward, inverse } = state;
  const normalized = new Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    need(typeof lib[i] === 'bigint' && lib[i].toString() === raw[i], 'LIBRARY_WITNESS_VALUE', `${i}`);
    normalized[forward[i]] = raw[i];
  }
  for (let i = 0; i < raw.length; i++) need(normalized[forward[i]] === raw[i] && raw[inverse[i]] === normalized[i], 'WITNESS_INVERSE', `${i}`);
  need(normalized[0] === '1', 'ONE_ASSIGNMENT', 'normalized ONE retained');
  const witness = artifact({
    schema: 'kpi-signature-normalized-witness/v1', field: FIELD.toString(),
    nVars: raw.length, nInstances: 67, nWitnesses: raw.length - 67,
    mappingSha256: state.mappingSha256, normalizedMatrixSha256: state.normalizedMatrixSha256,
    values: normalized,
  });
  const metadata = artifact({
    schema: 'kpi-signature-witness-admission/v1', status: 'FORMAT_ONLY_NOT_SAT_CHECKED',
    input: identity(input.pin), frozen: { mappingSha256: state.mappingSha256, normalizedMatrixSha256: state.normalizedMatrixSha256 }, normalizedWitnessSha256: witness.sha256,
    rawOne: '1', canonicalRawFields: true, completeNVars: raw.length,
    libraryParity: 'every raw witness value', inverseChecks: 'every assignment entry',
    semanticPolicy: 'do not reject canonical-Fr bad bytes/limbs/S here; actual R1CS rows decide',
    scope: 'assignment admission only; parser refusal never substitutes for residual UNSAT',
  });
  return { witness, metadata };
}

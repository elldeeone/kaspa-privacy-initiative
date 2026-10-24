// Adapted public JSON predicates from baseline b7b41ab0; old module unchanged.
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
  need(!Buffer.isBuffer(raw) || Buffer.from(text,'utf8').equals(raw), 'json-utf8');
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

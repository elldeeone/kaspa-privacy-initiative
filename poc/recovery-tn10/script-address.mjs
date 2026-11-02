#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const k = createRequire(import.meta.url)(path.join(repo, '.local/sdk/kaspa-wasm32-sdk/nodejs/kaspa'));
const [recordPath, indexText] = process.argv.slice(2);
const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const index = Number(indexText);
assert(Number.isSafeInteger(index) && index >= 0 && index < record.transaction.outputs.length);
const encoded = record.transaction.outputs[index].scriptPublicKey;
assert(/^[0-9a-f]+$/.test(encoded) && encoded.length >= 4);
const script = new k.ScriptPublicKey(Number.parseInt(encoded.slice(0, 4), 16), encoded.slice(4));
console.log(k.addressFromScriptPublicKey(script, 'testnet').toString());

// Existing full public descriptor parser; no SDK load, key or RPC API call.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const [tree, pp, ps, dp, ds] = process.argv.slice(2);
const selected = await import(pathToFileURL(path.join(tree,
  'runtime-source/poc/four-wallet-chain/selection.mjs')).href);
const profile = selected.profile(fs.readFileSync(pp), ps);
selected.descriptor(fs.readFileSync(dp), ds, profile, ps);
process.stdout.write(JSON.stringify({status: 'FULL_PUBLIC_DESCRIPTOR_SHAPE_VALID', SDK_or_network_used: false}) + '\n');

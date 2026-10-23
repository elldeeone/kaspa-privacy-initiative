// Offline public-key -> TN10 address adapter. Never receives a private key.
const fs = require('node:fs');
try {
  const k = require(process.argv[2]);
  const keys = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (!Array.isArray(keys) || keys.some(x => !/^[0-9a-f]{64}$/.test(x))) throw Error();
  const result = keys.map(hex => {
    const key = new k.XOnlyPublicKey(hex);
    const address = key.toAddress('testnet-10').toString();
    const spk = k.payToAddressScript(address);
    if (!address.startsWith('kaspatest:') || spk.version !== 0 || spk.script !== `20${hex}ac`) throw Error();
    return {xonly_hex32: hex, address, spk_version: spk.version, spk_hex: spk.script};
  });
  process.stdout.write(JSON.stringify(result));
} catch (_) {
  process.stderr.write('offline TN10 address conversion failed\n');
  process.exit(1);
}

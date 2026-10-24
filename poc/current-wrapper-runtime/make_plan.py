#!/usr/bin/env python3
"""Inventory only explicit current public sources; never inspect owner inputs."""
from pathlib import Path
import argparse
import hashlib
import json

from prepare import PROFILE, EXECUTABLES

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT.parent

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main(args):
    assert sha(args.wallet_freeze) == args.wallet_freeze_sha256
    freeze=json.loads(args.wallet_freeze.read_bytes())
    rows=[];seen=set()
    def add(kind, name, source, expected=None):
        source=Path(source).absolute()
        assert source.is_file() and not any(p.is_symlink() for p in (source,*source.parents))
        assert name not in seen;seen.add(name)
        actual=sha(source)
        if expected is not None:assert actual==expected, name
        rows.append({'kind':kind,'path':name,'source':str(source),
                     'bytes':source.stat().st_size,'sha256':actual})
    for row in freeze['files']:
        if row['path'] != 'poc/shared-settlement-wallet/test_wallet.py':
            add('runtime-source','runtime-source/'+row['path'],ROOT/row['path'],row['sha256'])
    generic={
        'poc/compact-batch-lifecycle/primitives.py':'184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
        'poc/compact-batch-lifecycle/receiver.py':'9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b',
        'poc/compact-batch-lifecycle/actions.py':'a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484',
        'poc/compact-batch-lifecycle/native_runtime.py':'dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af',
        'poc/shared-settlement/wire.py':'64598cb094f8821c66777278169a33a8a0b15c05f220f0d990a8d0c793360044',
        'poc/shared-settlement/policy.py':'982ec706f6a3d5d85b223e1c642ee0466e1d35e5047e339da039414930e40b68',
        'poc/shared-settlement/virtual.py':'6e0fd44e27ddabd45c32cbb9a019948b831d70331c1bd5cd5213faf50182c222',
        'poc/future-recipient/v2/recipient.py':'93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2',
        'poc/private-cashout-trial/sdk.mjs':'7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63',
    }
    for relative,expected in generic.items():add('runtime-source','runtime-source/'+relative,ROOT/relative,expected)
    executables={
        'prover':BASE/'capacity-exit-selected-prover-01/prover',
        'w-codec':BASE/'shared-settlement-native-target/release/kpi-shared-settlement-native',
        'native-validator':Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator'),
        'node':Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'),
        'crypto':Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')}
    for name,path in executables.items():add('selected-executable','runtime/'+name,path,EXECUTABLES['runtime/'+name])
    sdk=Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
    for name,expected in {
        'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
        'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
        'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
    }.items():add('runtime-source','runtime-sdk/'+name,sdk/name,expected)
    cap_freeze=ROOT/'research/next-session/independent-payments/exits/SOURCE-FREEZE-SELECTED.json'
    assert sha(cap_freeze)=='c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3'
    for row in json.loads(cap_freeze.read_bytes())['files']:
        add('source','source/'+row['path'],ROOT/row['path'],row['sha256'])
    add('source','source/poc/private-exit-stress/prover/LICENSE-MIT',ROOT/'poc/compact-batch-prover/LICENSE-MIT')
    for relative in ['Cargo.toml','Cargo.lock','NOTICE','src/main.rs','src/policy.rs','src/receipt.rs']:
        add('source','source/poc/shared-settlement-native/'+relative,ROOT/'poc/shared-settlement-native'/relative)
    add('source','source/poc/shared-settlement-proof/child-profile.json',ROOT/'poc/shared-settlement-proof/child-profile.json',PROFILE['child_profile_sha256'])
    for name in ['prepare.py','make_plan.py','vendor/software_bundle.py','vendor/unpack_bundle.py']:
        add('source','source/poc/current-wrapper-runtime/'+name,Path(__file__).parent/name)
    for name,source,expected in [
        ('WALLET-SOURCE-FREEZE.json',args.wallet_freeze,args.wallet_freeze_sha256),
        ('child-profile.json',ROOT/'poc/shared-settlement-proof/child-profile.json',PROFILE['child_profile_sha256']),
        ('public-parameters.json',ROOT/'poc/private-exit-stress/prover/pins/compact2/public-parameters.json',PROFILE['role_manifest_sha256']),
        ('PROVER-SOURCE-FREEZE.json',cap_freeze,'c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3'),
        ('PROVER-SELECTION.json',ROOT/'research/next-session/independent-payments/exits/PROVER-SELECTION.json',None),
    ]:add('public-metadata','selection/'+name,source,expected)
    for name,source,expected in [
        ('prestate.json',BASE/'adr59-public-two-actor-01/prestate.json','82ae8087adf61fd65cf20a539d10f446ee31f0f224aec5fcd87b99f0d62a08be'),
        ('genuine-W-case.json',BASE/'adr59-genuine-native-01/genuine-R0-receipt-ACTUAL-W-POSITIVE/validation-case.json','9c94f36cfa85c1a8d5a5e0bd28e764f27f7879418cb12b5d9820be6cc80aa7bc'),
        ('genuine-W-result.json',ROOT/'research/next-session/independent-payments/settlement/genuine-native-01/RESULTS.json','7b25030bc14498fb57a68da19e1cd3b8051403dfeff0f049be8b0d42f3e779e3'),
    ]:add('public-canary','public/'+name,source,expected)
    plan={'schema':'kpx5-current-W-runtime-source-plan/v1','profile':PROFILE,
          'wallet_source_freeze_sha256':args.wallet_freeze_sha256,'files':sorted(rows,key=lambda r:r['path'])}
    with args.output.open('x') as target:json.dump(plan,target,sort_keys=True,indent=2);target.write('\n')
    print(json.dumps({'explicit_public_files':len(rows),'payload_bytes':sum(r['bytes']for r in rows),
                      'source_plan_sha256':sha(args.output),'backup_or_PK_or_owner_seed_read':False}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wallet-freeze',type=Path,required=True)
    parser.add_argument('--wallet-freeze-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args())

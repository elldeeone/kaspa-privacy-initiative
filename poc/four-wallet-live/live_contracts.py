"""Authenticate a public software tree before fixed financial modules execute."""
import importlib.util
import copy
from pathlib import Path
import subprocess
import sys
import tempfile

from public import (ROOT, digest, encoded, forbidden_backups, guard_public_paths, need,
                    parse, read_public, write_new)

HELPER = 'poc/current-wrapper-runtime/vendor/software_bundle.py'
HELPER_SHA = 'b3e933ca76cfad21e70b50568824b6f9fff3034c58c4cbf5d8d36d7932e1a705'
OWN = ('public.py', 'journal.py', 'owner_journal.py', 'ledger.py', 'live_contracts.py',
       'preflight.py', 'journal_cli.py', 'submit.mjs', 'offline_sdk.mjs', 'runner.py')
SDK_PINS = {
    'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'}
REQUIRED = (
    'poc/four-wallet-profile/selection.py',
    *(f'poc/four-wallet-lifecycle/{name}.py' for name in
      ('compat', 'contracts', 'paths', 'runtime', 'replay')),
    'poc/four-wallet-bootstrap/gn2.py', 'poc/four-wallet-bootstrap/gn2_common.py',
    *(f'poc/four-wallet-chain/{name}' for name in
      ('chain_replay.py', 'selection.mjs', 'wire.mjs', 'json.mjs', 'acquire.mjs', 'verify_bundle.mjs',
       'anchor.mjs', 'fetch.mjs')),
    *(f'poc/four-wallet-live/{name}' for name in OWN), HELPER)


def module(path, name):
    """Only call after the entire externally selected tree was authenticated."""
    need(name not in sys.modules, 'fresh-fixed-module-namespace')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    try:
        spec.loader.exec_module(value)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return value


def authenticate_tree(root, inventory_path, expected_sha256, trial_directory):
    root = Path(root).absolute()
    raw = read_public(inventory_path, expected_sha256, trial_directory)
    value = parse(raw)
    need(type(value) is dict and type(value.get('files')) is list, 'typed-public-inventory')
    names = [row['path'] for row in value['files']]
    need(len(names) == len(set(names)), 'unique-software-members')
    # Metadata for every selected member precedes every member-byte read.
    for name in names:
        need(type(name) is str and not Path(name).is_absolute()
             and '..' not in Path(name).parts and str(Path(name)) == name,
             'canonical-software-member')
    selected_paths = guard_public_paths([root / name for name in names], trial_directory)
    # The installed source/runtime tree is trusted immutable during use. The
    # caller's mutable chain pages are separately copied before replay.
    need(all(path.stat().st_mode & 0o222 == 0 for path in selected_paths),
         'selected-public-software-members-readonly')
    helper = module_from_owned_bytes(read_public(ROOT / HELPER, HELPER_SHA, trial_directory))
    private = tuple(p for p in forbidden_backups(trial_directory) if p.exists())
    receipt = helper.verify(root, raw, expected_sha256, forbidden_inputs=private)
    prefix = 'runtime-source/'
    need({prefix + name for name in REQUIRED} <= set(names), 'complete-live-fixed-source-closure')
    for name in OWN:
        # A different working-copy bootstrap cannot silently validate a tree
        # and then run its own unselected controller implementation.
        selected = next(row for row in value['files']
                        if row['path'] == prefix + 'poc/four-wallet-live/' + name)
        need(read_public(ROOT / 'poc/four-wallet-live' / name,
                         selected['sha256'], trial_directory) is not None,
             'running-controller-matches-selected-source')
    return root / 'runtime-source', root / 'runtime', receipt


def module_from_owned_bytes(raw):
    import types
    result = types.ModuleType('_kpx6_live_public_byte_verifier')
    result.__file__ = str(ROOT / HELPER)
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    return result


def stage_sdk(software_root, destination, trial_directory):
    """Fresh immutable SDK copy, with all four backup exclusions before reads."""
    sdk = Path(software_root) / 'runtime-sdk'
    guard_public_paths([sdk / name for name in SDK_PINS], trial_directory)
    destination = Path(destination)
    need(not destination.exists(), 'fresh-public-SDK-staging')
    destination.mkdir(mode=0o700)
    for name, expected in SDK_PINS.items():
        target = destination / name
        write_new(target, read_public(sdk / name, expected, trial_directory)); target.chmod(0o400)
    return destination


def public_runtime(source_root, runtime_root, profile_raw, profile_sha256, trial_directory):
    selected = module(source_root / 'poc/four-wallet-profile/selection.py',
                      '_kpx6_live_selected_financial').load(profile_raw, profile_sha256)
    # The process has imported only stdlib and the live stdlib helpers. The
    # fixed lifecycle module graph now supplies its reviewed namespace/pins.
    directory = str(source_root / 'poc/four-wallet-lifecycle')
    sys.path.insert(0, directory)
    need('runtime' not in sys.modules, 'fresh-public-runtime-namespace')
    from runtime import Runtime
    class PublicRuntime(Runtime):
        def sdk(self, body, contexts):
            # The owner namespace masks the historical fixed SDK cache path.
            # Public replay instead uses this fixed roundtrip-only adapter and
            # a freshly owned copy of the selected inventory SDK. It never
            # opens that mutable host cache or accepts a signing secret.
            raw_body = copy.deepcopy(body)
            for row in raw_body['inputs']: row['sequence'] = str(row['sequence'])
            for row in raw_body['outputs']: row['value'] = str(row['value'])
            for name in ('lockTime', 'gas'): raw_body[name] = str(raw_body[name])
            raw_body['storageMass'] = str(raw_body.pop('mass'))
            request = {'schema': 'kpx6-four-wallet-public-offline-SDK/v1',
                'network_id': 'testnet-10',
                'genesis_hash_hex': 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
                'transaction': raw_body, 'contexts': contexts}
            with tempfile.TemporaryDirectory(prefix='kpx6-public-offline-SDK-') as temporary:
                destination = stage_sdk(Path(runtime_root).parent, Path(temporary) / 'sdk', trial_directory)
                result = subprocess.run([str(self.node.path),
                    str(source_root / 'poc/four-wallet-live/offline_sdk.mjs'), str(destination)],
                    input=encoded(request), capture_output=True,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
            need(result.returncode == 0 and not result.stderr, 'fixed-public-offline-SDK-complete')
            checked = parse(result.stdout)
            need(checked == {'schema': 'kpx6-four-wallet-public-offline-SDK-result/v1',
                'transaction': raw_body, 'exact_SDK_roundtrip': True,
                'network_signing_or_broadcast': False}, 'exact-public-offline-SDK-body')
            return body
    runtime = PublicRuntime(selected, runtime_root)
    chain = module(source_root / 'poc/four-wallet-chain/chain_replay.py',
                   '_kpx6_live_selected_accepted_chain')
    return selected, runtime, chain

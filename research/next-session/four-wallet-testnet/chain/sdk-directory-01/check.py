"""Public argv/path controls only; intercepts execution before SDK/native work."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[5]
SOURCE = ROOT / 'poc/four-wallet-chain/chain_replay.py'
spec = importlib.util.spec_from_file_location('_chain_sdk_directory_control', SOURCE)
chain = importlib.util.module_from_spec(spec)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), chain.__dict__)
NODE = Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
raw_profile = b'{}'
profile = SimpleNamespace(raw_bytes=raw_profile,
    profile_sha256=chain.digest(raw_profile))
runtime = SimpleNamespace(profile=profile, paths={'node': NODE})
raw_descriptor = b'{}'
raw_fetch = json.dumps({'financial_profile_sha256': profile.profile_sha256}).encode()
captures = []
reads = []


class Captured(Exception):
    pass


def financial(raw, expected):
    reads.append('financial')
    assert raw == profile.raw_bytes and expected == profile.profile_sha256
    return profile


def run(argv, **kwargs):
    captures.append(argv)
    assert kwargs['stdin'] is chain.subprocess.DEVNULL
    raise Captured()


chain._financial = financial
chain.subprocess.run = run
results = []
with tempfile.TemporaryDirectory(prefix='kpi-chain-sdk-directory-') as directory:
    root = Path(directory)
    sdk = root / 'selected sdk'
    sdk.mkdir()
    arguments = (raw_descriptor, chain.digest(raw_descriptor), raw_fetch,
                 chain.digest(raw_fetch), profile, runtime)
    for name, option in [('explicit-staged-SDK', {'sdk_directory': sdk}),
                         ('masked-owner-default', {})]:
        output = root / name
        try:
            chain.replay_bundle(*arguments, output, bundle_directory=root, **option)
        except Captured:
            pass
        else:
            raise AssertionError('SDK execution was not intercepted')
        argv = captures[-1]
        assert argv[0] == str(NODE)
        assert argv[1] == str(ROOT / 'poc/four-wallet-chain/verify_bundle.mjs')
        assert len(argv) == (11 if option else 10)
        assert argv[-1] == (str(sdk) if option else str(output / 'sdk-verification.json'))
        results.append({'case': name, 'result': 'PASS'})
    alias = root / 'sdk-alias'
    alias.symlink_to(sdk, target_is_directory=True)
    regular = root / 'regular-file'
    regular.write_text('public marker')
    for name, invalid in [('missing-directory', root / 'missing'),
                          ('regular-file', regular), ('symlink-directory', alias),
                          ('parent-traversal', root / '..' / root.name / 'selected sdk')]:
        output = root / (name + '-output')
        before = (len(reads), len(captures))
        try:
            chain.replay_bundle(*arguments, output, bundle_directory=root,
                                sdk_directory=invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid SDK directory accepted')
        assert not output.exists() and before == (len(reads), len(captures))
        results.append({'case': name, 'result': 'PASS'})
report = {'schema': 'kpx5-gn2-chain-SDK-directory-controls/v1',
          'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
          'classification': 'PUBLIC_PATH_AND_FIXED_ARGV_CONTROLS_SUBPROCESS_INTERCEPTED',
          'initial_harness_failure': 'Root parent index 6 instead of 5; failed before source read or subprocess; fixed without changing production checks.',
          'network_native_proof_or_secret_operation': False, 'cases': results}
target = Path(__file__).with_name('RESULTS.json')
with target.open('x') as handle:
    json.dump(report, handle, sort_keys=True, indent=2)
    handle.write('\n')
print(json.dumps(report, sort_keys=True))

"""GN2/W accepted-prefix composition; no owner seed, PK or signing operation.

Fresh SDK checks bind COMPLETE bodies and populated contexts to retained Full
pages. Strict GN2 and the selected Runtime then execute financial/native
semantics. The remote validating node and non-atomic observation remain explicit
premises; this does not independently prove consensus or perpetual currentness.
"""
import builtins
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
NODE_SHA = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
FINANCIAL_SHA = '425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553'
# Candidate contract pins are updated only to independently reviewed source
# before integration/funding. No runtime argument supplies code or callbacks.
GN2_SOURCES = {'gn2_common': '2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b', 'gn2': 'cdfcebe9edf2a44306284a38892e44d347a0d68ad901bed03b394e9ce9e51f8c'}
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
MAX = 2_870_000_000_000_000_000
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
_cache = {}


def need(value, code):
    if not value:
        raise ValueError('accepted-W:' + code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(value):
    path = Path(value)
    need('..' not in path.parts, 'canonical-public-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public-path-symlink')
    return path


def parse(raw):
    need(type(raw) is bytes, 'public-raw-bytes')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate-json-field')
            value[key] = item
        return value
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('json-constant')),
        parse_float=lambda _: (_ for _ in ()).throw(ValueError('float-not-allowed')))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def integer(value, ceiling=(1 << 64) - 1, *, positive=False):
    need(type(value) is str and re.fullmatch('0|[1-9][0-9]*', value) is not None,
         'canonical-decimal-boundary')
    result = int(value)
    need((0 < result if positive else 0 <= result) and result <= ceiling,
         'integer-boundary-range')
    return result


def _load(path, expected, name):
    if name in _cache:
        return _cache[name]
    raw = checked(path).read_bytes()
    need(digest(raw) == expected and name not in sys.modules, 'selected-contract-source')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    _cache[name] = module
    return module


def _financial(raw, expected):
    module = _load(ROOT / 'poc/four-wallet-profile/selection.py', FINANCIAL_SHA,
                   '_kpx6_chain_financial_contract')
    return module.load(raw, expected)


def _gn2():
    key = '_kpx6_chain_GN2'
    if key in _cache:
        return _cache[key]
    need(set(GN2_SOURCES) == {'gn2_common', 'gn2'}, 'GN2-source-selection-not-ready')
    modules, sources = {}, {}
    for name, expected in GN2_SOURCES.items():
        path = checked(ROOT / 'poc/four-wallet-bootstrap' / (name + '.py'))
        source = path.read_bytes()
        need(digest(source) == expected, 'selected-GN2-source')
        full = key + '_' + name
        need(full not in sys.modules, 'fresh-GN2-source-namespace')
        module = types.ModuleType(full)
        module.__file__ = str(path)
        sys.modules[full] = module
        modules[name], sources[name] = module, source

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    try:
        for name, module in modules.items():
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imported)
            exec(compile(sources[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    _cache[key] = modules['gn2']
    return _cache[key]


def native_case(row):
    """Explicit lossless boundary: RPC strings -> native validator integers."""
    source = row['transaction']
    body = copy.deepcopy(source)
    for item in body['inputs']:
        item['sequence'] = integer(item['sequence'])
    for item in body['outputs']:
        item['value'] = integer(item['value'], MAX, positive=True)
    body['lockTime'] = integer(body['lockTime'])
    body['gas'] = integer(body['gas'])
    body['mass'] = integer(body.pop('storageMass'))
    entries, contexts = [], []
    need(len(body['inputs']) == len(row['accepted_input_contexts']), 'populated-context-count')
    for item, source_context in zip(body['inputs'], row['accepted_input_contexts']):
        need(source_context['outpoint'] == item['previousOutpoint']
             and source_context['is_coinbase'] is False
             and source_context['covenant_id'] is None, 'populated-context-point-and-flags')
        amount = integer(source_context['amount_sompi'], MAX, positive=True)
        daa = integer(source_context['block_daa_score'])
        entries.append({'amount': amount, 'scriptPublicKey': source_context['script_public_key'],
            'blockDaaScore': daa, 'isCoinbase': False, 'covenantId': None})
        contexts.append({'amount_sompi': str(amount), 'script_public_key': source_context['script_public_key'],
            'block_daa_score': str(daa), 'is_coinbase': False, 'covenant_id': None})
    return {'transaction': body, 'entries': entries}, contexts


def _point(value):
    need(type(value) is dict and set(value) == {'transactionId', 'index'}
         and type(value['transactionId']) is str
         and re.fullmatch('[0-9a-f]{64}', value['transactionId']) is not None
         and type(value['index']) is int and 0 <= value['index'] < 1 << 32,
         'actual-outpoint')
    return value['transactionId'], value['index']


def bundle_public_files(raw_fetch, fetch_sha256, bundle_directory):
    """Enumerate ALL page paths from metadata; read/hash/decompress none.

    The owner launcher first guards the fetch file itself, then invokes this
    function and checks all resulting page inodes against its one backup before
    any page is opened. Returning a tuple preserves repeated exclusion passes.
    """
    need(digest(raw_fetch) == fetch_sha256, 'external-fetch-file-pin')
    value = parse(raw_fetch)
    need(value['schema'] == 'kpx5-gn2-network-fetch/v1'
         and value['status'] == 'FETCHED_PENDING_REPLAY', 'complete-fetch-page-metadata')
    root = checked(bundle_directory)
    first = value['pages']
    second = value['current_view']['post_query_delta']['pages']
    need(type(first) is list and type(second) is list, 'finite-page-metadata-lists')
    result = []
    for row in [*first, *second]:
        relative = row['path']
        need(type(relative) is str and relative and '\\' not in relative
             and not relative.startswith('/') and '..' not in Path(relative).parts
             and str(Path(relative)) == relative, 'canonical-relative-page-path')
        target = checked(root / relative)
        need(target.is_relative_to(root) and target != root, 'page-outside-public-bundle')
        result.append(target)
    need(len(result) == len(set(result)), 'duplicate-page-metadata-path')
    return tuple(result)


def replay_bundle(raw_descriptor, descriptor_sha256, raw_fetch, fetch_sha256,
                  financial, runtime, output, *, bundle_directory):
    """Compose a newly selected public acquisition; never trust JSON status alone.

    Runtime is the fixed application-selected lifecycle Runtime, constructed by
    the authenticated owner launcher; no network/caller JSON supplies a native
    validator or semantic callback. All referenced source files belong to that
    independently selected software inventory.
    """
    # Validate paths before the first external read or any output creation.
    output, bundle_directory = checked(output), checked(bundle_directory)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-replay-output-outside-Git')
    need(digest(raw_descriptor) == descriptor_sha256 and digest(raw_fetch) == fetch_sha256,
         'external-public-evidence-pins')
    installed = _financial(financial.raw_bytes, financial.profile_sha256)
    need(runtime.profile.raw_bytes == installed.raw_bytes
         and runtime.profile.profile_sha256 == installed.profile_sha256,
         'selected-runtime-financial-profile')
    d, bundle = parse(raw_descriptor), parse(raw_fetch)
    need(bundle['financial_profile_sha256'] == installed.profile_sha256,
         'selected-financial-evidence')
    output.mkdir(parents=True, mode=0o700)
    paths = [output / name for name in ('financial-profile.json', 'descriptor.json', 'fetch.json')]
    for file, raw in zip(paths, (installed.raw_bytes, raw_descriptor, raw_fetch)):
        with file.open('xb') as target:
            target.write(raw)
    # Execute the actual selected Node directly; there is no validator callback.
    node = checked(runtime.paths['node'])
    info = node.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500
         and not os.access(node, os.W_OK) and digest(node.read_bytes()) == NODE_SHA,
         'selected-readonly-SDK-runtime')
    receipt_path = output / 'sdk-verification.json'
    process = subprocess.run([str(node), str(HERE / 'verify_bundle.mjs'),
        str(paths[0]), installed.profile_sha256, str(paths[1]), descriptor_sha256,
        str(paths[2]), fetch_sha256, str(bundle_directory), str(receipt_path)],
        capture_output=True, text=True, env=dict(CLEAN), stdin=subprocess.DEVNULL)
    (output / 'sdk-verification.log').write_text(process.stdout + process.stderr)
    need(process.returncode == 0 and receipt_path.is_file(), 'fresh-full-SDK-evidence-check-failed')
    sdk = parse(receipt_path.read_bytes())
    need(sdk['financial_profile_sha256'] == installed.profile_sha256
         and sdk['descriptor_file_sha256'] == descriptor_sha256
         and sdk['fetch_file_sha256'] == fetch_sha256
         and sdk['transaction_ids_and_full_body_context_locators_recomputed'] is True
         and sdk['header_hashes_and_prefix_paths_recomputed'] is True
         and sdk['current_view_and_delta_consistent'] is True,
         'fresh-SDK-receipt-binding')
    cases = [native_case(row)[0] for row in bundle['transactions']]
    need(cases and cases[0]['transaction']['id'] == d['founding_outpoint']['transactionId'],
         'accepted-GN2-first')
    funding, contexts = native_case(bundle['transactions'][0])
    body, metrics = runtime.normalize(funding['transaction'], contexts, output / 'GN2-normalize')
    need(body == funding['transaction'], 'accepted-GN2-official-ID-mass')
    runtime.sdk(body, contexts)
    native, checked_metrics = runtime.validate(body, contexts, output / 'GN2-Full')
    need(native['all_input_engines_accepted'] is True and metrics == checked_metrics,
         'fresh-GN2-native-acceptance')
    # Historical budgets are not signed by V1 ALL or committed by txid.
    # Only AFTER the accepted Full body/context join and actual native checks
    # use the named historical facade; own proposals remain exact budget10.
    gn2 = _gn2()
    selection = gn2.EntrySelection(installed.profile_sha256, installed.domain, installed.w_tail).check()
    initial = gn2.validate_accepted_genesis(cases[0], selection, d['trial_id'])
    need(initial['founding_outpoint'] == d['founding_outpoint']
         and initial['redeem_hex'] == d['initial_redeem_hex']
         and digest(bytes.fromhex(initial['redeem_hex'])) == d['initial_redeem_sha256']
         and metrics['actual_fee_sompi'] == initial['fee_sompi'],
         'derived-GN2-descriptor-and-actual-fee-binding')
    semantic = runtime.replay_cases(initial['snapshot'], initial['founding_outpoint'],
        initial['reserve_sompi'], cases[1:], output / 'W-replay')
    need(semantic['point'] == sdk['discovered_head'], 'physical-head-semantic-evidence-binding')
    queries = {_point(q['outpoint']): q for q in bundle['current_view']['queries']}
    head_context = None
    if semantic['reserve']:
        query = queries[_point(semantic['point'])]
        need(query['entry'] is not None
             and integer(query['amount_sompi'], MAX, positive=True) == semantic['reserve'],
             'observed-current-reserve')
        entry = query['entry']
        head_context = {'amount_sompi': str(semantic['reserve']),
            'script_public_key': entry['script_public_key'],
            'block_daa_score': str(integer(entry['block_daa_score'])),
            'is_coinbase': False, 'covenant_id': None}
    else:
        need(semantic['point'] is None and len(cases) >= 2 and semantic['payouts'],
             'terminal-requires-actual-valid-native-transition')
    payouts = []
    for item in semantic['payouts']:
        query = queries[_point(item['outpoint'])]
        need(integer(query['amount_sompi'], MAX, positive=True) == item['amount_sompi']
             and query['script_public_key'] == item['script_public_key'], 'observed-payout-binding')
        payouts.append({**item, 'queried': True, 'current_utxo': query['entry']})
    return {**semantic, 'schema': 'kpx5-gn2-network-replay/v1',
        'financial_profile_sha256': installed.profile_sha256,
        'descriptor_sha256': descriptor_sha256, 'fetch_sha256': fetch_sha256, 'trial_id': d['trial_id'],
        'entry': initial, 'entry_fee_sompi': initial['fee_sompi'], 'payouts': payouts,
        'head_context': head_context, 'observation_checkpoint': bundle['current_view']['checkpoint'],
        'network_evidence_consistency_validated': True,
        'accepted_chain_backing_verified': True, 'currentness_verified': True,
        'currentness_scope': 'TRUSTED_NONATOMIC_NODE_OBSERVATION_AT_RECORDED_CHECKPOINT',
        'independent_consensus_verified': False, 'spend_authorized': False,
        'fresh_root_acquisition_and_recheck_required_before_broadcast': True,
        'GN2_native_report': native, 'SDK_public_evidence_receipt': sdk}

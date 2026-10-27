"""ADR0067 local-controller cache selection; public bytes only, no private reads."""
from pathlib import Path
from replay import BASE
from gn3_common import digest, encoded, fields, need, parse
from paths import HostPolicy

SOURCE57 = '29163ae54005653c12d6c9644c82a6de999a70be360d516f35099cbf8b08b4a3'
ROOT_HANDOFF = '73ee6f11fed5864ea7d6b692ab8b01d9831eb018dd3e52a966e5e69fe4d85ba5'
SCOPE = 'trusted-controller-local-state-only'
NAMES = ('cache_common.py', 'cache.mjs', 'acquire_cached.mjs', 'fetch_cached.mjs',
         'verify_bundle_cached.mjs', 'replay_cached.py', 'confirm_cached.py',
         'preflight_cached.py', 'submit_cached.mjs')


def flags(parser):
    for name in ('runtime-source', 'cache-admission', 'baseline-fetch'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--baseline-bundle-directory', type=Path, required=True)
    parser.add_argument('--baseline-cache', type=Path)
    parser.add_argument('--baseline-cache-sha256')
    parser.add_argument('--trusted-local-cache', action='store_true')


def arguments(a):
    result = []
    for name in ('runtime-source', 'cache-admission', 'baseline-fetch', 'baseline-bundle-directory', 'baseline-cache'):
        value = getattr(a, name.replace('-', '_'), None)
        if value is not None:
            result += ['--' + name, str(value)]
            if name != 'baseline-bundle-directory':
                result += ['--' + name + '-sha256', getattr(a, name.replace('-', '_') + '_sha256')]
    if a.trusted_local_cache:
        result += ['--trusted-local-cache']
    return result


def authenticate(a):
    guard = HostPolicy()
    row = {'path': str(a.runtime_source), 'sha256': a.runtime_source_sha256}
    value = parse(guard.read(a.runtime_source, a.runtime_source_sha256))
    fields(value, ('schema', 'frozen_sources', 'source_members'), 'cached-runtime-fields')
    need(value['schema'] == 'kpxa-local-cached-chain-runtime/v1'
         and value['frozen_sources']['sha256'] == SOURCE57, 'frozen-runtime57-required')
    frozen = parse(guard.read(value['frozen_sources']['path'], SOURCE57))
    members = {member['path']: member['sha256'] for member in value['source_members']}
    need(len(members) == len(value['source_members']), 'unique-cached-runtime-source-members')
    repo = BASE.parents[1]
    for member in frozen['source_members']:
        need(members.get(str(repo / member['path'])) == member['sha256'], 'old57-source-must-remain-exact')
    for name in NAMES:
        need(str(BASE / 'chain' / name) in members, 'complete-cached-runtime-siblings')
    for path, expected in members.items():
        guard.read(path, expected)
    admission = parse(guard.read(a.cache_admission, a.cache_admission_sha256))
    need(admission['schema'] == 'kpxa-local-verified-prefix-admission/v1'
         and admission['scope'] == SCOPE and admission['runtime_sources'] == row
         and admission['initial_handoff']['sha256'] == ROOT_HANDOFF
         and admission['domain_hex32'] == 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c',
         'explicit-reviewed-local-admission')
    for name in ('selection', 'descriptor', 'assets', 'parameters'):
        need(admission[name] == {'path': str(getattr(a, name)), 'sha256': getattr(a, name + '_sha256')},
             'same-cached-financial-selection')
    return admission


def receipt(a, fetch_row, previous=None):
    admission = authenticate(a)
    return {'schema': 'kpxa-local-verified-prefix-cache/v1', 'scope': SCOPE,
        'runtime_sources': {'path': str(a.runtime_source), 'sha256': a.runtime_source_sha256},
        'admission': {'path': str(a.cache_admission), 'sha256': a.cache_admission_sha256},
        'initial_handoff': admission['initial_handoff'], 'fetch': fetch_row,
        'selection': admission['selection'], 'descriptor': admission['descriptor'],
        'all_selected_pool_native_financial_history_replayed': True,
        'public_receipt_is_external_attestation': False, 'previous_cache': previous}

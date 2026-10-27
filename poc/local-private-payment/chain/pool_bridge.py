"""Explicit public-only fixed-role bridge; the pool never receives host authority.

The selected supervisor authenticates every declared byte before admission. This
builder authenticates manifests and enumerates their bounded page references;
it does not substitute a public PASS marker for chain or financial verification.
"""
from pathlib import Path, PurePosixPath
import subprocess
import sys

HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE.parent / 'bootstrap'))
from gn3_common import digest, encoded, fields, hx, need, parse, write_new
from paths import HostPolicy, checked

CLIENT = HERE.parent / 'execution' / 'public_pool_client.py'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
COMMON = ('selection', 'descriptor', 'assets', 'parameters', 'codec',
          'runtime-source', 'cache-admission', 'baseline-fetch')
CACHE = ('runtime-source', 'cache-admission', 'baseline-fetch',
         'baseline-bundle-directory', 'baseline-cache')
RUNTIME = ('crypto', 'node', 'native-validator', 'sdk-directory')
REPLAY_REQUIRED = ('selection', 'descriptor', 'fetch', 'assets', 'parameters',
                   'codec', 'bundle-directory', 'output')
PREFLIGHT_REQUIRED = ('mode', 'stage', 'trial-id', 'selection', 'case', 'output')
PREFLIGHT_OPTIONAL = ('assets', 'parameters', 'descriptor', 'fetch', 'codec',
                      'bundle-directory', 'sessions', 'source-pins')


def flags(parser):
    parser.add_argument('--pool-selection', type=Path, required=True)
    parser.add_argument('--pool-selection-sha256', required=True)


def value(a, name):
    return getattr(a, name.replace('-', '_'), None)


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'pool-canonical-absolute-path')
    return checked(path)


def selected(a, name):
    path = value(a, name)
    if path is None:
        return None
    expected = value(a, name + '-sha256')
    hx(expected, 32)
    return {'source': str(absolute(path)), 'sha256': expected,
            'mode': 0o500 if name == 'codec' else 0o400}


def role_argv(a, role):
    need(role in ('replay', 'preflight'), 'closed-public-pool-role')
    names = REPLAY_REQUIRED if role == 'replay' else PREFLIGHT_REQUIRED + PREFLIGHT_OPTIONAL
    names += CACHE + RUNTIME
    result = []
    for name in names:
        item = value(a, name)
        if item is None:
            need(name not in (REPLAY_REQUIRED if role == 'replay' else PREFLIGHT_REQUIRED),
                 'complete-public-role-arguments')
            continue
        result += ['--' + name, str(item)]
        if name in ('selection', 'descriptor', 'fetch', 'assets', 'parameters',
                    'codec', 'case', 'sessions', 'source-pins',
                    'runtime-source', 'cache-admission', 'baseline-fetch', 'baseline-cache'):
            expected = value(a, name + '-sha256')
            hx(expected, 32)
            result += ['--' + name + '-sha256', expected]
    # No private-directory exclusions, journal, RPC, or execute flag can enter
    # an offline role. The original fixed public guard remains authoritative.
    if value(a, 'trusted-local-cache'):
        result += ['--trusted-local-cache']
    return result


def job_files(a, role, guard):
    rows = {}

    def add(row):
        if row is None:
            return
        old = rows.get(row['source'])
        need(old is None or old == row, 'one-public-byte-selection-per-path')
        rows[row['source']] = row

    for name in COMMON + ('baseline-cache', 'fetch', 'case', 'sessions', 'source-pins'):
        add(selected(a, name))
    admission_row = selected(a, 'cache-admission')
    admission = parse(guard.read(admission_row['source'], admission_row['sha256']))
    initial = admission['initial_handoff']
    fields(initial, ('path', 'sha256'), 'explicit-initial-handoff-input-row')
    hx(initial['sha256'], 32)
    add({'source': str(absolute(initial['path'])), 'sha256': initial['sha256'], 'mode': 0o400})
    for name, directory in (('fetch', 'bundle-directory'),
                            ('baseline-fetch', 'baseline-bundle-directory')):
        row = selected(a, name)
        if row is None:
            continue
        root = absolute(value(a, directory))
        fetch = parse(guard.read(row['source'], row['sha256']))
        segments = (fetch['pages'], fetch['current_view']['post_query_delta']['pages'])
        for pages in segments:
            need(type(pages) is list, 'complete-public-page-record-list')
            for page in pages:
                relative = page['path']
                need(type(relative) is str and relative and
                     not PurePosixPath(relative).is_absolute() and
                     str(PurePosixPath(relative)) == relative and
                     all(part not in ('', '.', '..') for part in relative.split('/')),
                     'bounded-canonical-public-page-path')
                expected = page['gzip_sha256']
                hx(expected, 32)
                add({'source': str(root / relative), 'sha256': expected, 'mode': 0o400})
    # Optional alternate runtimes are explicit public inputs. Canonical runtimes
    # and the official SDK are otherwise supplied by the static pool selection.
    for name in RUNTIME[:-1]:
        path = value(a, name)
        if path is not None:
            raw = guard.read(absolute(path))
            add({'source': str(absolute(path)), 'sha256': digest(raw), 'mode': 0o500})
    sdk = value(a, 'sdk-directory')
    if sdk is not None:
        for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json'):
            path = absolute(sdk) / name
            raw = guard.read(path)
            add({'source': str(path), 'sha256': digest(raw), 'mode': 0o400})
    return [rows[name] for name in sorted(rows)]


def invoke(a, role, request_path):
    guard = HostPolicy()
    pool = parse(guard.read(a.pool_selection, a.pool_selection_sha256))
    client = pool['client']
    fields(client, ('path', 'sha256'), 'selected-public-pool-client')
    need(client['path'] == str(CLIENT), 'fixed-public-pool-client-path')
    guard.read(CLIENT, client['sha256'])
    output = absolute(a.output)
    need(str(output).startswith('/var/tmp/kpi-local-private-payment-01/'),
         'public-pool-output-root')
    need(not output.exists(), 'fresh-public-pool-role-output')
    need(output.name == 'result' and not output.parent.exists(),
         'fresh-pool-only-output-parent')
    request_path = absolute(request_path)
    need(str(request_path).startswith('/var/tmp/kpi-local-private-payment-01/'),
         'public-pool-request-root')
    need(request_path != output and output.parent not in request_path.parents,
         'request-outside-fresh-role-output')
    request = {'schema': 'kpxa-public-offline-role-job/v1', 'role': role,
               'argv': role_argv(a, role), 'files': job_files(a, role, guard)}
    raw = encoded(request) + b'\n'
    write_new(request_path, raw, 0o400)
    process = subprocess.run(['/usr/bin/python3', '-B', str(CLIENT),
        '--pool-selection', str(a.pool_selection), '--pool-selection-sha256', a.pool_selection_sha256,
        '--role', role, '--request', str(request_path), '--request-sha256', digest(raw),
        '--output', str(output)], env=CLEAN, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(process.returncode == 0 and not process.stderr, 'public-pool-fixed-role-incomplete')
    # The private controller may replace files while this offline job runs.
    # A fresh instance of the unchanged guard checks current private aliases
    # without retaining unrelated historical inode numbers across that wait.
    guard = HostPolicy()
    provenance = parse(guard.read(output / 'POOL-PROVENANCE.json'))
    need(provenance['schema'] == 'kpxa-public-offline-pool-provenance/v1'
         and provenance['pool_selection'] == {'path': str(a.pool_selection), 'sha256': a.pool_selection_sha256}
         and provenance['role'] == role
         and provenance['request'] == {'path': str(request_path), 'sha256': digest(raw)}
         and provenance['output'] == str(output)
         and provenance['stdout_sha256'] == digest(process.stdout)
         and provenance['network'] == 'none', 'exact-public-pool-export-provenance')
    summary = parse(process.stdout)
    if role == 'replay':
        result = parse(guard.read(output / 'RESULTS.json'))
        need(summary == result and result['submission_performed'] is False,
             'exported-replay-result-equals-fixed-role-stdout')
        return result
    need(summary['status'] == 'NATIVE_FINANCIAL_PREFLIGHT_PASS_PENDING_EXACT_LIVE_INPUT_QUERY'
         and summary['output'] == str(output), 'exported-preflight-summary')
    candidate = guard.read(output / 'SDK-CANDIDATE.json', summary['candidate_sha256'])
    parsed = parse(candidate)
    need(parsed['case_sha256'] == a.case_sha256 and parsed['trial_id'] == a.trial_id
         and parsed['stage'] == a.stage and parsed['mode'] == a.mode
         and parsed['actual_native_Full_passed'] is True
         and parsed['broadcast_performed'] is False, 'exported-preflight-exact-scope')
    return summary

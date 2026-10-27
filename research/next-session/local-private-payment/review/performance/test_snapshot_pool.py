#!/usr/bin/python3
"""Known-public SnapshotStore controls; never an owner or financial worker."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import time

REVIEW = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/local-private-payment/review')
BASELINE = {'path': str(REVIEW / 'PUBLIC-PYTHON-OS-CLOSURE-01.json'),
            'sha256': '5c0fb936dda86e5eb94721a3b1706b0594067c0d20cc67c65a824aed80e2bf35'}
PYTHON_DELTAS = {
    '/usr/lib/python3.14/os.py': '1494f3b93c6714d7a511963586f2b392dc92f3181c0d1ead82c621a4b0aad969',
    '/usr/lib/python3.14/base64.py': '202d288f0b6d25ed1b206640f86e934381e6766fa0496f6f8d87d9c1bf92cdef',
    '/usr/lib/python3.14/textwrap.py': '7f05d89c983f5aa8cefcff707a9cc561ed60c51fc8a68e2e3ab61cc6dfa84544'}
EXPECTED = b'KNOWN PUBLIC SNAPSHOT POOL INPUT VERSION ONE\n'
FIXTURE = r'''import hashlib,json,os,runpy,sys
from pathlib import Path
mode,source,output,absent=sys.argv[1:5]
out=Path(output)
out.mkdir(parents=True,exist_ok=True)
if mode=='probe':
    raw=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](source,sys.argv[5])
    assert raw==b'KNOWN PUBLIC SNAPSHOT POOL INPUT VERSION ONE\n'
    descriptors=[]
    for name in os.listdir('/proc/self/fd'):
        if int(name)>2:
            try:os.readlink('/proc/self/fd/'+name)
            except FileNotFoundError:continue
            descriptors.append(int(name))
    assert descriptors==[]
    assert not Path(absent).exists()
    assert not Path('/home/luke/.ssh').exists()
    assert not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists()
    changes={}
    for name,op in [('write',lambda:Path(source).write_bytes(b'FORBIDDEN')),
                    ('rename',lambda:Path(source).rename(source+'.renamed')),
                    ('hardlink',lambda:os.link(source,source+'.link'))]:
        try:op()
        except OSError:changes[name]='REFUSED'
        else:raise AssertionError('immutable input changed')
    result={'scope':'PUBLIC_ONLY_POOL_RUNTIME_CONTROL','input_sha256':hashlib.sha256(raw).hexdigest(),
            'inherited_nonstdio_fds':descriptors,'unrequested_target_unavailable':True,
            'input_mutations':changes,'owner_or_financial_authority':False}
    (out/'RESULTS.json').write_text(json.dumps(result,sort_keys=True)+'\n')
elif mode=='symlink':
    (out/'RESULTS.json').symlink_to(source)
elif mode=='hardlink':
    (out/'RESULTS.json').write_bytes(b'PUBLIC OUTPUT\n')
    os.link(out/'RESULTS.json',out/'SECOND.json')
elif mode=='fifo':
    os.mkfifo(out/'PIPE')
elif mode=='directory-symlink':
    (out/'LINKED-DIRECTORY').symlink_to(Path(source).parent,target_is_directory=True)
elif mode=='provenance':
    (out/'POOL-PROVENANCE.json').write_text('{"untrusted_success_flag":true}\n')
elif mode=='failure':
    (out/'RESULTS.json').write_text('{"untrusted_success_flag":true}\n')
    sys.stderr.write('KNOWN PUBLIC CHILD FAILURE\n')
    sys.exit(9)
elif mode=='empty':
    assert not Path(absent).exists()
else:raise AssertionError('unknown public mode')
'''


def pin(raw):
    return hashlib.sha256(raw).hexdigest()


def selected_module(read, path, expected, name):
    scope = {'__name__': name, '__file__': str(path)}
    exec(compile(read(str(path), expected), str(path), 'exec'), scope)
    return scope


def write_public(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def run(a):
    started = time.perf_counter()
    host = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    read = host['read']
    core = selected_module(read, a.core, a.core_sha256, '_pool_test_selected_core')
    admission = selected_module(read, a.admission, a.admission_sha256, '_pool_test_selected_admission')
    library = selected_module(read, a.library, a.library_sha256, '_pool_test_selected_library')
    supervisor = read(str(a.supervisor), a.supervisor_sha256)
    baseline = json.loads(read(BASELINE['path'], BASELINE['sha256']))
    static = {row['destination']: {'source': row['path'], 'target': row['destination'],
              'sha256': row['sha256'], 'mode': int(row['mode'], 8)} for row in baseline['files']}
    for path, expected in PYTHON_DELTAS.items():
        static[path] = {'source': path, 'target': path, 'sha256': expected, 'mode': 0o400}
    for path, expected in core['HELPER_PINS'].items():
        static[path] = {'source': path, 'target': path, 'sha256': expected, 'mode': 0o400}
    root = a.fixtures_root.absolute()
    assert '..' not in root.parts and not str(root).startswith('//') and not root.exists()
    assert all(root != protected and protected not in root.parents for protected in host['m'].GUARD.directories)
    for ancestor in root.parents:
        assert not ancestor.is_symlink()
    root.mkdir(parents=True, mode=0o700)
    (root / 'results').mkdir(mode=0o700)
    fixture, source = root / 'PUBLIC-FIXTURE.py', root / 'PUBLIC-INPUT.txt'
    write_public(fixture, FIXTURE.encode())
    write_public(source, EXPECTED)
    fixture_row = {'source': str(fixture), 'sha256': pin(FIXTURE.encode()), 'mode': 0o400}
    source_row = {'source': str(source), 'sha256': pin(EXPECTED), 'mode': 0o400}
    store = library['SnapshotStore'](core, admission, host['m'].GUARD.directories,
                                     supervisor, list(static.values()))
    controls, serial = [], 0

    def output(label):
        nonlocal serial
        serial += 1
        return root / 'results' / (str(serial).zfill(3) + '-' + label) / 'result'

    def execute(label, *, files=None, input_path=source, absent=None, mode='probe', dest=None):
        dest = output(label) if dest is None else dest
        argv = ['/usr/bin/python3.14', '-I', '-S', '-B', str(fixture), mode,
                str(input_path), str(dest), str(absent or root / 'NEVER-ADMITTED.txt'), pin(EXPECTED)]
        result = store.execute(argv, [fixture_row, source_row] if files is None else files, dest)
        return result, dest

    def success(label, **kwargs):
        result, dest = execute(label, **kwargs)
        assert result['returncode'] == 0 and not base64.b64decode(result['stderr_base64'],validate=True), result
        exported_read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        body = json.loads(exported_read(str(dest / 'RESULTS.json')))
        assert body['input_sha256'] == pin(EXPECTED) and body['inherited_nonstdio_fds'] == []
        assert body['unrequested_target_unavailable'] and body['owner_or_financial_authority'] is False
        assert set(body['input_mutations'].values()) == {'REFUSED'}
        controls.append({'name': label, 'status': 'PASS'})

    def refusal(label, function, *, allow_child_failure=False):
        try:
            result = function()
        except (ValueError, OSError, RuntimeError):
            controls.append({'name': label, 'status': 'EXPECTED_REFUSAL'})
            return
        if isinstance(result, tuple):
            result = result[0]
        assert allow_child_failure, ('invalid plan/export reached an application result',label,result)
        assert type(result) is dict and result['returncode'] != 0 and not result['exports'], result
        controls.append({'name': label, 'status': 'EXPECTED_REFUSAL'})

    try:
        success('known-public-unchanged-helper-readonly-and-zero-fds')
        source.chmod(0o600)
        source.write_bytes(b'KNOWN PUBLIC HOST INPUT VERSION TWO\n')
        source.chmod(0o400)
        fixture.chmod(0o600)
        fixture.write_bytes(b"raise RuntimeError('HOST PUBLIC CODE VERSION TWO')\n")
        fixture.chmod(0o400)
        success('admitted-code-and-input-survive-own-host-mutation')

        changed = {**source_row, 'sha256': pin(b'KNOWN PUBLIC HOST INPUT VERSION TWO\n')}
        refusal('known-source-pin-change', lambda: execute('changed-pin', files=[fixture_row, changed]))
        refusal('known-source-mode-change', lambda: execute('changed-mode', files=[fixture_row, {**source_row, 'mode': 0o500}]))
        refusal('double-leading-source-alias', lambda: execute('alias', files=[fixture_row, {**source_row, 'source': '/' + str(source)}]))
        refusal('dynamic-row-target-override', lambda: execute('target-override', files=[fixture_row, {**source_row, 'target': '/fixture/overridden'}]))
        protected = {'source': '/var/tmp/kpi-owner-private-lifecycle-01/private/POOL-FAKE-NOT-AN-ORIGINAL.txt',
                     'sha256': pin(EXPECTED), 'mode': 0o400}
        refusal('protected-source-selector-before-content', lambda: execute('protected', files=[fixture_row, source_row, protected]))

        uncommitted = root / 'PUBLIC-UNCOMMITTED.txt'
        write_public(uncommitted,EXPECTED)
        uncommitted_row = {'source':str(uncommitted),'sha256':pin(EXPECTED),'mode':0o400}
        refusal('failed-plan-with-valid-new-row-is-atomic',lambda:execute('atomic-plan',files=[fixture_row,uncommitted_row,changed]))
        uncommitted.chmod(0o600)
        uncommitted.write_bytes(b'KNOWN PUBLIC UNCOMMITTED VERSION TWO\n')
        uncommitted.chmod(0o400)
        refusal('rejected-plan-did-not-cache-new-source',lambda:execute('no-uncommitted-cache',files=[fixture_row,uncommitted_row],input_path=uncommitted))
        success('old-scope-usable-after-rejected-plans')

        duplicate = root / 'PUBLIC-SAME-BYTES.txt'
        write_public(duplicate, EXPECTED)
        duplicate_row = {'source': str(duplicate), 'sha256': pin(EXPECTED), 'mode': 0o400}
        success('new-public-path-same-bytes-admitted', files=[fixture_row, duplicate_row], input_path=duplicate)
        success('prior-unrequested-target-not-mounted', absent=duplicate)

        overlap = root / 'PUBLIC-OUTPUT-OVERLAP'
        overlap.mkdir(mode=0o700)
        overlap_input = overlap / 'PUBLIC-INPUT.txt'
        write_public(overlap_input,EXPECTED)
        overlap_row = {'source':str(overlap_input),'sha256':pin(EXPECTED),'mode':0o400}
        success('admit-overlap-fixture-before-host-removal',files=[fixture_row,overlap_row],input_path=overlap_input)
        overlap_input.unlink()
        overlap.rmdir()
        refusal('writable-parent-cannot-cover-cached-input',lambda:execute('input-overlap',files=[fixture_row,overlap_row],input_path=overlap_input,dest=overlap/'result'))

        linked = root / 'PUBLIC-HARDLINK-A.txt'
        write_public(linked, EXPECTED)
        second = root / 'PUBLIC-HARDLINK-B.txt'
        os.link(linked, second)
        link_row = {'source': str(linked), 'sha256': pin(EXPECTED), 'mode': 0o400}
        refusal('new-same-hash-hardlink-still-guard-admitted', lambda: execute('hardlinked-source', files=[fixture_row, link_row], input_path=linked))
        symlink = root / 'PUBLIC-SYMLINK.txt'
        symlink.symlink_to(duplicate)
        refusal('new-same-hash-symlink-still-guard-admitted', lambda: execute('symlinked-source', files=[fixture_row, {'source': str(symlink), 'sha256': pin(EXPECTED), 'mode': 0o400}], input_path=symlink))

        inherited = os.open(duplicate, os.O_RDONLY)
        try:
            os.set_inheritable(inherited, True)
            success('inheritable-public-host-fd-does-not-reach-app')
        finally:
            os.close(inherited)
        refusal('exported-symlink-rejected', lambda: execute('bad-export-symlink', mode='symlink'))
        refusal('exported-hardlinks-rejected', lambda: execute('bad-export-hardlink', mode='hardlink'))
        refusal('exported-fifo-rejected-before-open', lambda: execute('bad-export-fifo', mode='fifo'))
        refusal('exported-directory-symlink-rejected', lambda: execute('bad-export-directory-link', mode='directory-symlink'))
        refusal('application-cannot-export-pool-provenance', lambda: execute('bad-provenance', mode='provenance'))
        refusal('failed-child-success-looking-output-rejected', lambda: execute('failed-child', mode='failure'),allow_child_failure=True)
        refusal('output-dotdot-rejected', lambda: execute('dotdot-output', dest=root / 'results' / '..' / 'ESCAPE' / 'result'))
        refusal('output-double-leading-alias-rejected', lambda: execute('alias-output', dest=Path('/' + str(output('alias-destination')))))
        refusal('output-cannot-replace-selected-source', lambda: execute('existing-output', dest=source))
        success('old-valid-job-after-all-failures')
        result, empty_out = execute('fresh-output-has-no-previous-result', mode='empty')
        assert result['returncode'] == 0 and not result['exports'] and not (empty_out / 'RESULTS.json').exists(), result
        controls.append({'name': 'fresh-output-has-no-previous-result', 'status': 'PASS'})
    finally:
        store.close()

    report = {'schema': 'kpxa-public-snapshot-pool-runtime-controls/v1',
              'scope': 'KNOWN_PUBLIC_FIXTURES_NOT_FINANCIAL_OR_OWNER_ACCEPTANCE',
              'sources': {str(a.library): a.library_sha256, str(a.core): a.core_sha256,
                          str(a.supervisor): a.supervisor_sha256, str(a.admission): a.admission_sha256},
              'fixtures_root': str(root), 'controls': controls, 'passed': len(controls),
              'payment_owner_ledger_network_prover_or_GPU_execution': False,
              'private_content_reads': False, 'live_sources_or_callers_modified': False,
              'seconds': time.perf_counter() - started}
    raw = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
    write_public(a.output, raw)
    return {'path': str(a.output), 'sha256': pin(raw), 'passed': len(controls)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('library', 'core', 'supervisor', 'admission'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--fixtures-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(run(parser.parse_args()), sort_keys=True))

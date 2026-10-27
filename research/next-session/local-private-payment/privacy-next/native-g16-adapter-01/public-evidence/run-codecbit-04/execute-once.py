import hashlib
import json
import os
import runpy
import stat
import struct
import subprocess
import time

OWNED = '/dev/shm/kpi-native-g16-adapter-01'
RUN = OWNED + '/run-codecbit-04'
SELECTION_SHA = 'fb565a3c7bff09c189589134878f166abac3f9e12006785bedac9077665f49fa'
H = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')


def read(path, sha=None):
    return H['read'](path, sha)


def identity(path, sha=None):
    b = read(path, sha)
    return {'path': path, 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def memory():
    out = {}
    with open('/proc/meminfo') as f:
        for line in f:
            key, value = line.split(':', 1)
            if key in ('MemTotal', 'MemAvailable', 'SwapFree'):
                out[key] = int(value.split()[0]) * 1024
    return out


def allocated():
    seen = set()
    total = 0
    for base, dirs, files in os.walk(OWNED, followlinks=False):
        for name in files + dirs:
            s = os.lstat(os.path.join(base, name))
            k = (s.st_dev, s.st_ino)
            if k not in seen:
                total += s.st_blocks * 512
                seen.add(k)
    return total


def dump(path, obj):
    with open(path, 'x') as f:
        json.dump(obj, f, indent=2)
        f.write('\n')


selection = json.loads(read(RUN + '/SELECTION.json', SELECTION_SHA))
assert not os.path.exists(RUN + '/EXECUTION.json')
assert not os.path.lexists(selection['binary'])
for row in selection['source_members']:
    assert identity(row['path'], row['sha256']) == row
read(selection['source_preparation']['path'], selection['source_preparation']['sha256'])
spec_path = selection['build_cwd'].removesuffix('/adapter') + '/RUN-SPEC-03.md'
read(spec_path, selection['run_spec_sha256'])
assert allocated() < selection['optional_scratch_max_bytes']

out = {
    'schema': 'kpxa-native-g16-codec-execution/v1',
    'selection_sha256': SELECTION_SHA,
    'scope': selection['scope'],
    'status': 'IN_PROGRESS',
    'started_unix_seconds': time.time(),
    'preflight_memory': memory(),
    'preflight_optional_allocated_bytes': allocated(),
    'stages': [],
    'resource_limitation': 'GNUtime MaxRSS is not an aggregate-process RSS sum. Own cgroup counters are observed only while the scope exists; missing final counters remain unknown.',
}


def stage(name, argv, unit):
    record = {'name': name, 'argv': argv, 'started_unix_seconds': time.time(),
              'maximum_observed_cgroup_memory_peak_bytes': None,
              'maximum_observed_cgroup_memory_current_bytes': None,
              'last_observed_cpu_stat': None, 'observed_cgroup_paths': []}
    out['stages'].append(record)
    cgroup = '/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/' + unit + '.scope'
    with open(RUN + '/' + name + '-STDOUT.txt', 'xb') as stdout, open(RUN + '/' + name + '-STDERR.txt', 'xb') as stderr:
        process = subprocess.Popen(argv, cwd=selection['build_cwd'], stdout=stdout, stderr=stderr)
        last_scratch = 0
        while True:
            if os.path.isdir(cgroup):
                if cgroup not in record['observed_cgroup_paths']:
                    record['observed_cgroup_paths'].append(cgroup)
                for filename, key in [('memory.peak', 'maximum_observed_cgroup_memory_peak_bytes'), ('memory.current', 'maximum_observed_cgroup_memory_current_bytes')]:
                    try:
                        with open(cgroup + '/' + filename) as f:
                            value = int(f.read())
                        record[key] = max(record[key] or 0, value)
                    except FileNotFoundError:
                        pass
                try:
                    with open(cgroup + '/cpu.stat') as f:
                        record['last_observed_cpu_stat'] = f.read()
                except FileNotFoundError:
                    pass
            if time.monotonic() - last_scratch >= 1:
                record['last_observed_optional_allocated_bytes'] = allocated()
                last_scratch = time.monotonic()
                if record['last_observed_optional_allocated_bytes'] > selection['optional_scratch_max_bytes']:
                    subprocess.run(['/usr/bin/systemctl', '--user', 'stop', unit + '.scope'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    process.wait()
                    raise RuntimeError('owned optional scratch exceeded selected ceiling')
            code = process.poll()
            if code is not None:
                break
            time.sleep(0.02)
    record.update(exit_code=code, finished_unix_seconds=time.time())
    record['wall_seconds'] = record['finished_unix_seconds'] - record['started_unix_seconds']
    if code != 0:
        raise RuntimeError(name + ' exited ' + str(code))


try:
    stage('BUILD', selection['build_argv'], 'kpi-native-g16-codecbit-build-04')
    binary = read(selection['binary'])
    assert binary[:6] == b'\x7fELF\x02\x01'
    phoff = struct.unpack_from('<Q', binary, 32)[0]
    entsize, count = struct.unpack_from('<HH', binary, 54)
    assert all(struct.unpack_from('<I', binary, phoff + i * entsize)[0] != 3 for i in range(count))
    out['binary'] = {'path': selection['binary'], 'bytes': len(binary), 'sha256': hashlib.sha256(binary).hexdigest(), 'elf64_little_endian_no_PT_INTERP': True}
    del binary
    stage('SOLVE', selection['runtime_argv'], 'kpi-native-g16-codecbit-solve-04')
    result_bytes = read(RUN + '/SOLVE-STDOUT.txt')
    result = json.loads(result_bytes)
    out['codec_result_identity'] = {'path': RUN + '/SOLVE-STDOUT.txt', 'bytes': len(result_bytes), 'sha256': hashlib.sha256(result_bytes).hexdigest()}
    assert result['status'] == 'PASS_FROZEN_ENCODING_ONLY_CONTROLS'
    assert result['run_spec_sha256'] == selection['run_spec_sha256']
    assert result['scope'] == selection['scope']
    assert len(result['systems']) == 2 and len(result['cases']) == 42
    for system in result['systems']:
        assert system['commitments'] == 0
        for key, expected in selection['expected_systems'][system['name']].items():
            assert system[key] == expected, ('compiled identity changed', key)
    prior = json.loads(read(OWNED + '/run-codecbit-03/SOLVE-STDOUT.txt', '5e5357de2214bfcf8c75dc4a7b7bb55019a429396cf9b6fc072af02b5e33f190'))
    cases = {case['name']: case for case in result['cases']}
    for case in prior['cases']:
        actual = cases[case['name']]
        assert {k:v for k,v in case.items() if k != 'wall_ms'} == {k:v for k,v in actual.items() if k != 'wall_ms'}
    assert sum(c['classification'] == 'ACCEPT' for c in result['cases']) == 13
    assert sum(c['classification'] == 'UNSATISFIED' for c in result['cases']) == 29
    assert all(c['matches'] for c in result['cases'])
    assert all(not result[k] for k in ['groth16_verified','curve_claims_for_field_controls','setup_or_proof_performed','privacy_claim'])
    out.update(status='PASS_RAW_ENCODING_ONLY_RESULT_RETAINED_FOR_CANONICAL_CID_REVIEW', codec_status=result['status'], codec_case_count=42, codec_system_count=2, original40_verdicts_and_residuals_unchanged=True, exact_prior_compiled_system_identities=True)
except BaseException as e:
    out.update(status='FIRST_UNEXPECTED_RESULT_RETAINED', error_class=type(e).__name__, error=str(e))
finally:
    out.update(finished_unix_seconds=time.time(), postflight_memory=memory(), postflight_optional_allocated_bytes=allocated())
    try:
        for row in selection['source_members']:
            assert identity(row['path'], row['sha256']) == row
        out['selected_source_bytes_unchanged'] = True
    except BaseException as e:
        out.update(status='FIRST_UNEXPECTED_RESULT_RETAINED', selected_source_bytes_unchanged=False, source_error=str(e))
    dump(RUN + '/EXECUTION.json', out)
    print(json.dumps({'status': out['status'], 'record': RUN + '/EXECUTION.json', 'stages': [{'name': s['name'], 'exit_code': s.get('exit_code'), 'wall_seconds': s.get('wall_seconds')}for s in out['stages']]}), flush=True)

if out['status'] != 'PASS_RAW_ENCODING_ONLY_RESULT_RETAINED_FOR_CANONICAL_CID_REVIEW':
    raise SystemExit(2)

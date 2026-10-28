#!/usr/bin/python3
import hashlib
import json
from pathlib import Path
import runpy
import threading
import time
import types

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
OUT = ROOT/'.local/recovery-publication-resume-20261028-01/public-pool-controls-02'
OUT.mkdir(mode=0o700, exist_ok=False)
POOL = ROOT/'poc/local-private-payment/recovery/public_admission_pool.py'
POOL_SHA = 'a27c1a0760429219c3f809df5b1214ff9d194cb85e11e5d029d5d420a0927385'
guard = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
pool = types.ModuleType('selected_public_admission_pool')
pool.__file__ = str(POOL)
exec(compile(guard['read'](POOL, POOL_SHA), str(POOL), 'exec'), pool.__dict__)
source = ROOT/'poc/local-private-payment/recovery/final_publication_launch_large.py'
raw = guard['read'](source, pool.BASE_SHA)
selected = {'source': str(source), 'sha256': pool.BASE_SHA, 'bytes': len(raw)}
base = pool.base_module(guard, selected)


def fixtures(label, count=16):
    directory = OUT/label
    directory.mkdir(mode=0o700)
    rows = []
    for i in range(count):
        raw = ('PUBLIC_ONLY_POOL_CONTROL_'+str(i)+'\n').encode()
        path = directory/(str(i)+'.txt')
        path.write_bytes(raw)
        rows.append({'source': str(path), 'path': str(i)+'.txt', 'bytes': len(raw),
                     'sha256': hashlib.sha256(raw).hexdigest()})
    return rows


def runtime(label):
    directory = OUT/label
    directory.mkdir(mode=0o700)
    return directory


records = []
rows = fixtures('ordered-input')
start = time.monotonic()
serial = [base.candidate_entry(guard, row, i, runtime('serial') if i == 0 else OUT/'serial')
          for i, row in enumerate(rows)]
serial_seconds = time.monotonic()-start
start = time.monotonic()
parallel = pool.admit(rows, runtime('parallel'), selected, POOL_SHA, base, guard)
parallel_seconds = time.monotonic()-start
assert len(serial) == len(parallel) == len(rows)
for i, (left, right) in enumerate(zip(serial, parallel)):
    assert left[1:] == right[1:]
    data = guard['read'](right[0], rows[i]['sha256'])
    assert len(data) == rows[i]['bytes']
records.append({'control': 'sixteen-real-public-admissions-match-serial-order-and-bytes',
                'status': 'PASS', 'files': 16, 'serial_seconds': serial_seconds,
                'parallel_seconds': parallel_seconds})

wrong = fixtures('wrong-sha-input', 2)
wrong[0]['sha256'] = '0'*64
try:
    pool.admit(wrong, runtime('wrong-sha'), selected, POOL_SHA, base, guard)
except ValueError:
    records.append({'control': 'wrong-expected-sha-refuses', 'status': 'PASS'})
else:
    raise AssertionError('wrong SHA admitted')

race = fixtures('race-input')
race_runtime = runtime('race')
changed = threading.Event()


def writer():
    while not (race_runtime/'candidates/0.bin').exists():
        time.sleep(0.01)
    Path(race[0]['source']).write_bytes(b'MUTATED_PUBLIC_FIXTURE\n')
    changed.set()


thread = threading.Thread(target=writer, daemon=True)
thread.start()
try:
    pool.admit(race, race_runtime, selected, POOL_SHA, base, guard)
except ValueError:
    assert changed.is_set()
    records.append({'control': 'source-mutation-after-child-read-refuses', 'status': 'PASS'})
else:
    raise AssertionError('changed source admitted')
thread.join()

boundary = fixtures('boundary-input', 2)
large = OUT/'boundary-input/exact-64MiB.bin'
with large.open('xb') as stream:
    stream.truncate(pool.PARALLEL_LIMIT)
raw = guard['read'](large)
boundary.append({'source': str(large), 'path': 'exact-64MiB.bin', 'bytes': len(raw),
                 'sha256': hashlib.sha256(raw).hexdigest()})
del raw
admitted = pool.admit(boundary, runtime('boundary'), selected, POOL_SHA, base, guard)
assert admitted[2][0] == large and admitted[2][3] is True
records.append({'control': 'exact-64MiB-serial-boundary-with-real-bytes', 'status': 'PASS'})

private = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01/public-admission-synthetic-control-02')
private.mkdir(mode=0o700, exist_ok=False)
marker = b'SYNTHETIC_PUBLIC_MARKER_NO_WALLET_OR_SECRET\n'
leaf = private/'SYNTHETIC-PUBLIC-MARKER.bin'
leaf.write_bytes(marker)
leaf.chmod(0o400)
private_row = [{'source': str(leaf), 'path': 'synthetic-marker', 'bytes': len(marker),
                'sha256': hashlib.sha256(marker).hexdigest()}]
try:
    pool.admit(private_row, runtime('private-origin'), selected, POOL_SHA, base, guard)
except ValueError:
    records.append({'control': 'guard09-protected-origin-refuses-known-public-marker', 'status': 'PASS',
                    'actual_originals_or_private_values_used': False})
else:
    raise AssertionError('protected origin admitted')

result = {'schema': 'kpi-parallel-public-admission-controls/v1', 'status': 'PASS',
          'source_sha256': POOL_SHA, 'controls': records,
          'actual_originals_opened_read_or_hashed': False,
          'private_wallet_or_truth_used': False}
(OUT/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))

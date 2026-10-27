"""Exact public artifact reuse only; execute after Root's selected run02 GO."""
from pathlib import Path
import hashlib
import json
import os
import runpy

GUARD = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
SOURCE = Path('/dev/shm/kpi-two-owner-aggregate-scratch-01/run-01')
TARGET = SOURCE.parent / 'run-02'
CASE_SHA = 'da00ccd3471b15f3531aafb8069f3d5164ff673adfd94a37e88d418871974d57'
COMPILED_SHA = '99d1079afb8bc9b2344a41b67d8afdd1a794594514b839c499f427592d7f8413'
HANDOFF_SHA = '284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218'


def read(path, expected=None):
    return GUARD['read'](str(path), expected)


case_raw = read(SOURCE / 'CASE-SELECTION.json', CASE_SHA)
compiled_raw = read(SOURCE / 'COMPILED-SELECTION.json', COMPILED_SHA)
cases, compiled = json.loads(case_raw), json.loads(compiled_raw)
ids = [f'P{i:02d}' for i in range(1, 8)] + [f'N{i:02d}' for i in range(1, 23)]
assert [r['id'] for r in cases['rows']] == ids
assert all(r['actualCheckerRequired'] is True and r['expectedAccepted'] is (i < 7)
           for i, r in enumerate(cases['rows']))
paths = {'ordinaryR1cs': 'build-ordinary/aggregate.r1cs', 'cppR1cs': 'build-cpp/aggregate.r1cs',
         'cppGenerator': 'build-cpp/aggregate_cpp/aggregate',
         'cppData': 'build-cpp/aggregate_cpp/aggregate.dat', 'sym': 'build-ordinary/aggregate.sym'}
assert set(compiled) == {'schema', *paths}
assert compiled['schema'] == 'two-owner-aggregate-compiled-selection/v1'
selected = [{'path': 'HANDOFF.json', 'sha256': HANDOFF_SHA, 'bytes': 173104},
            {'path': 'CASE-SELECTION.json', 'sha256': CASE_SHA, 'bytes': len(case_raw)},
            {'path': 'COMPILED-SELECTION.json', 'sha256': COMPILED_SHA, 'bytes': len(compiled_raw)}]
for row in cases['rows']:
    assert row['input']['path'] == 'cases/' + row['id'] + '.json'
    selected.append(row['input'])
for key, name in paths.items():
    assert compiled[key]['path'] == name
    selected.append(compiled[key])
assert len(selected) == 37 and len({r['path'] for r in selected}) == 37
TARGET.mkdir(mode=0o700, exist_ok=False)
copied = []
for row in selected:
    raw = read(SOURCE / row['path'], row['sha256'])
    assert len(raw) == row['bytes']
    target = TARGET / row['path']
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with target.open('xb') as stream:
        assert stream.write(raw) == len(raw)
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o500 if row['path'] == paths['cppGenerator'] else 0o600)
    assert read(target, row['sha256']) == raw
    copied.append(dict(row))
record = {'schema': 'two-owner-aggregate-run02-exact-reuse/v1', 'copiedFiles': copied,
          'sourceRun01Unchanged': True, 'freshRun02': True, 'allFullBytesCompared': True,
          'noReprepareRecompileRekey': True, 'noStopResultOrWitnessCopied': True,
          'caseSelectionSHA256': CASE_SHA, 'compiledSelectionSHA256': COMPILED_SHA,
          'logicalBytesCopied': sum(r['bytes'] for r in copied)}
data = (json.dumps(record, indent=2) + '\n').encode()
with (TARGET / 'COPY-RECORD.json').open('xb') as stream:
    stream.write(data)
print(json.dumps({'files': len(copied), 'logicalBytesCopied': record['logicalBytesCopied'],
                  'copyRecordSHA256': hashlib.sha256(data).hexdigest(),
                  'caseSelectionSHA256': CASE_SHA, 'compiledSelectionSHA256': COMPILED_SHA}))

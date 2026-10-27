#!/usr/bin/env python3
"""Known-public opaque-byte controls; never construct accepted financial history."""
import argparse
import ast
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import tarfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    source = Path(__file__).absolute().with_name('prepare_data_packet_batched.py')
    source_raw = read(str(source), args.source_sha256)
    module = {'__name__': '_public_batched_packet_controls', '__file__': str(source)}
    exec(compile(source_raw, str(source), 'exec'), module)
    base = module['pinned_preimage']()
    controls = []

    def check(name, function):
        function()
        controls.append({'control': name, 'passed': True})

    def rejects(name, function):
        try:
            function()
        except (ValueError, OSError, KeyError, tarfile.TarError):
            controls.append({'control': name, 'passed': True})
            return
        raise AssertionError('expected-public-fixture-refusal:' + name)

    token = uuid.uuid4().hex
    control_root = Path('/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01') / ('batched-public-controls-' + token)
    control_root.mkdir(mode=0o700)
    fixture = control_root / 'fixture'
    fixture.mkdir(mode=0o700)
    save = base['write_new']
    dig = module['sha']
    known = [b'KNOWN PUBLIC WHOLE MAIN PAGE\x00\xff\n', b'KNOWN PUBLIC WHOLE POST QUERY PAGE\n']
    compressed = [gzip.compress(known[0], mtime=0),
                  gzip.compress(known[1][:12], mtime=0) + gzip.compress(known[1][12:], mtime=0)]
    names = ['chain/attempt/pages/00000.json.gz', 'chain/attempt/post-query/pages/00000.json.gz']
    rows = []
    pages = {}
    for number, name in enumerate(names):
        path = fixture / ('page-%d.gz' % number)
        save(path, compressed[number])
        rows.append({'source': str(path), 'path': name, 'bytes': len(compressed[number]),
                     'sha256': dig(compressed[number]), 'kind': 'full-source-page'})
        pages[name] = {'path': name[len('chain/'):], 'request': {'known_public_fixture': True},
            'decoded_bytes': len(known[number]), 'decoded_sha256': dig(known[number]),
            'gzip_bytes': len(compressed[number]), 'gzip_sha256': dig(compressed[number]),
            'encoding': 'KNOWN_PUBLIC_OPAQUE_BYTES_NOT_ACCEPTED_HISTORY'}
    opaque = b'{ "fixture" : "KNOWN PUBLIC OPAQUE METADATA", "timing" : 1.25 }\n'
    opaque_path = fixture / 'spacing.json'
    save(opaque_path, opaque)
    opaque_row = {'source': str(opaque_path), 'path': 'evidence/spacing.json', 'bytes': len(opaque),
                  'sha256': dig(opaque), 'kind': 'public-evidence'}
    rows.append(opaque_row)
    rows.sort(key=lambda row: row['path'])
    role_rows = {name: opaque_row for name in base['ROLES']}
    fetch = {'pages': [pages[names[0]]], 'current_view': {'post_query_delta': {'pages': [pages[names[1]]]}}}
    check('both-public-main-and-post-query-page-closure', lambda: base['page_contract'](fetch, rows))
    rejects('missing-post-query-page', lambda: base['page_contract'](fetch, rows[:1] + rows[2:]))
    extra = dict(rows[0]); extra['path'] = 'chain/extra.gz'
    rejects('extra-public-page', lambda: base['page_contract'](fetch, [*rows, extra]))
    decoded = module['decode_verify_discard'](base, read, rows, pages)
    check('all-gzip-members-verified-and-discarded', lambda: None if len(decoded) == 2
          and not (control_root / 'decoded').exists() else (_ for _ in ()).throw(AssertionError()))
    wrong_pages = copy.deepcopy(pages); wrong_pages[names[1]]['decoded_sha256'] = '00' * 32
    rejects('decoded-SHA-mismatch-before-materialization',
            lambda: module['decode_verify_discard'](base, read, rows, wrong_pages))
    wrong_pages = copy.deepcopy(pages); wrong_pages[names[0]]['decoded_bytes'] -= 1
    rejects('decoded-size-mismatch-before-materialization',
            lambda: module['decode_verify_discard'](base, read, rows, wrong_pages))
    raw_bad = compressed[0] + b'NOT GZIP'
    bad_record = dict(pages[names[0]], gzip_bytes=len(raw_bad), gzip_sha256=dig(raw_bad))
    rejects('non-gzip-trailing-data-refused', lambda: list(base['decoded_chunks'](raw_bad, bad_record)))
    check('original239bb-still-pinned', lambda: read(str(source.with_name('prepare_data_packet.py')),
          '239bb48bfc25a65390940d7fcdc9c128437e82ed12702aeb73d7d38ba9c72de0'))

    output = control_root / 'packet'
    output.mkdir(mode=0o700)
    aliases, packet = module['write_packet'](base, read, rows, role_rows, decoded, output)
    # Evaluate only original metadata expressions, never the financial preflight
    # or original prepare(). No fixture accepted HISTORY/CONTEXT is constructed.
    preimage_raw = read(str(source.with_name('prepare_data_packet_tmpfs.py')), module['PREIMAGE_SHA'])
    old_prepare = next(node for node in ast.parse(preimage_raw).body
                       if isinstance(node, ast.FunctionDef) and node.name == 'prepare')
    assignments = {node.targets[0].id: node for node in old_prepare.body
                   if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    expected = dict(base)
    expected.update(rows=rows, role_rows=role_rows, decoded_rows=decoded)
    for name in ('inventory_rows', 'inventory', 'inventory_raw'):
        exec(compile(ast.Module(body=[assignments[name]], type_ignores=[]), '<pinned-metadata-expression>', 'exec'), expected)
    payloads = {row['path']: read(row['source'], row['sha256']) for row in rows}
    payloads['DATA-INVENTORY.json'] = expected['inventory_raw']
    expected['archive_raw'] = base['canonical_tar'](payloads)
    for name in ('packet', 'packet_raw', 'sums'):
        exec(compile(ast.Module(body=[assignments[name]], type_ignores=[]), '<pinned-metadata-expression>', 'exec'), expected)
    expected_objects = {'data.tar': expected['archive_raw'], 'DATA-INVENTORY.json': expected['inventory_raw'],
                        'PACKET.json': expected['packet_raw'], 'SHA256SUMS': expected['sums']}
    for name, raw in expected_objects.items():
        check('exact-e958-known-public-object-byte-parity-' + name,
              lambda name=name, raw=raw: None if read(str(output / name), dig(raw)) == raw
              else (_ for _ in ()).throw(AssertionError()))
    check('no-raw-member-physical-extraction', lambda: None if sorted(p.name for p in output.iterdir())
          == sorted(expected_objects) else (_ for _ in ()).throw(AssertionError()))
    archive_raw = read(str(output / 'data.tar'), packet['archive']['sha256'])
    check('strict-member-source-alias-equality', lambda: module['verify_member_aliases'](base, read, archive_raw, aliases))
    altered = bytearray(archive_raw); altered[100] ^= 1
    rejects('changed-canonical-header-refused', lambda: module['verify_member_aliases'](base, read, bytes(altered), aliases))
    rejects('appended-tar-data-refused', lambda: module['verify_member_aliases'](base, read, archive_raw + b'PUBLIC', aliases))
    wrong_aliases = copy.deepcopy(aliases); wrong_aliases[names[0]]['sha256'] = '00' * 32
    rejects('wrong-alias-SHA-refused', lambda: module['verify_member_aliases'](base, read, archive_raw, wrong_aliases))
    index = module['candidate_index'](base, read, rows, pages, aliases, packet, output, '11' * 32)
    index_raw = module['encoded'](index); index_sha = dig(index_raw)
    budget = max(map(len, known))
    plan = module['batch_plan'](base, index, index_sha, budget)
    plan_raw = module['encoded'](plan); plan_sha = dig(plan_raw)
    check('deterministic-whole-page-greedy-plan', lambda: None if len(plan['batches']) == 3
          and module['batch_plan'](base, index, index_sha, budget) == plan else (_ for _ in ()).throw(AssertionError()))
    check('exact-disjoint-global-index-union', lambda: None if
          [i for batch in plan['batches'] for i in batch['candidate_indices']] == list(range(len(index['candidates'])))
          else (_ for _ in ()).throw(AssertionError()))
    check('nonempty-whole-page-batches', lambda: None if all(batch['candidate_indices'] for batch in plan['batches'])
          and all(batch['bytes'] <= budget for batch in plan['batches'][1:]) else (_ for _ in ()).throw(AssertionError()))
    rejects('page-larger-than-operator-budget-refused', lambda: module['batch_plan'](base, index, index_sha, budget - 1))
    rejects('boolean-budget-refused', lambda: module['batch_plan'](base, index, index_sha, True))
    rejects('zero-budget-refused', lambda: module['batch_plan'](base, index, index_sha, 0))
    for name, mutate in [
        ('duplicate-global-coverage', lambda p: p['batches'][1]['candidate_indices'].append(p['batches'][1]['candidate_indices'][0])),
        ('omitted-global-coverage', lambda p: p['batches'].pop()),
        ('empty-decoded-batch', lambda p: p['batches'][1].update(candidate_indices=[])),
        ('wrong-batch-byte-total', lambda p: p['batches'][1].update(bytes=0)),
        ('changed-global-index-pin', lambda p: p.update(global_index_sha256='00' * 32)),
        ('boolean-candidate-index-refused', lambda p: p['batches'][0]['candidate_indices'].__setitem__(1, True)),
        ('boolean-batch-byte-count-refused', lambda p: p['batches'][0].update(bytes=True)),
    ]:
        wrong = copy.deepcopy(plan); mutate(wrong)
        rejects(name, lambda wrong=wrong: module['validate_plan'](base, index, index_sha, wrong))
    for name, mutate in [
        ('noncontiguous-global-index', lambda i: i['candidates'][0].update(index=99)),
        ('duplicate-global-path', lambda i: i['candidates'][1].update(path=i['candidates'][0]['path'])),
        ('decoded-source-alias-not-null', lambda i: i['candidates'][-1].update(source=str(opaque_path))),
        ('decoded-gzip-member-join-tamper', lambda i: i['candidates'][-1]['gzip'].update(sha256='00' * 32)),
        ('whole-archive-identity-tamper', lambda i: i['archive'].update(sha256='00' * 32)),
        ('private-source-prefix-refused', lambda i: i['candidates'][0].update(source='/var/tmp/kpi-local-original-metadata-01/not-read.json')),
    ]:
        wrong = copy.deepcopy(index); mutate(wrong)
        rejects(name, lambda wrong=wrong: module['validate_index'](base, wrong))
    index_path, plan_path = control_root / 'GLOBAL-CANDIDATE-INDEX.json', control_root / 'BATCH-PLAN.json'
    save(index_path, index_raw); save(plan_path, plan_raw)
    shm = base['SHM_OUTPUT_BASE']
    if not shm.exists():
        shm.mkdir(mode=0o700)
    info = shm.lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
    for number, batch in enumerate(plan['batches'][1:], 1):
        result = module['materialize'](index_path, index_sha, plan_path, plan_sha, batch['batch_id'],
                                      shm / ('batched-public-' + token + '-D%d' % number))
        descriptor = base['parse'](read(result['descriptor']['path'], result['descriptor']['sha256']))
        assert result['verified_candidate_indices'] == batch['candidate_indices']
        assert result['whole_decoded_pages'] is True and result['gzip_and_decoded_identities_verified'] is True
        assert descriptor['candidate_indices'] == batch['candidate_indices']
        for row in descriptor['files']:
            raw = read(row['source'], row['sha256'])
            assert len(raw) == row['bytes'] and raw in known
        check('whole-decoded-batch-materialized-exactly-' + batch['batch_id'], lambda: None)
        check('decoded-original-artifact-path-retained-' + batch['batch_id'], lambda descriptor=descriptor:
              None if all(row['path'].startswith('decoded-gzip/chain/') for row in descriptor['files'])
              else (_ for _ in ()).throw(AssertionError()))
    rejects('existing-batch-descriptor-refused', lambda: module['materialize'](index_path, index_sha,
        plan_path, plan_sha, 'D000001', shm / ('batched-public-' + token + '-repeat')))
    rejects('raw-BASE-not-decoded-materialization', lambda: module['materialize'](index_path, index_sha,
        plan_path, plan_sha, 'BASE', shm / ('batched-public-' + token + '-base')))
    rejects('disk-decoded-materialization-refused', lambda: module['materialize'](index_path, index_sha,
        plan_path, plan_sha, 'D000002', base['OUTPUT_BASE'] / ('batched-public-' + token + '-disk')))
    report = {'schema': 'kpxa-known-public-batched-packet-controls/v1',
        'source_sha256': dig(source_raw), 'immutable_preimage_sha256': module['PREIMAGE_SHA'],
        'all_passed': True, 'control_count': len(controls), 'controls': controls,
        'fixtures': 'KNOWN_PUBLIC_OPAQUE_BYTES_ONLY_NOT_ACCEPTED_HISTORY',
        'actual_terminal_selection_or_packet': False, 'private_original_or_worker_used': False,
        'network_or_publication_executed': False, 'old_source_or_software02_changed': False}
    save(args.report, (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'all_passed': True, 'controls': len(controls), 'report': str(args.report)}, sort_keys=True))


if __name__ == '__main__':
    main()

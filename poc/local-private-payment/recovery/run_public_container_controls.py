"""Known-public byte controls only; no final selection/history/private worker."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import runpy
import tarfile


def main():
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    source = '/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01/prepare_data_packet.py'
    raw_source = read(source)
    module = {'__name__': '_known_public_container_controls', '__file__': source}
    exec(compile(raw_source, source, 'exec'), module)
    Refused = module['Refused']
    rows = []

    def check(name, function):
        function()
        rows.append({'control': name, 'passed': True})

    def rejects(name, function):
        try:
            function()
        except (Refused, ValueError):
            rows.append({'control': name, 'passed': True})
            return
        raise AssertionError('public-control-expected-refusal')

    payload = {'z/data.bin': b'KNOWN PUBLIC BYTES\x00\xff NOT A PRIVATE WITNESS',
               'a/spacing.json': b'{ "known" : "public" , "n" : 1 }\n'}
    archive = module['canonical_tar'](payload)

    def roundtrip():
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as reader:
            members = reader.getmembers()
            assert [x.name for x in members] == sorted(payload)
            for item in members:
                assert item.type == tarfile.REGTYPE and not item.pax_headers and item.linkname == ''
                assert item.mode == 0o400 and item.uid == item.gid == item.mtime == 0
                assert item.uname == item.gname == '' and item.offset_data - item.offset == 512
                assert reader.extractfile(item).read() == payload[item.name]
    check('exact-byte-roundtrip-regular-members', roundtrip)
    check('deterministic-sorted-canonical-USTAR', lambda: None if module['canonical_tar'](payload) == archive
          else (_ for _ in ()).throw(AssertionError('tar-not-deterministic')))
    for name in ('../escape', '/absolute', 'a//b', 'a/./b', '.hidden/file', 'a\\b'):
        rejects('unsafe-path-' + name.replace('/', '_'), lambda name=name: module['relative'](name))
    rejects('backup-source-refused', lambda: module['public_source']('/var/tmp/known-public/BACKUP.json'))
    rejects('PK-source-refused', lambda: module['public_source']('/var/tmp/known-public/parameters.pk'))
    rejects('private-parent-refused', lambda: module['public_source']('/var/tmp/known-public/private/object.json'))
    rejects('original-metadata-refused', lambda: module['public_source']('/var/tmp/known-public/ORIGINALS-02.json'))
    rejects('raw-log-source-refused', lambda: module['public_source']('/var/tmp/known-public/raw.log'))
    for name in ('BACKUP-copy.json', 'OWNER-copy.json', 'private_plan.json', 'privateplan.json',
                 'INVOICE208.bin', 'raw-log.txt', 'worker.stdout.txt'):
        rejects('sensitive-leaf-pattern-' + name, lambda name=name: module['public_source']('/var/tmp/known-public/' + name))
    for prefix in ('/var/tmp/kpi-owner-private-lifecycle-01/private',
                   '/var/tmp/kpi-local-original-metadata-01',
                   '/var/tmp/kpi-local-private-payment-01/publication-contexts'):
        rejects('known-local-prefix-' + prefix.rsplit('/', 1)[-1],
                lambda prefix=prefix: module['public_source'](prefix + '/explicit-extra.json'))
    generic = {'source': '/var/tmp/known-public/a.json', 'path': 'evidence/a.json', 'bytes': 1,
               'sha256': '00' * 32, 'kind': 'public-evidence'}
    rejects('duplicate-file-row', lambda: module['file_rows']([generic, generic]))
    ancestor, child = dict(generic), dict(generic)
    ancestor['path'], child['path'] = 'a', 'a/b'
    rejects('regular-file-ancestor-collision', lambda: module['file_rows']([ancestor, child]))
    reserved_child = dict(generic); reserved_child['path'] = 'DATA-INVENTORY.json/child'
    rejects('generated-inventory-ancestor-collision', lambda: module['file_rows']([reserved_child]))
    audit_child = dict(generic); audit_child['path'] = 'audit-only/decoded/page.bin'
    rejects('audit-only-path-not-upload-member', lambda: module['file_rows']([audit_child]))
    rejects('pure-tar-ancestor-collision', lambda: module['canonical_tar']({'a': b'KNOWN', 'a/b': b'PUBLIC'}))
    check('finite-operational-timing-float-accepted', lambda: None if module['parse'](b'{"wall_seconds":1.25}') == {'wall_seconds': 1.25}
          else (_ for _ in ()).throw(AssertionError('timing-float-rejected')))
    rejects('NaN-metadata-refused', lambda: module['parse'](b'{"wall_seconds":NaN}'))
    rejects('infinite-metadata-refused', lambda: module['parse'](b'{"wall_seconds":1e999}'))
    rejects('duplicate-metadata-key-refused', lambda: module['parse'](b'{"n":1,"n":2}'))
    rejects('float-amount-or-count-refused', lambda: module['uint'](1.0))
    rejects('bool-amount-or-count-refused', lambda: module['uint'](True))
    known_roles = {name: {'sha256': hashlib.sha256(('KNOWN PUBLIC ' + name).encode()).hexdigest()}
                   for name in ('history', 'context', 'fetch', 'selection')}
    known_report = {name + '_sha256': row['sha256'] for name, row in known_roles.items()}
    check('metadata-only-replay-pin-joins', lambda: module['replay_pin_joins'](known_report, known_roles))
    wrong_report = dict(known_report); wrong_report['selection_sha256'] = '00' * 32
    rejects('metadata-only-wrong-selection-pin', lambda: module['replay_pin_joins'](wrong_report, known_roles))

    known = b'  KNOWN PUBLIC DECODED PAGE BYTES\n\x00not JSON; preserve exactly\n'
    compressed = gzip.compress(known, mtime=0)
    def record(path, raw=compressed, decoded=known):
        return {'path': path, 'request': {'known_public_control': True},
                'decoded_sha256': hashlib.sha256(decoded).hexdigest(), 'decoded_bytes': len(decoded),
                'gzip_sha256': hashlib.sha256(raw).hexdigest(), 'gzip_bytes': len(raw),
                'encoding': 'KNOWN_PUBLIC_BYTE_FIXTURE_NOT_ACCEPTED_HISTORY'}
    def decoded(raw, meta):
        return b''.join(module['decoded_chunks'](raw, meta))
    check('exact-gzip-decoded-bytes-no-JSON-reserialization', lambda: None if decoded(compressed, record('main.gz')) == known
          else (_ for _ in ()).throw(AssertionError('decoded-bytes-changed')))
    wrong = record('main.gz'); wrong['gzip_sha256'] = '00' * 32
    rejects('compressed-SHA-mismatch', lambda: decoded(compressed, wrong))
    wrong = record('main.gz'); wrong['decoded_sha256'] = '00' * 32
    rejects('decoded-SHA-mismatch', lambda: decoded(compressed, wrong))
    wrong = record('main.gz'); wrong['decoded_bytes'] -= 1
    rejects('decoded-length-mismatch', lambda: decoded(compressed, wrong))
    concatenated = gzip.compress(b'KNOWN ', mtime=0) + gzip.compress(b'PUBLIC', mtime=0)
    check('all-concatenated-gzip-members-decoded', lambda: None if decoded(concatenated, record('multi.gz', concatenated, b'KNOWN PUBLIC')) == b'KNOWN PUBLIC'
          else (_ for _ in ()).throw(AssertionError('gzip-member-omitted')))
    trailing = compressed + b'NOT A GZIP MEMBER'
    rejects('non-gzip-trailing-bytes-refused', lambda: decoded(trailing, record('trailing.gz', trailing, known)))

    main_page, post_page = record('attempt-01/pages/00000.json.gz'), record('attempt-01/post-query/pages/00000.json.gz')
    fetch = {'pages': [main_page], 'current_view': {'post_query_delta': {'pages': [post_page]}}}
    page_rows = [{'source': '/var/tmp/known-public/' + str(i) + '.gz',
                  'path': 'chain/' + p['path'], 'bytes': p['gzip_bytes'],
                  'sha256': p['gzip_sha256'], 'kind': 'full-source-page'}
                 for i, p in enumerate((main_page, post_page))]
    check('exact-main-and-post-query-page-closure', lambda: None if len(module['page_contract'](fetch, page_rows)) == 2
          else (_ for _ in ()).throw(AssertionError('page-closure-changed')))
    rejects('missing-main-page', lambda: module['page_contract'](fetch, page_rows[1:]))
    rejects('missing-post-query-page', lambda: module['page_contract'](fetch, page_rows[:1]))
    extra = dict(page_rows[0]); extra['path'] = 'chain/extra.json.gz'
    rejects('extra-page', lambda: module['page_contract'](fetch, [*page_rows, extra]))
    missing_list = copy.deepcopy(fetch); del missing_list['current_view']['post_query_delta']['pages']
    rejects('missing-post-query-list', lambda: module['page_contract'](missing_list, page_rows))
    empty_main = copy.deepcopy(fetch); empty_main['pages'] = []
    rejects('empty-main-prefix-with-post-pages-refused', lambda: module['page_contract'](empty_main, page_rows[1:]))
    duplicate = copy.deepcopy(fetch); duplicate['current_view']['post_query_delta']['pages'] = [main_page]
    rejects('duplicate-fetch-relative-page', lambda: module['page_contract'](duplicate, page_rows))
    output = {'schema': 'kpxa-known-public-container-controls/v1',
        'source_sha256': hashlib.sha256(raw_source).hexdigest(), 'all_passed': True,
        'control_count': len(rows), 'controls': rows,
        'fixtures': 'KNOWN_PUBLIC_OPAQUE_BYTES_ONLY_NOT_ACCEPTED_HISTORY',
        'actual_final_selection_packet_private_worker_or_network_used': False,
        'live_sources_or_software02_changed': False}
    target = Path('/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01/PUBLIC-CONTAINER-CONTROLS-06.json')
    with target.open('xb') as stream:
        stream.write((json.dumps(output, sort_keys=True, indent=2) + '\n').encode())
    target.chmod(0o400)
    print(json.dumps({'all_passed': True, 'controls': len(rows), 'actual_private_or_final_inputs': False}, sort_keys=True))


if __name__ == '__main__':
    main()

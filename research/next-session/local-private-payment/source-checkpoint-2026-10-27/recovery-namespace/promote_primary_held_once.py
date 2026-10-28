#!/usr/bin/env python3
"""Promote only an exact Root-reviewed held PRIMARY graph; metadata-only moves.

This does not perform or replace primary_checked(). A separately pinned Root
review of the complete frozen graph is mandatory; a Boolean checkpoint is not
authority. No Original content, packet payload or private capture is read here.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import runpy
import stat

AUDIT = Path('/var/tmp/kpi-local-private-payment-01/publication-audits')
PACKET = Path('/var/tmp/kpi-local-private-payment-01/publication-release/terminal-final-data-01')
ROOTS = {'audit': AUDIT, 'packet': PACKET}
DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
KEYS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def absolute(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and '\0' not in value and '\\' not in value, 'canonical absolute path')
    out = Path(value)
    need(str(out) == value and '..' not in out.parts, 'canonical absolute path')
    return out


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256 pin')
    return value


def meta(info):
    return dict(zip(KEYS, (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
        info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)))


def identity(info):
    return tuple(info[key] for key in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink'))


def check_stat(value):
    need(type(value) is dict and set(value) == set(KEYS)
         and all(type(v) is int for v in value.values()), 'exact stat row')
    return value


def open_dir(path):
    fd = os.open('/', DIRFLAGS)
    try:
        for name in path.parts[1:]:
            child = os.open(name, DIRFLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError('destination exists; no overwrite fallback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--release', required=True)
    parser.add_argument('--release-sha256', required=True)
    args = parser.parse_args()
    need(args.execute, 'explicit Root promotion execution required')
    h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')

    def selected(row):
        need(type(row) is dict and set(row) == {'path', 'sha256'}, 'exact selector')
        return parse(h['read'](absolute(row['path']), sha(row['sha256'])))

    release = parse(h['read'](absolute(args.release), sha(args.release_sha256)))
    fields = {'schema', 'action', 'operator_sha256', 'namespace_release', 'held_receipt',
              'root_graph_review', 'moves', 'journal_path', 'trusted_host_quiescence'}
    need(type(release) is dict and set(release) == fields
         and release['schema'] == 'kpxa-root-reviewed-primary-promotion/v1'
         and release['action'] == 'PROMOTE_ONLY_EXACT_ROOT_REVIEWED_PRIMARY_OUTPUTS'
         and release['trusted_host_quiescence'] is True, 'exact Root promotion authorization')
    h['read'](str(Path(__file__).absolute()), sha(release['operator_sha256']))
    namespace = selected(release['namespace_release'])
    h['read'](str(Path(__file__).absolute().with_name('run_primary_namespace_once.py')),
              sha(namespace['operator_sha256']))
    held = selected(release['held_receipt'])
    review = selected(release['root_graph_review'])
    need(namespace['schema'] == 'kpxa-root-finite-primary-fd-namespace/v1'
         and namespace['action'] == 'RUN_ONLY_FROZEN_PRIMARY_HOLD_ALL_OUTPUTS'
         and held['schema'] == 'kpxa-finite-primary-fd-namespace/v1'
         and held['status'] == 'HELD_PENDING_EXACT_RESULT_AND_PROMOTION_REVIEW'
         and held['release_sha256'] == release['namespace_release']['sha256']
         and held['returncode'] == 0 and held['canonical_outputs_promoted'] is False,
         'selected completed held namespace required')
    need(type(review) is dict
         and review.get('schema') == 'kpxa-root-reviewed-held-primary-graph/v1'
         and review.get('namespace_release_sha256') == release['namespace_release']['sha256']
         and review.get('held_receipt_sha256') == release['held_receipt']['sha256']
         and review.get('execution_plan_sha256') == namespace['execution_plan']['sha256']
         and review.get('primary_graph_source_sha256') == namespace['audit_core']['sha256']
         and review.get('complete_frozen_primary_graph_checked') is True
         and review.get('original_count') == 9
         and review.get('worker_kinds') == ['literal', 'derived']
         and review.get('descriptor_stage_checked') is False
         and review.get('global_audit_complete') is False,
         'explicit Root review of full graph, never Boolean checkpoint authority')
    public_sources = {row['target']: row for row in namespace['public_files']}
    execution_row = public_sources[namespace['execution_plan']['path']]
    execution = parse(h['read'](absolute(execution_row['source']), namespace['execution_plan']['sha256']))
    batch_selector = execution['batch_plan']
    batch_source = public_sources[batch_selector['path']]
    batch_document = parse(h['read'](absolute(batch_source['source']), sha(batch_selector['sha256'])))
    expected_batches = [row['batch_id'] for row in batch_document['batches']]
    batches = review.get('primary_batch_ids')
    need(type(batches) is list and batches and batches[0] == 'BASE'
         and len(set(batches)) == len(batches)
         and batches == expected_batches
         and review.get('literal_cells_checked') == review.get('derived_cells_checked') == 9 * len(batches),
         'complete nine-by-batches-by-two graph review counts')
    expected_journal = absolute(held['holders']['audit']) / Path(namespace['controller_output']).name / 'LOCAL-UNPUBLISHED-PRIMARY-JOURNAL.json'
    need(review['primary_journal']['path'] == str(expected_journal), 'reviewed journal must belong to held controller output')
    # Pin the reviewed complete journal. This is not a replacement for graph validation.
    selected(review['primary_journal'])
    for row in namespace['originals']:
        record = row['stat']
        h['m'].GUARD.inodes.add((record['dev'], record['ino']))
        source = absolute(row['path'])
        need(not any(p.is_symlink() for p in (source, *source.parents))
             and meta(source.lstat()) == record, 'Original metadata changed since held execution')
    h['refresh']()
    for row in namespace['public_files']:
        source = absolute(row['source'])
        h['m'].GUARD.metadata(source)
        need(meta(source.lstat()) == row['stat'], 'public source changed since held execution')
    need(held['holders'] == {key: row['path'] for key, row in namespace['holders'].items()}, 'exact held holder correspondence')
    need(namespace['packet_directory'] == str(PACKET), 'fixed packet parent')
    planned = {(row['root'], row['name']) for row in namespace['promotions']}
    expected_planned = {('audit', Path(namespace['controller_output']).name)}
    expected_planned.update(('audit', 'prepared-' + execution['run_label'] + '-' + bid.lower()) for bid in batches)
    expected_planned.update(('packet', bid + '-BATCH.json') for bid in batches if bid != 'BASE')
    need(planned == expected_planned, 'complete exact controller/prepared/descriptor output set')
    moves = release['moves']
    need(type(moves) is list and moves
         and len({(row['root'], row['name']) for row in moves}) == len(moves)
         and {(row['root'], row['name']) for row in moves} == planned, 'exact finite planned moves')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    need(rename is not None, 'atomic NOREPLACE unavailable; no fallback')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    handles, checked = {}, []
    parent_identities = {}
    journal_fd = journal_parent_fd = None
    try:
        for root in ('audit', 'packet'):
            source = absolute(held['holders'][root])
            source_fd, destination_fd = open_dir(source), open_dir(ROOTS[root])
            handles[root] = (source_fd, destination_fd)
            original_holder = namespace['holders'][root]['stat']
            need(os.fstat(source_fd).st_uid == os.getuid()
                 and stat.S_IMODE(os.fstat(source_fd).st_mode) == 0o700
                 and all(meta(os.fstat(source_fd))[key] == original_holder[key]
                         for key in ('dev', 'ino', 'mode', 'uid', 'gid'))
                 and os.fstat(source_fd).st_dev == os.fstat(destination_fd).st_dev,
                 'owned same-filesystem holder and destination')
            need(os.fstat(destination_fd).st_uid == os.getuid()
                 and stat.S_IMODE(os.fstat(destination_fd).st_mode) == 0o700, 'owned canonical destination parent')
            parent_identities[root] = tuple(meta(os.fstat(destination_fd))[key]
                                            for key in ('dev', 'ino', 'mode', 'uid', 'gid'))
        # Read-only input binds leave empty mountpoint scaffolding after the guest
        # exits. Validate it explicitly; never promote those placeholder files.
        write_roots = {**ROOTS, 'decoded': Path('/dev/shm/kpi-local-private-payment-publication-01')}
        for root, virtual in write_roots.items():
            holder = absolute(held['holders'][root])
            directory_fd = open_dir(holder)
            try:
                scaffold_files, scaffold_dirs = set(), {'.': set()}
                for target in public_sources:
                    target = absolute(target)
                    if virtual not in target.parents:
                        continue
                    relative = target.relative_to(virtual)
                    scaffold_files.add(str(relative))
                    for parent in relative.parents:
                        scaffold_dirs.setdefault(str(parent), set())
                    for node in (relative, *relative.parents):
                        if str(node) != '.':
                            scaffold_dirs[str(node.parent)].add(node.name)
                promoted_here = {name for kind, name in planned if kind == root}
                need(not promoted_here & scaffold_dirs['.'], 'input scaffold/output collision')
                need(set(os.listdir(directory_fd)) == scaffold_dirs['.'] | promoted_here,
                     'unexpected/missing held root entry or leftover decoded stage')
                for relative in scaffold_files:
                    info = (holder / relative).lstat()
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                         and info.st_uid == os.getuid() and info.st_size == 0, 'input mountpoint scaffold changed')
                for relative, names in scaffold_dirs.items():
                    if relative == '.':
                        continue
                    fd = open_dir(holder / relative)
                    try:
                        need(set(os.listdir(fd)) == names and os.fstat(fd).st_uid == os.getuid(),
                             'input scaffold directory changed')
                    finally:
                        os.close(fd)
            finally:
                os.close(directory_fd)

        def verify_tree(move):
            root, name = move['root'], move['name']
            source_fd, destination_fd = handles[root]
            need(tuple(meta(ROOTS[root].lstat())[key] for key in ('dev', 'ino', 'mode', 'uid', 'gid'))
                 == tuple(meta(os.fstat(destination_fd))[key] for key in ('dev', 'ino', 'mode', 'uid', 'gid'))
                 == parent_identities[root], 'canonical destination parent retargeted')
            expected = check_stat(move['stat'])
            actual = meta(os.stat(name, dir_fd=source_fd, follow_symlinks=False))
            need(actual == expected and expected['uid'] == os.getuid()
                 and expected['dev'] == os.fstat(source_fd).st_dev, 'promotion source metadata drift')
            absent(destination_fd, name)
            source = absolute(held['holders'][root]) / name
            if root == 'packet':
                need(re.fullmatch(r'D[0-9]{6}-BATCH\.json', name)
                     and stat.S_ISREG(expected['mode']) and expected['nlink'] == 1
                     and move['tree'] == [], 'only new ordinary decoded descriptors enter packet')
                h['m'].GUARD.metadata(source)
            else:
                need(stat.S_ISDIR(expected['mode']), 'audit promotion must be a directory')
                rows = move['tree']
                need(type(rows) is list and rows, 'complete audited directory metadata tree')
                by_relative, children = {}, {}
                for row in rows:
                    need(type(row) is dict and set(row) == {'relative', 'stat'}, 'exact tree metadata row')
                    relative = row['relative']
                    p = Path(relative)
                    need(type(relative) is str and not p.is_absolute() and '..' not in p.parts
                         and (relative == '.' or str(p) == relative)
                         and relative not in by_relative, 'canonical unique relative tree path')
                    by_relative[relative] = check_stat(row['stat'])
                need(by_relative.get('.') == expected, 'tree root metadata join')
                for relative, record in by_relative.items():
                    node = source if relative == '.' else source / relative
                    need(meta(node.lstat()) == record and record['uid'] == os.getuid()
                         and record['dev'] == expected['dev'], 'tree metadata drift')
                    if stat.S_ISDIR(record['mode']):
                        children[relative] = set()
                    else:
                        need(stat.S_ISREG(record['mode']) and record['nlink'] == 1, 'no symlink/hardlink/special tree leaf')
                        h['m'].GUARD.metadata(node)
                for relative in by_relative:
                    if relative != '.':
                        parent = str(Path(relative).parent)
                        need(parent in children, 'complete directory ancestry required')
                        children[parent].add(Path(relative).name)
                for relative, names in children.items():
                    fd = open_dir(source if relative == '.' else source / relative)
                    try:
                        need(set(os.listdir(fd)) == names, 'unexpected/missing held output entry')
                    finally:
                        os.close(fd)
            return expected

        for move in moves:
            need(type(move) is dict and set(move) == {'root', 'name', 'stat', 'tree'}
                 and move['root'] in ROOTS and type(move['name']) is str
                 and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.json)?', move['name']), 'closed finite move row')
            checked.append((move, verify_tree(move)))
        journal_path = absolute(release['journal_path'])
        need(not any(journal_path == root or root in journal_path.parents
                     for root in [*ROOTS.values(), *(absolute(p) for p in held['holders'].values())]),
             'journal outside moved/current output roots')
        journal_parent_fd = open_dir(journal_path.parent)
        ji = os.fstat(journal_parent_fd)
        need(ji.st_uid == os.getuid() and stat.S_IMODE(ji.st_mode) == 0o700, 'owned local journal parent')
        absent(journal_parent_fd, journal_path.name)
        # All metadata/closure/source/destination checks finish before this write/move.
        journal_fd = os.open(journal_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=journal_parent_fd)

        def event(value):
            raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
            while raw:
                count = os.write(journal_fd, raw)
                need(count > 0, 'journal write failed')
                raw = raw[count:]
            os.fsync(journal_fd)

        event({'event': 'PREPARED', 'release_sha256': args.release_sha256, 'moves': len(moves)})
        os.fsync(journal_parent_fd)
        completed = []
        try:
            for move, expected in checked:
                verify_tree(move)
                source_fd, destination_fd = handles[move['root']]
                name = move['name'].encode()
                event({'event': 'MOVE_INTENT', 'root': move['root'], 'name': move['name']})
                need(meta(os.stat(move['name'], dir_fd=source_fd, follow_symlinks=False)) == expected,
                     'source changed before atomic move')
                if rename(source_fd, name, destination_fd, name, 1) != 0:  # RENAME_NOREPLACE
                    error = ctypes.get_errno()
                    raise ValueError('atomic destination collision' if error == errno.EEXIST else 'atomic move refused')
                completed.append((move['root'], move['name']))
                after = meta(os.stat(move['name'], dir_fd=destination_fd, follow_symlinks=False))
                need(identity(after) == identity(expected), 'promoted inode identity changed')
                os.fsync(source_fd)
                os.fsync(destination_fd)
                event({'event': 'MOVED', 'root': move['root'], 'name': move['name']})
            event({'event': 'COMPLETED', 'moves': len(completed), 'global_audit_complete': False,
                   'supplemental_and_positive_checks_still_required': True})
        except Exception:
            event({'event': 'INCOMPLETE', 'moves_completed': completed, 'rollback_or_overwrite_attempted': False})
            raise
    finally:
        if journal_fd is not None:
            os.close(journal_fd)
        if journal_parent_fd is not None:
            os.close(journal_parent_fd)
        for source_fd, destination_fd in handles.values():
            os.close(source_fd)
            os.close(destination_fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('PRIMARY promotion refused/incomplete; preserve holders, destinations and journal')

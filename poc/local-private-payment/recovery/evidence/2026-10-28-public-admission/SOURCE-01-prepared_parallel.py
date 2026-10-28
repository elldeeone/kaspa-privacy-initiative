#!/usr/bin/env python3
"""Admit one finite PUBLIC batch once; isolate each unchanged owner audit.

This derivative resolves five exact historical public document origins before
parallel guard09 admission. Files of at least64MiB remain serial. It uses the pinned c465 launcher functions. It
does not replace helper09, cache an audit PASS, read an Original, or retain an
Original FD. Large candidate files remain ordinary direct read-only views under
the same trusted-host/no-concurrent-mutation boundary as c465; they are NOT
sealed files. Every unchanged worker still authenticates all candidate bytes
before its private leaf read. Small candidates and public code stage once.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess
import time
import types

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
BASE_SHA = 'c465c8e6c77b80a9d4f3928cbbe97704751104ec96488fcf9516efe007ceff42'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PARENTS = (Path('/var/tmp/kpi-local-private-payment-01/publication-audits'),
           Path('/dev/shm/kpi-local-private-payment-publication-01'))
_TOKEN = object()

# Exact immutable public pre-wrapup document origins. The logical candidate,
# original SHA/length and all worker bytes remain unchanged. Current worktree
# documents are never replaced or relabelled as their historical versions.
PUBLIC_DOCUMENT_SNAPSHOTS = {'/home/luke/projects/kpi-intensive-2026-10-22/continuation/QUESTIONS.md': {'snapshot': '/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/wrapup-2026-10-27/previous-selected-documents/QUESTIONS.md', 'path': 'extras/publication/QUESTIONS.md', 'bytes': 35916, 'sha256': '7ed6f98921ec7aec89445606265b3890eeb2f551e2e6e58e8cb835cbe9753399'}, '/home/luke/projects/kpi-intensive-2026-10-22/continuation/THREAT-MODEL.md': {'snapshot': '/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/wrapup-2026-10-27/previous-selected-documents/THREAT-MODEL.md', 'path': 'extras/publication/THREAT-MODEL.md', 'bytes': 85306, 'sha256': '46ec6fe710879c9600de24af8780222f967a643028557402c11ace19e7f2cd54'}, '/home/luke/projects/kpi-intensive-2026-10-22/continuation/docs/ARCHITECTURE.md': {'snapshot': '/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/wrapup-2026-10-27/previous-selected-documents/docs/ARCHITECTURE.md', 'path': 'extras/publication/docs/ARCHITECTURE.md', 'bytes': 79538, 'sha256': '23b27867319afcc5f72531a11b7dc76fe2efaa94b63bc76f847f016931f0833b'}, '/home/luke/projects/kpi-intensive-2026-10-22/continuation/docs/rfc/0029-local-native-kas-private-transfer.md': {'snapshot': '/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/wrapup-2026-10-27/previous-selected-documents/docs/rfc/0029-local-native-kas-private-transfer.md', 'path': 'extras/publication/docs/rfc/0029-local-native-kas-private-transfer.md', 'bytes': 21211, 'sha256': '4711f92aec4b758601ff4e01ceaa86dbf2823e5c6992b2abd01f9fc46caba896'}, '/home/luke/projects/kpi-intensive-2026-10-22/continuation/docs/shielded-kas-next.md': {'snapshot': '/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/wrapup-2026-10-27/previous-selected-documents/docs/shielded-kas-next.md', 'path': 'extras/publication/docs/shielded-kas-next.md', 'bytes': 31364, 'sha256': 'da4a6eec5e51e13bc5e54fd8e15d1fede16b973b302ca9bf53a198a905a85c03'}}


def candidate_origin(row):
    """Resolve only the five exact frozen public candidates, before guard09."""
    route = PUBLIC_DOCUMENT_SNAPSHOTS.get(row.get('source'))
    if route is None:
        return row
    need(row == {'source': row['source'], 'path': route['path'],
                 'bytes': route['bytes'], 'sha256': route['sha256']})
    return {**row, 'source': route['snapshot']}




def need(value):
    if not value:
        raise ValueError('prepared-publication-audit-refused')


def _selected(read, row):
    need(type(row) is dict and set(row) == {'source', 'bytes', 'sha256'}
         and type(row['source']) is str and type(row['bytes']) is int
         and row['bytes'] >= 0 and type(row['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', row['sha256']))
    raw = read(row['source'], row['sha256'])
    need(len(raw) == row['bytes'])
    return raw


def _fresh_runtime(value):
    path = Path(value)
    need(path.is_absolute() and str(path) == str(value) and '..' not in path.parts
         and path.parent in PARENTS and re.fullmatch('prepared-[a-z0-9-]{1,64}', path.name)
         and not path.exists() and not any(p.is_symlink() for p in (path, *path.parents)))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid())
    if path.parent == PARENTS[1]:
        need(stat.S_IMODE(info.st_mode) == 0o700)
    path.mkdir(mode=0o700)
    return path


class PreparedPublicSnapshot:
    """Process-local prepared object, never reconstructed from a PASS marker."""

    def __init__(self, token, base, guard, runtime, rows, candidates, contexts,
                 provenance, tracked):
        need(token is _TOKEN)
        self._base, self._guard, self._runtime = base, guard, runtime
        self._rows, self._candidates, self._contexts = rows, candidates, contexts
        self._provenance, self._tracked = provenance, tracked
        self._used, self._closed = set(), False

    @property
    def public_preparation_provenance(self):
        # Return an independent public value; callers cannot rewrite authority.
        return json.loads(self._base.encoded(self._provenance))

    def _check(self):
        need(not self._closed)
        self._base.check_candidate_metadata(self._guard, self._candidates)
        for path, expected in self._tracked:
            selected, info = self._guard['m'].GUARD.metadata(path)
            need(selected == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and not any(p.is_symlink() for p in (path, *path.parents))
                 and self._base.attributes(info) == expected)

    def close(self):
        # No private FDs or long-lived worker exist. Retain public files/evidence.
        self._closed = True

    def execute(self, original_metadata_args, cohort, identity):
        m = self._base
        need(not self._closed and cohort in self._contexts
             and type(identity) is str and re.fullmatch('audit-[a-z0-9-]{1,64}', identity)
             and identity not in self._used)
        self._used.add(identity)  # A failed attempt never silently reuses a name.
        owner, before = m.original_metadata(original_metadata_args)  # lstat only
        context = self._contexts[cohort]
        self._check()
        runtime = self._runtime / identity
        runtime.mkdir(mode=0o700)
        common = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc',
            '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8']
        for index, (selected, _, _, _) in enumerate(self._candidates):
            need(selected is not None)
            common += ['--ro-bind', str(selected), '/candidates/' + str(index) + '.bin']
        by_mount = {}
        for row, staged in context['sources']:
            common += ['--ro-bind', str(staged), row['mount']]
            by_mount[row['mount']] = row['sha256']
        summary = {'schema': 'kpxa-one-leaf-publication-audit/v1',
            'release_sha256': context['release_sha256'],
            'candidate_file_count': len(self._rows),
            'candidate_bytes': sum(row['bytes'] for row in self._rows),
            'source_files': len(context['sources']),
            'candidate_manifest_sha256': m.sha(m.encoded(self._rows)),
            'original_content_read_or_hashed_by_controller': False,
            'actual_original_check_executed': False,
            'literal_and_derived_are_separate': True,
            'trusted_host_mutation_outside_model': True,
            **context['scope']}
        workers = {}
        started = time.monotonic()
        for kind, schema, result_schema in (
            ('literal', 'kpx8-new-owner-seed-export-allowlist/v1', 'kpxa-literal-seed-export-result/v1'),
            ('derived', 'kpxa-derived-export-candidates/v1', 'kpxa-derived-export-result/v1')):
            self._check()
            need(m.attributes(m.original_metadata(original_metadata_args)[1]) == m.attributes(before))
            raw_manifest = m.encoded({'schema': schema, 'files': self._rows})
            manifest = runtime / (kind + '-ALLOWLIST.json')
            m.save(manifest, raw_manifest)
            out = runtime / (kind + '-out')
            out.mkdir(mode=0o700)
            command = common + ['--ro-bind', str(owner), '/BACKUP.json',
                '--ro-bind', str(manifest), '/ALLOWLIST.json', '--bind', str(out), '/out',
                '/usr/bin/python3', '-B', '/public/recovery/publication_' + kind + '.py',
                '--owner', '/BACKUP.json', '--allowlist', '/ALLOWLIST.json',
                '--allowlist-sha256', m.sha(raw_manifest), '--candidates', '/candidates',
                '--output', '/out/RESULTS.json']
            if kind == 'derived':
                for option, mount in [('assets', '/public/ASSETS.json'),
                    ('history', '/public/HISTORY.json'), ('context', '/public/CONTEXT.json')]:
                    command += ['--' + option, mount, '--' + option + '-sha256', by_mount[mount]]
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=m.CLEAN, close_fds=True)
            need(process.returncode == 0)
            # A newly created public result may reuse an inode formerly held by
            # an ephemeral private file. Use a fresh unchanged helper09 reader;
            # never clear a guard or relax current private-origin/alias checks.
            raw_result = runpy.run_path(GUARD)['read'](str(out / 'RESULTS.json'))
            result = m.parse(raw_result)
            expected = {'schema', 'status', 'candidate_count', 'candidate_bytes',
                        'matched_candidate_count', 'scope'}
            if kind == 'derived':
                expected.add('literal_seed_coverage')
            need(set(result) == expected and result['schema'] == result_schema
                 and result['status'] == 'PASS' and type(result['matched_candidate_count']) is int
                 and result['matched_candidate_count'] == 0
                 and type(result['candidate_count']) is int and result['candidate_count'] == len(self._rows) + 1
                 and type(result['candidate_bytes']) is int
                 and result['candidate_bytes'] == summary['candidate_bytes'] + len(raw_manifest))
            if kind == 'derived':
                need(result['literal_seed_coverage'] is False
                     and result['scope'] == 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF')
            else:
                need(result['scope'] == 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF')
            self._check()
            need(m.attributes(m.original_metadata(original_metadata_args)[1]) == m.attributes(before))
            summary[kind + '_status'] = result['status']
            workers[kind] = {'sha256': m.sha(raw_result), 'bytes': len(raw_result),
                             'candidate_manifest_sha256': summary['candidate_manifest_sha256'], **result}
        summary.update({'own_historical_payout_keys_checked': context['scope']['context_kind'] == 'ACCEPTED_HISTORY',
            'actual_original_check_executed': True, 'one_original_leaf_read_only_per_namespace': True,
            'parent_sibling_root_or_home_mounted': False,
            'private_values_paths_hashes_or_indices_exported': False})
        return {'summary': summary, 'workers': workers,
                'public_preparation_provenance': self.public_preparation_provenance,
                'worker_pair_wall_seconds': time.monotonic() - started}


def prepare(files, releases_by_context, runtime, selected_c465_row):
    """Authenticate closed public rows before accepting any Original metadata."""
    started = time.monotonic()
    guard = runpy.run_path(GUARD)
    need(selected_c465_row.get('sha256') == BASE_SHA)
    raw_base = _selected(guard['read'], selected_c465_row)
    base = types.ModuleType('pinned_c465_publication_launcher')
    base.__file__ = selected_c465_row['source']
    exec(compile(raw_base, base.__file__, 'exec'), base.__dict__)
    need(type(files) is list and files and type(releases_by_context) is dict and releases_by_context)
    runtime = _fresh_runtime(runtime)
    pool_source = str(Path(__file__).absolute().with_name('public_admission_pool.py'))
    pool = types.ModuleType('selected_public_admission_pool')
    pool.__file__ = pool_source
    pool_sha = '10e4dd65a637c273a9f668d55243e433643dd07fe18ceebfaab9949f79182068'
    exec(compile(guard['read'](pool_source, pool_sha), pool_source, 'exec'), pool.__dict__)
    # Validate all logical rows before launching any public-only child.
    names = set()
    for row in files:
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256'})
        name = PurePosixPath(row['path'])
        need(type(row['path']) is str and str(name) == row['path'] and not name.is_absolute()
             and name.parts and '..' not in name.parts and '\\' not in row['path']
             and '\0' not in row['path'] and row['path'] not in names)
        names.add(row['path'])
    entries = pool.admit([candidate_origin(row) for row in files], runtime,
                         selected_c465_row, pool_sha, base, guard)
    rows, candidates, names, tracked = [], [], set(), []
    for index, row in enumerate(files):
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256'})
        name = PurePosixPath(row['path'])
        need(type(row['path']) is str and str(name) == row['path'] and not name.is_absolute()
             and name.parts and '..' not in name.parts and '\\' not in row['path']
             and '\0' not in row['path'] and row['path'] not in names)
        names.add(row['path'])
        entry = entries[index]
        rows.append({key: row[key] for key in ('path', 'bytes', 'sha256')})
        candidates.append(entry)
        if not entry[3]:
            staged = entry[0]
            tracked.append((staged, base.attributes(staged.lstat())))
    contexts = {}
    for cohort, selected in releases_by_context.items():
        need(type(cohort) is str and re.fullmatch('[a-z0-9-]{1,64}', cohort))
        release = base.parse(_selected(guard['read'], selected))
        need(type(release) is dict and set(release) == {'schema', 'domain_hex32', 'files', 'sources'}
             and release['schema'] == 'kpxa-publication-audit-release/v1'
             and release['domain_hex32'] == DOMAIN and release['files'] == files
             and type(release['sources']) is list and release['sources'])
        mounts, source_raw, staged_rows = set(), {}, []
        for index, row in enumerate(release['sources']):
            need(type(row) is dict and set(row) == {'source', 'mount', 'bytes', 'sha256', 'mode'})
            mount = PurePosixPath(row['mount'])
            need(type(row['mount']) is str and str(mount) == row['mount']
                 and mount.is_relative_to('/public') and mount != PurePosixPath('/public')
                 and '..' not in mount.parts and '\\' not in row['mount'] and '\0' not in row['mount']
                 and row['mount'] not in mounts and row['mode'] in ('0400', '0500'))
            mounts.add(row['mount'])
            raw = guard['read'](row['source'], row['sha256'])
            need(type(row['bytes']) is int and row['bytes'] >= 0 and len(raw) == row['bytes'])
            staged = runtime / 'sources' / cohort / (str(index) + '.bin')
            base.save(staged, raw, int(row['mode'], 8))
            tracked.append((staged, base.attributes(staged.lstat())))
            staged_rows.append((dict(row), staged))
            source_raw[row['mount']] = raw
        required = {'/public/recovery/publication_literal.py', '/public/recovery/publication_derived.py',
                    '/public/ASSETS.json', '/public/HISTORY.json', '/public/CONTEXT.json',
                    '/public/CANARY-CONTEXT-SCOPE.json'}
        need(required <= mounts
             and base.sha(source_raw['/public/recovery/publication_literal.py']) ==
             '0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52'
             and base.sha(source_raw['/public/recovery/publication_derived.py']) ==
             'e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489')
        scope = base.final_scope(source_raw, base.sha(base.encoded(rows)))
        contexts[cohort] = {'sources': staged_rows, 'scope': scope,
                            'release_sha256': selected['sha256']}
    provenance = {'schema': 'kpxa-prepared-publication-public-admission/v1',
        'base_launcher_sha256': BASE_SHA,
        'prepared_launcher_source_sha256': base.sha(guard['read'](str(Path(__file__).absolute()))),
        'candidate_manifest_sha256': base.sha(base.encoded(rows)),
        'candidate_files': len(rows), 'candidate_bytes': sum(r['bytes'] for r in rows),
        'context_releases': {k: v['release_sha256'] for k, v in contexts.items()},
        'large_direct_readonly_views': sum(c[3] for c in candidates),
        'small_candidate_staged_bytes': sum(r['bytes'] for r in rows if r['bytes'] < base.LARGE_PUBLIC_LEAF),
        'public_source_stage_bytes': sum(p.lstat().st_size for p, _ in tracked
                                      if 'sources' in p.relative_to(runtime).parts),
        'largest_transient_candidate_bytes': max(r['bytes'] for r in rows),
        'public_candidate_set_admitted_once': True, 'public_PASS_markers_used_as_authority': False,
        'sealed_storage_or_hostile_host_protection': False,
        'trusted_host_no_concurrent_mutation_required': True,
        'worker_whole_candidate_authentication_before_each_private_read': True,
        'original_content_read_or_hashed_by_preparer': False,
        'original_fds_opened_or_cached_by_preparer': False,
        'public_admission_wall_seconds': time.monotonic() - started}
    prepared = PreparedPublicSnapshot(_TOKEN, base, guard, runtime, rows, candidates,
                                      contexts, provenance, tracked)
    prepared._check()
    return prepared

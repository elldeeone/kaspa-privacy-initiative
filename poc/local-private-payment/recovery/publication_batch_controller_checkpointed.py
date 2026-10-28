#!/usr/bin/python3
"""Whole-batch recovery around the unchanged publication controller.

Selection fields: schema=kpxa-publication-checkpointed-run/v1, execution_plan
({path,sha256}), stage_label (fresh, <=20 characters), resume. Resume is null,
{checkpoint:{path,sha256}}, or {batch_records:[{path,sha256},...]}. The latter
recovers complete batches if the final prefix checkpoint could not be written.
Records and checkpoints are trusted-local evidence, not public attestations.
No process-local prepared object is restored. An incomplete batch is rerun in
full with a fresh stage label; its old receipts are never mixed with a new timer.
"""
import argparse
import copy
import ctypes
import errno
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import sys
import time
import types

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
CORE = '/var/tmp/kpi-terminal-audit-two-checker-fix-01/publication_batch_audit_path_fix.py'
CORE_SHA = '53a8cb735d8063425cdc3e02046e4dcac581806b44cf92c792907619c93abeec'
BASE = str(Path(__file__).with_name('publication_batch_controller.py').absolute())
BASE_SHA = '0d972cbb114c3c922183d76a5fcf16d9b2909b3e05336dbcb0476f9f238078b7'
PREPARED_SHA = '59bf821031feaa7339f46e478cc851d47b316081750b4ec9d86cff597694b95f'
OUTPUT_ROOT = Path('/var/tmp/kpi-local-private-payment-01/publication-audits')


class Controller:
    def __init__(self, prepare_phase=None):
        self.read = runpy.run_path(GUARD)['read']
        self.a = types.ModuleType('publication_batch_audit')
        self.a.__file__ = CORE
        exec(compile(self.read(CORE, CORE_SHA), CORE, 'exec'), self.a.__dict__)
        sys.modules['publication_batch_audit'] = self.a
        self.c = types.ModuleType('checkpointed_frozen_publication_controller')
        self.c.__file__ = BASE
        exec(compile(self.read(BASE, BASE_SHA), BASE, 'exec'), self.c.__dict__)
        self.source_sha = self.a.sha(self.read(str(Path(__file__).absolute())))
        self._write_attempt = self.a.save
        self.prepare_phase = prepare_phase

    def phase(self, name, batch):
        # Scheduling/telemetry is never acceptance authority.
        if self.prepare_phase is not None:
            try:
                self.prepare_phase(name, batch)
            except Exception:
                pass

    def fresh_guard(self):
        return runpy.run_path(GUARD)

    def new_public_read(self, path, expected=None):
        # Match prepared59bf: a newly created public inode may have previously
        # belonged to a removed private leaf. Never clear or relax a guard.
        return self.fresh_guard()['read'](path, expected)

    def sync_fd(self, fd, name):
        while True:
            try:
                os.fsync(fd)
                return
            except OSError as error:
                if error.errno not in (errno.ENOSPC, errno.EDQUOT):
                    raise
                self.phase('STORAGE_WAIT', name)
                time.sleep(5)

    def identities(self):
        return {'checkpoint_controller_sha256': self.source_sha,
                'base_controller_sha256': BASE_SHA, 'core_sha256': CORE_SHA,
                'prepared_launcher_sha256': PREPARED_SHA}

    def public_path(self, path):
        path = Path(path)
        self.a.absolute(str(path))
        self.a.need(path.is_relative_to(OUTPUT_ROOT) and path != OUTPUT_ROOT
                    and not any(p.is_symlink() for p in (path, *path.parents)),
                    'checkpoint-owned-public-output-only')
        return path

    def sync_directories(self, path):
        path = Path(path)
        self.a.absolute(str(path))
        self.a.need(path.is_relative_to(OUTPUT_ROOT)
                    and not any(p.is_symlink() for p in (path, *path.parents)),
                    'checkpoint-owned-public-directory-only')
        while path != OUTPUT_ROOT.parent:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.sync_fd(fd, path.name)
            finally:
                os.close(fd)
            path = path.parent

    def sync_public_leaves(self, paths):
        """Finite already-authenticated public leaves; metadata and fsync only."""
        guard = self.fresh_guard()
        guard['refresh']()  # Unchanged guard09's current private-inode inventory.
        for path in dict.fromkeys(Path(p) for p in paths):
            path = self.public_path(path)
            selected, before = guard['m'].GUARD.metadata(path)
            self.a.need(selected == path and stat.S_ISREG(before.st_mode)
                        and before.st_nlink == 1 and before.st_uid == os.getuid(),
                        'checkpoint-owned-single-public-leaf')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                def identity(info):
                    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                            info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                self.a.need(identity(os.fstat(fd)) == identity(before), 'checkpoint-stable-public-fsync-leaf')
                self.sync_fd(fd, path.name)
                self.a.need(identity(os.fstat(fd)) == identity(before), 'checkpoint-unchanged-public-fsync-leaf')
            finally:
                os.close(fd)
            self.sync_directories(path.parent)

    def sync_record_references(self, releases, output, descriptor_row=None):
        paths = []
        if descriptor_row is not None and Path(descriptor_row['path']).is_relative_to(output):
            paths.append(descriptor_row['path'])
        for release in releases.values():
            paths.append(release['row']['path'])
            paths.extend(row['source'] for row in release['release']['sources']
                         if row['mount'] == self.c.SCOPE_MOUNT)
        # Canonical BASE descriptors/context originals predate this stage.
        self.sync_public_leaves(p for p in paths if Path(p).is_relative_to(output))

    def runtime_leaves(self, wrapped, value):
        bid = wrapped['batch_record']['descriptor']['batch_id']; label = wrapped['stage_label']
        runtime = OUTPUT_ROOT / ('prepared-' + label + '-' + bid.lower())
        paths = []
        for original in value['originals']:
            oid = original['original_id']
            job = runtime / ('audit-' + label + '-' + bid.lower() + '-' + oid.lower())
            for kind in ('literal', 'derived'):
                paths += [job / (kind + '-ALLOWLIST.json'), job / (kind + '-out') / 'RESULTS.json']
        return paths

    def save(self, path, value):
        """Publish complete public metadata, retaining partial writes on ENOSPC.

        This is called before owner intake or after workers have exited. Waiting
        keeps the real provenance alive; no elapsed value is reconstructed.
        A failed attempt has a distinct retained name. Atomic NOREPLACE publish
        ensures a final record is never partial and no evidence is overwritten.
        """
        path = self.public_path(path)
        attempt, number, published = None, 0, False
        while True:
            try:
                if not published:
                    if attempt is None:
                        while True:
                            number += 1
                            attempt = path.with_name('.' + path.name + '.write-' + str(number).zfill(6))
                            if not attempt.exists() and not attempt.is_symlink():
                                break
                        try:
                            self._write_attempt(attempt, value)
                        except OSError:
                            attempt = None  # Any partial file remains evidence.
                            raise
                    self.sync_directories(attempt.parent)
                    rename = ctypes.CDLL(None, use_errno=True).renameat2
                    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
                    rename.restype = ctypes.c_int
                    if rename(-100, os.fsencode(attempt), -100, os.fsencode(path), 1) != 0:
                        code = ctypes.get_errno()
                        raise OSError(code, 'checkpoint-public-metadata-publish-refused')
                    published = True
                self.sync_directories(path.parent)
                return {'path': str(path), 'sha256': self.a.sha(self.a.encoded(value))}
            except OSError as error:
                if error.errno not in (errno.ENOSPC, errno.EDQUOT):
                    raise
                self.phase('STORAGE_WAIT', path.name)
                time.sleep(5)  # No timeout, disk threshold, unlock or PASS bypass.

    def record_checked(self, record, batch, value, index, plan, contexts):
        a = self.a
        a.fields(record, ('descriptor', 'descriptor_row', 'materialization', 'releases',
                          'preparation', 'producer_preparation'), 'checkpoint-full-batch-record')
        a.descriptor_checked(record['descriptor'], batch, index,
                             value['index']['sha256'], value['batch_plan']['sha256'])
        a.row(record['descriptor_row'])
        a.need(a.sha(a.encoded(record['descriptor'])) == record['descriptor_row']['sha256'],
               'checkpoint-descriptor-SHA')
        a.need(a.parse(a.guarded(record['descriptor_row'])) == record['descriptor'],
               'checkpoint-retained-original-descriptor')
        a.materialization_checked(record['materialization'], batch, record['descriptor'],
                                  record['descriptor_row'], value['index']['sha256'], value['batch_plan']['sha256'])
        if batch['batch_id'] == 'BASE':
            a.producer_preparation_checked(record['producer_preparation'], index,
                value['index']['sha256'], plan, value['batch_plan']['sha256'])
            a.need(record['producer_preparation']['result']['base_verification'] == record['materialization'],
                   'checkpoint-same-BASE-authority')
        else:
            a.need(record['producer_preparation'] is None, 'checkpoint-no-foreign-BASE-authority')
        a.fields(record['releases'], ('creation', 'actual02'), 'checkpoint-both-context-releases')
        for cohort, release in record['releases'].items():
            a.fields(release, ('release', 'row'), 'checkpoint-context-release')
            a.need(a.parse(a.guarded(release['row'])) == release['release'],
                   'checkpoint-retained-original-release')
            a.need(a.core_sources(release['release']['sources']) == a.core_sources(contexts[cohort]['sources']),
                   'checkpoint-same-context-source-closure')
        a.preparation_checked(record['preparation'], record['releases'],
                              record['descriptor']['files'], PREPARED_SHA)

    def wrapper(self, plan_row, stage_label, output, record):
        return {'schema': 'kpxa-publication-durable-batch-record/v1',
                'sources': self.identities(), 'execution_plan': plan_row,
                'stage_label': stage_label, 'stage_output': str(output), 'batch_record': record}

    def pairs_checked(self, wrapped, value, contexts):
        a, record = self.a, wrapped['batch_record']
        bid = record['descriptor']['batch_id']
        output = self.public_path(wrapped['stage_output'])
        label = wrapped['stage_label']
        runtime = OUTPUT_ROOT / ('prepared-' + label + '-' + bid.lower())
        result = []
        for original in value['originals']:
            oid, cohort = original['original_id'], original['cohort']
            path = output / 'local-invocations' / bid / (oid + '.json')
            envelope = a.parse_metadata(self.new_public_read(self.public_path(path)))
            release = record['releases'][cohort]
            a.invocation_checked(envelope, original, record['descriptor'], record['descriptor_row'],
                release['release'], release['row'], contexts[cohort], value['index']['sha256'],
                value['batch_plan']['sha256'], record['preparation'], PREPARED_SHA)
            # Rejoin actual retained public worker leaves, not a PASS/cache flag.
            job = runtime / ('audit-' + label + '-' + bid.lower() + '-' + oid.lower())
            for kind in ('literal', 'derived'):
                schema = ('kpx8-new-owner-seed-export-allowlist/v1' if kind == 'literal'
                          else 'kpxa-derived-export-candidates/v1')
                allowlist = a.encoded({'schema': schema,
                                      'files': a.candidate_manifest(record['descriptor']['files'])})
                a.need(self.new_public_read(self.public_path(job / (kind + '-ALLOWLIST.json'))) == allowlist,
                       'checkpoint-original-worker-allowlist')
                receipt = envelope['worker_receipts'][kind]
                raw = self.new_public_read(self.public_path(job / (kind + '-out') / 'RESULTS.json'), receipt['sha256'])
                a.need(len(raw) == receipt['bytes'] and a.parse(raw) == envelope['workers'][kind],
                       'checkpoint-original-worker-result')
            result.append(envelope)
        self.sync_public_leaves(self.runtime_leaves(wrapped, value))
        return result

    def prefix_checked(self, resume, plan_row, value, index, plan, contexts):
        a = self.a
        if resume is None:
            return [], [], []
        a.need(type(resume) is dict and set(resume) in ({'checkpoint'}, {'batch_records'}),
               'checkpoint-explicit-resume-form')
        if 'checkpoint' in resume:
            a.row(resume['checkpoint']); self.public_path(resume['checkpoint']['path'])
            prefix = a.parse_metadata(a.guarded(resume['checkpoint']))
            a.fields(prefix, ('schema', 'sources', 'execution_plan', 'completed_batches', 'batch_records'),
                     'checkpoint-completed-prefix-fields')
            a.need(prefix['schema'] == 'kpxa-publication-completed-prefix/v1'
                   and prefix['sources'] == self.identities() and prefix['execution_plan'] == plan_row
                   and type(prefix['completed_batches']) is int
                   and prefix['completed_batches'] == len(prefix['batch_records']), 'checkpoint-prefix-binding')
            rows = prefix['batch_records']
        else:
            rows = resume['batch_records']
        a.need(type(rows) is list and len(rows) <= len(plan['batches']), 'checkpoint-whole-planned-prefix')
        records, invocations = [], []
        for batch, row in zip(plan['batches'], rows):
            a.row(row); self.public_path(row['path'])
            wrapped = a.parse_metadata(a.guarded(row))
            a.fields(wrapped, ('schema', 'sources', 'execution_plan', 'stage_label', 'stage_output', 'batch_record'),
                     'checkpoint-durable-record-fields')
            a.need(wrapped['schema'] == 'kpxa-publication-durable-batch-record/v1'
                   and wrapped['sources'] == self.identities() and wrapped['execution_plan'] == plan_row,
                   'checkpoint-source-and-plan-binding')
            self.label_checked(wrapped['stage_label'])
            output = self.public_path(wrapped['stage_output'])
            a.need(row['path'] == str(output / 'local-batches' / batch['batch_id'] / 'RECORD.json'),
                   'checkpoint-original-record-route')
            record = wrapped['batch_record']
            self.record_checked(record, batch, value, index, plan, contexts)
            invocations.extend(self.pairs_checked(wrapped, value, contexts))
            records.append(record)
        return records, invocations, rows

    def label_checked(self, label):
        self.a.need(type(label) is str and re.fullmatch('[a-z0-9-]{1,20}', label),
                    'checkpoint-fresh-neutral-stage-label')

    def load(self, selector):
        a = self.a
        selected = a.parse(a.guarded(selector))
        a.fields(selected, ('schema', 'execution_plan', 'stage_label', 'resume'), 'checkpoint-execution-selector')
        a.need(selected['schema'] == 'kpxa-publication-checkpointed-run/v1', 'checkpoint-selected-execution')
        self.label_checked(selected['stage_label']); a.row(selected['execution_plan'])
        value, index, plan, contexts, coverage = self.c.load_plan(selected['execution_plan'])
        a.need(value['prepared_launcher']['sha256'] == PREPARED_SHA, 'checkpoint-unchanged-prepared-source')
        records, invocations, rows = self.prefix_checked(selected['resume'], selected['execution_plan'],
                                                         value, index, plan, contexts)
        for row in rows:
            wrapped = a.parse_metadata(a.guarded(row))
            a.need(wrapped['stage_label'] != selected['stage_label'], 'checkpoint-new-tail-stage-identity')
        return selected, value, index, plan, contexts, coverage, records, invocations, rows

    def base_authority(self, value, index, plan, producer, output):
        a = self.a
        result = a.parse(a.guarded(value['base_materialization']))
        archive_row = next(c for c in index['candidates'] if c['path'] == 'raw/data.tar')
        archive = self.read(archive_row['source'], archive_row['sha256'])
        a.need(len(archive) == archive_row['bytes'], 'whole-raw-archive-identity')
        aliases = {c['path'][len('members/'):]: c for c in index['candidates'] if c['path'].startswith('members/')}
        producer.verify_member_aliases(producer.pinned_preimage(), self.read, archive, aliases)
        del archive
        authority = {'source_sha256': value['producer']['sha256'], 'result': result,
                     'raw_archive_member_aliases_reverified': True}
        a.producer_preparation_checked(authority, index, value['index']['sha256'], plan, value['batch_plan']['sha256'])
        self.save(output / 'local-public' / 'BASE-AUTHORITY.json', authority)
        return authority

    def finish_primary(self, output, value, index, plan, contexts, coverage, records, invocations):
        a, c = self.a, self.c
        a.primary_checked(index, value['index']['sha256'], plan, value['batch_plan']['sha256'],
            value['originals'], contexts, records, invocations, coverage, value['canary_assets'], PREPARED_SHA)
        metadata = [value['index'], value['batch_plan'], *[r['descriptor_row'] for r in records]]
        files = []
        for n, selected in enumerate(metadata):
            raw = a.guarded(selected)
            files.append({'source': selected['path'], 'path': 'public-descriptors/' + str(n).zfill(6) + '.json',
                          'bytes': len(raw), 'sha256': selected['sha256']})
        releases = {cohort: c.release_for(output, 'DESCRIPTORS', cohort, files, context)
                    for cohort, context in contexts.items()}
        self.sync_record_references(releases, output)
        stage = {'batch_id': 'DESCRIPTORS', 'files': files,
                 'required_public_metadata': {'index': value['index'], 'plan': value['batch_plan']},
                 'supplemental_public_metadata': [], 'releases': releases}
        descriptor_release = self.save(output / 'LOCAL-UNPUBLISHED-DESCRIPTOR-RELEASE.json', stage)
        journal = {'schema': 'kpxa-publication-primary-audit-checkpoint/v1', 'execution_plan_value': value,
                   'index': index, 'plan': plan, 'contexts': contexts, 'coverage': coverage,
                   'batches': records, 'invocations': invocations, 'descriptor_release': descriptor_release}
        journal_row = self.save(output / 'LOCAL-UNPUBLISHED-PRIMARY-JOURNAL.json', journal)
        result = {'primary_checks_complete': True, 'descriptor_stage_checked': False,
                  'global_audit_complete': False, 'external_descriptor_release_required': True}
        self.save(output / 'PRIMARY-ONLY-BOOLEAN-CHECKPOINT.json', result)
        self.save(output / 'LOCAL-UNPUBLISHED-RESUME-HANDOFF.json',
                  {'primary_journal': journal_row, 'descriptor_release': descriptor_release,
                   'actual_Original_workers_after_this_boundary': False})
        return result

    def execute(self, selector, output):
        loaded = self.load(selector)
        selected, value, index, plan, contexts, coverage, records, invocations, rows = loaded
        a, c = self.a, self.c
        output = c.fresh_control_output(self.public_path(output))
        self.sync_directories(output)
        runtime_value = copy.deepcopy(value); runtime_value['run_label'] = selected['stage_label']
        remaining = plan['batches'][len(records):]
        for batch in remaining:
            a.need(not (OUTPUT_ROOT / ('prepared-' + selected['stage_label'] + '-' + batch['batch_id'].lower())).exists(),
                   'checkpoint-fresh-tail-runtime')
        if remaining:
            prepared_api = c.selected_module(value['prepared_launcher'], 'checkpointed_selected_prepared_launcher')
            producer = c.selected_module(value['producer'], 'checkpointed_selected_public_materializer')
            shm_base = Path(producer.pinned_preimage()['SHM_OUTPUT_BASE'])
            authority = (records[0]['producer_preparation'] if records else
                         self.base_authority(value, index, plan, producer, output))
            copies = None
            for batch in remaining:
                bid, temporary = batch['batch_id'], None
                if bid == 'BASE':
                    proof = authority['result']['base_verification']
                else:
                    if copies is None:
                        copies = [self.save(output / 'materialization-inputs' / name, doc)
                                  for name, doc in (('GLOBAL-CANDIDATE-INDEX.json', index), ('BATCH-PLAN.json', plan))]
                        a.need([r['sha256'] for r in copies] == [value['index']['sha256'], value['batch_plan']['sha256']],
                               'checkpoint-exact-small-materializer-input-copies')
                    temporary = shm_base / ('batch-' + selected['stage_label'] + '-' + bid.lower())
                    a.need(not temporary.exists(), 'checkpoint-fresh-owned-decoded-directory')
                    proof = c.materialize(value['producer'], copies[0], copies[1], batch, temporary)
                descriptor_row = proof['descriptor']; descriptor = a.parse(a.guarded(descriptor_row))
                releases = {cohort: c.release_for(output, bid, cohort, descriptor['files'], context)
                            for cohort, context in contexts.items()}
                self.phase('PUBLIC_ADMISSION', bid)
                try:
                    prepared, preparation = c.prepare_snapshot(runtime_value, descriptor, releases, prepared_api)
                finally:
                    self.phase('SCANNERS', bid)
                try:
                    record = {'descriptor': descriptor, 'descriptor_row': descriptor_row, 'materialization': proof,
                              'releases': releases, 'preparation': preparation,
                              'producer_preparation': authority if bid == 'BASE' else None}
                    self.record_checked(record, batch, value, index, plan, contexts)
                    self.sync_record_references(releases, output, descriptor_row)
                    wrapped = self.wrapper(selected['execution_plan'], selected['stage_label'], output, record)
                    row = self.save(output / 'local-batches' / bid / 'RECORD.json', wrapped)
                    # Only after the complete record and its directories are durable
                    # may the unchanged one-Original launcher be called.
                    pairs = []
                    for original in value['originals']:
                        pairs.append(c.audit_one(runtime_value, original, descriptor, descriptor_row,
                            releases[original['cohort']], contexts[original['cohort']], output, prepared, preparation))
                        self.sync_directories(output / 'local-invocations' / bid)
                    # audit_one already deeply checks actual execution returns.
                    # Historical resume additionally rejoins all retained bytes.
                    self.sync_public_leaves(self.runtime_leaves(wrapped, value))
                finally:
                    prepared.close()
                records.append(record); invocations.extend(pairs); rows.append(row)
                checkpoint = {'schema': 'kpxa-publication-completed-prefix/v1', 'sources': self.identities(),
                              'execution_plan': selected['execution_plan'], 'completed_batches': len(rows),
                              'batch_records': rows}
                self.save(output / 'local-checkpoints' / ('PREFIX-' + str(len(rows)).zfill(6) + '.json'), checkpoint)
                if temporary is not None:
                    a.need(temporary.parent == shm_base and temporary.name.startswith('batch-' + selected['stage_label'] + '-'),
                           'checkpoint-owned-decoded-cleanup-only')
                    shutil.rmtree(temporary)
        return self.finish_primary(output, value, index, plan, contexts, coverage, records, invocations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    controller = Controller()
    selector = {'path': args.selection, 'sha256': args.selection_sha256}
    if args.execute:
        result = controller.execute(selector, args.output)
    else:
        loaded = controller.load(selector)
        result = {'public_resume_checked': True, 'completed_batches': len(loaded[6]),
                  'actual_original_workers_invoked': False, 'global_audit_complete': False}
    print(__import__('json').dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No exception values, local objects, Original routes or private logs.
        raise SystemExit('checkpointed publication incomplete; retain stage evidence') from None

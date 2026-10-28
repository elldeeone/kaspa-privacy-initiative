"""Parallel public-byte admission with unchanged helper09 in clean processes.

Jobs contain public candidate rows only. Every child authenticates this source
and the fixed base launcher, then calls its unchanged candidate_entry. There
are no Original routes, Original descriptors or cached PASS records in this API.
Files of at least 64 MiB run serially after every child has exited.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import types

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
BASE_SHA = 'c465c8e6c77b80a9d4f3928cbbe97704751104ec96488fcf9516efe007ceff42'
PARALLEL_LIMIT = 64 * 1024 * 1024
WORKERS = 8
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def need(value):
    if not value:
        raise ValueError('public-admission-pool-refused')


def parse(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out)
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def base_module(guard, selected):
    need(set(selected) == {'source', 'bytes', 'sha256'} and selected['sha256'] == BASE_SHA)
    raw = guard['read'](selected['source'], BASE_SHA)
    need(len(raw) == selected['bytes'])
    module = types.ModuleType('selected_public_admission_base')
    module.__file__ = selected['source']
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def sealed_job(value):
    fd = os.memfd_create('public-admission-job', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        raw = memoryview(encoded(value))
        while raw:
            count = os.write(fd, raw)
            need(count > 0)
            raw = raw[count:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def worker(args):
    need(re.fullmatch('[0-9a-f]{64}', args.self_sha256))
    guard = runpy.run_path(GUARD)
    guard['read'](str(Path(__file__).absolute()), args.self_sha256)
    need(stat.S_ISREG(os.fstat(args.job_fd).st_mode)
         and fcntl.fcntl(args.job_fd, fcntl.F_GET_SEALS) & SEALS == SEALS)
    with os.fdopen(os.dup(args.job_fd), 'rb') as stream:
        job = parse(stream.read())
    need(set(job) == {'schema', 'rows', 'runtime', 'base', 'source_sha256'}
         and job['schema'] == 'kpi-public-admission-job/v1'
         and job['source_sha256'] == args.self_sha256)
    base = base_module(guard, job['base'])
    runtime = Path(job['runtime'])
    need(runtime.is_absolute() and not any(p.is_symlink() for p in (runtime, *runtime.parents)))
    results = []
    for index, row in job['rows']:
        need(type(index) is int and index >= 0 and type(row) is dict
             and set(row) == {'source', 'path', 'bytes', 'sha256'}
             and type(row['bytes']) is int and 0 <= row['bytes'] < PARALLEL_LIMIT)
        selected, source, attributes, direct = base.candidate_entry(guard, row, index, runtime)
        results.append([index, str(selected), str(source), attributes, direct])
    raw = memoryview(encoded({'schema': 'kpi-public-admission-results/v1',
                              'source_sha256': args.self_sha256, 'entries': results}))
    while raw:
        count = os.write(args.result_fd, raw)
        need(count > 0)
        raw = raw[count:]


def admit(rows, runtime, selected_base, source_sha256, base, guard):
    """Parent-owned executions, exact ordered rows and fresh metadata checks."""
    source = str(Path(__file__).absolute())
    guard['read'](source, source_sha256)
    small = [(i, row) for i, row in enumerate(rows) if row['bytes'] < PARALLEL_LIMIT]
    large = [(i, row) for i, row in enumerate(rows) if row['bytes'] >= PARALLEL_LIMIT]
    count = min(WORKERS, len(small))
    processes, results = [], {}
    try:
        for n in range(count):
            jobs = small[n::count]
            job = sealed_job({'schema': 'kpi-public-admission-job/v1',
                              'rows': jobs, 'runtime': str(runtime), 'base': selected_base,
                              'source_sha256': source_sha256})
            reader, writer = os.pipe2(os.O_CLOEXEC)
            try:
                process = subprocess.Popen(['/usr/bin/python3', '-I', '-S', '-B', source,
                    '--worker', '--job-fd', str(job), '--result-fd', str(writer),
                    '--self-sha256', source_sha256], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True, pass_fds=(job, writer),
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
                processes.append((process, reader, jobs))
            except BaseException:
                os.close(reader)
                raise
            finally:
                os.close(job)
                os.close(writer)
        for process, reader, jobs in processes:
            chunks, size = [], 0
            while True:
                raw = os.read(reader, 65536)
                if not raw:
                    break
                size += len(raw)
                need(size <= 4 * 1024 * 1024)
                chunks.append(raw)
            need(process.wait() == 0)
            value = parse(b''.join(chunks))
            need(set(value) == {'schema', 'source_sha256', 'entries'}
                 and value['schema'] == 'kpi-public-admission-results/v1'
                 and value['source_sha256'] == source_sha256
                 and [r[0] for r in value['entries']] == [r[0] for r in jobs])
            for entry in value['entries']:
                need(type(entry) is list and len(entry) == 5
                     and type(entry[0]) is int and entry[0] not in results)
                results[entry[0]] = entry
        # No large byte read overlaps a child. There is no imported PASS authority:
        # these are the parent's own source-pinned child processes and pipes.
        for index, row in large:
            selected, origin, attributes, direct = base.candidate_entry(guard, row, index, runtime)
            results[index] = [index, str(selected), str(origin), parse(encoded(attributes)), direct]
        need(set(results) == set(range(len(rows))))
        guard['refresh']()
        admitted = []
        for index, row in enumerate(rows):
            _, selected, origin, attributes, direct = results[index]
            need(origin == row['source'] and type(direct) is bool
                 and direct == (row['bytes'] >= base.LARGE_PUBLIC_LEAF))
            expected = Path(origin) if direct else Path(runtime)/'candidates'/(str(index)+'.bin')
            need(selected == str(expected))
            checked, info = guard['m'].GUARD.metadata(Path(origin))
            actual = base.attributes(info)
            need(checked == Path(origin) and stat.S_ISREG(info.st_mode)
                 and info.st_nlink == 1 and info.st_size == row['bytes']
                 and parse(encoded(actual)) == attributes)
            admitted.append((expected, checked, actual, direct))
        return admitted
    finally:
        for process, reader, _ in processes:
            if process.poll() is None:
                process.terminate()  # Owned public-only workers; no Original input.
            process.wait()
            os.close(reader)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true', required=True)
    parser.add_argument('--job-fd', type=int, required=True)
    parser.add_argument('--result-fd', type=int, required=True)
    parser.add_argument('--self-sha256', required=True)
    args = parser.parse_args()
    try:
        worker(args)
    except Exception:
        raise SystemExit(1)  # No exception values, locals or private diagnostics.

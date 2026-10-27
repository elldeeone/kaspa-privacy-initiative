#!/usr/bin/env python3
"""Finite public-byte admission by fresh unchanged-helper processes, not threads."""
import fcntl
import hashlib
import json
import os
import struct
import subprocess

WORKER = r'''
import hashlib,json,runpy,struct,sys
request=json.load(sys.stdin)
assert request['schema']=='kpxa-public-admission-batch/v1'
read=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
out=sys.stdout.buffer
for row in request['sources']:
    raw=read(row['source'],row['sha256'])
    assert hashlib.sha256(raw).hexdigest()==row['sha256']
    header=json.dumps({'source':row['source'],'sha256':row['sha256'],'bytes':len(raw)},
                      sort_keys=True,separators=(',',':')).encode()
    out.write(struct.pack('<Q',len(header)));out.write(header);out.write(raw)
out.flush()
'''


def exact(fd, count):
    parts = []
    while count:
        raw = os.read(fd, count)
        if not raw:
            raise ValueError('incomplete public admission response')
        parts.append(raw)
        count -= len(raw)
    return b''.join(parts)


def read_many(rows, workers=4):
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('one to four isolated public guard processes required')
    selected = {}
    for row in rows:
        path, pin = row['source'], row['sha256']
        if path in selected and selected[path] != pin:
            raise ValueError('conflicting public source identity')
        selected[path] = pin
    ordered = [{'source': p, 'sha256': pin} for p, pin in sorted(selected.items())]
    groups = [ordered[i::workers] for i in range(workers)]
    active = []
    try:
        for group in groups:
            if not group:
                continue
            fd = os.memfd_create('public-admission-response', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                process = subprocess.Popen(['/usr/bin/python3.14', '-I', '-S', '-B', '-c', WORKER],
                    stdin=subprocess.PIPE, stdout=fd, stderr=subprocess.PIPE, close_fds=True,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
            except BaseException:
                os.close(fd)
                raise
            active.append((process, fd, group))
            raw = json.dumps({'schema': 'kpxa-public-admission-batch/v1', 'sources': group},
                             sort_keys=True, separators=(',', ':')).encode()
            process.stdin.write(raw)
            process.stdin.close()
            process.stdin = None
        output = {}
        for process, fd, group in active:
            _, error = process.communicate()
            if process.returncode != 0:
                raise ValueError('unchanged public guard batch refused input: ' + error.decode(errors='replace')[:500])
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            os.lseek(fd, 0, os.SEEK_SET)
            for expected in group:
                width = struct.unpack('<Q', exact(fd, 8))[0]
                if not 0 < width <= 1_048_576:
                    raise ValueError('invalid public response header')
                header = json.loads(exact(fd, width))
                if set(header) != {'source', 'sha256', 'bytes'} or type(header['bytes']) is not int \
                        or not 0 <= header['bytes'] < 1 << 63 \
                        or {k: header[k] for k in ('source', 'sha256')} != expected:
                    raise ValueError('public admission response identity differs')
                raw = exact(fd, header['bytes'])
                if hashlib.sha256(raw).hexdigest() != expected['sha256']:
                    raise ValueError('public admission response bytes differ')
                output[(expected['source'], expected['sha256'])] = raw
            if os.read(fd, 1):
                raise ValueError('unexpected public admission response data')
        if len(output) != len(selected):
            raise ValueError('missing public admission response')
        return output
    finally:
        for process, fd, _ in active:
            if process.poll() is None:
                process.kill()
                process.wait()
            for pipe in (process.stdin, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
            os.close(fd)

#!/usr/bin/env python3
"""Selected local public-pool IPC; stdout is exactly the old offline program's."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import socket
import stat
import struct
import sys


def need(ok,message):
    if not ok:
        raise ValueError(message)


def parse(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def exact(stream,count):
    parts = []
    while count:
        body = stream.recv(count)
        need(body,'incomplete local pool reply')
        parts.append(body);count -= len(body)
    return b''.join(parts)


def run(a):
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    row = {'path':str(a.pool_selection),'sha256':a.pool_selection_sha256}
    selection = parse(read(row['path'],row['sha256']))
    need(selection['schema'] == 'kpxa-public-offline-pool-selection/v1'
         and selection['scope'] == 'local-offline-public-replay-and-preflight-only','selected offline pool contract')
    own = selection['client']
    need(own['path'] == str(Path(__file__).absolute()),'selected actual client')
    read(own['path'],own['sha256'])
    address = Path(selection['socket'])
    need(address.is_absolute() and str(PurePosixPath(address)) == str(address) and '..' not in address.parts,'canonical local socket')
    for parent in (address,*address.parents):
        need(not parent.is_symlink(),'local socket symlink')
    info = address.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,'owned selected local socket')
    parent = address.parent.stat()
    need(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,'private local IPC parent')
    request = {'path':str(a.request),'sha256':a.request_sha256}
    message = {'schema':'kpxa-public-offline-pool-call/v1','pool_selection':row,
               'role':a.role,'request':request,'output':str(a.output)}
    body = encoded(message)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.connect(str(address));stream.sendall(struct.pack('<Q',len(body))+body)
        width = struct.unpack('<Q',exact(stream,8))[0]
        need(0 < width < 1 << 63,'local reply frame width')
        reply = parse(exact(stream,width))
    need(reply['schema'] == 'kpxa-public-offline-pool-reply/v1' and reply['pool_selection'] == row
         and reply['role'] == a.role and reply['request'] == request and reply['output'] == str(a.output)
         and type(reply['returncode']) is int,'bound local offline reply')
    stdout = base64.b64decode(reply['stdout_base64'],validate=True)
    stderr = base64.b64decode(reply['stderr_base64'],validate=True)
    if reply['returncode'] == 0:
        need(stderr == b'','successful offline role emitted stderr')
        # This is a new public export after a long child operation. Use the
        # unchanged guard with current private metadata, never clear a guard.
        export_read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        proof = parse(export_read(str(a.output/'POOL-PROVENANCE.json')))
        need(proof['pool_selection'] == row and proof['role'] == a.role and proof['request'] == request
             and proof['output'] == str(a.output) and proof['network'] == 'none'
             and proof['stdout_sha256'] == hashlib.sha256(stdout).hexdigest(),'export provenance binds old stdout')
    sys.stdout.buffer.write(stdout);sys.stderr.buffer.write(stderr)
    return reply['returncode']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pool-selection','request','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('pool-selection-sha256','request-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--role',choices=('replay','preflight'),required=True)
    try:
        raise SystemExit(run(parser.parse_args()))
    except (ValueError,OSError,KeyError,TypeError):
        raise SystemExit('public offline pool incomplete')

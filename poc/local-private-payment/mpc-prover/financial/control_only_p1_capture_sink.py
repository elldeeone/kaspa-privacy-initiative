#!/usr/bin/env python3
"""Privately preserve one C03 stream; never mint launch/privacy authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct


MAGIC = b'KPBP1C03'
HEADER_BYTES = 112
MAX_CHUNK_BYTES = 1 << 16


def need(value):
    if not value:
        raise RuntimeError('control-only-p1-capture-refused')


def write_all(descriptor, value):
    offset = 0
    while offset < len(value):
        count = os.write(descriptor, value[offset:])
        need(count > 0)
        offset += count


def fsync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def publish_new(temporary, path):
    # link(2) is the portable no-replace publication primitive here. rename(2)
    # would silently overwrite a same-UID race target.
    os.link(temporary, path, follow_symlinks=False)
    os.unlink(temporary)
    fsync_directory(path.parent)


def write_receipt(path, value):
    temporary = path.with_name(path.name + '.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        write_all(descriptor, json.dumps(
            value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    publish_new(temporary, path)


def preserve(connection, raw_output):
    partial = raw_output.with_name(raw_output.name + '.partial')
    incomplete = raw_output.with_name(raw_output.name + '.incomplete')
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    digest = hashlib.sha256()
    total = 0

    def take(count):
        nonlocal total
        blocks = []
        remaining = count
        while remaining:
            block = connection.recv(remaining)
            if not block:
                raise RuntimeError('truncated-control-c03')
            write_all(descriptor, block)
            digest.update(block)
            total += len(block)
            blocks.append(block)
            remaining -= len(block)
        return b''.join(blocks)

    sequence = 0
    next_message = 0
    current = None
    frame_count = 0
    ended = False
    try:
        while not ended:
            header = take(HEADER_BYTES)
            need(header[:8] == MAGIC and header[13:16] == bytes(3))
            record_type, semantic, direction, peer, flags = header[8:13]
            monotonic_ns = struct.unpack('>Q', header[16:24])[0]
            selected_sequence = struct.unpack('>Q', header[24:32])[0]
            message = struct.unpack('>Q', header[32:40])[0]
            chunk = struct.unpack('>I', header[40:44])[0]
            size = struct.unpack('>I', header[44:48])[0]
            payload_digest = header[80:112]
            need(selected_sequence == sequence and monotonic_ns > 0 and
                 1 <= record_type <= 6 and semantic > 0 and
                 direction in (1, 2, 3) and flags & ~3 == 0 and
                 size <= MAX_CHUNK_BYTES)
            payload = take(size)
            need(hashlib.sha256(payload).digest() == payload_digest)
            first = bool(flags & 1)
            last = bool(flags & 2)
            if first:
                need(current is None and message == next_message and chunk == 0)
                current = (message, record_type, semantic, direction, peer, 0)
                next_message += 1
            else:
                need(current is not None and message == current[0] and
                     chunk == current[5] + 1)
            need(current is not None and
                 (record_type, semantic, direction, peer) == current[1:5])
            current = (*current[:5], chunk)
            if last:
                current = None
            if frame_count == 0:
                need(record_type == 1 and first and last)
            if record_type == 5:
                need(first and last and size == 0 and current is None)
                ended = True
            sequence += 1
            frame_count += 1
        need(connection.recv(1) == b'')
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        publish_new(partial, raw_output)
        return total, frame_count, digest.hexdigest()
    except BaseException:
        if descriptor >= 0:
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if partial.exists():
            publish_new(partial, incomplete)
        raise


def run(socket_path, raw_output, receipt_path):
    temporary_paths = (
        raw_output.with_name(raw_output.name + '.partial'),
        raw_output.with_name(raw_output.name + '.incomplete'),
        receipt_path.with_name(receipt_path.name + '.new'),
    )
    for path in (socket_path, raw_output, receipt_path, *temporary_paths):
        need(path.is_absolute() and not path.exists())
        parent = path.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and
             stat.S_IMODE(parent.st_mode) & 0o077 == 0)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        connection, _ = listener.accept()
        with connection:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack('3i', credentials)
            need(uid == os.getuid())
            total, frames, identity = preserve(connection, raw_output)
        write_receipt(receipt_path, {
            'schema': 'kpb-p1-control-only-private-capture/v1',
            'status': 'CONTROL_ONLY_UNREGISTERED_CAPTURED',
            'c03_sha256': identity,
            'c03_bytes': total,
            'frame_count': frames,
            'configured': False,
            'launch_authorized': False,
            'actual_receipt_enabled': False,
            'serialized_receipt_is_authority': False,
            'raw_capture_path_exported': False,
            'raw_capture_body_exported': False,
        })
    finally:
        listener.close()
        try:
            info = socket_path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                socket_path.unlink()
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--raw-output', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.socket, args.raw_output, args.receipt)
    except BaseException:
        raise SystemExit(78) from None


if __name__ == '__main__':
    main()

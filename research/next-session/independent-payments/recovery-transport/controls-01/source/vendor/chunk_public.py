#!/usr/bin/env python3
"""Optional raw public-file chunk transport; external whole-file anchor wins.

No private inputs, parameter decoding, executable selection, proof or network.
Returned paths remain subject to ADR0054's trusted-host assumption. The existing
parameter loader must repeat whole-owned-buffer authentication before seed use.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets

import capsule as c


CHUNK_BYTES = 1_073_741_824
BUFFER_BYTES = 1_048_576
INDEX_LIMIT = 1_048_576
SCHEMA = 'kpx4-public-object-chunks/v1'


def _anchor(length, digest):
    c.uint(length, 'invalid-expected-length', positive=True)
    c.hx(digest, 32, 'invalid-expected-sha256')


def _same(before, after):
    return tuple(getattr(before, f) for f in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) == \
        tuple(getattr(after, f) for f in
              ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _parent(path):
    """Owned output parent FD, rejecting every symbolic-link component."""
    path = c._path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _create(fd, name):
    return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                   os.O_CLOEXEC, 0o600, dir_fd=fd)


def _publish(fd, temporary, final):
    # link is atomic and refuses an existing destination, unlike rename().
    os.link(temporary, final, src_dir_fd=fd, dst_dir_fd=fd,
            follow_symlinks=False)
    os.unlink(temporary, dir_fd=fd)
    os.fsync(fd)


def _basename(index, digest):
    return f'chunk-{index:08d}-{digest}.bin'


def _manifest(raw, length, digest):
    c.need(len(raw) <= INDEX_LIMIT, 'chunk-index-too-large')
    value = c.parse(raw)
    c.exact(value, ('schema', 'object_bytes', 'object_sha256', 'chunk_bytes',
                    'chunks'), 'chunk-index-fields')
    c.need(value['schema'] == SCHEMA, 'chunk-index-schema')
    c.uint(value['object_bytes'], 'chunk-index-length', positive=True)
    c.hx(value['object_sha256'], 32, 'chunk-index-sha256')
    c.need(value['object_bytes'] == length and value['object_sha256'] == digest,
           'chunk-index-external-anchor-mismatch')
    c.need(type(value['chunk_bytes']) is int and
           value['chunk_bytes'] == CHUNK_BYTES, 'chunk-size-rule')
    chunks = value['chunks']
    c.need(type(chunks) is list and
           len(chunks) == (length + CHUNK_BYTES - 1) // CHUNK_BYTES,
           'chunk-count')
    for i, chunk in enumerate(chunks):
        c.exact(chunk, ('index', 'offset', 'bytes', 'sha256', 'basename'),
                'chunk-fields')
        for key in ('index', 'offset', 'bytes'):
            c.uint(chunk[key], 'chunk-integer')
        c.hx(chunk['sha256'], 32, 'chunk-sha256')
        c.need(chunk['index'] == i and chunk['offset'] == i * CHUNK_BYTES and
               chunk['bytes'] == min(CHUNK_BYTES, length - i * CHUNK_BYTES),
               'chunk-position-or-length')
        c.need(chunk['basename'] == _basename(i, chunk['sha256']),
               'chunk-basename')
    return value


def _absence(paths):
    for raw in paths:
        path = c._path(raw)
        c.need(not path.exists() and not path.is_symlink(),
               'required-original-path-visible')
    return {'original_path_absence_probe_count': len(paths),
            'all_requested_original_paths_absent': True if paths else None}


def pack(source, length, digest, output_directory, forbidden_paths=()):
    _anchor(length, digest)
    forbidden = c._metadata_forbidden(forbidden_paths)
    stream, before = c._open_public(source, forbidden)
    parent = directory = None
    created = False
    owned_names = []
    chunks = []
    whole = hashlib.sha256()
    try:
        c.need(before.st_size == length, 'source-length-mismatch')
        parent, name = _parent(output_directory)
        os.mkdir(name, 0o700, dir_fd=parent)
        created = True
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=parent)
        for index, offset in enumerate(range(0, length, CHUNK_BYTES)):
            size = min(CHUNK_BYTES, length - offset)
            temporary = '.partial-' + secrets.token_hex(16)
            owned_names.append(temporary)
            chunk_hash = hashlib.sha256()
            with os.fdopen(_create(directory, temporary), 'wb') as target:
                remaining = size
                while remaining:
                    raw = stream.read(min(BUFFER_BYTES, remaining))
                    c.need(bool(raw), 'source-truncated')
                    target.write(raw)
                    chunk_hash.update(raw)
                    whole.update(raw)
                    remaining -= len(raw)
                target.flush()
                os.fsync(target.fileno())
                os.fchmod(target.fileno(), 0o444)
            chunk_digest = chunk_hash.hexdigest()
            basename = _basename(index, chunk_digest)
            _publish(directory, temporary, basename)
            owned_names.remove(temporary)
            owned_names.append(basename)
            chunks.append({'index': index, 'offset': offset, 'bytes': size,
                           'sha256': chunk_digest, 'basename': basename})
        c.need(stream.read(1) == b'', 'source-trailing-bytes')
        c.need(_same(before, os.fstat(stream.fileno())), 'source-changed')
        c.need(whole.hexdigest() == digest, 'source-whole-sha256-mismatch')
        value = {'schema': SCHEMA, 'object_bytes': length,
                 'object_sha256': digest, 'chunk_bytes': CHUNK_BYTES,
                 'chunks': chunks}
        raw = c.encoded(value)
        _manifest(raw, length, digest)
        temporary = '.partial-' + secrets.token_hex(16)
        owned_names.append(temporary)
        with os.fdopen(_create(directory, temporary), 'wb') as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o444)
        _publish(directory, temporary, 'manifest.json')
        owned_names.remove(temporary)
        owned_names.append('manifest.json')
        os.fsync(parent)
        return {'schema': 'kpx4-public-object-chunk-pack-result/v1',
                'whole_bytes': length, 'whole_sha256': digest,
                'chunk_bytes': CHUNK_BYTES, 'chunk_count': len(chunks),
                'index_sha256_hint_not_authority': c.sha(raw),
                'whole_verified': True, 'published_externally': False}
    except BaseException:
        if directory is not None:
            for owned in reversed(owned_names):
                try:
                    os.unlink(owned, dir_fd=directory)
                except FileNotFoundError:
                    pass
        if created:
            os.rmdir(name, dir_fd=parent)
        raise
    finally:
        stream.close()
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)


def restore(manifest, length, digest, mirrors, output, forbidden_paths=(),
            must_be_absent=()):
    _anchor(length, digest)
    # Reuse exclusions for metadata preflight and manifest open. Materialize a
    # one-shot caller iterable before either pass can consume it.
    forbidden_paths = tuple(forbidden_paths)
    must_be_absent = tuple(must_be_absent)
    forbidden = c._metadata_forbidden(forbidden_paths)
    absence = _absence(must_be_absent)
    # This performs the manifest inode guard before even opening its content.
    raw = c.read_public(manifest, forbidden_paths, maximum=INDEX_LIMIT)
    value = _manifest(raw, length, digest)
    c.need(bool(mirrors), 'no-chunk-mirrors')
    roots = [c._path(root) for root in mirrors]
    parent = None
    temporary = '.partial-' + secrets.token_hex(16)
    published = False
    selected = []
    rejected = []
    whole = hashlib.sha256()
    try:
        parent, name = _parent(output)
        # Metadata-only existence check; never open a caller-selected target.
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise c.Invalid('output-already-exists')
        with os.fdopen(_create(parent, temporary), 'wb') as target:
            for chunk in value['chunks']:
                ok = False
                for candidate, root in enumerate(roots):
                    tentative = whole.copy()
                    chunk_hash = hashlib.sha256()
                    try:
                        source, before = c._open_public(root / chunk['basename'],
                                                        forbidden)
                        with source:
                            c.need(before.st_size == chunk['bytes'],
                                   'chunk-file-length-mismatch')
                            remaining = chunk['bytes']
                            while remaining:
                                part = source.read(min(BUFFER_BYTES, remaining))
                                c.need(bool(part), 'chunk-truncated')
                                target.write(part)
                                chunk_hash.update(part)
                                tentative.update(part)
                                remaining -= len(part)
                            c.need(source.read(1) == b'', 'chunk-trailing-bytes')
                            c.need(_same(before, os.fstat(source.fileno())),
                                   'chunk-file-changed')
                        c.need(chunk_hash.hexdigest() == chunk['sha256'],
                               'chunk-content-sha256-mismatch')
                    except (c.Invalid, OSError) as error:
                        target.seek(chunk['offset'])
                        target.truncate()
                        rejected.append({'chunk': chunk['index'],
                                         'mirror': candidate,
                                         'reason': str(error) if isinstance(
                                             error, c.Invalid) else
                                             'chunk-read-unavailable'})
                        continue
                    whole = tentative
                    selected.append(candidate)
                    ok = True
                    break
                c.need(ok, 'required-chunk-unavailable')
            c.need(target.tell() == length and whole.hexdigest() == digest,
                   'reconstructed-whole-anchor-mismatch')
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o444)
        _publish(parent, temporary, name)
        published = True
        return {'schema': 'kpx4-public-object-chunk-restore-result/v1',
                'whole_bytes': length, 'whole_sha256': digest,
                'chunk_bytes': CHUNK_BYTES,
                'chunk_count': len(value['chunks']),
                'selected_mirror_ordinals': selected,
                'rejected_candidates': rejected, 'whole_verified': True,
                'parameters_decoded_or_private_input_read': False,
                'native_or_chain_currentness_claimed': False,
                'independent_provider_or_retention_claimed': False, **absence}
    finally:
        if parent is not None:
            if not published:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('pack', 'restore'):
        arg = sub.add_parser(operation)
        arg.add_argument('--expected-bytes', required=True, type=int)
        arg.add_argument('--expected-sha256', required=True)
        arg.add_argument('--forbidden', action='append', default=[], type=Path)
        if operation == 'pack':
            arg.add_argument('--source', required=True, type=Path)
            arg.add_argument('--output-dir', required=True, type=Path)
        else:
            arg.add_argument('--manifest', required=True, type=Path)
            arg.add_argument('--mirror', required=True, action='append', type=Path)
            arg.add_argument('--output', required=True, type=Path)
            arg.add_argument('--must-be-absent', action='append', default=[],
                             type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'pack':
            result = pack(args.source, args.expected_bytes,
                          args.expected_sha256, args.output_dir, args.forbidden)
        else:
            result = restore(args.manifest, args.expected_bytes,
                             args.expected_sha256, args.mirror, args.output,
                             args.forbidden, args.must_be_absent)
    except (c.Invalid, OSError) as error:
        print(json.dumps({'status': 'PUBLIC_CHUNK_TRANSPORT_INCOMPLETE',
                          'reason': str(error) if isinstance(error, c.Invalid)
                          else 'public-path-or-io-unavailable'}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

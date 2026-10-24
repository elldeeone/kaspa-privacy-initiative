"""Scheduled producer invocations using opaque handles, public outputs only."""
import os
from pathlib import Path
import sys

from commands import OwnerHandles
from public import hx, need

ROOT = Path(__file__).resolve().parents[1]


def created_public(guard, path):
    """First read of a newly produced public export, before its pin exists."""
    path, before = guard.metadata(path)
    need(before.st_size <= 1 << 20, 'bounded-producer-public-export')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        attrs = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(opened, key) == getattr(before, key) for key in attrs) and
             (opened.st_dev, opened.st_ino) not in guard.forbidden, 'public-producer-swapped-before-read')
        raw = stream.read((1 << 20) + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and all(getattr(after, key) == getattr(before, key) for key in attrs),
         'stable-new-public-export')
    return raw


def invoke_owner(args, guard):
    need(args.execute and type(args.party) is int and 0 <= args.party < 3,
         'scheduled-owner-operation-explicit')
    guard.read(ROOT / 'wallet/run_owner.py', args.wallet_script_sha256)
    handles = OwnerHandles(args.exclude_owner_private_directory, args.exclude_private_root)
    operation = args.op.removeprefix('owner-')
    if operation == 'init':
        guard.read(args.crypto[0], args.crypto[1])
        hx(args.participant_id, 32)
        extra = ['--participant-id', args.participant_id, '--position', str(args.party),
                 '--admission-sompi', str(args.admission_sompi), '--crypto', args.crypto[0]]
    else:
        need(args.assets is not None and args.session is not None, 'selected-owner-public-assets-session')
        guard.read(args.assets[0], args.assets[1]); guard.read(args.session[0], args.session[1])
        extra = ['--assets', args.assets[0], '--assets-sha256', args.assets[1],
                 '--session', args.session[0], '--session-sha256', args.session[1]]
        if operation == 'prepare':
            guard.read(args.context[0], args.context[1])
            extra += ['--context', args.context[0], '--context-sha256', args.context[1],
                      '--party', str(args.party)]
        else:
            guard.read(args.projection[0], args.projection[1])
            relative = Path(args.own_mpc_result)
            need(not relative.is_absolute() and '..' not in relative.parts,
                 'own-MPC-result-relative-handle-only')
            extra += ['--projection', args.projection[0], '--projection-sha256', args.projection[1],
                      '--own-mpc-result', str(relative)]
    handles.execute(handles.owner(operation, args.party, args.output, extra + ['--execute']))


def invoke_construction(args, guard):
    need(args.execute, 'scheduled-construction-operation-explicit')
    guard.read(ROOT / 'construction/backend.py', args.backend_sha256)
    handles = OwnerHandles(args.exclude_owner_private_directory, args.exclude_private_root)
    operation = args.op.removeprefix('mpc-')
    if operation == 'prepare':
        guard.read(args.session[0], args.session[1])
        extra = ['--engine-root', args.engine_root, '--session', args.session[0],
                 '--session-sha256', args.session[1], '--program-sha256', args.program_sha256,
                 '--codec-sha256', args.codec_sha256, '--party-sha256', args.party_sha256,
                 '--coordinator-sha256', args.coordinator_sha256]
    else:
        guard.read(Path(args.prepared_root) / 'PREPARED.json', args.prepared_sha256)
        extra = ['--prepared-root', args.prepared_root, '--prepared-sha256', args.prepared_sha256, '--execute']
    handles.execute(handles.construction(operation, args.output, extra))


def native_projection(args, guard, body):
    guard.read(args.native_codec[0], args.native_codec[1])
    sys.path.insert(0, str(ROOT / 'verification'))
    from native_case import NativeCodec, make_case
    return make_case(NativeCodec(Path(args.native_codec[0]), args.native_codec[1]), body,
                     hx(args.outer_image_hex32, 32), hx(args.component_profile_sha256, 32),
                     args.compute_budget)

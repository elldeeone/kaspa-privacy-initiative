"""UNSELECTED finite network-off launcher for the received Native/INDEX role.

Only source, public parameters, and typed completion bytes are host-readable.
The received structured capture and private INDEX are never opened or hashed.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from method03_guard import load_guard
_GUARD = load_guard()

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
DEV = ROOT / '.local/private-exit-method03-source-01'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(value, category):
    if not value:
        raise ValueError(category)


def write_new(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(item.is_symlink() for item in (path, *path.parents)), 'method03-native-canonical-path')
    return path


def translate_ref(ref, alias, host):
    """Translate a source-produced PUBLIC ref; do not read/hash its data."""
    need(type(ref) is dict and set(ref) == {'path', 'sha256'}, 'method03-native-public-ref-shape')
    path = Path(ref['path']); base = Path(alias)
    need(path.is_relative_to(base) and '..' not in path.parts, 'method03-native-public-ref-alias')
    pin = ref['sha256']
    need(type(pin) is str and len(pin) == 64 and bytes.fromhex(pin).hex() == pin,
         'method03-native-public-ref-pin')
    target = checked(Path(host) / path.relative_to(base)); info = target.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
         'method03-native-public-owned-leaf')
    return {'path': str(target), 'sha256': pin}


def prepare_capture(selected, selection_sha, generation, capture, read):
    from method03_generation import binding, CODEC, ENGINE, PARAMETERS, TAIL, bootstrap, lifecycle
    context = binding(selected, selection_sha)
    need(capture['binding'] == context and capture['broadcast'] is False,
         'method03-native-actual-transport-binding')
    public = checked(selected['public']) / 'received-native'
    private = checked(generation['private']) / 'received-native'
    public.mkdir(mode=0o700); private.mkdir(mode=0o700)
    native_output = private / 'output'; native_output.mkdir(mode=0o700)
    capture_dir = checked(capture['raw_capture']['directory'])
    need(capture_dir.is_relative_to(checked(selected['transport_compartments']['capture_root']))
         and stat.S_ISDIR(capture_dir.lstat().st_mode), 'method03-native-capture-only-subtree')
    sources = [(DEV / 'method03_native.py', '/app/method03_native.py'),
        (HERE / 'exit_wire.py', '/app/trial/exit_wire.py'),
        (HERE.parent / 'verification/wire.py', '/app/verification/wire.py')]
    shared = checked(selected['public']) / 'selected-public'
    mounts = []
    for source, alias in sources:
        row = next(row for row in selected['source_members'] if row['path'] == str(source))
        leaf = shared / ('source-' + str(row['index']))
        read(leaf, row['sha256'])
        mounts += ['--ro-bind', str(leaf), alias]
    tools = [(CODEC, '/tools/codec', selected['native_source_pins']['codec']),
        (ENGINE, '/tools/engine', selected['native_source_pins']['engine']),
        (bootstrap.BINARY, '/tools/verifier', selected['native_source_pins']['verifier']),
        (PARAMETERS, '/parameters/PARAMETERS.json', selected['native_source_pins']['parameters']),
        (lifecycle.EXIT_PARAMETERS / 'MANIFEST.json', '/parameters/MANIFEST.json', selected['native_source_pins']['manifest']),
        (TAIL, '/parameters/IMMUTABLE-TAIL.bin', selected['native_source_pins']['tail'])]
    for path, alias, pin in tools:
        read(path, pin); mounts += ['--ro-bind', str(path), alias]
    spec = {'schema': 'kpb-method03-received-native-specification/v1', 'binding': context,
        'source_pins': selected['native_source_pins'],
        'public_notes': {'path': '/public/NOTES.json', 'sha256': generation['notes']['sha256']},
        'transport_parameters': capture['transport_parameters']}
    spec_path = public / 'SPECIFICATION.json'; write_new(spec_path, spec)
    marker = public / 'NO-ORIGINAL-METHOD03-NATIVE'
    marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(marker_fd, 'wb') as handle:
        handle.write(b'METHOD03_CAPTURE_ONLY_NETWORK_OFF\n'); handle.flush(); os.fsync(handle.fileno())
    import hashlib
    spec_sha = hashlib.sha256(read(spec_path)).hexdigest()
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *mounts, '--ro-bind', str(spec_path), '/public/NATIVE-SPEC.json',
        '--ro-bind', str(marker), '/NO-ORIGINAL-METHOD03-NATIVE',
        '--ro-bind', generation['notes']['path'], '/public/NOTES.json',
        '--ro-bind', str(capture_dir), '/capture/arrivals', '--bind', str(native_output), '/native',
        '--bind', str(public / 'public-output'), '/public-output', '--chdir', '/tmp',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-I', '-B', '-S', '/app/method03_native.py',
        '--specification', '/public/NATIVE-SPEC.json', '--specification-sha256', spec_sha,
        '--capture', '/capture/arrivals', '--output', '/native/result', '--public-output', '/public-output/result']
    (public / 'public-output').mkdir(mode=0o700)
    started = time.monotonic_ns()
    # stdout is a fixed public completion only; raw diagnostics stay private.
    with (private / 'STDERR.log').open('xb') as stderr:
        process = subprocess.run(argv, env=CLEAN, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr)
    ended = time.monotonic_ns()
    write_new(public / 'OPERATOR-ROUTE.json', {'schema': 'kpb-method03-native-source-route/v1',
        'binding': context, 'argv': argv, 'started_monotonic_ns': started,
        'completed_monotonic_ns': ended, 'returncode': process.returncode,
        'controller_capture_or_INDEX_body_read_or_hash': False})
    completion = json.loads(process.stdout)
    need(process.returncode == 0 and completion['schema'] == 'kpb-method03-native-completion/v1'
         and completion['status'] in ('COMPLETE', 'UNQUALIFIED')
         and type(completion['actual_checks_passed']) is bool
         and type(completion['records_seen']) is int and completion['records_seen'] == 6
         and type(completion['checks_completed']) is int and 0 <= completion['checks_completed'] <= 6,
         'method03-native-source-producer-incomplete')
    index = Path(completion['index_path'])
    need(index.is_relative_to('/native/result') and '..' not in index.parts,
         'method03-native-private-index-alias')
    index_path = checked(native_output / index.relative_to('/native'))
    info = index_path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) in (0o400, 0o600), 'method03-native-private-index-metadata')
    return {'schema': 'kpb-method03-source-produced-capture/v1', 'binding': context,
        'private_index': {'path': str(index_path), 'bytes': info.st_size, 'dev': info.st_dev,
                          'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns},
        'public_exits': translate_ref(completion['public_exits'], '/public-output', public / 'public-output'),
        'native_public_result': translate_ref(completion['native_public_result'], '/public-output', public / 'public-output'),
        'metadata_journal': capture['metadata_journal'],
        'baseline_A_exposure': capture['baseline_A_exposure'],
        'actual_native_checks_passed': completion['actual_checks_passed'],
        'full_packet_available': False, 'controller_capture_or_INDEX_body_read_or_hash': False}

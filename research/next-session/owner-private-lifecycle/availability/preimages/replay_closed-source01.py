#!/usr/bin/env python3
"""Replay selected public chain data using an authenticated downloaded runtime.

This standard-library-only bootstrap is separately selected from the immutable
software archive. It never mounts an owner directory, key, PK or original path.
The fixed financial replay executes only inside the fresh public namespace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


INVENTORY_SHA = '24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca'
PROFILE_SHA = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
CODEC_SHA = '8f724750bb4cc849e2e4bde26fc8da2b5bc7f9a7e4ffd09153ee1af15858d208'
CODEC_BYTES = 1544152
RESERVED = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
ORIGINAL_REPOSITORY = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
SHA = re.compile('[0-9a-f]{64}\\Z')
INPUTS = frozenset(('selection', 'descriptor', 'fetch', 'parameters', 'sessions', 'source-pins'))
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-public-JSON-key')
            result[key] = value
        return result

    def no_float(_):
        raise Refused('non-integer-public-JSON-number')

    return json.loads(raw, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)


def checked(value):
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == str(value),
         'canonical-absolute-public-path')
    need(not path.is_symlink() and all(not parent.is_symlink() for parent in path.parents),
         'public-path-symlink')
    return path


def relative(value):
    need(type(value) is str, 'public-relative-path-type')
    path = PurePosixPath(value)
    need(value and bool(path.parts) and value == path.as_posix() and not path.is_absolute()
         and '\\' not in value and all(part not in ('.', '..') for part in path.parts),
         'canonical-public-relative-path')
    return value


def attributes(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def retained_roots():
    """Only metadata is inspected; nonexistent old fixtures are not required."""
    roots = [RESERVED]
    for trial in ('kpi-four-wallet-local-rehearsal-01', 'kpi-four-wallet-live-01'):
        roots.extend(Path('/var/tmp') / trial / 'owners' / role for role in 'ABCD')
    roots.extend(Path('/var/tmp/kpi-owner-private-integration-01') / name
                 for name in ('party-0', 'party-1', 'party-2', 'controller-private'))
    diagnostic = Path('/var/tmp/kpi-owner-private-diagnostics-01')
    if diagnostic.is_dir():
        roots.extend(p for p in diagnostic.iterdir()
                     if p.name not in ('public', 'PUBLIC-SELECTOR.json') and p.is_dir())
    for number in range(1, 17):
        world = Path('/var/tmp/kpi-owner-private-cohort-01') / f'world-{number:02d}'
        roots.extend(world / name for name in
                     ('party-0', 'party-1', 'party-2', 'controller-private'))
    roots.extend(Path('/var/tmp') / name for name in
                 ('kpi-owner-private-cohort-controller-01',
                  'kpi-owner-private-publication-runtime-01',
                  'kpi-owner-private-publication-runtime-02'))
    return tuple(p for p in roots if p == RESERVED or p.exists())


class PublicPolicy:
    def __init__(self, roots):
        self.roots = tuple(checked(root) for root in roots)
        need(self.roots and len(set(self.roots)) == len(self.roots), 'private-roots-required')
        # This check precedes every caller-selected content read, including the
        # packet and inventory. A small own-backup parent is insufficient.
        need(all(any(root.is_relative_to(parent) for parent in self.roots)
                 for root in retained_roots()), 'whole-retained-private-coverage')
        need(all(not Path(system).is_relative_to(root) and not root.is_relative_to(Path(system))
                 for root in self.roots for system in ('/usr', '/lib', '/lib64')),
             'private-roots-outside-system-mounts')
        self.inodes = set()
        self.refresh()

    def refresh(self):
        for root in self.roots:
            if not root.exists():
                continue
            need(root.is_dir() and not root.is_symlink(), 'private-root-directory-metadata')
            for current, _, names in os.walk(root, followlinks=False):
                for name in names:
                    info = (Path(current) / name).lstat()
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    need(stat.S_ISREG(info.st_mode), 'private-file-metadata-type')
                    self.inodes.add((info.st_dev, info.st_ino))

    def public(self, value):
        path = checked(value)
        need(all(not path.is_relative_to(root) for root in self.roots), 'public-inside-private')
        return path

    def read(self, value, expected, size=None):
        self.refresh()
        path = self.public(value)
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and (before.st_dev, before.st_ino) not in self.inodes,
             'public-private-inode-or-type')
        need(size is None or before.st_size == size, 'selected-public-length')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            need(attributes(os.fstat(fd)) == attributes(before)
                 and (before.st_dev, before.st_ino) not in self.inodes, 'public-before-first-byte')
            with os.fdopen(os.dup(fd), 'rb') as source:
                raw = source.read()
            need(attributes(os.fstat(fd)) == attributes(before)
                 and attributes(path.lstat()) == attributes(before)
                 and len(raw) == before.st_size and (expected is None or digest(raw) == expected),
                 'whole-selected-public-bytes')
        finally:
            os.close(fd)
        return raw


def row(value):
    need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}, 'public-object-fields')
    relative(value['path'])
    need(type(value['bytes']) is int and 0 < value['bytes'] < 1 << 64
         and type(value['sha256']) is str and SHA.fullmatch(value['sha256']), 'public-object-identity')
    return value


def packet(raw):
    value = parse(raw)
    need(type(value) is dict and set(value) == {
        'schema', 'financial_profile_sha256', 'inputs', 'pages', 'expected'}, 'closed-replay-packet-fields')
    need(value['schema'] == 'kpx8-closed-replay-public-inputs/v1'
         and value['financial_profile_sha256'] == PROFILE_SHA, 'closed-replay-profile')
    need(type(value['inputs']) is dict and set(value['inputs']) == INPUTS
         and type(value['pages']) is list, 'closed-replay-input-set')
    rows = [*(row(item) for item in value['inputs'].values()), *(row(item) for item in value['pages'])]
    names = [item['path'] for item in rows]
    need(len(names) == len(set(names)) and all(
        not any(str(parent) in names for parent in PurePosixPath(name).parents if str(parent) != '.')
        for name in names), 'distinct-public-packet-files')
    expected = value['expected']
    need(type(expected) is dict and set(expected) == {'history_sha256', 'checkpoint_sha256'}
         and all(type(pin) is str and SHA.fullmatch(pin) for pin in expected.values()),
         'externally-selected-replay-output-pins')
    return value


def page_paths(fetch):
    rows = [*fetch['pages'], *fetch['current_view']['post_query_delta']['pages']]
    paths = [relative(record['path']) for record in rows]
    need(len(paths) == len(set(paths)), 'distinct-full-and-post-query-page-paths')
    return set(paths)


def write(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


ENTRY = '''from pathlib import Path
import hashlib,json,resource,sys,time
sys.dont_write_bytecode=True
options=json.loads(Path('/inputs/options.json').read_bytes())
absence={str(i):not Path(path).exists() for i,path in enumerate(options['absence'])}
assert all(absence.values()), 'original-path-visible-to-public-replay'
assert not list(Path('/dev').glob('nvidia*'))
sys.path.insert(0,'/work/poc/owner-private-lifecycle/chain')
import replay
assert Path(replay.__file__)==Path('/work/poc/owner-private-lifecycle/chain/replay.py')
packet=json.loads(Path('/inputs/packet.json').read_bytes())
inputs=packet['inputs']
def raw(name):return Path('/data',inputs[name]['path']).read_bytes()
def pin(name):return inputs[name]['sha256']
started=time.monotonic()
result=replay.replay(raw('selection'),pin('selection'),raw('descriptor'),pin('descriptor'),
 raw('fetch'),pin('fetch'),Path('/data'),raw('parameters'),pin('parameters'),
 Path('/runtime/native-codec'),options['codec_sha256'],raw('sessions'),pin('sessions'),
 raw('source-pins'),pin('source-pins'),Path('/out/replayed'),
 runtime_paths={name:Path('/work/runtime')/name for name in ('crypto','node','native-validator')},
 sdk_directory=Path('/work/sdk/kaspa'))
for name,expected in [('HISTORY.json',packet['expected']['history_sha256']),
 ('CHECKPOINT.json',packet['expected']['checkpoint_sha256'])]:
 assert hashlib.sha256(Path('/out/replayed',name).read_bytes()).hexdigest()==expected, 'replayed-output-pin'
usage=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
report={'schema':'kpx8-closed-public-replay-result/v1','status':result['status'],
 'history_sha256':packet['expected']['history_sha256'],'checkpoint_sha256':packet['expected']['checkpoint_sha256'],
 'all_original_paths_absent':all(absence.values()),'network_unshared':True,'GPU_mounted':False,
 'owner_backup_seed_witness_or_PK_mounted':False,'all_native_Full_and_input_engines_executed':True,
 'elapsed_seconds':time.monotonic()-started,
 'CPU_seconds_self_and_children':usage.ru_utime+usage.ru_stime+children.ru_utime+children.ru_stime,
 'independent_consensus_or_continuous_currentness':False,'spend_authorized':False}
Path('/out/ISOLATION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\\n')
print(json.dumps(report,sort_keys=True))
'''


def run(args):
    policy = PublicPolicy(args.exclude_private_directory)
    root = policy.public(args.software_root)
    data_root = policy.public(args.data_root)
    selected = packet(policy.read(args.packet, args.packet_sha256))
    inventory = parse(policy.read(args.software_inventory, INVENTORY_SHA))
    need(type(inventory) is dict and set(inventory) == {'schema', 'classification', 'files'}
         and inventory['schema'] == 'kpx4-public-software-bundle/v1'
         and inventory['classification'] == 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
         and type(inventory['files']) is list and len(inventory['files']) == 63,
         'fixed-complete-software-inventory')
    members = []
    for item in inventory['files']:
        need(type(item) is dict and set(item) == {'kind', 'path', 'bytes', 'sha256'}, 'software-member-fields')
        need(type(item['kind']) is str, 'software-member-kind')
        row({key: item[key] for key in ('path', 'bytes', 'sha256')})
        members.append((item, policy.read(root / item['path'], item['sha256'], item['bytes'])))
    need(len({item['path'] for item, _ in members}) == len(members), 'distinct-software-members')
    need(any(item['path'] == 'poc/owner-private-lifecycle/financial-profile.json'
             and item['sha256'] == PROFILE_SHA for item, _ in members), 'fixed-financial-profile-member')
    codec = policy.read(args.codec, CODEC_SHA, CODEC_BYTES)
    data = {}
    for item in [*selected['inputs'].values(), *selected['pages']]:
        data[item['path']] = policy.read(data_root / item['path'], item['sha256'], item['bytes'])
    fetch = parse(data[selected['inputs']['fetch']['path']])
    need(page_paths(fetch) == {item['path'] for item in selected['pages']}, 'complete-retained-page-closure')
    output = policy.public(args.output)
    need(not output.exists() and not output.is_relative_to(root) and not output.is_relative_to(data_root)
         and not output.is_relative_to(ORIGINAL_REPOSITORY), 'fresh-public-replay-output')
    output.mkdir(parents=True, mode=0o700)
    for item, raw in members:
        write(output / 'stage/software' / item['path'], raw,
              0o500 if item['kind'] == 'selected-executable' else 0o400)
    for name, raw in data.items():
        write(output / 'stage/data' / name, raw)
    write(output / 'stage/native-codec', codec, 0o500)
    write(output / 'stage/entry.py', ENTRY.encode())
    write(output / 'stage/packet.json', encoded(selected))
    absence = ['/home/luke', str(ORIGINAL_REPOSITORY), '/home/luke/.cargo',
               '/home/luke/.cache/kpi-sdk', '/var/tmp/kpi-owner-private-lifecycle-01']
    absence.extend(str(path) for path in policy.roots)
    write(output / 'stage/options.json', encoded({'absence': absence, 'codec_sha256': CODEC_SHA}))
    public = output / 'public'
    public.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv']
    for system in ('/usr', '/lib', '/lib64'):
        if Path(system).exists():
            command.extend(('--ro-bind', system, system))
    command.extend(('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
        '--ro-bind', str(output / 'stage/software'), '/work',
        '--ro-bind', str(output / 'stage/data'), '/data', '--dir', '/runtime',
        '--ro-bind', str(output / 'stage/native-codec'), '/runtime/native-codec',
        '--dir', '/inputs', '--ro-bind', str(output / 'stage/packet.json'), '/inputs/packet.json',
        '--ro-bind', str(output / 'stage/options.json'), '/inputs/options.json',
        '--ro-bind', str(output / 'stage/entry.py'), '/entry.py', '--bind', str(public), '/out',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '--chdir', '/work', '/usr/bin/python3', '-B', '/entry.py'))
    write(output / 'COMMAND.json', encoded(command))
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    write(output / 'stdout.log', process.stdout)
    write(output / 'stderr.log', process.stderr)
    need(process.returncode == 0, 'closed-public-replay-refused')
    raw = policy.read(public / 'ISOLATION.json', None)
    # This public output has no secret-bearing mounts. Its source/packet pins
    # and financial limitations remain explicit in the supervisor receipt.
    result = json.loads(raw)  # Fixed child operational metrics include finite floats.
    need(result['all_original_paths_absent'] and result['network_unshared']
         and result['all_native_Full_and_input_engines_executed'], 'closed-replay-isolation')
    receipt = {'schema': 'kpx8-closed-public-replay-run/v1',
               'packet_sha256': args.packet_sha256, 'software_inventory_sha256': INVENTORY_SHA,
               'codec_sha256': CODEC_SHA, 'typed_software_files': len(members),
               'retained_full_pages': len(selected['pages']), 'result': result,
               'financial_authorization_or_broadcast': False}
    write(output / 'RESULT.json', encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('software-root', 'software-inventory', 'data-root', 'packet', 'codec', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--exclude-private-directory', type=Path, action='append', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(2, 'closed public replay refused; inspect public-only retained logs\n')


if __name__ == '__main__':
    main()

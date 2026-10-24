#!/usr/bin/env python3
"""Run opaque public-byte recovery in a fresh minimal filesystem namespace."""
from pathlib import Path
import argparse
import json
import os
import stat
import subprocess
import time

import closure


SOURCE_PATHS = (
    'poc/owner-private-lifecycle/recovery/closure.py',
    'poc/four-wallet-storage/restore.py',
    'poc/current-wrapper-runtime/transport/public_fetch.py',
    'poc/current-wrapper-runtime/transport/trusted_util.py',
    'poc/current-wrapper-runtime/transport/vendor/capsule.py',
    'poc/current-wrapper-runtime/transport/vendor/chunk_public.py',
)
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def checked(value):
    path = Path(value).absolute()
    closure.need('..' not in path.parts
                 and not any(p.is_symlink() for p in (path, *path.parents)),
                 'canonical-no-symlink-public-path')
    return path


def attrs(info):
    return tuple(getattr(info, name) for name in
        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class PublicPolicy:
    """Metadata exclusions only; declared private contents are never opened."""
    def __init__(self, roots):
        self.roots = tuple(checked(root) for root in roots)
        closure.need(bool(self.roots) and len(set(self.roots)) == len(self.roots),
                     'all-private-exclusions-required')
        closure.need(all(not p.is_relative_to(closure.ROOT)
                         and not p.is_relative_to(Path('/usr'))
                         and not p.is_relative_to(Path('/lib'))
                         and not p.is_relative_to(Path('/etc')) for p in self.roots),
                     'private-exclusions-outside-bootstrap-system-mounts')
        self.identities = set()
        self.refresh()

    def refresh(self):
        for root in self.roots:
            closure.need(root.is_dir(), 'private-exclusion-directory-metadata')
            for current, _, names in os.walk(root, followlinks=False):
                for name in names:
                    info = (Path(current) / name).lstat()
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    closure.need(stat.S_ISREG(info.st_mode),
                                 'private-exclusion-regular-file-metadata')
                    self.identities.add((info.st_dev, info.st_ino))

    def public_path(self, path):
        path = checked(path)
        closure.need(all(not path.is_relative_to(root) for root in self.roots),
                     'public-source-inside-private-exclusion')
        return path

    def read(self, path, expected=None):
        self.refresh()
        path = self.public_path(path)
        before = path.lstat()
        closure.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and (before.st_dev, before.st_ino) not in self.identities,
                     'public-file-private-alias-or-type')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            closure.need(attrs(opened) == attrs(before)
                         and (opened.st_dev, opened.st_ino) not in self.identities,
                         'public-file-swapped-before-first-byte')
            with os.fdopen(os.dup(fd), 'rb') as source:
                raw = source.read()
            closure.need(attrs(os.fstat(fd)) == attrs(before)
                         and len(raw) == before.st_size, 'public-file-mutated')
        finally:
            os.close(fd)
        closure.need(expected is None or closure.digest(raw) == expected,
                     'selected-public-bootstrap-pin')
        return raw


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


ENTRY = '''from pathlib import Path
import json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/runtime-source/poc/owner-private-lifecycle/recovery')
import closure
options=json.loads(Path('/inputs/OPTIONS.json').read_bytes())
absent={row['id']:not Path(row['path']).exists() for row in options['absence']}
assert all(absent.values()), 'original-path-visible-in-replacement-namespace'
Path('/out/ABSENCE.json').write_bytes(closure.encoded({
 'schema':'owner-private-lifecycle-public-restore-absence/v1',
 'all_requested_original_paths_absent':all(absent.values()),
 'path_observations':absent,'wallet_private_mounts':False}))
fetch=None
if options['synthetic']:
 def fixture_fetch(replica,asset,hosts,output):
  raw=(Path('/fixtures')/asset['id']).read_bytes()
  output.write_bytes(raw)
  return {'transport':'PUBLIC_SYNTHETIC_ISOLATION_CONTROL_NOT_HTTPS'}
 fetch=fixture_fetch
result=closure.restore(Path('/inputs/CLOSURE.json').read_bytes(),
 options['closure_sha256'],Path('/inputs/SELECTION.json').read_bytes(),
 Path('/out/restored'),excluded=options['excluded'],
 denied_hosts=options['denied_hosts'],fetch=fetch)
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if result['status']=='DECLARED_CLOSURE_RESTORED' else 2)
'''


def run(args):
    policy = PublicPolicy(args.exclude_private_directory)
    inventory_raw = policy.read(args.bootstrap_inventory, args.bootstrap_inventory_sha256)
    policy.read(closure.STORAGE_SOURCE, closure.STORAGE_SHA256)
    storage = closure.storage_module()
    inventory = storage.parse(inventory_raw)
    closure.need(type(inventory) is dict and set(inventory) == {'schema', 'files'}
                 and inventory['schema'] == 'owner-private-lifecycle-recovery-bootstrap/v1'
                 and type(inventory['files']) is list, 'public-bootstrap-inventory')
    rows = inventory['files']
    closure.need(all(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
                     and type(row['path']) is str
                     and type(row['bytes']) is int and row['bytes'] > 0
                     and type(row['sha256']) is str
                     and closure.HEX32.fullmatch(row['sha256']) for row in rows)
                 and len(rows) == len(SOURCE_PATHS)
                 and {row['path'] for row in rows} == set(SOURCE_PATHS),
                 'exact-public-bootstrap-file-set')
    closure_raw = policy.read(args.closure, args.closure_sha256)
    selection_raw = policy.read(args.selection)
    manifest, selection, _, _ = closure.validate(
        closure_raw, args.closure_sha256, selection_raw, storage=storage)
    output = policy.public_path(args.output)
    closure.need(not output.exists()
                 and not output.is_relative_to(closure.ROOT),
                 'fresh-restore-run-outside-source')
    parent = output.parent
    while not parent.exists():
        parent = parent.parent
    git = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, env=CLEAN)
    closure.need(git.returncode != 0 or git.stdout.strip() != 'true',
                 'restore-run-outside-Git')
    # Authenticate every bootstrap file before staging or network requests.
    sources = [(row, policy.read(closure.ROOT / row['path'], row['sha256'])) for row in rows]
    closure.need(all(len(raw) == row['bytes'] for row, raw in sources),
                 'public-bootstrap-length')
    fixture_objects = []
    if args.synthetic_fixture is not None:
        root = policy.public_path(args.synthetic_fixture)
        for asset in selection['assets']:
            raw = policy.read(root / asset['id'], asset['sha256'])
            closure.need(len(raw) == asset['bytes'], 'synthetic-object-length')
            fixture_objects.append((asset['id'], raw))
    output.mkdir(parents=True, mode=0o700)
    source_root = output / 'runtime-source'
    for row, raw in sources:
        write_new(source_root / row['path'], raw)
    inputs = output / 'inputs'
    write_new(inputs / 'CLOSURE.json', closure_raw)
    write_new(inputs / 'SELECTION.json', selection_raw)
    write_new(output / 'entry.py', ENTRY.encode())
    absence = [{'id':'original-home','path':'/home/luke'},
               {'id':'original-repository','path':str(closure.ROOT)},
               {'id':'original-cargo-cache','path':'/home/luke/.cargo'},
               {'id':'original-sdk-cache','path':'/home/luke/.cache/kpi-sdk'}]
    absence += [{'id':'declared-private-parent-' + str(index), 'path':str(root)}
                for index, root in enumerate(policy.roots)]
    absence += [{'id':'declared-original-path-' + str(index), 'path':str(checked(path))}
                for index, path in enumerate(args.absent_original_path)]
    options = {'closure_sha256':args.closure_sha256,
        'excluded':args.exclude_provider,'denied_hosts':args.deny_host,
        'absence':absence,'synthetic':args.synthetic_fixture is not None}
    write_new(inputs / 'OPTIONS.json', closure.encoded(options))
    if fixture_objects:
        for identifier, raw in fixture_objects:
            write_new(output / 'fixtures' / identifier, raw)
    client = output / 'client-output'
    client.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-uts',
        '--unshare-ipc','--die-with-parent','--new-session']
    if args.synthetic_fixture is not None:
        command.append('--unshare-net')
    for system in ('/usr','/lib','/lib64'):
        if Path(system).exists():
            command.extend(('--ro-bind',system,system))
    command.extend(('--dir','/etc','--ro-bind','/etc/ssl','/etc/ssl'))
    for name in ('resolv.conf','nsswitch.conf','hosts','ld.so.cache'):
        system = Path('/etc') / name
        if system.exists():
            command.extend(('--ro-bind',str(system),str(system)))
    command.extend(('--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/home',
        '--ro-bind',str(source_root),'/runtime-source',
        '--ro-bind',str(inputs),'/inputs',
        '--ro-bind',str(output/'entry.py'),'/entry.py',
        '--bind',str(client),'/out'))
    if fixture_objects:
        command.extend(('--ro-bind',str(output/'fixtures'),'/fixtures'))
    command.extend(('--chdir','/runtime-source','/usr/bin/python3','-B','/entry.py'))
    started = time.monotonic()
    process = subprocess.run(command,stdin=subprocess.DEVNULL,
                             capture_output=True,text=True,env=CLEAN)
    elapsed = time.monotonic()-started
    write_new(output/'stdout.log',process.stdout.encode())
    write_new(output/'stderr.log',process.stderr.encode())
    receipt = {'schema':'owner-private-lifecycle-public-restore-run/v1',
        'returncode':process.returncode,'elapsed_seconds':elapsed,
        'closure_sha256':args.closure_sha256,
        'bootstrap_inventory_sha256':args.bootstrap_inventory_sha256,
        'domain_hex32':manifest['domain_hex32'],
        'profile_reference_sha256':manifest['profile_reference_sha256'],
        'required_public_objects':len(selection['assets']),
        'required_public_bytes':sum(asset['bytes'] for asset in selection['assets']),
        'private_files_opened':0,'downloaded_software_executed':False,
        'synthetic_network_off':args.synthetic_fixture is not None,
        'HTTPS_transport_selected':args.synthetic_fixture is None,
        'actual_HTTPS_restore_completed':args.synthetic_fixture is None
            and process.returncode==0,
        'original_host_filesystem_available_to_client':False,
        'same_host_separate_process':True,'independent_administration_demonstrated':False,
        'retention_guarantee_demonstrated':False,
        'wallet_recovery_or_payout_demonstrated':False}
    for name in ('ABSENCE.json','restored/HANDOFF.json','restored/RESULT.json'):
        path = client / name
        if path.exists():
            raw = policy.read(path)
            receipt[name.replace('/','_')+'_sha256'] = closure.digest(raw)
    write_new(output/'EXECUTION.json',closure.encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-inventory',type=Path,required=True)
    parser.add_argument('--bootstrap-inventory-sha256',required=True)
    parser.add_argument('--closure',type=Path,required=True)
    parser.add_argument('--closure-sha256',required=True)
    parser.add_argument('--selection',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--exclude-private-directory',type=Path,action='append',default=[])
    parser.add_argument('--exclude-provider',action='append',default=[])
    parser.add_argument('--deny-host',action='append',default=[])
    parser.add_argument('--absent-original-path',type=Path,action='append',default=[])
    parser.add_argument('--synthetic-fixture',type=Path)
    args = parser.parse_args()
    try:
        result = run(args)
        print(json.dumps(result,sort_keys=True))
        return 0 if result['returncode']==0 else 2
    except (closure.Refused,OSError) as error:
        print(json.dumps({'status':'INCOMPLETE','reason':
            str(error) if isinstance(error,closure.Refused) else 'public-restore-run-io'}))
        return 2


if __name__=='__main__':
    raise SystemExit(main())

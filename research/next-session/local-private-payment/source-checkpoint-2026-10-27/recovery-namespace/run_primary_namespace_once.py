#!/usr/bin/env python3
"""Finite PRIMARY-only outer namespace. SOURCE DRAFT; no execution release exists.

Eight real bootstrap Originals are readable capabilities, used only as metadata
by frozen helpers. Public FD identity is not content immutability: Root must close
all host writers/mappings and private-generation writers for this operation.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess

BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment')
ENTRY = BASE / 'recovery/publication_batch_controller.py'
ENTRY_SHA = '0d972cbb114c3c922183d76a5fcf16d9b2909b3e05336dbcb0476f9f238078b7'
AUDIT = Path('/var/tmp/kpi-local-private-payment-01/publication-audits')
SHM = Path('/dev/shm/kpi-local-private-payment-publication-01')
RELEASE = Path('/var/tmp/kpi-local-private-payment-01/publication-release')
PACKET = RELEASE / 'terminal-final-data-01'
GUARD = Path('/var/tmp/kpi-root-guard-helper-09.py')
LEGACY = {Path('/var/tmp/kpi-four-wallet-' + trial + '/owners/' + role + '/backup.json')
          for trial in ('local-rehearsal-01', 'live-01') for role in 'ABCD'}
AUDIT_ORIGINALS = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
BOOT_PINS = {
    str(GUARD): '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd',
    '/var/tmp/kpi-root-guard-helper-08.py': 'd9261c9a1a03f1fd557c26388a09fd46878c24d83fccf8c643a42050e5a4301b',
    '/var/tmp/kpi-root-guard-helper-07.py': '7482cb2570e9231ee793f9a671df6613b68f20e356bde925bc41f7e6ce94b863',
    '/var/tmp/kpi-root-guard-helper-06.py': 'b147ac219d214d0ba9a459a46a1dcd3067e47e4d6e3c6a50eed7ed02bbbe5b94',
    '/var/tmp/kpi-root-guard-helper-05.py': '97a02a5b6105c63b4253c519117b0d3de02c711d53095406521b13a9d7c3b9b0',
    '/var/tmp/kpi-root-guard-helper-04.py': '1f93e06bbe903064d69fc5ce52616255b2f531521c799a72c54da63b3fb57ab5',
    '/var/tmp/kpi-root-guard-helper-03.py': 'b9a71e03764b30d65d56e58443102a2fce27377612abe3340a768288fe6212b4',
    '/var/tmp/kpi-root-guard-helper-01.py': 'e6f443deae2bd461949c383a397603b2cc43a73f5d4acd221f8e2d8307ff0050',
    str(BASE.parent / 'four-wallet-profile/outer_run.py'): 'da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195',
}
DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
CHECKS, BOOT = '/namespace-primary-checks.json', '/namespace-primary-bootstrap.py'
FIELDS = {'schema', 'action', 'operator_sha256', 'execution_plan', 'audit_core', 'controller_output',
          'packet_directory', 'public_files', 'originals', 'holders', 'promotions',
          'receipt_directory', 'capture_directory', 'trusted_host_quiescence', 'trusted_selected_system_runtime'}
STAT_KEYS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def parse(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def path(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and '\\' not in value and '\0' not in value, 'canonical absolute path')
    out = Path(value)
    need(str(out) == value and '..' not in out.parts, 'canonical absolute path')
    return out


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256 pin')
    return value


def snapshot(info):
    return dict(zip(STAT_KEYS, (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
        info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)))


def checked_stat(value):
    need(type(value) is dict and set(value) == set(STAT_KEYS)
         and all(type(x) is int and x >= 0 for x in value.values()), 'exact metadata snapshot')
    return value


def no_symlinks(item):
    need(not any(p.is_symlink() for p in (item, *item.parents)), 'symlink path refused')


def open_dir(item):
    fd = os.open('/', DIRFLAGS)
    try:
        for name in item.parts[1:]:
            new = os.open(name, DIRFLAGS, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def sealed_metadata(raw):
    fd = os.memfd_create('primary-bootstrap-metadata', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            size = os.write(fd, view)
            need(size > 0, 'metadata write failed')
            view = view[size:]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_new(directory_fd, name, value):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o400, dir_fd=directory_fd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--release', required=True)
    parser.add_argument('--release-sha256', required=True)
    args = parser.parse_args()
    need(args.execute, 'execution held without explicit flag and Root release')
    h = runpy.run_path(str(GUARD))
    release = parse(h['read'](path(args.release), pin(args.release_sha256)))
    need(type(release) is dict and set(release) == FIELDS, 'closed Root release')
    need(release['schema'] == 'kpxa-root-finite-primary-fd-namespace/v1'
         and release['action'] == 'RUN_ONLY_FROZEN_PRIMARY_HOLD_ALL_OUTPUTS'
         and release['trusted_host_quiescence'] is True
         and release['trusted_selected_system_runtime'] is True, 'explicit finite trusted-host scope')
    h['read'](str(Path(__file__).absolute()), pin(release['operator_sha256']))
    plan = release['execution_plan']
    need(type(plan) is dict and set(plan) == {'path', 'sha256'}, 'exact plan selector')
    plan_path, plan_sha = path(plan['path']), pin(plan['sha256'])
    core = release['audit_core']
    need(type(core) is dict and set(core) == {'path', 'sha256'}, 'exact Root-selected core')
    core_path, core_sha = path(core['path']), pin(core['sha256'])
    output, packet = path(release['controller_output']), path(release['packet_directory'])
    need(output.parent == AUDIT and packet == PACKET, 'fixed PRIMARY output roots')
    roots = {'audit': AUDIT, 'decoded': SHM, 'packet': packet}
    originals, public, opened, holders = {}, {}, [], {}
    receipt_fd = capture_fd = None
    try:
        # Originals: metadata and O_PATH only. Never pass them to read/sealed_metadata.
        for row in release['originals']:
            need(type(row) is dict and set(row) == {'path', 'stat', 'bootstrap', 'audit'}
                 and type(row['bootstrap']) is bool and type(row['audit']) is bool
                 and (row['bootstrap'] or row['audit']), 'exact Original metadata row')
            source, expected = path(row['path']), checked_stat(row['stat'])
            need(source not in originals and row['bootstrap'] == (source in LEGACY), 'exact Original routing')
            need(row['bootstrap'] != row['audit'], 'bootstrap and audit paths are disjoint')
            no_symlinks(source)
            fd = os.open(source, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened.append(fd)
            need(snapshot(source.lstat()) == snapshot(os.fstat(fd)) == expected
                 and stat.S_ISREG(expected['mode']), 'Original metadata drift')
            if row['audit']:
                need(source.is_relative_to(AUDIT_ORIGINALS) and source.name == 'BACKUP.json'
                     and expected['nlink'] == 1 and stat.S_IMODE(expected['mode']) == 0o600,
                     'frozen nine-Original audit metadata contract')
            originals[source] = (fd, expected, row['audit'])
            # Add-only reinforcement for every selected Original, never history clearing.
            h['m'].GUARD.inodes.add((expected['dev'], expected['ino']))
        audit_rows = {source: item for source, item in originals.items() if item[2]}
        need(len(originals) == 17 and LEGACY <= set(originals) and len(audit_rows) == 9
             and len({(item[1]['dev'], item[1]['ino']) for item in audit_rows.values()}) == 9,
             'eight real bootstrap leaves and nine approved audit routes required')
        need(set(release['holders']) == set(roots), 'exact three write holders')
        for name, guest in roots.items():
            row = release['holders'][name]
            need(type(row) is dict and set(row) == {'path', 'stat'}, 'exact holder metadata')
            source, expected = path(row['path']), checked_stat(row['stat'])
            no_symlinks(source)
            fd = open_dir(source)
            opened.append(fd)
            need(snapshot(os.fstat(fd)) == expected and stat.S_ISDIR(expected['mode'])
                 and expected['uid'] == os.getuid() and stat.S_IMODE(expected['mode']) == 0o700
                 and os.listdir(fd) == [], 'fresh owned empty holder')
            need(expected['dev'] == guest.parent.lstat().st_dev,
                 'holder filesystem must match its canonical target parent')
            need(not any(guest == p or p in guest.parents or guest in p.parents
                         or source == p or p in source.parents or source in p.parents
                         for p in originals), 'Original/write-holder collision')
            need(not any(source == p or p in source.parents for p in h['m'].GUARD.directories),
                 'write holder inside protected private scope')
            holders[name] = (source, fd, expected)
        need(len({(item[2]['dev'], item[2]['ino']) for item in holders.values()}) == 3,
             'write holders must be distinct directories')
        h['refresh']()
        for row in release['public_files']:
            need(type(row) is dict and set(row) == {'source', 'target', 'sha256', 'bytes', 'stat'}, 'exact public FD row')
            source, target = path(row['source']), path(row['target'])
            expected = checked_stat(row['stat'])
            need(not source.name.lower().endswith(('.pk', '.zkey', '.log', '.stdout', '.stderr')),
                 'proving key or raw capture is not a PRIMARY public input')
            need(target not in public and target not in (Path(BOOT), Path(CHECKS))
                 and target not in originals and not any(target.is_relative_to(p.parent) for p in originals)
                 and not target.is_relative_to('/proc') and not target.is_relative_to('/sys'), 'public target collision')
            need(not target.is_relative_to('/dev') or target.is_relative_to(SHM), 'no public device target')
            need(not any(target == root for root in roots.values()), 'public target replaces write root')
            pin(row['sha256'])
            need(type(row['bytes']) is int and row['bytes'] >= 0 and row['bytes'] == expected['bytes'], 'selected public length')
            h['m'].GUARD.metadata(source)
            fd = os.open(source, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened.append(fd)
            need(snapshot(source.lstat()) == snapshot(os.fstat(fd)) == expected
                 and stat.S_ISREG(expected['mode']) and expected['nlink'] == 1, 'public FD admission drift')
            public[target] = (source, fd, expected, row['sha256'], row['bytes'])
        targets = set(public) | set(originals) | {Path(BOOT), Path(CHECKS)}
        need(not any(a in b.parents for a in targets for b in targets), 'file/parent target collision')
        need(public.get(ENTRY, (None, None, None, None))[3] == ENTRY_SHA
             and public.get(plan_path, (None, None, None, None))[3] == plan_sha
             and Path('/usr/bin/python3') in public and Path('/usr/bin/bwrap') in public, 'fixed entry/plan/nested runtime missing')
        need(core_path in public and public[core_path][0] == core_path
             and public[core_path][3] == core_sha and public[ENTRY][0] == ENTRY,
             'controller/core must keep their honest selected file paths')
        plan_document = parse(h['read'](public[plan_path][0], plan_sha))
        selected_originals = plan_document.get('originals')
        need(type(selected_originals) is list and len(selected_originals) == 9
             and len({row['path'] for row in selected_originals}) == 9
             and {row['path'] for row in selected_originals} == {str(p) for p in audit_rows},
             'nine audit FD routes must equal selected plan routes')
        for row in selected_originals:
            expected = audit_rows[path(row['path'])][1]
            need((row['device'], row['inode'], row['bytes'], row['ctime_ns'])
                 == tuple(expected[key] for key in ('dev', 'ino', 'bytes', 'ctime_ns')),
                 'plan/Original FD metadata correspondence')
        batch_selector = plan_document['batch_plan']
        batch_path, batch_sha = path(batch_selector['path']), pin(batch_selector['sha256'])
        need(batch_path in public and public[batch_path][3] == batch_sha, 'selected batch plan FD missing')
        batch_document = parse(h['read'](public[batch_path][0], batch_sha))
        batch_ids = [row['batch_id'] for row in batch_document['batches']]
        need(batch_ids and batch_ids[0] == 'BASE' and len(set(batch_ids)) == len(batch_ids), 'PRIMARY batch identities')
        for target, sha in BOOT_PINS.items():
            need(Path(target) in public and public[Path(target)][3] == sha, 'unchanged guard source closure missing')
            # Authenticate bootstrap code before any of it executes in the guest.
            h['read'](public[Path(target)][0], sha)
        promotions = []
        for row in release['promotions']:
            need(type(row) is dict and set(row) == {'root', 'name'} and row['root'] in ('audit', 'packet'), 'finite promotion row')
            name = row['name']
            need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.json)?', name), 'promotion basename')
            if row['root'] == 'packet':
                need(re.fullmatch(r'D[0-9]{6}-BATCH\.json', name), 'only new decoded descriptors enter packet')
            destination = roots[row['root']] / name
            need(not any(t == destination or destination in t.parents for t in public), 'cannot promote input mount scaffolding')
            need(not destination.exists() and not destination.is_symlink(), 'promotion destination already exists')
            promotions.append((row['root'], name))
        need(len(set(promotions)) == len(promotions) and ('audit', output.name) in promotions, 'distinct output promotions required')
        expected_promotions = {('audit', output.name)}
        expected_promotions.update(('audit', 'prepared-' + plan_document['run_label'] + '-' + bid.lower())
                                   for bid in batch_ids)
        expected_promotions.update(('packet', bid + '-BATCH.json') for bid in batch_ids if bid != 'BASE')
        need(set(promotions) == expected_promotions, 'exact controller/prepared/D-descriptor promotion coverage')
        receipt_dir = path(release['receipt_directory'])
        need(not any(receipt_dir == p or p in receipt_dir.parents for p in list(roots.values()) + list(originals)), 'receipt outside guest writes/Originals')
        need(not any(receipt_dir == p or p in receipt_dir.parents for p in h['m'].GUARD.directories),
             'receipt inside protected private scope')
        receipt_fd = open_dir(receipt_dir)
        ri = os.fstat(receipt_fd)
        need(ri.st_uid == os.getuid() and stat.S_IMODE(ri.st_mode) == 0o700, 'owned receipt directory')
        capture = release['capture_directory']
        need(type(capture) is dict and set(capture) == {'path', 'stat'}, 'exact private capture metadata')
        capture_path, capture_stat = path(capture['path']), checked_stat(capture['stat'])
        need(any(capture_path == p or p in capture_path.parents for p in h['m'].GUARD.directories)
             and not any(capture_path == p or p in capture_path.parents or capture_path in p.parents for p in originals),
             'capture holder must be protected and separate from Originals')
        capture_fd = open_dir(capture_path)
        need(snapshot(os.fstat(capture_fd)) == capture_stat and stat.S_ISDIR(capture_stat['mode'])
             and capture_stat['uid'] == os.getuid() and stat.S_IMODE(capture_stat['mode']) == 0o700
             and os.listdir(capture_fd) == [], 'fresh owned private capture holder')
        need((capture_stat['dev'], capture_stat['ino']) not in
             {(item[2]['dev'], item[2]['ino']) for item in holders.values()}, 'capture/write-holder alias')
        for leaf in ('NAMESPACE-PRIMARY-01.json',):
            try:
                os.stat(leaf, dir_fd=receipt_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('receipt/capture already exists')
        checks = encoded({'files': [{'target': str(t), 'sha256': item[3], 'bytes': item[4]}
                                   for t, item in sorted(public.items())]})
        checks_sha = hashlib.sha256(checks).hexdigest()
        guest = ("import os,sys,runpy,json,types\n"
                 "for n in os.listdir('/proc/self/fd'):\n"
                 " if int(n)>2:\n"
                 "  try: os.close(int(n))\n"
                 "  except OSError: pass\n"
                 "h=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')\n"
                 f"r=json.loads(h['read']({CHECKS!r},{checks_sha!r}))\n"
                 "for f in r['files']:\n"
                 " b=h['read'](f['target'],f['sha256']);assert len(b)==f['bytes'];del b\n"
                 # Root selects the corrected core explicitly; do not spoof its __file__.
                 f"c=types.ModuleType('publication_batch_audit');c.__file__={str(core_path)!r}\n"
                 "sys.modules['publication_batch_audit']=c\n"
                 f"exec(compile(h['read']({str(core_path)!r},{core_sha!r}),{str(core_path)!r},'exec'),c.__dict__)\n"
                 f"a=[{str(ENTRY)!r},'--execution-plan',{str(plan_path)!r},"
                 f"'--selection-sha256',{plan_sha!r},'--output',{str(output)!r},'--execute']\n"
                 "sys.argv=a\n"
                 f"runpy.run_path({str(ENTRY)!r},run_name='__main__')\n").encode()
        check_fd, boot_fd = sealed_metadata(checks), sealed_metadata(guest)
        opened += [check_fd, boot_fd]
        directories = {Path('/proc'), Path('/dev'), Path('/etc/alternatives'), *roots.values()}
        for target in targets:
            directories.update(p for p in target.parents if p != Path('/'))
        command = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--new-session',
                   '--die-with-parent', '--cap-drop', 'ALL', '--clearenv', '--tmpfs', '/',
                   '--dir', '/proc', '--dir', '/dev', '--proc', '/proc', '--dev', '/dev']
        for directory in sorted(directories, key=lambda p: (len(p.parts), str(p))):
            command += ['--dir', str(directory)]
        inside = lambda t: any(t == r or r in t.parents for r in roots.values())
        for target, (_, fd, _, _, _) in sorted(public.items()):
            if not inside(target):
                command += ['--ro-bind', '/proc/self/fd/' + str(fd), str(target)]
        for target, (fd, _, _) in sorted(originals.items()):
            command += ['--ro-bind', '/proc/self/fd/' + str(fd), str(target)]
        command += ['--perms', '400', '--file', str(check_fd), CHECKS,
                    '--perms', '500', '--file', str(boot_fd), BOOT, '--remount-ro', '/']
        for name, target in roots.items():
            command += ['--bind', '/proc/self/fd/' + str(holders[name][1]), str(target)]
        for directory in sorted(directories, key=lambda p: (len(p.parts), str(p))):
            if inside(directory) and directory not in roots.values():
                command += ['--dir', str(directory)]
        for target, (_, fd, _, _, _) in sorted(public.items()):
            if inside(target):
                command += ['--ro-bind', '/proc/self/fd/' + str(fd), str(target)]
        command += ['--chdir', '/', '--', '/usr/bin/python3', '-I', '-S', '-B', BOOT]
        outfd = os.open('NAMESPACE-PRIMARY-STDOUT.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=capture_fd)
        errfd = os.open('NAMESPACE-PRIMARY-STDERR.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=capture_fd)
        try:
            child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=outfd, stderr=errfd,
                close_fds=True, pass_fds=tuple(set(opened)), env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
            os.fsync(outfd)
            os.fsync(errfd)
        finally:
            os.close(outfd)
            os.close(errfd)
        # A successful process marker alone never authorizes promotion.
        h['refresh']()
        for source, fd, expected, _, _ in public.values():
            h['m'].GUARD.metadata(source)
            need(snapshot(source.lstat()) == snapshot(os.fstat(fd)) == expected, 'post-run public origin/identity changed')
        for source, (fd, expected, _) in originals.items():
            no_symlinks(source)
            need(snapshot(source.lstat()) == snapshot(os.fstat(fd)) == expected, 'post-run Original metadata changed')
        for source, fd, expected in holders.values():
            need(all(snapshot(source.lstat())[key] == snapshot(os.fstat(fd))[key] == expected[key]
                     for key in ('dev', 'ino', 'mode', 'uid', 'gid')), 'write-holder identity changed')
        need(all(snapshot(capture_path.lstat())[key] == snapshot(os.fstat(capture_fd))[key] == capture_stat[key]
                 for key in ('dev', 'ino', 'mode', 'uid', 'gid')), 'private capture holder identity changed')
        need(child.returncode == 0, 'PRIMARY failed; preserve holders and captures')
        # Promotion stays HELD: Root must validate exact frozen PRIMARY result schema,
        # audit counts and all produced holder closures before an independent
        # no-replace promotion. This draft deliberately never overwrites a packet.
        write_new(receipt_fd, 'NAMESPACE-PRIMARY-01.json', {
            'schema': 'kpxa-finite-primary-fd-namespace/v1', 'status': 'HELD_PENDING_EXACT_RESULT_AND_PROMOTION_REVIEW',
            'release_sha256': args.release_sha256, 'execution_plan': plan, 'controller_sha256': ENTRY_SHA,
            'audit_core': core,
            'public_fd_rows': len(public), 'real_bootstrap_originals': 8, 'audit_original_routes': 9,
            'original_body_read_hashed_or_sealed_by_wrapper': False, 'private_mounts_exist': True,
            'metadata_only_bootstrap_is_trusted_code_behavior': True, 'nested_userns_not_disabled': True,
            'returncode': child.returncode, 'full_host_guard_pre_post_checks': True,
            'host_guard_history_cleared': False, 'canonical_outputs_promoted': False,
            'holders': {name: str(item[0]) for name, item in holders.items()},
            'requested_promotions': release['promotions'], 'supplemental_or_positive_checks_run': False})
    finally:
        if capture_fd is not None:
            os.close(capture_fd)
        if receipt_fd is not None:
            os.close(receipt_fd)
        for fd in reversed(opened):
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('PRIMARY namespace refused/incomplete; preserve all holders and local captures')

#!/usr/bin/env python3
"""Private controller for one portable-materials/first-owner integration.

`init` writes only an incomplete private configuration. Actual PK copying and
owner proof execution are separate explicit root releases. Never publish/hash
the private configuration, plans or controller directory recursively.
"""
import argparse
from contextlib import contextmanager
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import uuid

import capsule as c
from pack_local import pack_local

ROOT = Path(__file__).resolve().parents[2]
BASE = 'a6fcdf1edd904dbe1bb395285230649b6c40d44c'
CONFIG_FIELDS = {'schema', 'descriptor', 'history', 'compact_manifest', 'compact_pk',
    'owner_selection', 'selected_prover', 'own_backup', 'must_be_absent'}
SOURCE_COMPONENTS = {
    **{name.replace('.', '_'): ROOT / 'poc/compact-batch-lifecycle' / name for name in
       ('primitives.py', 'receiver.py', 'actions.py', 'history.py', 'native_runtime.py',
        'owner.py', 'run_owner.py')},
    'recipient_v2_py': ROOT / 'poc/future-recipient/v2/recipient.py',
    'offline_sdk_mjs': ROOT / 'poc/private-cashout-trial/sdk.mjs',
    **{'capsule_' + name.replace('.', '_'): Path(__file__).with_name(name) for name in
       ('capsule.py', 'https_mirror.py', 'pack_local.py')},
}


def private_write(path, value):
    with Path(path).open('x') as target:
        json.dump(value, target, sort_keys=True, indent=2)
        target.write('\n')
    Path(path).chmod(0o600)


def strict(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            c.need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(c.Invalid('json-constant')))
    except (ValueError, UnicodeDecodeError):
        raise c.Invalid('invalid-json') from None


def initialize(directory):
    directory = c._path(directory)
    c.need(not directory.is_relative_to(ROOT) and not directory.exists()
           and not any(p.is_symlink() for p in directory.parents), 'fresh-controller-outside-Git')
    directory.mkdir(mode=0o700)
    private_write(directory / 'PRIVATE-CONFIG.json',
        {**{key: None for key in CONFIG_FIELDS},
         'schema': 'kpx4-portable-first-owner-controller/v1', 'must_be_absent': []})
    private_write(directory / 'PRIVATE-CONTROLLER-NOTE.json', {
        'publish_or_hash': False, 'actual_PK_backup_or_proof_read': False,
        'materials_release': 'ROOT_RELEASED_REAL_COMPACT_PUBLIC_MATERIALS',
        'owner_proof_release': 'ROOT_RELEASED_FIRST_COMPACT_OWNER_PROOF',
        'only_one_selected_first_owner_proof_is_intended': True})
    return {'private_controller_prepared': True, 'actual_inputs_read': False}


def configuration(directory):
    directory = c._path(directory)
    c.need(not directory.is_relative_to(ROOT) and directory.is_dir()
           and not any(p.is_symlink() for p in (directory, *directory.parents))
           and directory.stat().st_mode & 0o777 == 0o700, 'private-controller-directory')
    path = directory / 'PRIVATE-CONFIG.json'
    c.need(not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600, 'private-configuration-file')
    value = strict(path.read_bytes())  # Operational paths, never seed bytes.
    c.exact(value, CONFIG_FIELDS, 'private-configuration-fields')
    c.need(value['schema'] == 'kpx4-portable-first-owner-controller/v1', 'private-configuration-schema')
    for key in CONFIG_FIELDS - {'schema', 'must_be_absent'}:
        c.need(type(value[key]) is str and bool(value[key]), 'configuration-not-complete')
    c.need(type(value['must_be_absent']) is list and bool(value['must_be_absent'])
           and all(type(p) is str and bool(p) for p in value['must_be_absent']),
           'explicit-source-cache-absence-probes-required')
    return directory, value


@contextmanager
def public_server(root):
    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0),
        functools.partial(Quiet, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def materials(directory, release):
    c.need(release == 'ROOT_RELEASED_REAL_COMPACT_PUBLIC_MATERIALS', 'root-materials-release-required')
    directory, config = configuration(directory)
    forbidden = [Path(config['own_backup'])]
    c._metadata_forbidden(forbidden)  # Metadata only, before public input reads/hashes.
    inputs = directory / 'canonical-public-inputs'
    inputs.mkdir(mode=0o700)
    selected = strict(c.read_public(config['owner_selection'], forbidden))
    c.exact(selected, {'schema', 'role', 'domain_hex32', 'descriptor_sha256',
        'parameter_manifest_sha256', 'vk_sha256', 'compiled_build_identity_sha256',
        'prover_sha256'}, 'owner-selection-fields')
    c.need(selected['schema'] == 'kpx4-compact-batch-owner-selection/v1'
           and selected['role'] == 'compact2', 'first-compact-owner-selection')
    descriptor_raw = c.encoded(strict(c.read_public(config['descriptor'], forbidden)))
    history_raw = c.encoded(strict(c.read_public(config['history'], forbidden)))
    manifest_raw = c.read_public(config['compact_manifest'], forbidden)
    manifest = c.parse(manifest_raw)
    c.need(c.sha(descriptor_raw) == selected['descriptor_sha256']
           and c.sha(manifest_raw) == selected['parameter_manifest_sha256']
           and manifest['role'] == 'compact2' and manifest['domain_hex32'] == selected['domain_hex32']
           and manifest['vk_sha256'] == selected['vk_sha256']
           and manifest['compiled_build_identity_sha256'] == selected['compiled_build_identity_sha256'],
           'installed-owner-static-selection')
    components = [{'component': name, 'sha256': c.sha(c.read_public(path, forbidden))}
                  for name, path in sorted(SOURCE_COMPONENTS.items())]
    # This inventories independently installed/selected software; it does not
    # download or select code from the capsule or claim every ELF was reread.
    components.append({'component': 'expected_selected_prover', 'sha256': selected['prover_sha256']})
    inventory = {'schema': 'kpx4-recovery-software-inventory/v1', 'program_label': c.PROGRAM,
        'source_base_commit': BASE, 'source_freeze_sha256': c.sha(c.encoded(components)),
        'components': components}
    inventory_raw = c.encoded(inventory)
    raws = {'descriptor': descriptor_raw, 'history': history_raw,
        'parameters_manifest': manifest_raw, 'software_inventory': inventory_raw}
    paths = {}
    for kind, raw in raws.items():
        path = inputs / kind
        path.write_bytes(raw)
        path.chmod(0o400)
        paths[kind] = path
    selection_value = {'schema': 'kpx4-recovery-capsule-selection/v1',
        'network_id': manifest['network_id'], 'genesis_hash_hex': manifest['genesis_hash_hex'],
        'domain_hex32': manifest['domain_hex32'], 'program_label': c.PROGRAM,
        'role': 'compact2', 'auth_magic_hex8': c.AUTH_MAGIC,
        'descriptor_sha256': c.sha(descriptor_raw),
        'parameters_manifest_sha256': c.sha(manifest_raw),
        'public_parameters_sha256': manifest['pk_sha256'],
        'public_parameters_bytes': manifest['pk_bytes'], 'vk_sha256': manifest['vk_sha256'],
        'software_inventory_sha256': c.sha(inventory_raw)}
    selection = c.TrustedSelection.from_dict(selection_value)
    selection_path = inputs / 'trusted-capsule-selection.json'
    selection_path.write_bytes(c.encoded(selection_value))
    selection_path.chmod(0o400)
    paths['public_parameters'] = Path(config['compact_pk'])
    packed = pack_local(selection, paths, directory / 'preferred-cas', forbidden)
    # Actual independent byte copies, same host/storage domain; this never
    # establishes independent-provider or long-term retention availability.
    fallback = directory / 'fallback-cas'
    shutil.copytree(directory / 'preferred-cas', fallback)
    c.need((fallback / 'objects/sha256' / manifest['pk_sha256']).stat().st_ino
           != (directory / 'preferred-cas/objects/sha256' / manifest['pk_sha256']).stat().st_ino,
           'fallback-must-be-an-owned-byte-copy')
    client = directory / 'retrieval-client-output'
    client.mkdir(mode=0o700)
    with public_server(fallback) as live_port:
        with public_server(directory / 'preferred-cas') as gone_port:
            pass
        with socket.socket() as probe:
            probe.settimeout(3)
            refused = probe.connect_ex(('127.0.0.1', gone_port)) != 0
        c.need(refused, 'preferred-source-not-observed-unavailable')
        absent = list(dict.fromkeys([*config['must_be_absent'], config['compact_pk'], str(ROOT)]))
        guard = ('import json,pathlib,runpy,sys; n=int(sys.argv[1]); '
            'paths=sys.argv[2:2+n]; '
            'assert all(not pathlib.Path(p).exists() and not pathlib.Path(p).is_symlink() for p in paths); '
            'pathlib.Path("/out/SOURCE-ABSENCE.json").write_text(json.dumps('
            '{"all_explicit_original_paths_absent":True,"path_count":n})); '
            'sys.argv=["/work/https_mirror.py"]+sys.argv[2+n:]; '
            'runpy.run_path("/work/https_mirror.py",run_name="__main__")')
        command = ['/usr/bin/bwrap', '--unshare-all', '--share-net', '--clearenv',
            '--die-with-parent', '--new-session', '--ro-bind', '/usr', '/usr',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
            '--ro-bind', str(Path(__file__).with_name('capsule.py')), '/work/capsule.py',
            '--ro-bind', str(Path(__file__).with_name('https_mirror.py')), '/work/https_mirror.py',
            '--ro-bind', str(selection_path), '/trusted-capsule-selection.json',
            '--bind', str(client), '/out', '--chdir', '/work', '--setenv', 'PATH', '/usr/bin:/bin',
            '/usr/bin/python3', '-B', '-c', guard, str(len(absent)), *absent,
            packed['capsule_sha256'], '/trusted-capsule-selection.json', '/out/restored',
            '--mirror-base', 'http://127.0.0.1:' + str(gone_port),
            '--mirror-base', 'http://127.0.0.1:' + str(live_port), '--allow-loopback-http']
        # This file contains operational path probes and must not be hashed or
        # published. It is not mounted in the actual retrieval client.
        private_write(directory / 'PRIVATE-RETRIEVAL-PLAN.json', {
            'publish_or_hash': False, 'command': command,
            'no_backup_prover_or_original_source_cache_or_mirror_filesystem_mounted': True})
        result = subprocess.run(command, capture_output=True, text=True)
        (directory / 'PRIVATE-RETRIEVAL-STDOUT.log').write_text(result.stdout)
        (directory / 'PRIVATE-RETRIEVAL-STDERR.log').write_text(result.stderr)
        c.need(result.returncode == 0, 'isolated-retrieval-client-failed')
    retrieved = strict(result.stdout)
    absence = strict((client / 'SOURCE-ABSENCE.json').read_bytes())
    c.need(absence['all_explicit_original_paths_absent'] is True
           and all(row['mirror_ordinal'] == 1 for row in retrieved['transport']['objects_downloaded'])
           and retrieved['capsule']['public_PK_staged'] is True
           and retrieved['capsule']['current_state_verified'] is False, 'exact-source-loss-material-result')
    restored = client / 'restored/spend-material'
    private_write(directory / 'PRIVATE-RESTORED-PATHS.json', {'publish_or_hash': False,
        'descriptor': str(restored / 'descriptor'), 'history': str(restored / 'history'),
        'manifest': str(restored / 'parameters_manifest'), 'pk': str(restored / 'public_parameters')})
    summary = {'schema': 'kpx4-real-compact-material-portability/v1',
        'classification': 'REAL_PUBLIC_PARAMETER_BYTES_LOCAL_PORTABILITY_NOT_NATIVE_OR_CURRENTNESS',
        'capsule_sha256': packed['capsule_sha256'], 'compact_PK_bytes': manifest['pk_bytes'],
        'compact_PK_sha256': manifest['pk_sha256'], 'preferred_endpoint_observed_unavailable': True,
        'all_original_source_cache_paths_absent_in_retrieval_namespace': True,
        'only_fallback_HTTP_supplied_index_and_all_five_objects': True,
        'same_host_mirrors_are_not_independent_providers': True,
        'actual_backup_contents_read_or_owner_proof_generated': False,
        'current_state_verified': False, 'spend_authorized': False,
        'private_input_paths_or_hashes_published': False}
    private_write(directory / 'PUBLIC-MATERIALS-OUTCOME.json', summary)
    return summary


def owner_proof(directory, release):
    c.need(release == 'ROOT_RELEASED_FIRST_COMPACT_OWNER_PROOF', 'root-owner-proof-release-required')
    directory, config = configuration(directory)
    restored = strict((directory / 'PRIVATE-RESTORED-PATHS.json').read_bytes())
    inventory = c.parse((directory / 'canonical-public-inputs/software_inventory').read_bytes())
    expected = {row['component']: row['sha256'] for row in inventory['components']}
    forbidden = [Path(config['own_backup'])]
    c.need(all(c.sha(c.read_public(path, forbidden)) == expected[name]
               for name, path in SOURCE_COMPONENTS.items()), 'installed-software-changed-since-material-selection')
    command = ['/usr/bin/python3', '-B', str(ROOT / 'poc/compact-batch-lifecycle/run_owner.py'),
        str(directory / 'first-owner'), '--role', 'compact2',
        '--selection', config['owner_selection'], '--descriptor', restored['descriptor'],
        '--history', restored['history'], '--manifest', restored['manifest'], '--pk', restored['pk'],
        '--prover', config['selected_prover'], '--backup', config['own_backup'], '--execute']
    for path in dict.fromkeys([*config['must_be_absent'], config['compact_pk'], str(ROOT)]):
        command += ['--must-be-absent', path]
    private_write(directory / 'PRIVATE-OWNER-COMMAND.json', {'publish_or_hash': False, 'command': command})
    result = subprocess.run(command, capture_output=True, text=True)
    (directory / 'PRIVATE-OWNER-STDOUT.log').write_text(result.stdout)
    (directory / 'PRIVATE-OWNER-STDERR.log').write_text(result.stderr)
    c.need(result.returncode == 0, 'portable-first-owner-proof-failed')
    summary = strict(result.stdout)
    c.need(summary['role'] == 'compact2' and summary['native_Full_all_engines_with_supplied_contexts'] is True
           and summary['accepted_chain_or_currentness_claimed'] is False,
           'portable-owner-result-scope')
    private_write(directory / 'PUBLIC-OWNER-OUTCOME.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    init = sub.add_parser('init')
    init.add_argument('directory', type=Path)
    for name in ('materials', 'owner-proof'):
        item = sub.add_parser(name)
        item.add_argument('directory', type=Path)
        item.add_argument('--root-release', required=True)
    args = parser.parse_args()
    if args.operation == 'init':
        result = initialize(args.directory)
    elif args.operation == 'materials':
        result = materials(args.directory, args.root_release)
    else:
        result = owner_proof(args.directory, args.root_release)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

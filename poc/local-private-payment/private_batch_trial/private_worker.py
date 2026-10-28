#!/usr/bin/env python3
"""Finite new-profile owner worker, invoked only inside its one-owner namespace.

The bootstrap supplies public dependencies read-only and either one new private
directory or one Original backup leaf. No network, legacy backup import, seed
export, private transcript export, funding or broadcast operation exists here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess

import output_producer
import wallet_profile as wallet

BACKUP_SCHEMA = 'kpb-ak-bound-original-seed-backup/v1'
KDF_TAG = 'KPBKDF01'


def need(value, category):
    if not value:
        raise wallet.Invalid(category)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def read(path, expected=None, *, private=False):
    path = Path(path)
    need(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), 'regular-selected-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'single-link-selected-file')
        if private:
            need(stat.S_IMODE(before.st_mode) == 0o600, 'original-backup-mode')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'stable-selected-file')
    if expected:
        need(hashlib.sha256(raw).hexdigest() == expected, 'selected-public-file-hash')
    return raw


def write(path, value, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(value if type(value) is bytes else encoded(value))
        handle.flush()
        os.fsync(handle.fileno())


class NamespaceAuthority(wallet.Authority):
    """The outer bwrap already supplies the complete owner-only sandbox.

    Nested user namespaces are disabled on this host. This adapter runs the
    same authenticated authority script directly in that existing namespace;
    it is never selected by the ordinary host wallet API.
    """
    def __init__(self, node, modules):
        need(wallet.digest_file(node) == wallet.NODE_SHA256, 'selected-node-pin')
        script = Path(wallet.__file__).parent / 'owner_authority.mjs'
        self.process = subprocess.Popen([str(node), str(script), str(modules / 'circomlibjs/main.js')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait()
        self.process.stdout.close()


class NamespaceProver(output_producer.OutputProver):
    """Existing new Output relation/parameters inside the outer owner sandbox."""
    def _call(self, operation, statement, private=None):
        request = {'operation': operation, 'role': 'new-output',
            'profile': {'domain_hex32': self.profile.domain.hex(), 'profile_id_hex32': self.profile.profile_id.hex()},
            'statement_hex': statement.hex()}
        if operation in ('prove', 'verify'):
            request['parameters'] = {'manifest': str(self.manifest), 'manifest_sha256': self.manifest_sha256}
        if operation == 'prove':
            request['parameters'].update(pk=str(self.proving_key), pk_sha256=self.pk_sha256)
        if private:
            request.update(private)
        result = subprocess.run([str(self.binary)], input=encoded(request), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
                                          'RAYON_NUM_THREADS': '2'})
        need(result.returncode == 0, 'namespace-output-prover-refused')
        return parse(result.stdout)


def load_backup(path, profile):
    value = parse(read(path, private=True))
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'profile_id_hex32',
         'kdf_tag_ascii8', 'seed_hex32'}, 'new-backup-exact-fields')
    need(value['schema'] == BACKUP_SCHEMA and value['domain_hex32'] == profile.domain.hex()
         and value['profile_id_hex32'] == profile.profile_id.hex() and value['kdf_tag_ascii8'] == KDF_TAG,
         'explicit-new-AK-bound-backup-profile')
    seed = bytes.fromhex(value['seed_hex32'])
    need(len(seed) == 32 and seed.hex() == value['seed_hex32'], 'canonical-original-seed')
    return seed


def run(args):
    marker = parse(read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                    'operation': args.operation, 'owner_slots': 1}, 'one-owner-namespace-marker')
    need(not Path('/home/luke/.codex').exists() and not Path('/home/luke/.ssh').exists()
         and not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists(), 'host-private-paths-absent')
    # bwrap's network namespace has no host interfaces or inherited sockets.
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'network-off-owner-namespace')
    config = parse(read('/CONFIG.json'))
    for row in config['source_members']:
        read(row['path'], row['sha256'])
    profile = wallet.Profile(bytes.fromhex(config['domain_hex32']), bytes.fromhex(config['profile_id_hex32']))
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['js_leaf_map_sha256'],
                                     '/runtime/js')
    crypto = wallet.Crypto('/runtime/crypto')
    prover = NamespaceProver(profile, '/runtime/prover', config['binary_sha256'],
        '/parameters/MANIFEST.json', config['manifest_sha256'], '/parameters/parameters.pk', read_public=read)
    with NamespaceAuthority('/runtime/node', modules) as authority:
        if args.operation == 'init':
            need(not Path('/owner/BACKUP.json').exists(), 'fresh-original-required')
            seed = secrets.token_bytes(32)
            # Persist the new immutable Original before proving. A failed run
            # remains an unused unfunded identity; it is never auto-replaced.
            write('/owner/BACKUP.json', {'schema': BACKUP_SCHEMA, 'domain_hex32': profile.domain.hex(),
                'profile_id_hex32': profile.profile_id.hex(), 'kdf_tag_ascii8': KDF_TAG, 'seed_hex32': seed.hex()})
            receiver = wallet.Receiver(seed, profile, crypto, authority)
            created = prover.create(crypto, receiver.invoice(0), 2_000_000_000, blind=bytes(32))
            need(receiver.open(created.row[96:360]).encode() == created.receipt.encode(),
                 'original-initial-receipt-roundtrip')
            funding = b'\0\0\x20' + receiver.invoice(0xffffffff).native_pk + b'\xac'
            public = {'schema': 'kpb-fresh-owner-initial-public/v1', 'domain_hex32': profile.domain.hex(),
                'profile_id_hex32': profile.profile_id.hex(), 'output_hex520': created.row.hex(),
                'admission_sompi': 2_000_000_000, 'funding_spk_hex36': funding.hex(),
                'original_backup_schema': BACKUP_SCHEMA, 'kdf_tag_ascii8': KDF_TAG,
                'public_known_seed_used': False, 'funding_or_native_acceptance': False}
        else:
            seed = load_backup('/original/BACKUP.json', profile)
            receiver = wallet.Receiver(seed, profile, crypto, authority)
            initial = parse(read('/initial/PUBLIC.json', config['initial_public_sha256']))
            need(initial['schema'] == 'kpb-fresh-owner-initial-public/v1'
                 and initial['domain_hex32'] == profile.domain.hex()
                 and initial['profile_id_hex32'] == profile.profile_id.hex()
                 and initial['original_backup_schema'] == BACKUP_SCHEMA, 'exact-new-profile-initial-export')
            row = bytes.fromhex(initial['output_hex520'])
            need(prover.verify(row), 'restored-initial-output-proof')
            receipt = receiver.open(row[96:360])
            need(receipt.commitment() == row[:32] and receipt.value_sompi == 2_000_000_000,
                 'original-only-initial-recovery')
            # Verify strict version separation locally. No legacy seed parser
            # or fallback KDF is reachable in this worker.
            public = {'schema': 'kpb-new-original-recovery-public/v1', 'seed_only': True,
                'new_profile_and_backup_version_checked': True, 'actual_output_proof_verified': True,
                'encrypted_note_and_AK_bound_descriptor_recovered': True, 'private_maps_imported': False,
                'private_values_or_seed_exported': False, 'legacy_backup_reinterpretation': False,
                'recovered_output_roles': 'unclassified', 'accepted_backing_or_spendability': False}
        write('/out/PUBLIC.json', public, 0o400)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init', 'restore-probe'))
    args = parser.parse_args()
    try:
        run(args)
    except BaseException as error:
        # This fixed type category is public. Detailed stdout/stderr stay in
        # the one owner's excluded log and are never controller-read/hashed.
        if Path('/out').is_dir() and not Path('/out/PUBLIC-FAILURE.json').exists():
            frame = error.__traceback__
            while frame and frame.tb_next:
                frame = frame.tb_next
            write('/out/PUBLIC-FAILURE.json', {'schema': 'kpb-owner-worker-failure/v1',
                  'category': type(error).__name__,
                  'source_site': None if frame is None else
                      {'file': Path(frame.tb_frame.f_code.co_filename).name, 'line': frame.tb_lineno}}, 0o400)
        raise


if __name__ == '__main__':
    main()

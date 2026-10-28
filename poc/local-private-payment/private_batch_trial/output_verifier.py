"""Genuine public Output verification without a proving-key dependency."""
import hashlib
import json
from pathlib import Path
import stat
import subprocess

import wallet_profile as wallet


class OutputVerifier:
    def __init__(self, profile, binary, binary_sha256, manifest, manifest_sha256, *, read_public):
        self.profile, self.binary, self.manifest = profile, Path(binary).absolute(), Path(manifest).absolute()
        self.manifest_sha256 = manifest_sha256
        info = self.binary.lstat()
        wallet.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o500, 'output-public-verifier-metadata')
        read_public(self.binary, binary_sha256)
        value = json.loads(read_public(self.manifest, manifest_sha256))
        wallet.need(value['schema'] == 'kpb-new-wallet-parameters/v1' and value['role'] == 'new-output'
            and value['domain_hex32'] == profile.domain.hex() and value['profile_id_hex32'] == profile.profile_id.hex()
            and value['instances'] == 3, 'output-public-verifier-profile')
        vk = bytes.fromhex(value['vk_hex328'])
        wallet.need(len(vk) == 328 and vk.hex() == value['vk_hex328']
                    and hashlib.sha256(vk).hexdigest() == value['vk_sha256'], 'output-public-verifier-VK')
        self.vk_sha256 = value['vk_sha256']

    def _call(self, operation, statement, private=None):
        wallet.need(operation == 'verify' and private is not None
                    and set(private) == {'proof_hex128'}, 'public-output-verifier-only')
        request = {'operation': 'verify', 'role': 'new-output',
            'profile': {'domain_hex32': self.profile.domain.hex(), 'profile_id_hex32': self.profile.profile_id.hex()},
            'statement_hex': statement.hex(), **private,
            'parameters': {'manifest': '/parameters/MANIFEST.json', 'manifest_sha256': self.manifest_sha256}}
        argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(self.binary), '/public/verifier',
            '--ro-bind', str(self.manifest), '/parameters/MANIFEST.json', '/public/verifier']
        result = subprocess.run(argv, input=json.dumps(request, separators=(',', ':')).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        wallet.need(result.returncode == 0, 'public-output-verifier-refused')
        return json.loads(result.stdout)

    def verify(self, row):
        wallet.need(type(row) is bytes and len(row) == 520 and row[:32] != bytes(32)
                    and hashlib.sha256(row[96:360]).digest() == row[360:392], 'public-output-complete-tuple')
        statement = b'KPXAOU01' + self.profile.domain + row[:96] + row[360:392]
        result = self._call('verify', statement, {'proof_hex128': row[392:].hex()})
        wallet.need(result['schema'] == 'kpb-new-wallet-proof-verification/v1' and result['role'] == 'new-output'
                    and type(result['accepted']) is bool, 'public-output-verifier-response')
        return result['accepted']

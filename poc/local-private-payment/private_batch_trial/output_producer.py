"""Owner-local new-profile Output proving with complete public tuples.

The caller authenticates its invoice and keeps CreatedOutput inside the wallet.
Only its 520-byte row is a public export. This verifies Output cryptography and
delivery; accepted history/currentness/backing remain the proved native path.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess

import wallet_profile as wallet

OUTPUT_TAG = b'KPXAOU01'
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041


def need(value, category):
    if not value:
        raise wallet.Invalid(category)


def fixed(value, length):
    need(type(value) is bytes and len(value) == length, 'output-fixed-width')
    return value


@dataclass(frozen=True, repr=False)
class CreatedOutput:
    """Wallet-local witness material; no automatic JSON/public representation."""
    row: bytes
    receipt: wallet.Receipt
    blind: bytes


class OutputProver:
    def __init__(self, profile, binary, binary_sha256, manifest, manifest_sha256,
                 proving_key, *, read_public):
        self.profile = profile
        self.binary = Path(binary).absolute()
        self.manifest = Path(manifest).absolute()
        self.proving_key = Path(proving_key).absolute()
        self.manifest_sha256 = manifest_sha256
        info = self.binary.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o500, 'output-prover-admission')
        read_public(self.binary, binary_sha256)
        raw = read_public(self.manifest, manifest_sha256)
        value = json.loads(raw)
        need(value['schema'] == 'kpb-new-wallet-parameters/v1'
             and value['role'] == 'new-output'
             and value['domain_hex32'] == profile.domain.hex()
             and value['profile_id_hex32'] == profile.profile_id.hex()
             and value['instances'] == 3
             and value['setup_entropy'] == 'PRIVATE_OS_RNG_NOT_RETAINED',
             'output-exact-profile-parameters')
        key_info = self.proving_key.lstat()
        need(stat.S_ISREG(key_info.st_mode) and not self.proving_key.is_symlink()
             and key_info.st_nlink == 1 and key_info.st_size == value['pk_bytes'],
             'output-complete-parameter-metadata')
        self.pk_sha256 = value['pk_sha256']
        self.vk_sha256 = value['vk_sha256']
        read_public(self.proving_key, self.pk_sha256)

    def _call(self, operation, statement, private=None):
        request = {'operation': operation, 'role': 'new-output',
                   'profile': {'domain_hex32': self.profile.domain.hex(),
                               'profile_id_hex32': self.profile.profile_id.hex()},
                   'statement_hex': statement.hex()}
        arguments = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent',
                     '--new-session', '--clearenv', '--ro-bind', '/usr', '/usr',
                     '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                     '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
                     '--dev', '/dev', '--tmpfs', '/tmp',
                     '--ro-bind', str(self.binary), '/public/prover',
                     '--ro-bind', str(self.manifest), '/parameters/MANIFEST.json',
                     '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                     '--setenv', 'TZ', 'UTC', '--setenv', 'RAYON_NUM_THREADS', '4']
        if operation in ('prove', 'verify'):
            request['parameters'] = {'manifest': '/parameters/MANIFEST.json',
                                     'manifest_sha256': self.manifest_sha256}
        if operation == 'prove':
            request['parameters'].update(pk='/parameters/parameters.pk',
                                         pk_sha256=self.pk_sha256)
            arguments += ['--ro-bind', str(self.proving_key), '/parameters/parameters.pk']
        if private:
            request.update(private)
        arguments.append('/public/prover')
        # Requests can contain note openings. Never write or log them. The
        # selected binary emits only fixed errors/public results; stderr is not
        # exported by this owner-local adapter. Verification gets no PK mount.
        result = subprocess.run(arguments, input=json.dumps(request, separators=(',', ':')).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        need(result.returncode == 0, 'output-prover-refused')
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError):
            raise wallet.Invalid('output-prover-response') from None

    def create(self, crypto, invoice, value_sompi, *, rho=None, blind=None):
        need(isinstance(invoice, wallet.Invoice) and invoice.domain == self.profile.domain,
             'output-exact-new-invoice')
        receipt = wallet.Receipt.for_invoice(invoice, value_sompi,
                    os.urandom(32) if rho is None else fixed(rho, 32))
        blind = secrets.randbelow(Q).to_bytes(32, 'little') if blind is None else fixed(blind, 32)
        need(int.from_bytes(blind, 'little') < Q, 'output-canonical-blinding')
        ciphertext = crypto.seal(invoice.delivery_pk, receipt.encode())
        fixed(ciphertext, 264)
        cfh = hashlib.sha256(ciphertext).digest()
        witness = {'note_hex168': receipt.note_bytes().hex(), 'blinding_hex32': blind.hex()}
        public = self._call('derive-output', b'', {**witness, 'cf_hash_hex32': cfh.hex()})
        statement = bytes.fromhex(public['statement_hex168'])
        need(len(statement) == 168 and statement[:8] == OUTPUT_TAG
             and statement[8:40] == self.profile.domain
             and statement[40:72] == receipt.commitment() and statement[136:] == cfh,
             'output-derived-statement')
        proof = self._call('prove', statement, witness)
        row = statement[40:136] + ciphertext + cfh + bytes.fromhex(proof['proof_hex128'])
        need(self.verify(row), 'output-produced-proof-rejected')
        return CreatedOutput(fixed(row, 520), receipt, blind)

    def verify(self, row):
        fixed(row, 520)
        need(row[:32] != bytes(32) and hashlib.sha256(row[96:360]).digest() == row[360:392],
             'output-complete-CF-binding')
        statement = OUTPUT_TAG + self.profile.domain + row[:96] + row[360:392]
        result = self._call('verify', statement, {'proof_hex128': row[392:].hex()})
        need(result['schema'] == 'kpb-new-wallet-proof-verification/v1'
             and result['role'] == 'new-output' and type(result['accepted']) is bool,
             'output-verifier-response')
        return result['accepted']

    def recover_owned(self, receiver, rows, expected_cm_root, spent_nfs):
        need(receiver.profile == self.profile and type(rows) is list, 'output-recovery-profile')
        for row in rows:
            need(self.verify(row), 'output-history-proof-rejected')
        deliveries = [wallet.legacy.Delivery(position, row[:32], row[96:360])
                      for position, row in enumerate(rows)]
        return wallet.recover_openings(receiver, deliveries, expected_cm_root, spent_nfs)

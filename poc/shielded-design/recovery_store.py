"""Single-host trusted-disk recovery envelope. No chain authority or submission.

POSIX flock/CAS serializes writers; fsync/replace publishes a complete generation.
phase_hook is a fault-injection boundary for real process-kill experiments.
"""
import fcntl
import os
from pathlib import Path
import tempfile

from recovery import integer, reconstruct_public, restore_wallet
from recovery_format import SCOPE, canonical, fields, hex32, read_json, reject
from recovery_session import RecoverySession


def validate_submission(request, export=None):
    kind = request.get('kind') if type(request) is dict else None
    if kind == 'payout':
        fields(request, 'kind claim recipient principal rent remaining_reserve')
    elif kind == 'fee_payment':
        fields(request, 'kind claim recipient amount remaining_reserve')
    else:
        reject('submission_kind')
    hex32(request['claim'])
    if type(request['recipient']) is not str or not request['recipient']:
        reject('submission_recipient')
    for key in ('principal', 'rent', 'remaining_reserve') if kind == 'payout' else ('amount', 'remaining_reserve'):
        integer(request[key])
    if export is not None:
        trial = RecoverySession(**export)
        if kind == 'payout':
            result = trial.payout(request['claim'], request['recipient'], request['principal'],
                                  request['rent'], request['remaining_reserve'])
        else:
            result = trial.pay_fee(request['claim'], request['recipient'], request['amount'], request['remaining_reserve'])
        if not result['accepted']:
            reject('submission_not_currently_authorized')


class RecoveryStore:
    def __init__(self, directory, phase_hook=None):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            reject('private_store_directory_required')
        self.path = self.directory / 'recovery.json'
        self.phase_hook = phase_hook or (lambda phase: None)

    def load(self, backups):
        if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
            reject('private_store_file_required')
        data = read_json(self.path)
        fields(data, 'schema scope revision export wallets pending_submission')
        if data['schema'] != 'kpi-model-recovery-store/v1' or data['scope'] != SCOPE:
            reject('store_domain_or_version')
        if integer(data['revision']) == 0:
            reject('store_revision')
        fields(data['export'], 'archive checkpoint')
        reconstruct_public(**data['export'])
        expected = {name: restore_wallet(**data['export'], backup=backup) for name, backup in backups.items()}
        if canonical(data['wallets']) != canonical(expected):
            reject('store_wallet_checkpoint_mismatch')
        if data['pending_submission'] is not None:
            validate_submission(data['pending_submission'])
        data['next_action'] = ('inspect_history_do_not_resubmit' if data['pending_submission'] is not None
                               else 'continue_at_model_horizon')
        return data

    def commit(self, export, backups, expected_revision, pending_submission=None):
        """Publish one coherent public horizon and private scan result atomically."""
        integer(expected_revision)
        fields(export, 'archive checkpoint')
        reconstruct_public(**export)
        wallets = {name: restore_wallet(**export, backup=backup) for name, backup in backups.items()}
        lock = os.open(self.directory / 'writer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.path.is_symlink():
                reject('private_store_file_required')
            previous = self.load(backups) if self.path.exists() else None
            current = previous['revision'] if previous else 0
            if current != expected_revision:
                reject('stale_store_revision')
            revision = integer(current + 1)
            pending = previous['pending_submission'] if previous else None
            if pending is not None:
                # A caller's trusted new history must contain the exact payment;
                # absence, unknown outcome or a reorg cannot trigger a retry.
                observed = any(canonical({key: value for key, value in record.items() if key != 'seq'}) == canonical(pending)
                               for record in export['archive']['records'])
                if observed:
                    pending = None
            if pending_submission is not None:
                if pending is not None:
                    reject('submission_still_unknown')
                validate_submission(pending_submission, export)
                pending = pending_submission
            data = {'schema': 'kpi-model-recovery-store/v1', 'scope': SCOPE, 'revision': revision,
                    'export': export, 'wallets': wallets, 'pending_submission': pending}
            fd, temporary = tempfile.mkstemp(prefix='pending-', dir=self.directory)
            with os.fdopen(fd, 'wb') as output:
                output.write(canonical(data) + b'\n')
                output.flush()
                os.fsync(output.fileno())
            self.phase_hook('file_synced')
            self.phase_hook('before_replace')
            os.replace(temporary, self.path)
            self.phase_hook('replaced')
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.phase_hook('directory_synced')
            return revision
        finally:
            os.close(lock)

"""Strict experiment encodings. Checkpoints are trusted MODEL inputs, not ZK/L1."""
import hashlib
import json
import os
from pathlib import Path

from model import NETWORK, POOL, VERSION, Note, Wallet, amount

SCOPE = 'OFFLINE_MODEL_ONLY_NO_CHAIN_OR_ZK'
DESCRIPTOR = {'network': NETWORK, 'pool': POOL, 'statement_version': VERSION,
              'genesis': 'MODEL-NO-CHAIN-GENESIS', 'lane': 'MODEL-RECOVERY-LANE',
              'note_format': 'existing-shielded-model-v1'}


class RecoveryError(ValueError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def reject(code):
    raise RecoveryError('rejected_unverifiable_input', code)


def fields(value, names):
    if type(value) is not dict:
        reject('object_required')
    expected = set(names.split())
    if expected - value.keys():
        raise RecoveryError('incomplete_data', 'missing_fields')
    if value.keys() - expected:
        reject('unknown_fields')


def hex32(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        reject('canonical_hex32_required')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def make_backup(wallet, expected_receipts=(), pending_notes=None):
    spending, incoming = wallet.export_secrets()
    backup = {'schema': 'kpi-model-backup/v1', 'scope': SCOPE,
              'descriptor_hash': digest(DESCRIPTOR), 'owner': wallet.owner,
              'incoming': wallet.address.incoming, 'spending_seed': spending.hex(),
              'incoming_secret': incoming.hex(), 'expected_receipts': list(expected_receipts)}
    if pending_notes is not None:
        backup['schema'] = 'kpi-model-backup/v2'
        backup['pending_notes'] = pending_notes
    wallet_from_backup(backup)
    return backup


def wallet_from_backup(backup):
    version2 = type(backup) is dict and backup.get('schema') == 'kpi-model-backup/v2'
    names = 'schema scope descriptor_hash owner incoming spending_seed incoming_secret expected_receipts'
    fields(backup, names + (' pending_notes' if version2 else ''))
    if backup['schema'] not in ('kpi-model-backup/v1', 'kpi-model-backup/v2') or (
            backup['scope'], backup['descriptor_hash']) != (SCOPE, digest(DESCRIPTOR)):
        reject('backup_domain_or_version')
    for key in ('owner', 'incoming', 'spending_seed', 'incoming_secret'):
        hex32(backup[key])
    receipts = backup['expected_receipts']
    if type(receipts) is not list:
        reject('receipt_inventory_required')
    for commitment in receipts:
        hex32(commitment)
    if len(set(receipts)) != len(receipts):
        reject('duplicate_expected_receipt')
    wallet = Wallet.from_secrets(bytes.fromhex(backup['spending_seed']), bytes.fromhex(backup['incoming_secret']))
    if wallet.owner != backup['owner'] or wallet.address.incoming != backup['incoming']:
        reject('backup_key_identity_mismatch')
    if version2:
        if type(backup['pending_notes']) is not list:
            reject('pending_note_inventory_required')
        seen = set()
        for entry in backup['pending_notes']:
            fields(entry, 'deposit note')
            identity = hex32(entry['deposit'])
            if identity in seen:
                reject('duplicate_pending_note')
            seen.add(identity)
            fields(entry['note'], 'owner value randomness')
            hex32(entry['note']['owner']); hex32(entry['note']['randomness'])
            try:
                note = Note(**entry['note'])
            except (ValueError, TypeError):
                reject('pending_note_format')
            if note.owner != wallet.owner:
                reject('pending_note_owner')
    return wallet


def pending_note_from_backup(backup, event):
    """Private metadata for retrying credit; refund authority needs keys only."""
    wallet = wallet_from_backup(backup)
    if type(event) is not dict:
        reject('pending_deposit_required')
    identity = hex32(event.get('id'))
    try:
        principal = amount(event.get('amount'))
    except ValueError:
        reject('pending_deposit_amount')
    for entry in backup.get('pending_notes', []):
        if entry['deposit'] == identity:
            note = Note(**entry['note'])
            if (note.commitment != event.get('commitment') or note.value != principal or
                    event.get('refund_owner') != wallet.owner):
                reject('pending_note_binding')
            return note
    raise RecoveryError('incomplete_wallet_data', 'pending_note_metadata_missing')


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                reject('duplicate_json_key')
            result[key] = value
        return result

    def noninteger(_):
        reject('noninteger_json_number')

    try:
        return json.loads(Path(path).read_text(), object_pairs_hook=pairs,
                          parse_float=noninteger, parse_constant=noninteger)
    except RecoveryError:
        raise
    except FileNotFoundError:
        raise RecoveryError('incomplete_data', 'input_file_missing') from None
    except (ValueError, UnicodeError, RecursionError):
        reject('invalid_json')


def write_private_json(path, value):
    """No overwrite, no symlink following; backup and derived wallet output are private."""
    raw = canonical(value) + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)

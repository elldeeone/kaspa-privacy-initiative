"""Incoming-only MODEL inspection; no spending key or authoritative spentness."""
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.signing import VerifyKey

from model import NETWORK, POOL, Wallet, canonical, refund_signature_bytes
from recovery import reconstruct_public, summed
from recovery_format import (DESCRIPTOR, SCOPE, RecoveryError, digest, fields, hex32,
                             reject, wallet_from_backup)


def make_view_backup(spending_backup):
    wallet = wallet_from_backup(spending_backup)
    return {'schema': 'kpi-model-view-backup/v1', 'scope': SCOPE,
            'descriptor_hash': digest(DESCRIPTOR), 'owner': wallet.owner,
            'incoming': wallet.address.incoming, 'address_signature': wallet.address.signature,
            'incoming_secret': spending_backup['incoming_secret'],
            'expected_receipts': list(spending_backup['expected_receipts'])}


class IncomingView:
    # Share exactly the existing authenticated receiver checks, without inheriting
    # a spend/sign/nullifier method or installing a fake spending secret.
    receive_record = Wallet.receive_record

    def __init__(self, backup):
        fields(backup, 'schema scope descriptor_hash owner incoming address_signature incoming_secret expected_receipts')
        if (backup['schema'], backup['scope'], backup['descriptor_hash']) != (
                'kpi-model-view-backup/v1', SCOPE, digest(DESCRIPTOR)):
            reject('view_backup_domain_or_version')
        for key in ('owner', 'incoming', 'incoming_secret'):
            hex32(backup[key])
        self.owner = backup['owner']
        self._view = PrivateKey(bytes.fromhex(backup['incoming_secret']))
        if bytes(self._view.public_key).hex() != backup['incoming']:
            reject('view_key_identity_mismatch')
        try:
            VerifyKey(bytes.fromhex(self.owner)).verify(
                canonical(['MODEL-RECEIVE', NETWORK, POOL, self.owner, backup['incoming']]),
                refund_signature_bytes(backup['address_signature']))
        except (ValueError, CryptoError):
            reject('view_address_authorization')
        if type(backup['expected_receipts']) is not list:
            reject('receipt_inventory_required')
        for commitment in backup['expected_receipts']:
            hex32(commitment)
        if len(set(backup['expected_receipts'])) != len(backup['expected_receipts']):
            reject('duplicate_expected_receipt')


def inspect_view(archive, checkpoint, backup):
    view = IncomingView(backup)
    state = reconstruct_public(archive, checkpoint)
    notes = []
    for output in state['outputs']:
        try:
            note = view.receive_record(output)
        except ValueError:
            reject('invalid_recipient_delivery')
        if note is not None:
            notes.append(note)
    if set(backup['expected_receipts']) - {note.commitment for note in notes}:
        raise RecoveryError('incomplete_wallet_data', 'expected_receipt_not_recoverable')
    return {'scope': SCOPE, 'status': 'view_only_spentness_unknown', 'can_spend': False,
            'chain_or_zk_verified': False, 'unknown_sender_delivery_guaranteed': False,
            'checkpoint_hash': state['checkpoint_hash'], 'accepted_received_sompi': summed(note.value for note in notes),
            'accepted_received_notes': [note.__dict__ for note in notes]}

"""Strict public two-owner entry derivation; no key, proof or chain authority."""
from dataclasses import dataclass
import copy
import hashlib
import uuid

from gn2_common import (GENESIS, MAX, NOTE_FLOOR, amount, digest, encoded, fields,
                    hx, need, reference, uint, uuid_text)

MAGIC = b'KPX5GN02'
WIDTH = 1080
RECORD_WIDTH = 496
APPROVAL_TAG = b'KPX6/GN2/UNSIGNED-CASE-APPROVAL/v1\0'


@dataclass(frozen=True)
class EntrySelection:
    profile_sha256: str
    domain: bytes
    tail: bytes

    def check(self):
        hx(self.profile_sha256, 32)
        need(type(self.domain) is bytes and len(self.domain) == 32 and self.domain != bytes(32),
             'selected-domain-width')
        need(type(self.tail) is bytes and self.tail, 'selected-immutable-W-tail')
        return self


def record(note, ciphertext, domain):
    need(type(note) is bytes and len(note) == 168
         and type(ciphertext) is bytes and len(ciphertext) == 264, 'GN2-record-width')
    value = int.from_bytes(note[64:72], 'little')
    need(NOTE_FLOOR <= value <= MAX, 'GN2-note-value')
    cm = hashlib.sha256(b'KPX1NOT\0' + domain + note).digest()
    return note + cm + ciphertext + hashlib.sha256(ciphertext).digest()


def decode_payload(raw, selection, expected_trial_id):
    selection.check()
    uuid_text(expected_trial_id)
    need(type(raw) is bytes and len(raw) == WIDTH and raw[:8] == MAGIC
         and raw[8:40].hex() == selection.profile_sha256 and raw[40:72] == selection.domain
         and raw[72:88] == uuid.UUID(expected_trial_id).bytes, 'GN2-header-profile-domain-trial')
    rows = []
    for i in range(2):
        row = raw[88 + i * RECORD_WIDTH:88 + (i + 1) * RECORD_WIDTH]
        note, cm, cipher, cf_hash = row[:168], row[168:200], row[200:464], row[464:496]
        need(record(note, cipher, selection.domain) == row, 'GN2-note-CM-CF-binding')
        rows.append({'note': note, 'cm': cm, 'cipher': cipher, 'cf_hash': cf_hash,
                     'value': int.from_bytes(note[64:72], 'little')})
    need(rows[0]['cm'] != rows[1]['cm'], 'GN2-distinct-initial-CMs')
    reserve = rows[0]['value'] + rows[1]['value']
    amount(reserve, True)
    p = reference('primitives')
    snapshot = p.Snapshot(2, tuple(p.Delivery(i, row['cm'], row['cipher'])
        for i, row in enumerate(rows)), (p.NFEntry(bytes(32), bytes(32), 0),)).verify()
    return rows, snapshot, reserve


def encode_payload(selection, trial_id, records):
    selection.check()
    uuid_text(trial_id)
    need(type(records) in (tuple, list) and len(records) == 2
         and all(type(r) is bytes and len(r) == RECORD_WIDTH for r in records), 'GN2-record-count-width')
    raw = MAGIC + hx(selection.profile_sha256, 32) + selection.domain + uuid.UUID(trial_id).bytes + b''.join(records)
    decode_payload(raw, selection, trial_id)
    return raw


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def snapshot_record(snapshot):
    return {'cm_cursor': snapshot.cm_cursor,
        'deliveries': [{'position': r.position, 'cm_hex32': r.cm.hex(),
                        'cipher_hex264': r.ciphertext.hex()} for r in snapshot.deliveries],
        'nullifiers': [{'value_hex32': r.value.hex(), 'next_value_hex32': r.next_value.hex(),
                        'next_index': r.next_index} for r in snapshot.nullifiers]}


def _validate_genesis(case, selection, expected_trial_id, *, required_fee=None, signed=False, history=False):
    """Derive all entry effects; native ID/Full/quote and currentness are separate.

    required_fee, when supplied by an independently recomputed native quote,
    closes the exact fee equation. Without it this validates the deterministic
    allocation of the actual input-output fee only, never a fee-rate claim.
    """
    fields(case, {'transaction', 'entries'}, 'GN2-case-fields')
    body, contexts = case['transaction'], case['entries']
    fields(body, {'version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
        'gas', 'payload', 'mass'}, 'GN2-body-fields')
    need(type(body['version']) is int and body['version'] == 1
         and type(body['lockTime']) is int and body['lockTime'] == 0
         and type(body['gas']) is int and body['gas'] == 0
         and body['subnetworkId'] == '00' * 20, 'GN2-canonical-header')
    hx(body['id'], 32)
    uint(body['mass'])
    need(type(body['inputs']) is list and len(body['inputs']) == 2
         and type(contexts) is list and len(contexts) == 2, 'GN2-two-funding-inputs')
    need(type(body['outputs']) is list and 1 <= len(body['outputs']) <= 3, 'GN2-output-count')
    points, scripts, amounts = [], [], []
    for row, ctx in zip(body['inputs'], contexts):
        fields(row, {'previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'}, 'GN2-input-fields')
        fields(row['previousOutpoint'], {'transactionId', 'index'}, 'GN2-source-point')
        hx(row['previousOutpoint']['transactionId'], 32)
        uint(row['previousOutpoint']['index'], 32)
        need(type(row['sequence']) is int and row['sequence'] == (1 << 64) - 1,
             'GN2-source-sequence')
        uint(row['computeBudget'], 16)
        if not history:
            need(row['computeBudget'] == 10, 'GN2-campaign-source-budget')
        sig = hx(row['signatureScript'])
        need((len(sig) == 66 and sig[:1] == b'\x41' and sig[-1:] == b'\x01') if signed
             else sig == b'\x41' + bytes(64) + b'\x01', 'GN2-canonical-ALL-or-placeholder')
        fields(ctx, {'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'}, 'GN2-context-fields')
        amount(ctx['amount'], True)
        uint(ctx['blockDaaScore'])
        need(ctx['isCoinbase'] is False and ctx['covenantId'] is None, 'GN2-ordinary-source-flags')
        script = hx(ctx['scriptPublicKey'], 36)
        need(script[:3] == b'\0\0\x20' and script[-1:] == b'\xac', 'GN2-ordinary-source-P2PK')
        points.append((row['previousOutpoint']['transactionId'], row['previousOutpoint']['index']))
        scripts.append(ctx['scriptPublicKey'])
        amounts.append(ctx['amount'])
    need(points[0] != points[1] and scripts[0] != scripts[1], 'GN2-distinct-funding-points-and-keys')
    rows, snapshot, reserve = decode_payload(hx(body['payload']), selection, expected_trial_id)
    state = snapshot.state(selection.domain)
    redeem = b'\x4c\x70' + state + selection.tail
    for row in body['outputs']:
        fields(row, {'value', 'scriptPublicKey', 'covenant'}, 'GN2-output-fields')
        amount(row['value'], True)
        hx(row['scriptPublicKey'])
        need(row['covenant'] is None, 'GN2-no-output-covenant')
    need(body['outputs'][0] == {'value': reserve, 'scriptPublicKey': p2sh(redeem), 'covenant': None},
         'GN2-exact-initial-W-reserve')
    changes = [0, 0]
    last = -1
    for row in body['outputs'][1:]:
        need(row['scriptPublicKey'] in scripts, 'GN2-no-foreign-change')
        index = scripts.index(row['scriptPublicKey'])
        need(index > last, 'GN2-change-order-or-duplicate')
        changes[index] = row['value']
        last = index
    total_fee = sum(amounts) - sum(row['value'] for row in body['outputs'])
    amount(total_fee, True)
    if required_fee is not None:
        amount(required_fee, True)
        need(total_fee == required_fee, 'GN2-exact-native-quoted-fee')
    fees = [total_fee // 2, total_fee - total_fee // 2]
    contributions = []
    for i in range(2):
        need(amounts[i] == rows[i]['value'] + changes[i] + fees[i], 'GN2-exact-owner-allocation')
        contributions.append({'input_index': i, 'note_value_sompi': rows[i]['value'],
            'ordinary_change_sompi': changes[i], 'entry_fee_sompi': fees[i],
            'source_amount_sompi': amounts[i], 'source_script_public_key': scripts[i]})
    return {'snapshot': snapshot_record(snapshot), 'state_hex112': state.hex(),
        'reserve_sompi': reserve, 'redeem_hex': redeem.hex(),
        'founding_outpoint': {'transactionId': body['id'], 'index': 0},
        'contributions': contributions, 'fee_sompi': total_fee}



def validate_genesis(case, selection, expected_trial_id, *, required_fee=None, signed=False):
    """Selected campaign entry: exact10/10 and signature-sized proposal quote."""
    return _validate_genesis(case, selection, expected_trial_id,
        required_fee=required_fee, signed=signed)


def validate_proposal(case, selection, expected_trial_id, *, required_fee=None):
    """Named unsigned campaign facade; no caller can opt into history rules."""
    return validate_genesis(case, selection, expected_trial_id, required_fee=required_fee)


def validate_accepted_genesis(case, selection, expected_trial_id):
    """Financial history shape only; caller MUST establish Native Full/acceptance.

    V1 budgets are unsigned. Any canonical u16 must be judged by actual native
    execution, not by this wallet's10/10 proposal pricing. Actual fee and exact
    per-owner split remain derived/bound; reference-rate equality is not an
    accepted-history predicate. No currentness or consensus assertion is made.
    """
    return _validate_genesis(case, selection, expected_trial_id, signed=True, history=True)


def approval_digest(case, selection, trial_id, fee_rate):
    """Process receipt only. Native financial authorization is the two ALL sigs."""
    uuid_text(trial_id)
    uint(fee_rate)
    need(fee_rate > 0, 'positive-entry-fee-rate')
    body = copy.deepcopy(case)
    for row in body['transaction']['inputs']:
        row['signatureScript'] = ''
    return digest(APPROVAL_TAG + hx(selection.profile_sha256, 32)
        + uuid.UUID(trial_id).bytes + fee_rate.to_bytes(8, 'little') + encoded(body))

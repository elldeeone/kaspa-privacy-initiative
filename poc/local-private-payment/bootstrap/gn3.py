"""Strict public three-owner entry derivation; no key, proof or chain authority."""
from dataclasses import dataclass
import copy
import hashlib
import uuid

from gn3_common import (GENESIS, MAX, NOTE_FLOOR, amount, digest, encoded, fields,
                    hx, need, reference, uint, uuid_text, parse)

MAGIC = b'KPXAGN01'
WIDTH = 1648
RECORD_WIDTH = 520
APPROVAL_TAG = b'KPXA/GN3/UNSIGNED-CASE-APPROVAL/v1\0'


@dataclass(frozen=True)
class EntrySelection:
    profile_sha256: str
    domain: bytes
    tail: bytes
    output_relation: dict
    output_vk_hex328: str
    initial_cv_hex64: str
    state_magic: bytes = b'KPXAST01'

    def check(self):
        hx(self.profile_sha256, 32)
        need(type(self.domain) is bytes and self.domain == bytes.fromhex(
             'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'),
             'selected-domain-width')
        need(type(self.tail) is bytes and self.tail, 'selected-immutable-W-tail')
        need(self.state_magic == b'KPXAST01',
             'selected-state-magic-width')
        fields(self.output_relation, {'path', 'sha256'}, 'selected-output-relation')
        hx(self.output_relation['sha256'],32);hx(self.output_vk_hex328,328);hx(self.initial_cv_hex64,64)
        return self

    def component(self, operation, statement=None, proof=None):
        from gn3_runtime import Executable
        program=Executable(self.output_relation['path'], self.output_relation['sha256'])
        if operation=='commit':
            return parse(program.run(['commit'],request={'schema':'kpxa-private-value-commitment/v1','value_sompi':'2000000000','blind_hex32':'00'*32}).stdout)
        answer=parse(program.run(['verify-output','--vk',self.output_vk_hex328,'--statement',statement.hex(),'--proof',proof.hex()]).stdout)
        need(answer=={'verified':True},'genuine-genesis-Output-proof')
        return answer


def fee_allocation(total_fee):
    """Two equal floor shares and the exact remainder on the last input."""
    amount(total_fee, True)
    base = total_fee // 3
    return [base, base, total_fee - 2 * base]


def record(row, selection):
    """Only encrypted Output520 is public; known20KAS admission CV uses blind0."""
    need(type(row) is bytes and len(row)==520, 'GN3-encrypted-output-width')
    cm,cv,cf,cfh,proof=row[:32],row[32:96],row[96:360],row[360:392],row[392:]
    need(cm not in (bytes(32),hashlib.sha256(b'KPX1CME\0').digest())
         and hashlib.sha256(cf).digest()==cfh,'GN3-CM-CFH-binding')
    expected=selection.component('commit')
    need(expected=={'cv_hex64':selection.initial_cv_hex64}
         and cv.hex()==selection.initial_cv_hex64,'GN3-public-20KAS-zero-blind-CV')
    selection.component('verify',b'KPXAOU01'+selection.domain+cm+cv+cfh,proof)
    return row


def decode_payload(raw, selection, expected_trial_id):
    selection.check()
    uuid_text(expected_trial_id)
    need(type(raw) is bytes and len(raw) == WIDTH and raw[:8] == MAGIC
         and raw[8:40].hex() == selection.profile_sha256 and raw[40:72] == selection.domain
         and raw[72:88] == uuid.UUID(expected_trial_id).bytes, 'GN3-header-profile-domain-trial')
    rows=[]
    for i in range(3):
        row=record(raw[88+i*RECORD_WIDTH:88+(i+1)*RECORD_WIDTH],selection)
        rows.append({'cm':row[:32],'cv':row[32:96],'cipher':row[96:360],
                     'cf_hash':row[360:392],'proof':row[392:],'row':row,'value':2_000_000_000})
    need(len({row['cm'] for row in rows})==3,'GN3-distinct-initial-CMs')
    snapshot=reference('local_trees').PublicState([row['cm'] for row in rows])
    return rows,snapshot,6_000_000_000


def encode_payload(selection, trial_id, records):
    selection.check()
    uuid_text(trial_id)
    need(type(records) in (tuple, list) and len(records) == 3
         and all(type(r) is bytes and len(r) == RECORD_WIDTH for r in records), 'GN3-record-count-width')
    raw = MAGIC + hx(selection.profile_sha256, 32) + selection.domain + uuid.UUID(trial_id).bytes + b''.join(records)
    decode_payload(raw, selection, trial_id)
    return raw


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def snapshot_record(snapshot):
    return {'cm_cursor':len(snapshot.cms),
        'deliveries':[{'position':i,'cm_hex32':cm.hex()} for i,cm in enumerate(snapshot.cms)],
        'nullifiers':[{'value_hex32':value.hex(),'next_value_hex32':nxt.hex(),'next_index':index}
                     for value,nxt,index in snapshot.entries]}


def _validate_genesis(case, selection, expected_trial_id, *, required_fee=None, signed=False, history=False):
    """Derive all entry effects; native ID/Full/quote and currentness are separate.

    required_fee, when supplied by an independently recomputed native quote,
    closes the exact fee equation. Without it this validates the deterministic
    allocation of the actual input-output fee only, never a fee-rate claim.
    """
    fields(case, {'transaction', 'entries'}, 'GN3-case-fields')
    body, contexts = case['transaction'], case['entries']
    fields(body, {'version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
        'gas', 'payload', 'mass'}, 'GN3-body-fields')
    need(type(body['version']) is int and body['version'] == 1
         and type(body['lockTime']) is int and body['lockTime'] == 0
         and type(body['gas']) is int and body['gas'] == 0
         and body['subnetworkId'] == '00' * 20, 'GN3-canonical-header')
    hx(body['id'], 32)
    uint(body['mass'])
    need(type(body['inputs']) is list and len(body['inputs']) == 3
         and type(contexts) is list and len(contexts) == 3, 'GN3-three-funding-inputs')
    need(type(body['outputs']) is list and 1 <= len(body['outputs']) <= 4, 'GN3-output-count')
    points, scripts, amounts = [], [], []
    for row, ctx in zip(body['inputs'], contexts):
        fields(row, {'previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'}, 'GN3-input-fields')
        fields(row['previousOutpoint'], {'transactionId', 'index'}, 'GN3-source-point')
        hx(row['previousOutpoint']['transactionId'], 32)
        uint(row['previousOutpoint']['index'], 32)
        need(type(row['sequence']) is int and row['sequence'] == (1 << 64) - 1,
             'GN3-source-sequence')
        uint(row['computeBudget'], 16)
        if not history:
            need(row['computeBudget'] == 10, 'GN3-campaign-source-budget')
        sig = hx(row['signatureScript'])
        need((len(sig) == 66 and sig[:1] == b'\x41' and sig[-1:] == b'\x01') if signed
             else sig == b'\x41' + bytes(64) + b'\x01', 'GN3-canonical-ALL-or-placeholder')
        fields(ctx, {'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'}, 'GN3-context-fields')
        amount(ctx['amount'], True)
        uint(ctx['blockDaaScore'])
        need(ctx['isCoinbase'] is False and ctx['covenantId'] is None, 'GN3-ordinary-source-flags')
        script = hx(ctx['scriptPublicKey'], 36)
        need(script[:3] == b'\0\0\x20' and script[-1:] == b'\xac', 'GN3-ordinary-source-P2PK')
        points.append((row['previousOutpoint']['transactionId'], row['previousOutpoint']['index']))
        scripts.append(ctx['scriptPublicKey'])
        amounts.append(ctx['amount'])
    need(len(set(points)) == 3 and len(set(scripts)) == 3, 'GN3-distinct-funding-points-and-keys')
    rows, snapshot, reserve = decode_payload(hx(body['payload']), selection, expected_trial_id)
    state = selection.state_magic + snapshot.state(selection.domain)[8:]
    redeem = b'\x4c\x70' + state + selection.tail
    for row in body['outputs']:
        fields(row, {'value', 'scriptPublicKey', 'covenant'}, 'GN3-output-fields')
        amount(row['value'], True)
        hx(row['scriptPublicKey'])
        need(row['covenant'] is None, 'GN3-no-output-covenant')
    need(body['outputs'][0] == {'value': reserve, 'scriptPublicKey': p2sh(redeem), 'covenant': None},
         'GN3-exact-initial-W-reserve')
    changes = [0, 0, 0]
    last = -1
    for row in body['outputs'][1:]:
        need(row['scriptPublicKey'] in scripts, 'GN3-no-foreign-change')
        index = scripts.index(row['scriptPublicKey'])
        need(index > last, 'GN3-change-order-or-duplicate')
        changes[index] = row['value']
        last = index
    total_fee = sum(amounts) - sum(row['value'] for row in body['outputs'])
    amount(total_fee, True)
    if required_fee is not None:
        amount(required_fee, True)
        need(total_fee == required_fee, 'GN3-exact-native-quoted-fee')
    fees = fee_allocation(total_fee)
    contributions = []
    for i in range(3):
        need(amounts[i] == rows[i]['value'] + changes[i] + fees[i], 'GN3-exact-owner-allocation')
        contributions.append({'input_index': i, 'note_value_sompi': rows[i]['value'],
            'ordinary_change_sompi': changes[i], 'entry_fee_sompi': fees[i],
            'source_amount_sompi': amounts[i], 'source_script_public_key': scripts[i]})
    return {'snapshot': snapshot_record(snapshot), 'state_hex112': state.hex(),
        'reserve_sompi': reserve, 'redeem_hex': redeem.hex(),
        'founding_outpoint': {'transactionId': body['id'], 'index': 0},
        'outpoint_hex36': body['id'] + '00000000',
        'cms_hex32': [row['cm'].hex() for row in rows],
        'ciphertexts_hex264': [row['cipher'].hex() for row in rows],
        'outputs_hex520':[row['row'].hex() for row in rows],
        'deposit_sompi':2_000_000_000,
        'genuine_genesis_Output_proofs_and_public_deposit_CVs_verified':True,
        'contributions': contributions, 'fee_sompi': total_fee}



def validate_genesis(case, selection, expected_trial_id, *, required_fee=None, signed=False):
    """Selected campaign entry: three exact10 budgets and sized ALL placeholders."""
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
    """Process receipt only. Native financial authorization is the three ALL sigs."""
    uuid_text(trial_id)
    uint(fee_rate)
    need(fee_rate > 0, 'positive-entry-fee-rate')
    body = copy.deepcopy(case)
    for row in body['transaction']['inputs']:
        row['signatureScript'] = ''
    return digest(APPROVAL_TAG + hx(selection.profile_sha256, 32)
        + uuid.UUID(trial_id).bytes + fee_rate.to_bytes(8, 'little') + encoded(body))

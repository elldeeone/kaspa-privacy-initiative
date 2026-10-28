"""Strict public encoding and identity checks for ADR-0077 settlement.

These helpers confer no live-acquisition or settlement authority. Financial
success is available only through the selected direct launcher.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
MAX_VALUE = 2870000000000000000
CORE_BYTES = 10364
BODY_BYTES = 10492
PROJECTION_BYTES = 10685
CLASS = 'RESEARCH_TESTNET_ONLY'


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-public-fields')


def parse(raw):
    if type(raw) is bytes:
        raw = raw.decode('utf-8')
    def pairs(values):
        result = {}
        for name, value in values:
            need(name not in result, 'duplicate-json-field')
            result[name] = value
        return result
    def reject(_):
        raise Refused('noninteger-json-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=reject,
                      parse_constant=reject)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_case_sha256(case):
    return sha(encoded(case) + b'\n')


def hx(value, count=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(c in '0123456789abcdef' for c in value), 'canonical-public-hex')
    raw = bytes.fromhex(value)
    need(count is None or len(raw) == count, 'public-hex-width')
    return raw


def digest(value):
    raw = hx(value, 32)
    need(raw != bytes(32), 'nonzero-identity')
    return value


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'public-integer-range')
    return value


def decimal(value, bits=64):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value == '0' or not value.startswith('0')), 'canonical-decimal')
    return uint(int(value), bits)


def point(value):
    fields(value, ('transactionId', 'index'))
    digest(value['transactionId'])
    uint(value['index'], 32)
    return value


def record(value):
    fields(value, ('path', 'sha256'))
    path = Path(value['path'])
    need(type(value['path']) is str and path.is_absolute()
         and '..' not in path.parts, 'canonical-public-path')
    digest(value['sha256'])
    return value


def read_finite(value):
    """Use only inside the public namespace; no private filesystem is mounted."""
    record(value)
    path = Path(value['path'])
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public-symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             'public-regular-single-link')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read()
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        need(all(getattr(before, key) == getattr(after, key) for key in keys)
             and len(raw) == before.st_size and sha(raw) == value['sha256'],
             'public-file-identity-or-race')
        return raw
    finally:
        os.close(fd)


def validate_case(case):
    fields(case, ('transaction', 'entries'))
    tx = case['transaction']
    fields(tx, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
                'gas', 'payload', 'mass'))
    need(uint(tx['version'],16) == 1 and uint(tx['lockTime']) == 0 and uint(tx['gas']) == 0
         and tx['subnetworkId'] == '00' * 20, 'selected-native-header')
    digest(tx['id'])
    uint(tx['mass'])
    payload = hx(tx['payload'])
    need(type(tx['inputs']) is list and len(tx['inputs']) == 1
         and type(case['entries']) is list and len(case['entries']) == 1
         and type(tx['outputs']) is list and 1 <= len(tx['outputs']) <= 2,
         'selected-native-shape')
    for item in tx['inputs']:
        fields(item, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'))
        point(item['previousOutpoint'])
        hx(item['signatureScript'])
        need(uint(item['sequence']) == 2**64-1, 'selected-native-sequence')
        uint(item['computeBudget'], 16)
    for item in tx['outputs']:
        fields(item, ('value', 'scriptPublicKey', 'covenant'))
        need(1 <= uint(item['value']) <= MAX_VALUE and item['covenant'] is None,
             'selected-native-output')
        need(len(hx(item['scriptPublicKey'])) in (36, 37), 'selected-output-script')
    for item in case['entries']:
        fields(item, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'))
        need(1 <= uint(item['amount']) <= MAX_VALUE and item['isCoinbase'] is False
             and item['covenantId'] is None, 'selected-input-context')
        hx(item['scriptPublicKey'], 37)
        uint(item['blockDaaScore'])
    return payload


def _rpc_boundary(row):
    """Official Full decimal boundary -> exact integer-sompi native CASE."""
    tx = json.loads(json.dumps(row['transaction']))
    contexts = row['accepted_input_contexts']
    need(len(tx['inputs']) == len(contexts), 'complete-Full-input-contexts')
    for item in tx['inputs']:
        item['sequence'] = decimal(item['sequence'])
    for item in tx['outputs']:
        item['value'] = decimal(item['value'])
    for name in ('lockTime', 'gas'):
        tx[name] = decimal(tx[name])
    tx['mass'] = decimal(tx.pop('storageMass'))
    entries = []
    for item, context in zip(tx['inputs'], contexts):
        need(item['previousOutpoint'] == context['outpoint'], 'Full-context-point')
        entries.append({'amount': decimal(context['amount_sompi']),
            'scriptPublicKey': context['script_public_key'],
            'blockDaaScore': decimal(context['block_daa_score']),
            'isCoinbase': context['is_coinbase'], 'covenantId': context['covenant_id']})
    return {'transaction': tx, 'entries': entries}


def rpc_case(row):
    result = _rpc_boundary(row)
    validate_case(result)
    return result


def rpc_producer_case(row):
    """Retain the admitted head's producer; GEN3 proof admission is separate."""
    result = _rpc_boundary(row)
    payload = hx(result['transaction']['payload'])
    if len(payload) != 1648 or payload[:8] != b'KPBGN301':
        validate_case(result)
        return result
    tx=result['transaction']
    fields(result, ('transaction','entries'))
    fields(tx, ('version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','mass'))
    need(uint(tx['version'],16)==1 and uint(tx['lockTime'])==0 and uint(tx['gas'])==0
         and tx['subnetworkId']=='00'*20, 'producer-header')
    digest(tx['id']);uint(tx['mass'])
    need(len(tx['inputs'])==3 and len(result['entries'])==3 and 1<=len(tx['outputs'])<=4,
         'GEN3-producer-shape')
    for item,entry in zip(tx['inputs'],result['entries']):
        fields(item, ('previousOutpoint','signatureScript','sequence','computeBudget'))
        point(item['previousOutpoint']);hx(item['signatureScript'],66)
        need(uint(item['sequence'])==2**64-1,'producer-sequence');uint(item['computeBudget'],16)
        fields(entry, ('amount','scriptPublicKey','blockDaaScore','isCoinbase','covenantId'))
        need(0<uint(entry['amount'])<=MAX_VALUE and entry['isCoinbase'] is False
             and entry['covenantId'] is None,'producer-input-context')
        hx(entry['scriptPublicKey'],36);uint(entry['blockDaaScore'])
    for output in tx['outputs']:
        fields(output, ('value','scriptPublicKey','covenant'))
        need(0<uint(output['value'])<=MAX_VALUE and output['covenant'] is None,'producer-output')
        need(len(hx(output['scriptPublicKey'])) in (36,37),'producer-output-script')
    return result


def validate_request(value):
    fields(value, ('schema', 'nonce_hex32', 'history_key_hex32', 'attempt_id_hex32',
        'locked_binding_sha256', 'prepared_core_sha256', 'context', 'head',
        'native_policy', 'egress', 'final_candidate', 'birth_start_hash'))
    need(value['schema'] == 'kpb-live-settlement-request/v2', 'settlement-request-schema')
    for name in ('nonce_hex32', 'history_key_hex32', 'attempt_id_hex32',
                 'locked_binding_sha256', 'prepared_core_sha256', 'birth_start_hash'):
        digest(value[name])
    context = value['context']
    fields(context, ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32',
                     'service_hex32', 'epoch_hex32'))
    for item in context.values():
        digest(item)
    need(context['chain_hex32'] == GENESIS, 'selected-testnet-genesis')
    fields(value['head'], ('outpoint', 'state_hex112', 'reserve_sompi'))
    point(value['head']['outpoint'])
    state = hx(value['head']['state_hex112'], 112)
    need(state[:8] == b'KPBAST01' and state[8:40].hex() == context['domain_hex32']
         and 60000000 <= decimal(value['head']['reserve_sompi']) <= MAX_VALUE,
         'locked-new-profile-head')
    policy = value['native_policy']
    fields(policy, ('old_script_public_key_hex37', 'immutable_tail_sha256',
                    'native_parameters_sha256'))
    hx(policy['old_script_public_key_hex37'], 37)
    digest(policy['immutable_tail_sha256'])
    digest(policy['native_parameters_sha256'])
    fields(value['egress'], ('core_sha256', 'aggregate_proof_sha256',
                            'projection_sha256', 'nfs_hex32'))
    for name in ('core_sha256', 'aggregate_proof_sha256', 'projection_sha256'):
        digest(value['egress'][name])
    nfs = value['egress']['nfs_hex32']
    need(type(nfs) is list and len(nfs) == 3 and all(type(nf) is str for nf in nfs)
         and nfs == sorted(set(nfs)), 'three-sorted-distinct-NFs')
    for nf in nfs:
        digest(nf)
    need(value['prepared_core_sha256'] == value['egress']['core_sha256'],
         'prepared-egress-core-binding')
    fields(value['final_candidate'], ('case', 'canonical_case_sha256', 'r0_receipt',
        'selection_sha256', 'image_hex32', 'journal_sha256', 'native_proof_sha256'))
    record(value['final_candidate']['case'])
    record(value['final_candidate']['r0_receipt'])
    digest(value['final_candidate']['canonical_case_sha256'])
    for name in ('selection_sha256', 'image_hex32', 'journal_sha256', 'native_proof_sha256'):
        digest(value['final_candidate'][name])
    need(value['final_candidate']['selection_sha256'] == policy['native_parameters_sha256'],
         'one-final-native-parameter-selection')
    return value


def verify_candidate(request, raw_case, codec_result):
    case = parse(raw_case)
    payload = validate_case(case)
    need(sha(raw_case) == request['final_candidate']['case']['sha256']
         and canonical_case_sha256(case) == request['final_candidate']['canonical_case_sha256'],
         'exact-whole-FINAL-CANDIDATE')
    need(len(payload) == BODY_BYTES and payload[:8] == b'KPBAEF01',
         'only-private-batch-settlement-resolves')
    context = request['context']
    for offset, key in ((8, 'chain_hex32'), (40, 'pool_hex32'), (72, 'profile_hex32'),
                        (104, 'domain_hex32'), (136, 'service_hex32')):
        need(payload[offset:offset+32].hex() == context[key], 'candidate-context')
    head = request['head']
    old = b'KPBAST01' + payload[104:136] + payload[204:236] + payload[268:272] + payload[236:268] + payload[272:276]
    need(old.hex() == head['state_hex112']
         and case['transaction']['inputs'][0]['previousOutpoint'] == head['outpoint']
         and case['entries'][0]['amount'] == decimal(head['reserve_sompi'])
         and case['entries'][0]['scriptPublicKey'] == request['native_policy']['old_script_public_key_hex37'],
         'exact-locked-head-and-policy')
    frame = hx(case['transaction']['inputs'][0]['signatureScript'])
    need(len(frame) > 247 and frame[:2] == b'\x4c\x80' and frame[130] == 0x4d
         and len(frame) == 133 + int.from_bytes(frame[131:133], 'little')
         and frame[133:135] == b'\x4c\x70' and frame[135:247] == old
         and sha(frame[247:]) == request['native_policy']['immutable_tail_sha256']
         and sha(frame[2:130]) == request['final_candidate']['native_proof_sha256'],
         'actual-selected-tail-state-and-native-proof')
    # NF/CV rows start after total fee and aggregate Delta: 404, then stride96.
    nfs = sorted(payload[offset:offset+32].hex() for offset in (404, 500, 596))
    egress = request['egress']
    need(nfs == egress['nfs_hex32'] and sha(payload[:CORE_BYTES]) == egress['core_sha256']
         and sha(payload[CORE_BYTES:]) == egress['aggregate_proof_sha256'], 'exact-EGRESS-artifact')
    projection = hx(codec_result['financial_projection_hex'], PROJECTION_BYTES)
    need(codec_result['mode'] == 'payment' and codec_result['case'] == case
         and sha(projection) == egress['projection_sha256']
         and codec_result['effects_digest_hex32'] == egress['core_sha256']
         and codec_result['outer_image_hex32'] == request['final_candidate']['image_hex32'],
         'actual-native-projection-and-core')
    journal = hx(codec_result['journal_hex104'], 104)
    need(sha(journal) == request['final_candidate']['journal_sha256'], 'exact-final-journal')
    return case, projection, journal

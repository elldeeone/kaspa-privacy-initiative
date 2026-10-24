"""Narrow ordinary mined-test-KAS funding policy; no pool or key IO."""
import copy
import hashlib
import json
import re

PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
NET = 'testnet-10'
TARGET = 2_100_000_000
MATURITY = 1000
U64 = (1 << 64) - 1
PLACEHOLDER = '41' + '00' * 64 + '01'


def need(value, category):
    if not value:
        raise ValueError(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-JSON-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def fields(value, names, category):
    need(type(value) is dict and set(value) == set(names), category)


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'unsigned-integer-range')
    return value


def decimal(value):
    need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value), 'canonical-u64-decimal')
    return uint(int(value))


def hx(value, size):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value), 'lowercase-hex-width')
    return value


def selection(profile_raw, identity_raw, identity_sha):
    need(digest(profile_raw) == PROFILE_SHA and digest(identity_raw) == hx(identity_sha, 32),
         'fixed-fresh-financial-and-funding-identity')
    profile, receipt = parse(profile_raw), parse(identity_raw)
    need(profile['network_id'] == NET and profile['genesis_hash_hex'] == GENESIS
         and receipt['financial_profile_id'] == profile['financial_profile_id']
         and receipt['domain_hex32'] == profile['child_domain_hex32'], 'funding-profile-binding')
    rows = receipt['funding_wallets']
    need(type(rows) is list and len(rows) == 2, 'exact-fresh-two-funding-wallets')
    wallets = {}
    for row in rows:
        fields(row, ('address', 'role', 'script_public_key', 'xonly_hex32'), 'public-funding-wallet-fields')
        need(row['role'] in ('A', 'C') and row['role'] not in wallets, 'exact-funding-roles')
        public = hx(row['xonly_hex32'], 32)
        need(row['script_public_key'] == '000020' + public + 'ac'
             and type(row['address']) is str and row['address'].startswith('kaspatest:'),
             'ordinary-native-P2PK-testnet-wallet')
        wallets[row['role']] = row
    need(set(wallets) == {'A', 'C'} and wallets['A']['script_public_key'] != wallets['C']['script_public_key'],
         'two-distinct-fresh-funding-wallets')
    import uuid
    trial = uuid.UUID(receipt['trial_id'])
    need(trial.version == 4 and str(trial) == receipt['trial_id'], 'funding-trial-UUIDv4')
    return {'trial_id': str(trial), 'domain': bytes.fromhex(profile['child_domain_hex32']),
            'wallets': wallets, 'identity_sha256': identity_sha}


def observation(value, chosen):
    fields(value, ('schema', 'network_id', 'genesis_hash_hex', 'financial_profile_sha256',
        'funding_identity_sha256', 'trial_id', 'virtual_daa_score', 'sources'), 'observation-fields')
    need(value['schema'] == 'kpx6-ordinary-mined-funding-observation/v1'
         and value['network_id'] == NET and value['genesis_hash_hex'] == GENESIS
         and value['financial_profile_sha256'] == PROFILE_SHA
         and value['funding_identity_sha256'] == chosen['identity_sha256']
         and value['trial_id'] == chosen['trial_id'], 'observation-scope')
    daa = decimal(value['virtual_daa_score'])
    sources = value['sources']
    need(type(sources) is list and len(sources) > 0, 'nonempty-mined-sources')
    entries, points, seen = [], [], set()
    for source in sources:
        fields(source, ('outpoint', 'entry'), 'source-fields')
        point, row = source['outpoint'], source['entry']
        fields(point, ('transactionId', 'index'), 'source-outpoint-fields')
        key = (hx(point['transactionId'], 32), uint(point['index'], 32))
        need(key not in seen, 'duplicate-source-outpoint')
        seen.add(key)
        fields(row, ('amount_sompi', 'script_public_key', 'block_daa_score',
                     'is_coinbase', 'covenant_id'), 'source-entry-fields')
        amount, birth = decimal(row['amount_sompi']), decimal(row['block_daa_score'])
        need(amount > 0 and row['script_public_key'] == chosen['wallets']['A']['script_public_key']
             and row['is_coinbase'] is True and row['covenant_id'] is None,
             'only-original-A-ordinary-mined-coinbase-sources')
        need(birth <= U64 - MATURITY and daa >= birth + MATURITY, 'actual-coinbase-maturity-1000-DAA')
        points.append(copy.deepcopy(point))
        entries.append({'amount': amount, 'scriptPublicKey': row['script_public_key'],
            'blockDaaScore': birth, 'isCoinbase': True, 'covenantId': None})
    need([(p['transactionId'], p['index']) for p in points] == sorted(seen),
         'canonical-source-order')
    uint(sum(row['amount'] for row in entries))
    return points, entries, daa


def draft(points, entries, chosen, fee):
    uint(fee)
    refund = sum(row['amount'] for row in entries) - 2 * TARGET - fee
    need(refund >= 0, 'mature-mined-funds-cover-two-targets-and-exact-fee')
    outputs = [{'value': TARGET, 'scriptPublicKey': chosen['wallets'][role]['script_public_key'],
                'covenant': None} for role in ('A', 'C')]
    if refund:
        outputs.append({'value': refund, 'scriptPublicKey': chosen['wallets']['A']['script_public_key'],
                        'covenant': None})
    return {'transaction': {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': copy.deepcopy(point), 'signatureScript': PLACEHOLDER,
                    'sequence': U64, 'computeBudget': 10} for point in points],
        'outputs': outputs, 'lockTime': 0, 'subnetworkId': '00' * 20,
        'gas': 0, 'payload': '', 'mass': 0}, 'entries': copy.deepcopy(entries)}


def validate_case(case, chosen, daa, mining_mass=None, signed=False):
    fields(case, ('transaction', 'entries'), 'native-case-fields')
    tx, entries = case['transaction'], case['entries']
    fields(tx, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
                'gas', 'payload', 'mass'), 'native-transaction-fields')
    need(tx['version'] == 1 and type(tx['version']) is int and tx['lockTime'] == 0
         and tx['gas'] == 0 and tx['subnetworkId'] == '00' * 20 and tx['payload'] == '',
         'native-V1-empty-payload-only')
    uint(tx['lockTime']); uint(tx['gas']); uint(tx['mass']); hx(tx['id'], 32)
    need(type(tx['inputs']) is list and type(entries) is list
         and len(tx['inputs']) == len(entries) > 0, 'one-context-per-input')
    sources = []
    for inp, row in zip(tx['inputs'], entries):
        fields(inp, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'), 'input-fields')
        fields(row, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'), 'context-fields')
        need(type(inp['computeBudget']) is int and inp['computeBudget'] == 10
             and uint(inp['sequence']) == U64, 'fixed-budget10-and-sequence')
        ss = hx(inp['signatureScript'], 66)
        need(ss.startswith('41') and ss.endswith('01') and (not signed or ss != PLACEHOLDER),
             'ordinary-ALL-signature-shape')
        uint(row['amount']); uint(row['blockDaaScore'])
        sources.append({'outpoint': inp['previousOutpoint'], 'entry': {
            'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
            'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': row['isCoinbase'],
            'covenant_id': row['covenantId']}})
    observation({'schema': 'kpx6-ordinary-mined-funding-observation/v1', 'network_id': NET,
        'genesis_hash_hex': GENESIS, 'financial_profile_sha256': PROFILE_SHA,
        'funding_identity_sha256': chosen['identity_sha256'], 'trial_id': chosen['trial_id'],
        'virtual_daa_score': str(uint(daa)), 'sources': sources}, chosen)
    outputs = tx['outputs']
    need(type(outputs) is list and len(outputs) in (2, 3), 'two-targets-and-optional-own-refund')
    for index, row in enumerate(outputs):
        fields(row, ('value', 'scriptPublicKey', 'covenant'), 'output-fields')
        need(uint(row['value']) > 0 and row['covenant'] is None, 'positive-ordinary-output')
        expected_role = 'C' if index == 1 else 'A'
        need(row['scriptPublicKey'] == chosen['wallets'][expected_role]['script_public_key'],
             'only-exact-fresh-A-C-and-own-refund-destinations')
        if index < 2:
            need(row['value'] == TARGET, 'exact21KAS-per-funder')
    source_sum, output_sum = sum(r['amount'] for r in entries), sum(r['value'] for r in outputs)
    uint(source_sum); uint(output_sum)
    need(source_sum >= output_sum, 'ordinary-value-conservation')
    fee = source_sum - output_sum
    if mining_mass is not None:
        uint(mining_mass)
        need(mining_mass > 0 and mining_mass <= U64 // 100 and fee == 100 * mining_mass,
             'exact-reference100-native-mining-fee')
    return fee


def sdk_body(case):
    body = copy.deepcopy(case['transaction'])
    for row in body['inputs']:
        row['sequence'] = str(row['sequence'])
    for row in body['outputs']:
        row['value'] = str(row['value'])
    body['lockTime'], body['gas'] = str(body['lockTime']), str(body['gas'])
    body['storageMass'] = str(body.pop('mass'))
    contexts = [{'amount_sompi': str(r['amount']), 'script_public_key': r['scriptPublicKey'],
        'block_daa_score': str(r['blockDaaScore']), 'is_coinbase': r['isCoinbase'],
        'covenant_id': r['covenantId']} for r in case['entries']]
    return body, contexts

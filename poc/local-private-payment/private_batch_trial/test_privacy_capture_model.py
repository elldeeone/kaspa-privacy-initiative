"""Public fixtures for typed complete observer-capture adapters."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

import privacy_capture_model as capture
import privacy_codec as codec
import privacy_fd40_structural as fd40
import privacy_observer as observer


COHORT = '22' * 32
ATTEMPT = 'capture-attempt-01'
PUBLIC_CV_HEX = (
    '25e7c480a7887fd76dc66a0076d64715c178cf77de4c4415601beb3127fed60f6cd9755831a01934fd925c095a0d28d2c5883e77b4f4c151a8647f54b65bcc05',
    'cdd338b1fb08c059b7af8ed11bdcd653e27554f8af3ef759f393bb50d436c20f4bba9484436da67f7edaa3857e38a2b95e09616abb024e8bc02ee6283ef4390d',
    '16c63f26a817f08b0e315169eb71b21c5b2763144b7a5933c9cabda411a56a23c9de0816535bad6d5b7f98f78f62473437a38097dedc99480747750e3389b42a',
    'c62ab7590c60f979d63ac587a3a8cfd56efee605391a5c1c383564b477ffd11bf94278c493823d2aee8b2a88f9f1b3fc0b70b45fe36d1df6e0d525df13af1510',
    '31d703d6e1aec6861f0b22e5714bdf97b241b09e791a474e848726d6ebebad0da3ad288e0b0cc17f6382887a0955aef6eedfdb464a7247d8fb1f5a2da9988d0a',
    'd348e57b71a445ef9e6772de6d4a10aaed8a20ca4962d004e9c57c10c682a9069706bc76b5799be8c9eb47ac75a3193186bc3804248b6c9df6273529d3cc2b09',
    '638aba257959822f613dac2a7a09e9fabb8423e50bdfc2040cf86f76e9923b2bd2c0c7a7dd24cca60f3e53a1c2dcaa0d65d221fd2391a38e8fa6e015705e1228',
    'a932ccea217d535b9c330a3e05f10eb283a10221109b2ddccc16ee7da03149204d7c3eea5a96176f7fae7913eea902e657483d2947b52df3ffaf7e3eaaf8951d',
    '8011dfe6775d7b9ed12ef77d13d73df7b6e9dab18593012a39eed81ca1811029eaff2d478a9c8143d4011a9f79c36cbf53baf05c6d7448b94dd84a8c3f32f30e',
)


def closure(records, payload_bytes, cohort=COHORT, attempt=ATTEMPT):
    stream_counts = {}
    for record in records:
        stream_counts[record['stream']] = stream_counts.get(record['stream'], 0) + 1
    return {'schema': 'kpb-capture-source-closure/v1',
        'attempt_id': attempt, 'cohort_sha256': cohort,
        'producer_record_count': len(records),
        'capture_record_count': len(records),
        'producer_payload_bytes': payload_bytes,
        'capture_payload_bytes': payload_bytes,
        'producer_stream_counts': stream_counts,
        'capture_stream_counts': stream_counts,
        'record_chain_sha256': hashlib.sha256(codec.encoded(records)).hexdigest(),
        'unknown_record_count': 0, 'capture_root_closed': True,
        'producer_fd_closed': True}


def projection(round_number):
    body = bytearray(10492); body[:8] = b'KPBAEF01'
    for index in range(5):
        body[8 + 32 * index:40 + 32 * index] = hashlib.sha256(
            b'capture-context' + bytes([round_number, index])).digest()
    point = hashlib.sha256(b'capture-point' + bytes([round_number])).digest() \
        + (round_number + 1).to_bytes(4, 'little')
    body[168:204] = point
    body[204:236] = hashlib.sha256(b'old-cm' + bytes([round_number])).digest()
    body[236:268] = hashlib.sha256(b'old-nf' + bytes([round_number])).digest()
    body[268:272] = (3).to_bytes(4, 'little')
    body[272:276] = (1).to_bytes(4, 'little')
    body[276:284] = (6_000_000_000).to_bytes(8, 'little')
    body[284:316] = hashlib.sha256(b'new-cm' + bytes([round_number])).digest()
    body[316:348] = hashlib.sha256(b'new-nf' + bytes([round_number])).digest()
    body[348:352] = (9).to_bytes(4, 'little')
    body[352:356] = (4).to_bytes(4, 'little')
    body[356:364] = (5_970_000_000).to_bytes(8, 'little')
    body[364:372] = (30_000_000).to_bytes(8, 'little')
    body[372:404] = (330).to_bytes(32, 'little')
    for index in range(3):
        nf = (100 * round_number + index + 1).to_bytes(32, 'little')
        body[404 + 96 * index:436 + 96 * index] = nf
        body[436 + 96 * index:500 + 96 * index] = bytes.fromhex(
            PUBLIC_CV_HEX[index])
    for index in range(6):
        cm = hashlib.sha256(b'capture-cm' + bytes([round_number, index])).digest()
        cv = bytes.fromhex(PUBLIC_CV_HEX[3 + index])
        ciphertext = bytes([1 + index]) * 264
        proof = hashlib.sha512(
            b'capture-output-proof' + bytes([round_number, index])).digest() * 2
        row = cm + cv + ciphertext + hashlib.sha256(ciphertext).digest() + proof
        assert len(row) == 520
        body[692 + 520 * index:692 + 520 * (index + 1)] = row
    body[3812:7292] = bytes([31 + round_number]) * 3480
    body[7292:10364] = bytes([41 + round_number]) * 3072
    # All-zero proof bytes are deliberately legal at this parsing layer; the
    # full evaluator, not this inventory adapter, decides proof validity.
    body[10364:10492] = bytes(128)
    script = bytes((0, 0, 0xaa, 0x20)) + bytes([77 + round_number]) * 32 \
        + bytes((0x87,))
    prefix = bytearray(193); prefix[:12] = b'KPBAFX01\x01\0\x01\0'
    prefix[12:48] = point; prefix[48:56] = bytes([255]) * 8
    prefix[56:64] = (6_000_000_000).to_bytes(8, 'little')
    prefix[64:66] = (37).to_bytes(2, 'little'); prefix[66:103] = script
    prefix[103:105] = (1).to_bytes(2, 'little')
    prefix[105:113] = (5_970_000_000).to_bytes(8, 'little')
    prefix[113:115] = (37).to_bytes(2, 'little'); prefix[115:152] = script
    prefix[189:193] = (10492).to_bytes(4, 'little')
    result = bytes(prefix + body)
    return result, observer.batch_from_projection(round_number, result)


def continuous_projection_pair():
    first_raw, _ = projection(1)
    second_raw, _ = projection(2)
    first = bytearray(first_raw); second = bytearray(second_raw)
    body = 193
    # Native structural evidence requires each round's old and successor
    # scripts to differ.  The next round then consumes the exact predecessor
    # successor script.
    first[115:152] = (bytes((0, 0, 0xaa, 0x20)) + bytes([0x91]) * 32
                      + bytes((0x87,)))
    second[body + 8:body + 168] = first[body + 8:body + 168]
    second[66:103] = first[115:152]
    second[body + 204:body + 236] = first[body + 284:body + 316]
    second[body + 236:body + 268] = first[body + 316:body + 348]
    second[body + 268:body + 276] = first[body + 348:body + 356]
    old_cm = int.from_bytes(second[body + 268:body + 272], 'little')
    old_nf = int.from_bytes(second[body + 272:body + 276], 'little')
    second[body + 348:body + 352] = (old_cm + 6).to_bytes(4, 'little')
    second[body + 352:body + 356] = (old_nf + 3).to_bytes(4, 'little')
    next_reserve = int.from_bytes(first[105:113], 'little')
    next_fee = int.from_bytes(second[body + 364:body + 372], 'little')
    second[56:64] = second[body + 276:body + 284] = \
        next_reserve.to_bytes(8, 'little')
    second[105:113] = second[body + 356:body + 364] = \
        (next_reserve - next_fee).to_bytes(8, 'little')
    first_raw, second_raw = bytes(first), bytes(second)
    return ([first_raw, second_raw],
            [observer.batch_from_projection(1, first_raw),
             observer.batch_from_projection(2, second_raw)])


def fd40_structural_prefix(raws, publics, classification=1):
    """Build the exact grammar as a non-authorizing parser fixture."""
    counter = 0
    def digest(label):
        nonlocal counter
        counter += 1
        return hashlib.sha256(
            label.encode() + counter.to_bytes(4, 'little')).digest()

    binding = bytearray((classification,))
    for _ in range(10):
        binding.extend(digest('binding'))
    binding.extend(digest('manifest'))
    binding.extend(digest('manifest-parent'))
    for _ in range(6):
        binding.extend(digest('binding'))
    for component in range(1, 11):
        binding.append(component)
        for _ in range(6):
            binding.extend(digest('manifest-entry'))
    for _ in range(3 * 6):
        binding.extend(digest('worker'))
    for name in ('financial', 'attempt', 'cohort', 'capture-plan'):
        binding.extend(digest(name + '-1'))
        binding.extend(digest(name + '-2'))
    for public in publics:
        binding.extend(bytes.fromhex(public['projection_sha256']))
    assert len(binding) == fd40.RUN_BINDING_BYTES

    shared_head = digest('shared-successor-head')
    round_values = []
    for index, raw_value in enumerate(raws):
        lineage = {name: digest(name + '-' + str(index + 1))
                   for name in fd40.LINEAGE_FIELDS}
        lineage['projection'] = hashlib.sha256(raw_value).digest()
        if index == 0:
            lineage['successor_head'] = shared_head
        else:
            lineage['accepted_input_head'] = shared_head
        lineage['producer_stream_process'] = lineage['stream_process']
        lineage['producer_stream_child_exit'] = \
            lineage['stream_child_exit']
        round_values.append({
            'lineage': lineage,
            'structural': fd40.structural_projection_evidence(raw_value),
        })

    identity_preimage = (
        b'KPB_STRUCTURAL_PROJECTION_CONTINUITY_AUTHORITY_V1\n'
        + bytes(binding) + bytes((classification,)))
    for value in round_values:
        identity_preimage += b''.join(
            value['lineage'][name] for name in fd40.LINEAGE_FIELDS)
        identity_preimage += value['structural'][
            'structural_projection_identity']
    identity_preimage += bytes((1, 0))
    continuity_identity = hashlib.sha256(identity_preimage).digest()

    section = bytearray(fd40.STRUCTURAL_MAGIC)
    section.extend(fd40.STRUCTURAL_VERSION.to_bytes(4, 'little'))
    section.extend(fd40.STRUCTURAL_BYTES.to_bytes(4, 'little'))
    section.extend(bytes((classification, 1, 0, 2)))
    section.extend(continuity_identity)
    for value in round_values:
        section.extend(b''.join(
            value['lineage'][name] for name in fd40.LINEAGE_FIELDS))
        section.extend(b''.join(
            value['structural'][name]
            for name in fd40.STRUCTURAL_DIGEST_FIELDS))
        for name in fd40.COUNT_FIELDS:
            section.extend(value['structural'][name].to_bytes(4, 'little'))
        for name in fd40.SOMPI_FIELDS:
            section.extend(value['structural'][name].to_bytes(8, 'little'))
    assert len(section) == fd40.STRUCTURAL_BYTES

    prefix = bytearray([0x55]) * fd40.PREFIX_BYTES
    prefix[:8] = fd40.CAPSULE_MAGIC
    prefix[8:12] = fd40.CAPSULE_VERSION.to_bytes(4, 'little')
    prefix[fd40.RUN_BINDING_OFFSET:
           fd40.RUN_BINDING_OFFSET + fd40.RUN_BINDING_BYTES] = binding
    prefix[fd40.STRUCTURAL_OFFSET:fd40.STRUCTURAL_END] = section
    prefix[fd40.LEAF_COUNT_OFFSET] = 10
    return bytes(prefix)


def fd40_run_binding_known_vector():
    value = bytearray((1,))
    seed = 1
    def add_digest():
        nonlocal seed
        value.extend(bytes((seed + 17 * index) & 0xff
                           for index in range(32)))
        seed += 1
    for _ in range(10):
        add_digest()
    add_digest(); add_digest()
    for _ in range(6):
        add_digest()
    for component in range(1, 11):
        value.append(component)
        for _ in range(6):
            add_digest()
    for _ in range(3 * 6 + 5 * 2):
        add_digest()
    assert seed == 107 and len(value) == fd40.RUN_BINDING_BYTES
    return bytes(value)


def c03_with_projection(wire, projection_bytes):
    """Replace only the exact semantic-9 data/end projection payloads."""
    result = bytearray(); cursor = 0
    while cursor < len(wire):
        header = bytearray(wire[cursor:cursor + 112])
        assert len(header) == 112 and header[:8] == b'KPBP1C03'
        size = int.from_bytes(header[44:48], 'big')
        payload = wire[cursor + 112:cursor + 112 + size]
        record_type, semantic = header[8], header[9]
        if semantic == 9 and record_type == 2 and size == 10685:
            payload = projection_bytes
        elif semantic == 9 and record_type == 3 and size == 32:
            payload = hashlib.sha256(projection_bytes).digest()
        header[80:112] = hashlib.sha256(payload).digest()
        result.extend(header); result.extend(payload)
        cursor += 112 + size
    assert cursor == len(wire)
    return bytes(result)


def dispatcher_fixture(public, *, cohort_sha256=COHORT,
                       run_sha256='41' * 32,
                       construction_attempt_sha256='43' * 32,
                       capture_plan_sha256='44' * 32):
    events = []
    def add(kind, owner, role, size=0, filename=None, public_sha=None,
            route_sha=None):
        events.append({'sequence': len(events), 'kind': kind,
            'owner_component': owner, 'role': role,
            'monotonic_ns': 100 + len(events), 'bytes': size,
            'filename': filename, 'public_sha256': public_sha,
            'route_sha256': route_sha, 'outcome': 'ok'})
    add('listeners-ready', None, 'server-roster')
    for owner in codec.OWNERS:
        add('owner-connected', owner, 'C' + str(owner))
        add('owner-upload-complete', owner, 'C' + str(owner), 84_333_120,
            'OWNER-PRIVATE-INPUT-V2.bin')
    add('aggregate-release', None, 'controller', 10685,
        'released-projection.bin', public['projection_sha256'])
    policy_preimage = capture._release_policy_preimage(
        public['round'], 1, 'SECRET_PERMUTATION_INDEPENDENT', 0,
        run_sha256, construction_attempt_sha256, cohort_sha256,
        capture_plan_sha256, public['projection_sha256'], '00' * 32)
    add('release-policy-bound', None, 'controller', len(policy_preimage),
        'RELEASE-ORDER-POLICY-V1.bin',
        hashlib.sha256(policy_preimage).hexdigest())
    events[-1]['monotonic_ns'] = events[-2]['monotonic_ns']
    add('outbound-route', None, 'controller', 10685,
        'released-projection.bin', public['projection_sha256'], '11' * 32)
    events[-1]['monotonic_ns'] = events[-2]['monotonic_ns'] + 1
    records = [{'stream': 'event', 'value': event} for event in events]
    return {'schema': 'kpb-dispatcher-observer-capture/v1',
        'round': public['round'],
        'projection_sha256': public['projection_sha256'],
        'cohort_sha256': cohort_sha256,
        'run_sha256': run_sha256,
        'construction_attempt_sha256': construction_attempt_sha256,
        'capture_plan_sha256': capture_plan_sha256,
        'construction_classification': 1,
        'release_order_policy': 'SECRET_PERMUTATION_INDEPENDENT',
        'direct_exports': [], 'events': events, 'retry_history': [],
        'closure': closure(records, sum(event['bytes'] for event in events),
                           cohort=cohort_sha256)}


def explicit_dispatcher_fixture(public, **bindings):
    value = dispatcher_fixture(public, **bindings)
    value['construction_classification'] = 2
    value['release_order_policy'] = 'EXPLICIT_OWNER_PUBLIC_EFFECTS'
    common = {
        'run_sha256': value['run_sha256'],
        'trial_sha256': '42' * 32,
        'attempt_sha256': value['construction_attempt_sha256'],
        'cohort_sha256': value['cohort_sha256'],
        'capture_plan_sha256': value['capture_plan_sha256'],
        'projection_sha256': public['projection_sha256'],
        'context_sha256': '45' * 32,
    }
    value['direct_exports'] = [{
        'owner_component': owner,
        'owner_contract_sha256': ('%02x' % (80 + owner)) * 32,
        'nf_hex32': public['nfs_hex32'][owner],
        'tuple_sha256': sorted(
            public['tuple_sha256'][2 * owner:2 * owner + 2]),
        **common,
    } for owner in codec.OWNERS]
    preimage = capture._explicit_owner_effects_preimage(
        public['round'], value['direct_exports'])
    policy_index = next(index for index, event in enumerate(value['events'])
                        if event['kind'] == 'release-policy-bound')
    value['events'].insert(policy_index, {
        'sequence': policy_index,
        'kind': 'explicit-owner-public-effects',
        'owner_component': None,
        'role': 'controller',
        'monotonic_ns': 100 + policy_index,
        'bytes': len(preimage),
        'filename': 'EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin',
        'public_sha256': hashlib.sha256(preimage).hexdigest(),
        'route_sha256': None,
        'outcome': 'ok',
    })
    policy_event = next(event for event in value['events']
                        if event['kind'] == 'release-policy-bound')
    policy_preimage = capture._release_policy_preimage(
        public['round'], 2, value['release_order_policy'], 3,
        value['run_sha256'], value['construction_attempt_sha256'],
        value['cohort_sha256'], value['capture_plan_sha256'],
        value['projection_sha256'], hashlib.sha256(preimage).hexdigest())
    policy_event['public_sha256'] = hashlib.sha256(
        policy_preimage).hexdigest()
    for sequence, event in enumerate(value['events']):
        event['sequence'] = sequence
        event['monotonic_ns'] = 100 + sequence
    policy_event['monotonic_ns'] = next(
        event['monotonic_ns'] for event in value['events']
        if event['kind'] == 'explicit-owner-public-effects')
    records = [{'stream': 'event', 'value': event}
               for event in value['events']]
    value['closure'] = closure(
        records, sum(event['bytes'] for event in value['events']))
    return value


def dispatcher_source_authority(value):
    value_raw = raw(value)
    return capture._test_only_mint_dispatcher_policy_source_authority({
        'artifact_sha256': hashlib.sha256(value_raw).hexdigest(),
        'round': value['round'],
        'projection_sha256': value['projection_sha256'],
        'cohort_sha256': value['cohort_sha256'],
        'run_sha256': value['run_sha256'],
        'construction_attempt_sha256':
            value['construction_attempt_sha256'],
        'capture_plan_sha256': value['capture_plan_sha256'],
        'construction_classification':
            value['construction_classification'],
        'release_order_policy': value['release_order_policy'],
        'source_identity': '91' * 32,
        'build_identity': '92' * 32,
        'runtime_identity': '93' * 32,
        'launcher_identity': '94' * 32,
        'process_identity': '95' * 32,
        'child_exit_identity': '96' * 32,
        'producer_closure_authority_identity': '97' * 32,
    })


def corrupt_fixture(public, projection_bytes):
    records = []
    def add(channel, phase, owner, semantic, encoding, payload):
        records.append({'sequence': len(records), 'channel': channel,
            'phase': phase, 'owner_component': owner, 'semantic': semantic,
            'encoding': encoding, 'payload_hex': payload.hex()})
    for owner in codec.OWNERS:
        add('owner-tls', 'preprocessing', owner,
            'owner-input-preprocessing-share', 'fr32le',
            b''.join((owner * 5 + index + 1).to_bytes(32, 'little')
                     for index in range(5)))
        add('owner-tls', 'intake', owner, 'owner-input-offset', 'fr32le',
            (owner + 7).to_bytes(32, 'little'))
    add('peer', 'preprocessing', None, 'mascot-message', 'bytes', b'MASCOT')
    add('local', 'setup', None, 'mac-key-share', 'fr32le',
        (29).to_bytes(32, 'little'))
    add('local', 'trace', None, 'authenticated-share', 'fr32le',
        (31).to_bytes(32, 'little'))
    add('local', 'validation', None, 'mac-share', 'fr32le',
        (37).to_bytes(32, 'little'))
    add('local', 'trace', None, 'randomness-share', 'fr32le',
        (41).to_bytes(32, 'little'))
    add('local', 'trace', None, 'randomness-mac', 'fr32le',
        (43).to_bytes(32, 'little'))
    add('local', 'proof', None, 'field-opening', 'fr32le',
        (47).to_bytes(32, 'little'))
    add('local', 'proof', None, 'masked-field-intermediate', 'fr32le',
        (53).to_bytes(32, 'little') + (59).to_bytes(32, 'little'))
    add('local', 'proof', None, 'masked-g1-intermediate', 'g1-65',
        bytes([61]) * 130)
    add('local', 'proof', None, 'final-proof-g1', 'g1-65',
        bytes([67]) * 130)
    add('local', 'proof', None, 'final-proof-g2', 'g2-129',
        bytes([71]) * 129)
    add('local', 'release', None, 'public-projection', 'bytes',
        projection_bytes)
    closure_records = [{'stream': row['semantic'], 'value': row}
                       for row in records]
    payload_bytes = sum(len(bytes.fromhex(row['payload_hex']))
                        for row in records)
    value = {'schema': 'kpb-corrupt-server-observer-capture/v1',
        'round': public['round'],
        'projection_sha256': public['projection_sha256'],
        'cohort_sha256': COHORT,
        'server_component': 1, 'protocol_source_sha256': '33' * 32,
        'build_policy': {'corruption_model': 'ONE_SERVER_PLUS_OWNER1',
            'insecure': False, 'debug_mac': False, 'print_mac': False,
            'no_client_tls': False}, 'records': records,
        'closure': closure(closure_records, payload_bytes)}
    return add_authenticated_group_states(value)


def add_authenticated_group_states(value):
    """Add the selected v8 local AuthG state transcript to a JSON fixture."""
    def point(byte, size):
        return bytes([1]) + b''.join(
            (byte + index).to_bytes(32, 'little')
            for index in range((size - 1) // 32))

    def g1(byte):
        return point(byte, 65) + point(byte + 2, 65)

    def g2(byte):
        return point(byte, 129) + point(byte + 4, 129)

    a, b1, l_value, h_value = (g1(byte) for byte in (80, 82, 84, 86))
    mixed = [g1(byte) for byte in (88, 90, 92, 94, 96, 98)]
    products = [g1(100), g1(102)]
    c_value = g1(104)
    b2 = g2(106)

    def record(semantic, encoding, payload):
        return {'sequence': 0, 'channel': 'local', 'phase': 'proof',
                'owner_component': None, 'semantic': semantic,
                'encoding': encoding, 'payload_hex': payload.hex()}

    states = [
        record('authenticated-g1-state', 'g1-share-mac',
               bytes([1]) + b''.join((a, b1, l_value, h_value))),
        record('authenticated-g2-state', 'g2-share-mac',
               bytes([1]) + b2),
        record('authenticated-g1-state', 'g1-share-mac',
               bytes([2]) + b''.join(mixed)),
        record('authenticated-g1-state', 'g1-share-mac',
               bytes([3]) + b''.join(products)),
        record('authenticated-g1-state', 'g1-share-mac',
               bytes([4]) + a + c_value),
        record('authenticated-g2-state', 'g2-share-mac',
               bytes([4]) + b2),
    ]
    first_opening = next(index for index, row in enumerate(value['records'])
                         if row['semantic'] ==
                         'masked-field-intermediate')
    final_opening = next(index for index, row in enumerate(value['records'])
                         if row['semantic'] == 'final-proof-g1')
    value['records'][first_opening:first_opening] = states[:3]
    value['records'][final_opening + 3:final_opening + 3] = states[3:]
    for sequence, row in enumerate(value['records']):
        row['sequence'] = sequence
    closure_records = [{'stream': row['semantic'], 'value': row}
                       for row in value['records']]
    value['closure'] = closure(
        closure_records,
        sum(len(bytes.fromhex(row['payload_hex']))
            for row in value['records']))
    return value


def colluder_fixture(public):
    incoming = (1 - public['round']) % 3
    outgoing = (1 + public['round']) % 3
    original = {'input_nf_hex32': public['nfs_hex32'][1],
        'input_amount_sompi': 100_000_000,
        'created_outputs': [
            {'kind': 'outgoing-payment',
             'tuple_sha256': public['tuple_sha256'][2],
             'amount_sompi': 30_000_000},
            {'kind': 'change', 'tuple_sha256': public['tuple_sha256'][3],
             'amount_sompi': 69_000_000}]}
    invoices = [
        {'direction': 'issued', 'source_owner_component': incoming,
         'target_owner_component': 1, 'operation_id_sha256': '66' * 32,
         'amount_sompi': 25_000_000},
        {'direction': 'accepted', 'source_owner_component': 1,
         'target_owner_component': outgoing,
         'operation_id_sha256': '66' * 32,
         'amount_sompi': 30_000_000},
    ]
    receipts = [
        {'kind': 'incoming-payment',
         'receipt_index': 2 * public['round'] - 1,
         'creator_owner_component': incoming,
         'tuple_sha256': public['tuple_sha256'][0],
         'cm_hex32': public['cms_hex32'][0],
         'amount_sompi': 25_000_000},
        {'kind': 'change', 'receipt_index': 2 * public['round'],
         'creator_owner_component': 1,
         'tuple_sha256': public['tuple_sha256'][3],
         'cm_hex32': public['cms_hex32'][3],
         'amount_sompi': 69_000_000},
    ]
    def observed(stage, stage_sequence, operation, contact, sequence,
                 monotonic_ns, value):
        return {'source': {
            'observer_stage': stage,
            'stage_sequence': stage_sequence,
            'operation_id_sha256': operation,
            'contact_owner_component': contact,
            'contact_binding_qualified': False,
            'source_event_sequence': sequence,
            'observed_monotonic_ns': monotonic_ns,
        }, 'value': value}
    original_observed = observed(
        'pay', 1, '88' * 32, outgoing, 1, 201, original)
    invoice_observed = [
        # The issuing stage operation is also the operation authenticated in
        # the issued invoice body.  Pay and scan retain their distinct stage
        # operations even though the accepted invoice refers back to issue.
        observed('invoice', 0, '66' * 32, incoming, 0, 100,
                 invoices[0]),
        observed('pay', 1, '88' * 32, outgoing, 0, 200, invoices[1]),
    ]
    receipt_observed = [
        observed('scan', 2, '99' * 32, incoming, 0, 300, receipts[0]),
        observed('scan', 2, '99' * 32, incoming, 1, 301, receipts[1]),
    ]
    records = ([{'stream': 'original', **original_observed}]
        + [{'stream': 'invoice', **row} for row in invoice_observed]
        + [{'stream': 'decrypted-receipt', **row}
           for row in receipt_observed])
    return {'schema': 'kpb-colluder-wallet-observer-capture/v1',
        'round': public['round'],
        'projection_sha256': public['projection_sha256'],
        'cohort_sha256': COHORT, 'owner_component': 1,
        'original': original_observed, 'invoices': invoice_observed,
        'decrypted_receipts': receipt_observed, 'retry_history': [],
        'closure': closure(
            records, sum(len(codec.encoded(row['value'])) for row in records))}


def qualified_colluder_fixture(public, *, cohort_sha256=None,
                               attempt_id=None, contact_authority=None):
    """Synthetic exact-v2 leaf; authority is minted separately in the test."""
    value = colluder_fixture(public)
    value['schema'] = 'kpb-colluder-wallet-observer-capture/v2'
    round_number = public['round']
    value['cohort_sha256'] = (cohort_sha256 or hashlib.sha256(
        b'c1-qualified-cohort' + bytes([round_number])).hexdigest())
    attempt_id = (attempt_id or
                  '00000000-0000-4000-8000-00000000000' +
                  str(round_number))
    frozen_amount = 500_000_000 if round_number == 1 else 200_000_000
    value['original']['value']['input_amount_sompi'] = 1_000_000_000
    value['original']['value']['created_outputs'][0][
        'amount_sompi'] = frozen_amount
    for row in value['invoices']:
        row['value']['amount_sompi'] = frozen_amount
    value['decrypted_receipts'][0]['value'][
        'amount_sompi'] = frozen_amount
    operation_words = {
        1: ('66' * 32, '88' * 32, '99' * 32),
        2: ('67' * 32, '89' * 32, '9a' * 32),
    }[round_number]
    for row in ([value['original']] + value['invoices']
                + value['decrypted_receipts']):
        stage = row['source']['observer_stage']
        row['source']['operation_id_sha256'] = operation_words[
            ('invoice', 'pay', 'scan').index(stage)]
    value['invoices'][0]['value']['operation_id_sha256'] = operation_words[0]
    value['invoices'][1]['value']['operation_id_sha256'] = operation_words[0]
    authority = (contact_authority or hashlib.sha256(
        b'c1-contact-value-authority' +
        bytes([public['round']])).hexdigest())
    value['contact_value_authority_sha256'] = authority
    stages = ('invoice', 'pay', 'scan')
    stage_configs = {
        stage: hashlib.sha256(
            b'c1-stage-config' + bytes([public['round'], index])).hexdigest()
        for index, stage in enumerate(stages)
    }
    kinds = {
        ('original', None): 'ORIGINAL',
        ('invoice', 'issued'): 'ISSUED_INVOICE',
        ('invoice', 'accepted'): 'ACCEPTED_INVOICE',
        ('decrypted-receipt', 'incoming-payment'): 'INCOMING_RECEIPT',
        ('decrypted-receipt', 'change'): 'CHANGE_RECEIPT',
    }
    rows = ([('original', value['original'])]
            + [('invoice', row) for row in value['invoices']]
            + [('decrypted-receipt', row)
               for row in value['decrypted_receipts']])
    for stream, row in rows:
        body = row['value']; source = row['source']
        discriminator = (body.get('direction') if stream == 'invoice'
                         else body.get('kind')
                         if stream == 'decrypted-receipt' else None)
        source.update({
            'schema': 'kpb-c1-authenticated-contact-value-source/v1',
            'contact_binding_qualified': True,
            'value_binding_qualified': True,
            'value_kind': kinds[(stream, discriminator)],
            'value_sha256': hashlib.sha256(codec.encoded(body)).hexdigest(),
            'stage_config_sha256': stage_configs[source['observer_stage']],
            'contact_value_authority_sha256': authority,
        })
        preimage = {
            'schema': 'kpb-c1-contact-value-event-binding/v1',
            'contact_value_authority_sha256': authority,
            'stage_config_sha256': source['stage_config_sha256'],
            'observer_stage': source['observer_stage'],
            'stage_sequence': source['stage_sequence'],
            'operation_id_sha256': source['operation_id_sha256'],
            'contact_owner_component': source['contact_owner_component'],
            'source_event_sequence': source['source_event_sequence'],
            'observed_monotonic_ns': source['observed_monotonic_ns'],
            'stream': stream,
            'value_kind': source['value_kind'],
            'value_sha256': source['value_sha256'],
        }
        source['source_event_binding_sha256'] = hashlib.sha256(
            b'KPB_C1_CONTACT_VALUE_EVENT_V1\n'
            + codec.encoded(preimage)).hexdigest()
    records = ([{'stream': 'original', **value['original']}]
        + [{'stream': 'invoice', **row} for row in value['invoices']]
        + [{'stream': 'decrypted-receipt', **row}
           for row in value['decrypted_receipts']])
    value['closure'] = closure(
        records, sum(len(codec.encoded(row['value'])) for row in records),
        cohort=value['cohort_sha256'], attempt=attempt_id)
    return value


def c1_contact_value_source_authority(value, *, role_closure='d0' * 32,
                                      process=None, child_exit=None):
    round_number = value['round']
    by_stage = {}
    for row in ([value['original']] + value['invoices']
                + value['decrypted_receipts']):
        source = row['source']
        by_stage.setdefault(source['observer_stage'], source)
    digest = lambda label: hashlib.sha256(
        label + bytes([round_number])).hexdigest()
    binding = {
        'artifact_sha256': hashlib.sha256(raw(value)).hexdigest(),
        'capture_identity_sha256': 'e1' * 32,
        'financial_run_sha256': digest(b'c1-financial-run'),
        'round_attempt_sha256': hashlib.sha256(
            b'KPB_CAPTURE_ATTEMPT_ID_V1\n'
            + value['closure']['attempt_id'].encode()).hexdigest(),
        'round_cohort_sha256': value['cohort_sha256'],
        'round_capture_plan_sha256': digest(b'c1-capture-plan'),
        'round_projection_sha256': value['projection_sha256'],
        'source_closure_sha256': role_closure,
        'role_closure_sha256': role_closure,
        'round': round_number,
        'attempt_id': value['closure']['attempt_id'],
        'fixed_fd': {1: 24, 2: 29}[round_number],
        'contact_value_authority_sha256':
            value['contact_value_authority_sha256'],
        'contact_owner_components': [
            by_stage[stage]['contact_owner_component']
            for stage in ('invoice', 'pay', 'scan')],
        'operation_id_sha256': [
            by_stage[stage]['operation_id_sha256']
            for stage in ('invoice', 'pay', 'scan')],
        'stage_config_sha256': [
            by_stage[stage]['stage_config_sha256']
            for stage in ('invoice', 'pay', 'scan')],
        'source_sha256': digest(b'c1-source'),
        'build_sha256': digest(b'c1-build'),
        'runtime_sha256': digest(b'c1-runtime'),
        'assets_sha256': digest(b'c1-assets'),
        'pinned_executable_sha256': digest(b'c1-pinned-executable'),
        'launcher_sha256': digest(b'c1-launcher'),
        'role_launch_sha256': role_closure,
        'route_manifest_sha256': digest(b'c1-route-manifest'),
        'route_source_sha256': digest(b'c1-route-source'),
        'stage_plan_sha256': digest(b'c1-stage-plan'),
        'process_sha256': process or digest(b'c1-process'),
        'child_exit_sha256': child_exit or digest(b'c1-child-exit'),
        'producer_closure_authority_sha256': 'e2' * 32,
    }
    return capture._test_only_mint_c1_contact_value_source_authority(binding)


def terminal_fixture(public, transparent=False):
    events = [
        {'sequence': 0, 'kind': 'candidate-constructed', 'monotonic_ns': 10,
         'candidate_sha256': '44' * 32, 'transaction_id_hex32': None,
         'outcome': 'ok'},
        {'sequence': 1, 'kind': 'native-full', 'monotonic_ns': 11,
         'candidate_sha256': '44' * 32, 'transaction_id_hex32': None,
         'outcome': 'ok'},
        {'sequence': 2, 'kind': 'trial-closed', 'monotonic_ns': 12,
         'candidate_sha256': '44' * 32, 'transaction_id_hex32': None,
         'outcome': 'ok'},
    ]
    if transparent:
        groups = [{'group_id_sha256': ('%02x' % (80 + owner)) * 32,
            'owner_component': owner,
            'nfs_hex32': [public['nfs_hex32'][owner]],
            'tuple_sha256': public['tuple_sha256'][2 * owner:2 * owner + 2]}
            for owner in codec.OWNERS]
    else:
        groups = [{'group_id_sha256': '55' * 32, 'owner_component': None,
            'nfs_hex32': public['nfs_hex32'],
            'tuple_sha256': public['tuple_sha256']}]
    value = {'schema': 'kpb-terminal-observer-history/v1',
        'round': public['round'],
        'projection_sha256': public['projection_sha256'],
        'cohort_sha256': COHORT,
        'mode': 'UNFUNDED_NETWORK_DISABLED', 'events': events,
        'groups': groups, 'amount_observations': [], 'retry_history': [],
        'rejected_or_orphaned': [], 'reorg_history': [],
        'cross_round_links': []}
    records = ([{'stream': 'event', 'value': row} for row in events]
        + [{'stream': 'group', 'value': row} for row in groups])
    value['closure'] = closure(
        records, sum(len(codec.encoded(row['value'])) for row in records))
    return value


def raw(value):
    return codec.encoded(value)


def repeat_complete_scalar_site(wire, site=2):
    """Repeat one complete v9 binding/share/MAC group and reclose counters."""
    frames = []
    at = 0
    while at < len(wire):
        size = int.from_bytes(wire[at + 44:at + 48], 'big')
        header = bytearray(wire[at:at + 112])
        payload = bytearray(wire[at + 112:at + 112 + size])
        frames.append([header, payload])
        at += 112 + size
    selected = next(index for index, (header, payload) in enumerate(frames)
                    if header[8] == 2 and header[9] == 17
                    and int.from_bytes(payload[2:4], 'big') == site)
    expected = 5 if site in capture.C03_SELECTED_RANDOMNESS_SITES else 3
    self_contained = frames[selected:selected + 3]
    if ([header[9] for header, _ in self_contained] !=
            [17, expected, expected + 1]):
        raise AssertionError('selected scalar group is not atomic')
    frames[selected + 3:selected + 3] = [
        [bytearray(header), bytearray(payload)]
        for header, payload in self_contained]

    footer_index = next(index for index, (header, _) in enumerate(frames)
                        if header[8] == 4)
    footer = frames[footer_index][1]
    increments = ((8, 3), (16, 3), (24, 80))
    for offset, amount in increments:
        footer[offset:offset + 8] = (
            int.from_bytes(footer[offset:offset + 8], 'big') + amount
        ).to_bytes(8, 'big')
    for semantic, byte_count in ((3, 32), (4, 32), (17, 16)):
        start = 32 + (semantic - 1) * 24
        for offset, amount in ((start, 1), (start + 8, 1),
                               (start + 16, byte_count)):
            footer[offset:offset + 8] = (
                int.from_bytes(footer[offset:offset + 8], 'big') + amount
            ).to_bytes(8, 'big')
    footer[472:480] = footer_index.to_bytes(8, 'big')
    footer[480:488] = (1_000_000).to_bytes(8, 'big')
    footer[488:496] = (1_000_000 + footer_index - 1).to_bytes(8, 'big')
    for sequence, (header, payload) in enumerate(frames):
        header[16:24] = (1_000_000 + sequence).to_bytes(8, 'big')
        header[24:32] = sequence.to_bytes(8, 'big')
        header[32:40] = sequence.to_bytes(8, 'big')
        header[80:112] = hashlib.sha256(payload).digest()
    return b''.join(bytes(header) + bytes(payload)
                    for header, payload in frames)


class CaptureAdapterControls(unittest.TestCase):
    def c03_fixture(self):
        import privacy_capture_producer as producer
        from test_privacy_capture_producer import p1_channel, selection

        selected = selection()
        projection_bytes, public = projection(1)
        wire = p1_channel(1, selected)
        with tempfile.TemporaryFile() as channel:
            channel.write(wire); channel.seek(0)
            _, closure_value = producer._consume_p1(
                channel.fileno(), selected, 1)
        authority = producer._p1_capture_authority(
            selected, 1, closure_value)
        role_launch = selected['role_launch_closure']
        role_launch_sha256 = hashlib.sha256(
            codec.encoded(role_launch)).hexdigest()
        return (wire, projection_bytes, public, authority, role_launch,
                role_launch_sha256, selected)

    def test_c03_bridge_requires_exact_source_build_launch_role_authority(self):
        wire, projection_bytes, public, authority, roles, roles_sha, \
            selected = \
            self.c03_fixture()
        modeled = capture.corrupt_server_c03(
            wire, public, projection_bytes, authority, roles, roles_sha)
        self.assertEqual(modeled['artifact_sha256'],
                         hashlib.sha256(wire).hexdigest())
        self.assertEqual(modeled['inventory']['c03_wire_bytes'], len(wire))
        self.assertTrue(modeled['inventory'][
            'c03_source_build_launch_role_bound'])
        binding = next(row for row in modeled['leakage_ledger']
                       if row['field_path'] ==
                       'capture.source_build_launch_role_binding')
        self.assertEqual(binding['status'], 'constraint_modeled')
        self.assertEqual(binding['constraint_count'], 1)
        ledger = {row['field_path']: row
                  for row in modeled['leakage_ledger']}
        for field_path in (
                'capture.model_preimage_binding',
                'capture.public_query_preimage_binding',
                'capture.scalar_callsite_manifest_binding'):
            self.assertEqual(ledger[field_path]['status'],
                             'constraint_modeled')
            self.assertEqual(ledger[field_path]['constraint_count'], 1)
        scalar = ledger[
            'records[scalar-capture-binding].site_kind_element_count_order']
        self.assertEqual(scalar['status'], 'constraint_modeled')
        self.assertEqual(scalar['constraint_count'], 22)
        self.assertEqual(ledger[
            'records[scalar-capture-binding].payload.nonliteral_implications'
        ]['status'], 'unmodeled')
        self.assertGreater(sum(row['status'] == 'unmodeled'
                               for row in modeled['leakage_ledger']), 0)

        for name, mutation in (
                ('source', ('source_sha256', 'f1' * 32)),
                ('build', ('build_sha256', 'f2' * 32)),
                ('launch', ('launch_sha256', 'f3' * 32)),
                ('model', ('model_preimage_sha256', 'e1' * 32)),
                ('query-store',
                 ('query_store_preimage_sha256', 'e2' * 32)),
                ('scalar-manifest',
                 ('scalar_capture_manifest_sha256', 'e3' * 32)),
                ('role', ('server_component', 0)),
                ('fd', ('fixed_fd', authority['fixed_fd'] + 1)),
                ('round', ('round', 2)),
                ('attempt', ('attempt_id',
                             'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')),
                ('cohort', ('cohort_sha256', 'f4' * 32)),
                ('financial', ('financial_run_id', 'f5' * 32)),
                ('capture', ('capture_identity',
                             'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'))):
            with self.subTest(name=name):
                changed = copy.deepcopy(authority)
                changed[mutation[0]] = mutation[1]
                with self.assertRaises(ValueError):
                    capture.corrupt_server_c03(
                        wire, public, projection_bytes, changed,
                        roles, roles_sha)

        changed = copy.deepcopy(authority)
        changed['closure']['record_chain_sha256'] = 'f6' * 32
        with self.assertRaises(ValueError):
            capture.corrupt_server_c03(
                wire, public, projection_bytes, changed, roles, roles_sha)
        changed = copy.deepcopy(authority)
        changed['closure']['capture_record_count'] += 1
        with self.assertRaises(ValueError):
            capture.corrupt_server_c03(
                wire, public, projection_bytes, changed, roles, roles_sha)
        for name, replacement in (
                ('raw_wire_bytes', authority['closure']['raw_wire_bytes'] + 1),
                ('raw_wire_sha256', 'd1' * 32),
                ('end_frame_identity', 'd2' * 32),
                ('eof_identity', 'd3' * 32)):
            with self.subTest(closure_field=name):
                changed = copy.deepcopy(authority)
                changed['closure'][name] = replacement
                with self.assertRaisesRegex(
                        ValueError, 'c03-source-closure-binding'):
                    capture.corrupt_server_c03(
                        wire, public, projection_bytes, changed,
                        roles, roles_sha)

        # A P1 row and HELLO cannot be substituted while leaving the selected
        # aggregate role-launch digest unchanged.
        changed = copy.deepcopy(authority)
        changed['source_sha256'] = 'f7' * 32
        with self.assertRaisesRegex(
                ValueError, 'c03-authority-role-launch-join'):
            capture.corrupt_server_c03(
                wire, public, projection_bytes, changed, roles, roles_sha)
        changed_roles = copy.deepcopy(roles)
        p1 = next(row for row in changed_roles
                  if row['round'] == 1
                  and row['kind'] == 'corrupt-server-capture')
        p1['source_sha256'] = 'f7' * 32
        with self.assertRaisesRegex(ValueError,
                                    'c03-role-launch-preimage'):
            capture.corrupt_server_c03(
                wire, public, projection_bytes, authority,
                changed_roles, roles_sha)

        # Rebuilding the caller-visible closure is not enough to move the
        # local MAC-key share behind a private lane.  The bridge independently
        # enforces the source call-site order.
        frames = []; at = 0
        while at < len(wire):
            size = int.from_bytes(wire[at + 44:at + 48], 'big')
            frames.append(bytearray(wire[at:at + 112 + size]))
            at += 112 + size
        frames[1], frames[2] = frames[2], frames[1]
        for sequence, frame in ((1, frames[1]), (2, frames[2])):
            frame[16:24] = (1000000 + sequence).to_bytes(8, 'big')
            frame[24:32] = sequence.to_bytes(8, 'big')
            frame[32:40] = sequence.to_bytes(8, 'big')
        reordered = b''.join(frames)
        changed = copy.deepcopy(authority)
        changed['closure']['record_chain_sha256'] = hashlib.sha256(
            reordered).hexdigest()
        with self.assertRaisesRegex(ValueError, 'c03-mac-key-order'):
            capture.corrupt_server_c03(
                reordered, public, projection_bytes, changed,
                roles, roles_sha)

        from test_privacy_capture_producer import p1_channel
        for mutation, category in (
                ('missing-site', 'c03-completeness-counters'),
                ('wrong-kind', 'c03-scalar-binding-shape'),
                ('wrong-count', 'c03-scalar-binding-width'),
                ('wrong-order', 'c03-scalar-binding-order'),
                ('duplicate-binding', 'c03-scalar-binding-order')):
            with self.subTest(scalar_mutation=mutation):
                changed_wire = p1_channel(
                    1, selected, scalar_mutation=mutation)
                changed = copy.deepcopy(authority)
                changed['closure']['record_chain_sha256'] = hashlib.sha256(
                    changed_wire).hexdigest()
                with self.assertRaisesRegex(ValueError, category):
                    capture.corrupt_server_c03(
                        changed_wire, public, projection_bytes, changed,
                        roles, roles_sha)
        for mutation, category in (
                ('g1-identity-alias',
                 'c03-authenticated-group-canonical'),
                ('g2-fq-range', 'c03-authenticated-group-canonical'),
                ('g1-stage', 'c03-authenticated-group-order'),
                ('g1-final-a-share',
                 'c03-authenticated-group-repeat'),
                ('g1-final-a-mac',
                 'c03-authenticated-group-repeat'),
                ('g2-final-share',
                 'c03-authenticated-group-repeat'),
                ('g2-final-mac',
                 'c03-authenticated-group-repeat')):
            with self.subTest(group_state_mutation=mutation):
                changed_wire = p1_channel(
                    1, selected, group_state_mutation=mutation)
                changed = copy.deepcopy(authority)
                changed['closure']['record_chain_sha256'] = hashlib.sha256(
                    changed_wire).hexdigest()
                with self.assertRaisesRegex(ValueError, category):
                    capture.corrupt_server_c03(
                        changed_wire, public, projection_bytes, changed,
                        roles, roles_sha)

        with self.assertRaises(ValueError):
            capture.corrupt_server_c03(
                wire[:-1], public, projection_bytes, authority,
                roles, roles_sha)

        # A self-authored JSON model still lacks the C03 authority binding.
        json_model = capture.corrupt_server(
            raw(corrupt_fixture(public, projection_bytes)), public,
            projection_bytes)
        json_binding = next(row for row in json_model['leakage_ledger']
                            if row['field_path'] ==
                            'capture.source_build_launch_role_binding')
        self.assertEqual(json_binding['status'], 'unmodeled')

    def test_source_only_producer_spool_roundtrips_into_v9_model(self):
        import privacy_capture_producer as producer
        from test_privacy_capture_producer import (
            p1_channel, pipes, selection, streams)

        selected = selection()
        raw_streams = streams(selected)
        for round_number in (1, 2):
            raw_streams[(round_number, 'corrupt-server-capture')] = \
                p1_channel(round_number, selected)
        raw_streams[(2, 'corrupt-server-capture')] = \
            repeat_complete_scalar_site(
                raw_streams[(2, 'corrupt-server-capture')])
        with tempfile.TemporaryDirectory(
                prefix='kpb-c03-model-spool-') as directory:
            root = Path(directory) / 'opaque-spool'
            receipt = producer.source_only_produce(
                selected, pipes(raw_streams), root)
            self.assertEqual(producer.verify_source_only(root, selected),
                             receipt)
            for round_number in (1, 2):
                round_root = root / ('round-' + str(round_number))
                wire = (round_root / 'corrupt-server.json').read_bytes()
                projection_bytes = (round_root / 'projection.bin').read_bytes()
                public = observer.batch_from_projection(
                    round_number, projection_bytes)
                modeled = capture.corrupt_server_c03(
                    wire, public, projection_bytes,
                    receipt['rounds'][round_number - 1][
                        'p1_capture_authority'],
                    selected['role_launch_closure'],
                    receipt['producer_role_launch_sha256'])
                self.assertEqual(modeled['artifact_sha256'],
                                 hashlib.sha256(wire).hexdigest())
                self.assertEqual(modeled['inventory'][
                    'c03_scalar_binding_count'],
                    22 if round_number == 1 else 23)
                self.assertEqual(modeled['inventory'][
                    'c03_scalar_site_bitmap'], (1 << 22) - 1)
                self.assertEqual(modeled['inventory'][
                    'c03_authenticated_group_equation_constraints'], {
                        'D_equals_Q_minus_U': 4,
                        'beaver_product_equations': 4,
                        'C_equals_products_plus_L_plus_H': 2,
                    })
                ledger = {(row['category'], row['field_path']): row
                          for row in modeled['leakage_ledger']}
                for field_path in (
                        'records[authenticated-g1-state].D_equals_Q_minus_U',
                        'records[authenticated-g1-state].beaver_product_equations',
                        'records[authenticated-g1-state].C_equals_products_plus_L_plus_H'):
                    self.assertEqual(ledger[(
                        'authenticated-group-state', field_path)]['status'],
                        'constraint_modeled')

    def test_c03_authenticated_group_equation_mutations_refuse(self):
        import privacy_capture_producer as producer
        from test_privacy_capture_producer import (
            p1_channel, pipes, selection, streams)

        failures = (
            ('equation-d', 'c03-authenticated-group-D-equation'),
            ('equation-product',
             'c03-authenticated-group-beaver-equations'),
            ('equation-c', 'c03-authenticated-group-C-equation'),
        )
        for mutation, category in failures:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                    prefix='kpb-c03-equation-') as directory:
                selected = selection(); raw_streams = streams(selected)
                raw_streams[(1, 'corrupt-server-capture')] = p1_channel(
                    1, selected, group_state_mutation=mutation)
                root = Path(directory) / 'opaque-spool'
                receipt = producer.source_only_produce(
                    selected, pipes(raw_streams), root)
                projection_bytes = (
                    root / 'round-1' / 'projection.bin').read_bytes()
                public = observer.batch_from_projection(1, projection_bytes)
                wire = (root / 'round-1' /
                        'corrupt-server.json').read_bytes()
                with self.assertRaisesRegex(ValueError, category):
                    capture.corrupt_server_c03(
                        wire, public, projection_bytes,
                        receipt['rounds'][0]['p1_capture_authority'],
                        selected['role_launch_closure'],
                        receipt['producer_role_launch_sha256'])

    def test_public_projection_inventories_every_lane_without_proof_claim(self):
        projection_bytes, public = projection(1)
        modeled = capture.public_projection(projection_bytes, public)
        self.assertEqual(modeled['constraints'], codec.empty_constraints())
        self.assertEqual(set(modeled['categories']),
                         capture.PROJECTION_CATEGORIES)
        self.assertEqual(modeled['inventory']['aggregate_proof_bytes'], 128)
        self.assertEqual(modeled['inventory']['individual_output_amount_fields'], 0)
        self.assertEqual(modeled['inventory']['aggregate_value_constraints'], {
            'reserve_sompi': 6_000_000_000,
            'remaining_sompi': 5_970_000_000,
            'fee_sompi': 30_000_000,
        })
        self.assertFalse(
            modeled['inventory']['proof_validity_or_privacy_claim'])
        lanes = modeled['inventory']['byte_lanes']
        self.assertEqual(modeled['inventory']['byte_lane_count'], 102)
        self.assertEqual(modeled['inventory']['byte_lane_total_bytes'], 10685)
        self.assertEqual((lanes[0]['start'], lanes[-1]['end']), (0, 10685))
        self.assertTrue(all(left['end'] == right['start']
                            for left, right in zip(lanes, lanes[1:])))
        self.assertEqual(len({row['name'] for row in lanes}), len(lanes))
        lane_digest = hashlib.sha256(codec.encoded(lanes)).hexdigest()
        self.assertEqual(lane_digest,
                         capture.PUBLIC_PROJECTION_LANE_MANIFEST_SHA256)
        self.assertEqual(lane_digest,
                         '1bf69a2f0df24e494e5ad212ebf4770ee98e2c40f1186b912f9a9ae898e305ea')
        shifted = copy.deepcopy(lanes)
        shifted[0]['end'] += 1
        shifted[1]['start'] += 1
        self.assertNotEqual(hashlib.sha256(codec.encoded(shifted)).hexdigest(),
                            lane_digest)
        with self.assertRaisesRegex(
                ValueError, 'public-projection-frozen-byte-lane-manifest'):
            capture._validate_public_projection_byte_lanes(shifted)
        relabelled = copy.deepcopy(lanes)
        relabelled[0]['field_path'] = relabelled[1]['field_path']
        self.assertNotEqual(
            hashlib.sha256(codec.encoded(relabelled)).hexdigest(), lane_digest)
        with self.assertRaisesRegex(ValueError,
                                    'public-projection-byte-lane-ledger-binding'):
            capture._validate_public_projection_byte_lanes(relabelled)
        self.assertEqual(
            [row['name'] for row in lanes
             if row['name'].startswith('nf-witness-0-')],
            ['nf-witness-0-predecessor-index',
             'nf-witness-0-predecessor',
             'nf-witness-0-successor',
             'nf-witness-0-successor-index',
             'nf-witness-0-predecessor-path',
             'nf-witness-0-append-path'])
        # Pinned crypto_box 0.9.1 seal() reaches crypto_secretbox 0.1.1
        # encrypt_in_place, which prepends Tag16 before encrypted Receipt216.
        self.assertEqual([
            (row['name'], row['start'], row['end'], row['field_path'])
            for row in lanes
            if row['name'].startswith('output-0-ciphertext-')], [
                ('output-0-ciphertext-ephemeral-public-key', 981, 1013,
                 'outputs[].ciphertext_ephemeral_public_key'),
                ('output-0-ciphertext-poly1305-tag', 1013, 1029,
                 'outputs[].ciphertext_poly1305_tag'),
                ('output-0-ciphertext-encrypted-receipt', 1029, 1245,
                 'outputs[].ciphertext_encrypted_receipt'),
                ('output-0-ciphertext-hash', 1245, 1277,
                 'outputs[].ciphertext_hash'),
            ])
        self.assertNotIn('projection.raw_bytes', {
            row['field_path'] for row in modeled['leakage_ledger']})
        cv_model = modeled['inventory']['cv_model']
        self.assertEqual(cv_model['canonical_subgroup_point_count'], 9)
        self.assertTrue(cv_model['joint_public_balance_verified'])
        self.assertEqual(cv_model['candidate_grouping_count'], 540)
        self.assertEqual(
            cv_model['candidate_grouping_pruned_count_without_openings'], 0)
        self.assertFalse(
            cv_model['candidate_residuals_feed_selected_prediction'])
        self.assertFalse(cv_model['hiding_or_fresh_blind_claim'])
        ledger = {(row['category'], row['field_path']): row
                  for row in modeled['leakage_ledger']}
        for category, field_path in (
                ('amounts', 'effect.reserve_sompi'),
                ('amounts', 'effect.remaining_sompi'),
                ('fees', 'effect.fee_sompi')):
            self.assertEqual(ledger[(category, field_path)]['status'],
                             'constraint_modeled')
            self.assertEqual(ledger[(category, field_path)][
                'constraint_count'], 1)
        for field_path, count in (
                ('inputs[].cv_bytes_and_subgroup', 3),
                ('outputs[].cv_bytes_and_subgroup', 6),
                ('effect.delta_scalar', 1),
                ('joint_public_balance_equation', 1)):
            row = ledger[('value-commitments', field_path)]
            self.assertEqual(row['status'], 'constraint_modeled')
            self.assertEqual(row['constraint_count'], count)
        self.assertEqual(ledger[('value-commitments',
            'joint_hiding_blind_freshness_and_reuse')]['status'],
            'unmodeled')
        self.assertEqual(ledger[('value-commitments',
            'candidate_group_residuals')]['status'], 'unmodeled')
        self.assertEqual(ledger[('value-commitments',
            'candidate_group_residuals')]['constraint_count'], 0)
        for category, field_path in (
                ('ciphertexts',
                 'outputs[].honest_encryption_provenance_and_malicious_owner_tagging'),
                ('state-transition',
                 'state.cross_attempt_public_byte_equalities'),
                ('state-transition',
                 'state.nf_witness_public_history_edges'),
                ('nullifiers',
                 'spends[].deterministic_retry_replay_equality')):
            self.assertEqual(ledger[(category, field_path)]['status'],
                             'unmodeled')
            self.assertEqual(ledger[(category, field_path)][
                'constraint_count'], 0)
        self.assertFalse(modeled['inventory'][
            'honest_encryption_producer_authority_consumed'])
        self.assertFalse(modeled['inventory'][
            'complete_public_multiattempt_history_joined'])
        self.assertEqual(len(modeled['inventory'][
            'nf_witness_public_history_edges']), 3)

        # Copy only the selected prefix tag lane from output 0 to output 1.
        # The tag equality must be observed without inventing an encrypted
        # receipt or ephemeral-key equality.
        tag_copy = bytearray(projection_bytes)
        first_ciphertext, second_ciphertext = 981, 981 + 520
        tag_copy[second_ciphertext + 32:second_ciphertext + 48] = \
            tag_copy[first_ciphertext + 32:first_ciphertext + 48]
        tag_copy[second_ciphertext + 264:second_ciphertext + 296] = \
            hashlib.sha256(tag_copy[
                second_ciphertext:second_ciphertext + 264]).digest()
        tag_public = observer.batch_from_projection(1, bytes(tag_copy))
        tag_model = capture.public_projection(bytes(tag_copy), tag_public)
        equalities = tag_model['inventory'][
            'same_projection_public_byte_equalities']
        self.assertEqual(equalities['ciphertext_poly1305_tag_pairs'], [[0, 1]])
        self.assertEqual(
            equalities['ciphertext_ephemeral_public_key_pairs'], [])
        self.assertEqual(
            equalities['ciphertext_encrypted_receipt_pairs'], [])

        for label, offsets in (
                ('reserve', (56, 193 + 276)),
                ('remaining', (105, 193 + 356)),
                ('fee', (193 + 364,))):
            with self.subTest(label=label):
                invalid = bytearray(projection_bytes)
                for offset in offsets:
                    value = int.from_bytes(
                        invalid[offset:offset + 8], 'little')
                    invalid[offset:offset + 8] = \
                        (value + 1).to_bytes(8, 'little')
                changed_public = observer.batch_from_projection(
                    1, bytes(invalid))
                with self.assertRaisesRegex(
                        ValueError, 'public-projection-money'):
                    capture.public_projection(bytes(invalid), changed_public)

        changed = bytearray(projection_bytes); changed[-1] ^= 1
        changed_public = observer.batch_from_projection(1, bytes(changed))
        still_only_inventory = capture.public_projection(
            bytes(changed), changed_public)
        self.assertEqual(still_only_inventory['constraints'],
                         codec.empty_constraints())
        malformed = bytearray(projection_bytes); malformed[0] ^= 1
        with self.assertRaises(ValueError):
            capture.public_projection(bytes(malformed), public)

        invalid_cv = bytearray(projection_bytes)
        invalid_cv[193 + 436] ^= 1
        invalid_public = observer.batch_from_projection(1, bytes(invalid_cv))
        with self.assertRaisesRegex(ValueError, 'public-cv-'):
            capture.public_projection(bytes(invalid_cv), invalid_public)

        # A pure permutation of valid input CVs preserves the public sum and
        # therefore prunes no owner grouping without individual fee/delta
        # openings. It does change the exhaustively derived residual receipt.
        swapped = bytearray(projection_bytes)
        first, second = 193 + 436, 193 + 532
        first_cv = bytes(swapped[first:first + 64])
        swapped[first:first + 64] = swapped[second:second + 64]
        swapped[second:second + 64] = first_cv
        swapped_public = observer.batch_from_projection(1, bytes(swapped))
        swapped_model = capture.public_projection(bytes(swapped),
                                                  swapped_public)
        self.assertEqual(swapped_model['inventory']['cv_model'][
            'candidate_grouping_pruned_count_without_openings'], 0)
        self.assertNotEqual(swapped_model['inventory']['cv_model'][
            'candidate_group_residual_partition_sha256'],
            cv_model['candidate_group_residual_partition_sha256'])

    def test_fd40_structural_record_is_exact_but_not_authority(self):
        run_binding_vector = fd40_run_binding_known_vector()
        self.assertEqual(
            hashlib.sha256(run_binding_vector).hexdigest(),
            '4e8f946c47189e9db77556584218058eab1678c69b5c9bf4721205ffb0f1b591')
        fd40._run_binding(run_binding_vector)
        raws, publics = continuous_projection_pair()
        unbound = capture.public_projection_pair(raws, publics)
        for artifact in unbound:
            ledger = {(row['category'], row['field_path']): row
                      for row in artifact['leakage_ledger']}
            self.assertEqual(ledger[('state-transition',
                'state.two_round_projection_structural_continuity')][
                    'status'], 'unmodeled')
            self.assertEqual(ledger[('context-identities',
                'context.two_round_structural_profile_script_binding')][
                    'status'], 'unmodeled')
            self.assertEqual(capture._public_projection_blocker_matrix(
                artifact)['row_count'], 21)
        self.assertFalse(hasattr(
            capture, '_test_only_mint_structural_projection_continuity_authority'))
        self.assertNotIn(
            'def _test_only_mint_structural_projection_continuity_authority',
            Path(capture.__file__).read_text())

        prefix = fd40_structural_prefix(raws, publics)
        parsed = capture.inspect_fd40_structural_continuity_prefix(
            prefix, raws, publics)
        self.assertEqual(parsed['schema'],
                         'kpb-fd40-structural-continuity-parse/v1')
        self.assertTrue(parsed['structural_projection_continuity'])
        self.assertFalse(parsed['accepted_chain_continuity'])
        self.assertFalse(parsed['authorizes_coverage'])
        self.assertTrue(parsed['requires_consumed_native_fd40_admission'])

        # A parsed record, public receipt, caller dict, raw prefix, or replay is
        # never the consumed native authority.
        substitutes = (parsed, prefix, {
            'structural_projection_continuity': True,
            'accepted_chain_continuity': False,
        })
        for substitute in substitutes:
            for _ in range(2):
                with self.assertRaisesRegex(
                        ValueError,
                        'structural-continuity-authenticated-fd40-admission-required'):
                    capture.public_projection_pair(
                        raws, publics, substitute)

        with self.assertRaisesRegex(ValueError,
                                    'fd40-structural-prefix-width'):
            capture.inspect_fd40_structural_continuity_prefix(
                prefix[:-1], raws, publics)
        section = prefix[fd40.STRUCTURAL_OFFSET:fd40.STRUCTURAL_END]
        missing = bytearray(prefix)
        missing[fd40.STRUCTURAL_OFFSET:fd40.STRUCTURAL_END] = \
            bytes(fd40.STRUCTURAL_BYTES)
        with self.assertRaisesRegex(ValueError,
                                    'fd40-structural-section-header'):
            capture.inspect_fd40_structural_continuity_prefix(
                bytes(missing), raws, publics)
        with self.assertRaisesRegex(ValueError,
                                    'fd40-structural-prefix-width'):
            capture.inspect_fd40_structural_continuity_prefix(
                prefix[:fd40.LEAF_COUNT_OFFSET] + section + bytes((10,)),
                raws, publics)

        accepted = bytearray(prefix)
        accepted[fd40.STRUCTURAL_OFFSET + 18] = 1
        with self.assertRaisesRegex(ValueError,
                                    'fd40-structural-section-header'):
            capture.inspect_fd40_structural_continuity_prefix(
                bytes(accepted), raws, publics)

        wrong_lineage = bytearray(prefix)
        wrong_lineage[fd40.STRUCTURAL_OFFSET + 52 + 32] ^= 1
        with self.assertRaises(ValueError):
            capture.inspect_fd40_structural_continuity_prefix(
                bytes(wrong_lineage), raws, publics)

        wrong_order = bytearray(prefix)
        first = fd40.STRUCTURAL_OFFSET + 52
        second = first + 968
        first_round = bytes(wrong_order[first:second])
        second_round = bytes(wrong_order[second:second + 968])
        wrong_order[first:second] = second_round
        wrong_order[second:second + 968] = first_round
        with self.assertRaises(ValueError):
            capture.inspect_fd40_structural_continuity_prefix(
                bytes(wrong_order), raws, publics)

        unrelated_raws = [projection(1)[0], projection(2)[0]]
        unrelated_publics = [observer.batch_from_projection(
            number, raw_value)
            for number, raw_value in enumerate(unrelated_raws, 1)]
        with self.assertRaises(ValueError):
            capture.inspect_fd40_structural_continuity_prefix(
                prefix, unrelated_raws, unrelated_publics)

    def test_complete_dispatcher_capture_is_modeled_without_private_body_hash(self):
        _, public = projection(1); value = dispatcher_fixture(public)
        result = capture.dispatcher(raw(value), public)
        self.assertEqual(result['constraints'], codec.empty_constraints())
        self.assertEqual(set(result['categories']), capture.DISPATCHER_CATEGORIES)
        mapping = next(row for row in result['leakage_ledger']
                       if row['field_path'] ==
                       'release_order_policy_and_direct_exports')
        self.assertEqual(mapping['status'], 'unmodeled')
        self.assertEqual(mapping['constraint_count'], 0)
        source_bound = capture.dispatcher(
            raw(value), public, dispatcher_source_authority(value))
        source_mapping = next(row for row in source_bound['leakage_ledger']
                              if row['field_path'] ==
                              'release_order_policy_and_direct_exports')
        self.assertEqual(source_mapping['status'], 'constraint_modeled')
        self.assertEqual(source_mapping['constraint_count'], 1)
        upload = [row for row in value['events']
                  if row['kind'] == 'owner-upload-complete']
        self.assertTrue(all(row['public_sha256'] is None for row in upload))

    def test_dispatcher_omission_or_unselected_field_refuses(self):
        _, public = projection(1)
        missing = dispatcher_fixture(public)
        missing['events'] = [event for event in missing['events']
                             if not (event['kind'] == 'owner-connected'
                                     and event['owner_component'] == 2)]
        for index, event in enumerate(missing['events']):
            event['sequence'] = index
        with self.assertRaises(ValueError):
            capture.dispatcher(raw(missing), public)
        extra = dispatcher_fixture(public); extra['events'][0]['secret'] = 1
        with self.assertRaises(ValueError):
            capture.dispatcher(raw(extra), public)
        retry = dispatcher_fixture(public)
        retry['retry_history'] = [{'attempt_id': 'changed-cohort',
            'owner_component': 0, 'start_monotonic_ns': 1,
            'complete_monotonic_ns': 2, 'outcome': 'refused'}]
        with self.assertRaises(ValueError):
            capture.dispatcher(raw(retry), public)

    def test_dispatcher_upload_order_publication_is_not_an_authority(self):
        _, public = projection(1)
        value = dispatcher_fixture(public)
        value['release_order_policy'] = 'UPLOAD_ORDER_PUBLIC_EFFECTS'
        with self.assertRaisesRegex(
                ValueError, 'dispatcher-release-order-policy'):
            capture.dispatcher(raw(value), public)

    def test_source_bound_explicit_baseline_mapping_is_exactly_modeled(self):
        _, public = projection(1)
        value = explicit_dispatcher_fixture(public)
        untrusted = capture.dispatcher(raw(value), public)
        self.assertEqual(untrusted['constraints'], codec.empty_constraints())
        untrusted_mapping = next(
            row for row in untrusted['leakage_ledger']
            if row['field_path'] ==
            'release_order_policy_and_direct_exports')
        self.assertEqual(untrusted_mapping['status'], 'unmodeled')
        authority = dispatcher_source_authority(value)
        modeled = capture.dispatcher(raw(value), public, authority)
        self.assertEqual(len(modeled['constraints']['input_edges']), 3)
        self.assertEqual(len(modeled['constraints']['creator_edges']), 6)
        self.assertEqual(len(modeled['constraints']['nf_pair_edges']), 3)
        candidate_model = codec.assignments(public, modeled['constraints'])
        self.assertEqual(candidate_model['joint_candidates'], 1)
        mapping = next(row for row in modeled['leakage_ledger']
                       if row['field_path'] ==
                       'release_order_policy_and_direct_exports')
        self.assertEqual(mapping['status'], 'constraint_modeled')
        self.assertEqual(mapping['constraint_count'], 4)
        with self.assertRaisesRegex(
                ValueError, 'dispatcher-policy-source-authority-type'):
            capture.dispatcher(raw(value), public, authority)

        wrong_authority = dispatcher_source_authority(value)
        wrong_authority._binding['artifact_sha256'] = 'fe' * 32
        with self.assertRaisesRegex(
                ValueError, 'dispatcher-policy-source-authority-binding'):
            capture.dispatcher(raw(value), public, wrong_authority)

        mutations = []
        changed = copy.deepcopy(value)
        changed['direct_exports'][1]['context_sha256'] = 'ff' * 32
        mutations.append(('lineage', changed,
                          'dispatcher-direct-export-binding'))
        changed = copy.deepcopy(value)
        changed['direct_exports'][1]['tuple_sha256'][0] = \
            changed['direct_exports'][0]['tuple_sha256'][0]
        mutations.append(('duplicate-tuple', changed,
                          'dispatcher-direct-export-binding'))
        changed = copy.deepcopy(value)
        changed['direct_exports'][0], changed['direct_exports'][1] = \
            changed['direct_exports'][1], changed['direct_exports'][0]
        mutations.append(('owner-order', changed,
                          'dispatcher-direct-export-binding'))
        changed = copy.deepcopy(value)
        explicit = next(event for event in changed['events']
                        if event['kind'] ==
                        'explicit-owner-public-effects')
        explicit['public_sha256'] = 'ee' * 32
        mutations.append(('event-digest', changed,
                          'dispatcher-explicit-owner-effects-binding'))
        changed = copy.deepcopy(value)
        changed['release_order_policy'] = 'SECRET_PERMUTATION_INDEPENDENT'
        mutations.append(('candidate-disclosure', changed,
                          'dispatcher-secret-order-no-direct-export'))
        changed = copy.deepcopy(value)
        changed['construction_classification'] = 1
        mutations.append(('classification', changed,
                          'dispatcher-three-explicit-exports'))
        changed = copy.deepcopy(value)
        changed['capture_plan_sha256'] = 'ef' * 32
        mutations.append(('top-level-lineage', changed,
                          'dispatcher-direct-export-binding'))
        changed = copy.deepcopy(value)
        policy_event = next(event for event in changed['events']
                            if event['kind'] == 'release-policy-bound')
        policy_event['public_sha256'] = 'ed' * 32
        mutations.append(('policy-digest', changed,
                          'dispatcher-release-policy-binding'))
        changed = copy.deepcopy(value)
        policy_index = next(index for index, event in enumerate(
            changed['events']) if event['kind'] == 'release-policy-bound')
        policy_event = changed['events'].pop(policy_index)
        changed['events'].append(policy_event)
        for sequence, event in enumerate(changed['events']):
            event['sequence'] = sequence
            event['monotonic_ns'] = 100 + sequence
        mutations.append(('policy-order', changed,
                          'dispatcher-explicit-policy-order'))
        changed = copy.deepcopy(value)
        changed['construction_classification'] = 1
        changed['release_order_policy'] = 'SECRET_PERMUTATION_INDEPENDENT'
        changed['direct_exports'] = []
        changed['events'] = [
            event for event in changed['events']
            if event['kind'] != 'explicit-owner-public-effects']
        for sequence, event in enumerate(changed['events']):
            event['sequence'] = sequence
            event['monotonic_ns'] = 100 + sequence
        mutations.append(('cross-arm-policy-digest', changed,
                          'dispatcher-release-policy-binding'))
        for name, changed, category in mutations:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, category):
                    capture.dispatcher(
                        raw(changed), public,
                        dispatcher_source_authority(changed))

    def test_complete_corrupt_server_lanes_and_literal_leak_detection(self):
        projection_bytes, public = projection(1)
        value = corrupt_fixture(public, projection_bytes)
        modeled = capture.corrupt_server(raw(value), public, projection_bytes)
        self.assertEqual(modeled['constraints'], codec.empty_constraints())
        self.assertEqual(set(modeled['categories']), capture.SERVER_CATEGORIES)
        self.assertEqual(
            modeled['inventory']['masked_field_intermediate_count'], 1)
        self.assertEqual(
            modeled['inventory']['masked_g1_intermediate_count'], 1)
        self.assertEqual(modeled['inventory']['final_proof_g1_count'], 1)
        self.assertEqual(modeled['inventory']['final_proof_g2_count'], 1)
        self.assertNotIn('b1', codec.encoded(
            modeled['leakage_ledger']).decode().lower())

        leaked = copy.deepcopy(value)
        offset = next(row for row in leaked['records']
                      if row['semantic'] == 'owner-input-offset'
                      and row['owner_component'] == 0)
        offset['payload_hex'] = public['nfs_hex32'][0]
        leaked_records = [{'stream': row['semantic'], 'value': row}
                          for row in leaked['records']]
        leaked['closure'] = closure(
            leaked_records,
            sum(len(bytes.fromhex(row['payload_hex']))
                for row in leaked['records']))
        detected = capture.corrupt_server(raw(leaked), public,
                                          projection_bytes)
        self.assertEqual(detected['constraints']['input_edges'], [{
            'owner_component': 0, 'slot_id': public['nfs_hex32'][0],
            'provenance': 'direct-export'}])
        ledger = {(row['category'], row['field_path']): row
                  for row in detected['leakage_ledger']}
        self.assertEqual(ledger[(
            'server-local-shares',
            'records[owner-input-offset].payload.literal_public_identifiers'
        )]['status'], 'constraint_modeled')
        for semantic in (
                'field-opening', 'masked-field-intermediate',
                'masked-g1-intermediate', 'final-proof-g1',
                'final-proof-g2'):
            self.assertEqual(ledger[(
                'authenticated-transcript',
                'records[' + semantic +
                '].payload.literal_public_identifiers')]['status'],
                'constraint_modeled')
            self.assertEqual(ledger[(
                'authenticated-transcript',
                'records[' + semantic +
                '].payload.nonliteral_implications')]['status'],
                'unmodeled')
        for field_path in (
                'wire.frames[].monotonic_ns',
                'wire.frames[].payload_length',
                'wire.frames[].sequence_message_chunk_order',
                'wire.frames[].direction_peer_fork',
                'attempt.abort_retry_partial_transcript',
                'capture.source_build_launch_role_binding'):
            self.assertEqual(ledger[(
                'authenticated-transcript', field_path)]['status'],
                'unmodeled')

    def test_v8_authenticated_group_state_is_complete_but_nonliteral_unmodeled(self):
        projection_bytes, public = projection(1)
        value = corrupt_fixture(public, projection_bytes)
        modeled = capture.corrupt_server(raw(value), public,
                                         projection_bytes)
        self.assertEqual(modeled['inventory'][
            'authenticated_g1_stage_object_counts'], {
                'BASE': 4, 'MIXED': 6, 'PRODUCTS': 2, 'FINAL': 2})
        self.assertEqual(modeled['inventory'][
            'authenticated_g2_stage_object_counts'], {
                'BASE': 1, 'FINAL': 1})
        ledger = {(row['category'], row['field_path']): row
                  for row in modeled['leakage_ledger']}
        for semantic in ('authenticated-g1-state',
                         'authenticated-g2-state'):
            literal = ledger[(
                'authenticated-group-state',
                'records[' + semantic +
                '].payload.literal_public_identifiers')]
            nonliteral = ledger[(
                'authenticated-group-state',
                'records[' + semantic +
                '].payload.nonliteral_implications')]
            self.assertEqual(literal['status'], 'constraint_modeled')
            self.assertGreater(literal['constraint_count'], 0)
            self.assertEqual(nonliteral['status'], 'unmodeled')
        for field_path in (
                'records[authenticated-group-query-msm-temporary].capture_correspondence',
                'records[authenticated-g1-state].D_equals_Q_minus_U',
                'records[authenticated-g1-state].beaver_product_equations',
                'records[authenticated-g1-state].C_equals_products_plus_L_plus_H'):
            self.assertEqual(ledger[(
                'authenticated-group-state', field_path)]['status'],
                'unmodeled')
        self.assertEqual(ledger[(
            'authenticated-transcript',
            'wire.frames[].mixed_protocol_nonliteral_implications')][
                'status'], 'unmodeled')
        boundary = modeled['inventory'][
            'out_of_scope_unqualified_boundaries']
        self.assertEqual(boundary['status'],
                         'UNQUALIFIED_FOR_GENERAL_ACTIVE_OR_HOST_CLAIMS')
        self.assertFalse(boundary['modeled_or_harmless'])
        self.assertTrue(boundary['blocks_general_active_or_host_claims'])
        self.assertEqual(set(boundary['boundaries']), {
            'P1_INTERNAL_OT_PRNG_RANDOM_TAPE',
            'ARBITRARY_MODIFIED_OR_MALICIOUS_HOST_OR_BINARY',
            'HOST_MEMORY_LOG_SWAP_CACHE_PAGE_SCHEDULE_CPU_GPU_STATE',
            'COVERT_AND_NETWORK_STACK_CHANNELS',
        })

        def reclose(changed):
            records = [{'stream': row['semantic'], 'value': row}
                       for row in changed['records']]
            changed['closure'] = closure(
                records,
                sum(len(bytes.fromhex(row['payload_hex']))
                    for row in changed['records']))

        # Canonical changes to every captured AuthG stage/half remain exact
        # observations, but cannot be promoted into unmeasured algebra.  A and
        # B2 are changed in both repeated records so the explicit equality
        # control remains satisfied.
        mutations = (
            ('g1-base-b1', 'authenticated-g1-state', (1,), 1, 65),
            ('g1-repeated-a', 'authenticated-g1-state', (1, 4), 0, 65),
            ('g1-mixed', 'authenticated-g1-state', (2,), 0, 65),
            ('g1-products', 'authenticated-g1-state', (3,), 0, 65),
            ('g1-final-c', 'authenticated-g1-state', (4,), 1, 65),
            ('g2-repeated-b2', 'authenticated-g2-state', (1, 4), 0, 129),
        )
        for label, semantic, stages, object_index, point_bytes in mutations:
            for half, half_offset in (('share', 0), ('mac', point_bytes)):
                with self.subTest(label=label, half=half):
                    changed = copy.deepcopy(value)
                    for row in changed['records']:
                        if row['semantic'] != semantic:
                            continue
                        payload = bytearray.fromhex(row['payload_hex'])
                        if payload[0] not in stages:
                            continue
                        at = (1 + object_index * 2 * point_bytes
                              + half_offset + 1)
                        payload[at] ^= 1
                        row['payload_hex'] = payload.hex()
                    reclose(changed)
                    observed = capture.corrupt_server(
                        raw(changed), public, projection_bytes)
                    self.assertFalse(observed['inventory'][
                        'cryptographic_independence_or_privacy_claim'])
                    observed_ledger = {
                        (row['category'], row['field_path']): row
                        for row in observed['leakage_ledger']}
                    for field_path in (
                            'records[authenticated-g1-state].D_equals_Q_minus_U',
                            'records[authenticated-g1-state].beaver_product_equations',
                            'records[authenticated-g1-state].C_equals_products_plus_L_plus_H'):
                        self.assertEqual(observed_ledger[(
                            'authenticated-group-state', field_path)][
                                'status'], 'unmodeled')

        unequal = copy.deepcopy(value)
        final_g1 = [row for row in unequal['records']
                    if row['semantic'] == 'authenticated-g1-state'][-1]
        payload = bytearray.fromhex(final_g1['payload_hex'])
        payload[2] ^= 1
        final_g1['payload_hex'] = payload.hex(); reclose(unequal)
        with self.assertRaisesRegex(ValueError,
                                    'corrupt-authenticated-group-repeat'):
            capture.corrupt_server(raw(unequal), public, projection_bytes)

        wrong_stage = copy.deepcopy(value)
        final_g2 = [row for row in wrong_stage['records']
                    if row['semantic'] == 'authenticated-g2-state'][-1]
        payload = bytearray.fromhex(final_g2['payload_hex'])
        payload[0] = 3
        final_g2['payload_hex'] = payload.hex(); reclose(wrong_stage)
        with self.assertRaisesRegex(ValueError,
                                    'corrupt-authenticated-group-stages'):
            capture.corrupt_server(raw(wrong_stage), public,
                                   projection_bytes)

        noncanonical = copy.deepcopy(value)
        mixed_g1 = [row for row in noncanonical['records']
                    if row['semantic'] == 'authenticated-g1-state'][1]
        payload = bytearray.fromhex(mixed_g1['payload_hex'])
        payload[1] = 2
        mixed_g1['payload_hex'] = payload.hex(); reclose(noncanonical)
        with self.assertRaisesRegex(
                ValueError, 'corrupt-authenticated-group-canonical'):
            capture.corrupt_server(raw(noncanonical), public,
                                   projection_bytes)

    def test_transformed_server_mapping_leak_stays_explicitly_unmodeled(self):
        projection_bytes, public = projection(1)
        value = corrupt_fixture(public, projection_bytes)
        # This reversible transform carries the public NF without containing
        # its literal bytes.  Literal substring extraction must not turn the
        # rest of the authenticated share lane into claimed coverage.
        transformed = (int.from_bytes(bytes.fromhex(public['nfs_hex32'][0]),
                                      'little') + 12_345).to_bytes(32, 'little')
        offset = next(row for row in value['records']
                      if row['semantic'] == 'owner-input-offset'
                      and row['owner_component'] == 0)
        offset['payload_hex'] = transformed.hex()
        records = [{'stream': row['semantic'], 'value': row}
                   for row in value['records']]
        value['closure'] = closure(
            records, sum(len(bytes.fromhex(row['payload_hex']))
                         for row in value['records']))
        server = capture.corrupt_server(raw(value), public, projection_bytes)
        self.assertEqual(server['constraints'], codec.empty_constraints())
        self.assertIn({
            'category': 'server-local-shares',
            'field_path':
                'records[owner-input-offset].payload.nonliteral_implications',
            'status': 'unmodeled',
            'constraint_count': 0,
            'assumption_sha256': None,
        }, server['leakage_ledger'])
        artifacts = [
            capture.public_projection(projection_bytes, public),
            capture.terminal(raw(terminal_fixture(public)), public),
            capture.dispatcher(raw(dispatcher_fixture(public)), public),
            server,
            capture.colluder_wallet(raw(colluder_fixture(public)), public),
        ]
        derived = capture.derive_view_artifacts(public, artifacts)
        corrupt_coverage = derived['views']['corrupt-server-plus-wallet'][
            'leakage_coverage']
        self.assertGreater(
            corrupt_coverage['server-local-shares']['unmodeled_fields'], 0)
        self.assertEqual(
            corrupt_coverage['server-local-shares'][
                'source_assumption_covered_fields'], 0)

    def test_legacy_masked_owner_share_lane_is_rejected_not_aliased(self):
        projection_bytes, public = projection(1)
        value = corrupt_fixture(public, projection_bytes)
        offset = next(row for row in value['records']
                      if row['semantic'] == 'owner-input-offset')
        offset['semantic'] = 'masked-owner-share'
        records = [{'stream': row['semantic'], 'value': row}
                   for row in value['records']]
        value['closure'] = closure(
            records, sum(len(bytes.fromhex(row['payload_hex']))
                         for row in value['records']))
        with self.assertRaisesRegex(ValueError, 'corrupt-record-enum'):
            capture.corrupt_server(raw(value), public, projection_bytes)

    def test_legacy_generic_opening_and_raw_b1_lanes_are_rejected(self):
        projection_bytes, public = projection(1)
        for legacy in ('masked-opening', 'raw-b1'):
            with self.subTest(legacy=legacy):
                value = corrupt_fixture(public, projection_bytes)
                opening = next(row for row in value['records']
                               if row['semantic'] == 'final-proof-g1')
                opening['semantic'] = legacy
                records = [{'stream': row['semantic'], 'value': row}
                           for row in value['records']]
                value['closure'] = closure(
                    records,
                    sum(len(bytes.fromhex(row['payload_hex']))
                        for row in value['records']))
                with self.assertRaisesRegex(ValueError,
                                            'corrupt-record-enum'):
                    capture.corrupt_server(raw(value), public,
                                           projection_bytes)

    def test_zero_count_field_cannot_claim_constraint_modeled_coverage(self):
        projection_bytes, public = projection(1)
        artifacts = [
            capture.public_projection(projection_bytes, public),
            capture.terminal(raw(terminal_fixture(public)), public),
            capture.dispatcher(raw(dispatcher_fixture(public)), public),
            capture.corrupt_server(raw(corrupt_fixture(
                public, projection_bytes)), public, projection_bytes),
            capture.colluder_wallet(raw(colluder_fixture(public)), public),
        ]
        forged = copy.deepcopy(artifacts)
        row = next(item for item in forged[0]['leakage_ledger']
                   if item['status'] == 'unmodeled')
        row['status'] = 'constraint_modeled'
        row['constraint_count'] = 0
        with self.assertRaisesRegex(
                ValueError,
                'constraint-modeled-requires-positive-field-count'):
            capture.derive_view_artifacts(public, forged)

    def test_uncited_source_assumption_digest_cannot_cover_a_field(self):
        projection_bytes, public = projection(1)
        artifacts = [
            capture.public_projection(projection_bytes, public),
            capture.terminal(raw(terminal_fixture(public)), public),
            capture.dispatcher(raw(dispatcher_fixture(public)), public),
            capture.corrupt_server(raw(corrupt_fixture(
                public, projection_bytes)), public, projection_bytes),
            capture.colluder_wallet(raw(colluder_fixture(public)), public),
        ]
        forged = copy.deepcopy(artifacts)
        row = next(item for item in forged[3]['leakage_ledger']
                   if item['status'] == 'unmodeled')
        row['status'] = 'source_assumption_covered'
        row['assumption_sha256'] = 'aa' * 32
        with self.assertRaisesRegex(
                ValueError, 'unselected-source-assumption'):
            capture.derive_view_artifacts(public, forged)

    def test_colluder_wallet_models_legitimate_facts_not_forbidden_exports(self):
        _, public = projection(1)
        value = colluder_fixture(public)
        modeled = capture.colluder_wallet(raw(value), public)
        self.assertEqual(set(modeled['categories']),
                         capture.COLLUDER_CATEGORIES)
        self.assertEqual(len(modeled['constraints']['input_edges']), 1)
        self.assertEqual(len(modeled['constraints']['creator_edges']), 2)
        self.assertIn({
            'category': 'colluder-decrypted-receipts',
            'field_path': 'decrypted_receipts[].source',
            'status': 'unmodeled', 'constraint_count': 0,
            'assumption_sha256': None,
        }, modeled['leakage_ledger'])
        self.assertEqual(modeled['constraints']['nf_pair_edges'][0][
            'provenance'], 'colluder-knowledge')
        candidate_model = codec.assignments(public, modeled['constraints'])
        self.assertGreater(candidate_model['joint_candidates'], 0)
        self.assertLess(candidate_model['joint_candidates'], 540)
        self.assertEqual(candidate_model['forbidden_exports'], 0)

        missing = copy.deepcopy(value); missing['decrypted_receipts'].pop()
        with self.assertRaises(ValueError):
            capture.colluder_wallet(raw(missing), public)
        amount_link = copy.deepcopy(value)
        amount_link['invoices'][0]['value']['amount_sompi'] += 1
        with self.assertRaises(ValueError):
            capture.colluder_wallet(raw(amount_link), public)

        # The accepted invoice must refer back to the exact invoice-stage
        # operation captured prospectively by the supervisor.  A semantically
        # valid word chosen by the artifact cannot replace that binding.
        for name, mutate in (
                ('accepted-operation', lambda row: row['invoices'][1]
                    ['value'].__setitem__('operation_id_sha256', '77' * 32)),
                ('issued-source-operation', lambda row: row['invoices'][0]
                    ['source'].__setitem__('operation_id_sha256', '65' * 32)),
                ('boolean-stage-sequence', lambda row: row['invoices'][0]
                    ['source'].__setitem__('stage_sequence', False)),
                ('boolean-contact', lambda row: row['invoices'][0]
                    ['source'].__setitem__('contact_owner_component', False)),
                ('wrong-contact', lambda row: row['invoices'][0]
                    ['source'].__setitem__('contact_owner_component', 2)),
                ('claimed-qualified-contact', lambda row: row['invoices'][0]
                    ['source'].__setitem__('contact_binding_qualified', True))):
            with self.subTest(name=name):
                changed = copy.deepcopy(value)
                mutate(changed)
                records = ([{'stream': 'original', **changed['original']}]
                    + [{'stream': 'invoice', **row}
                       for row in changed['invoices']]
                    + [{'stream': 'decrypted-receipt', **row}
                       for row in changed['decrypted_receipts']])
                changed['closure'] = closure(
                    records,
                    sum(len(codec.encoded(row['value'])) for row in records))
                with self.assertRaises(ValueError):
                    capture.colluder_wallet(raw(changed), public)

    def test_qualified_c1_contact_values_prune_lattice_only_with_pair_authority(self):
        publics = [projection(number)[1] for number in (1, 2)]
        values = [qualified_colluder_fixture(public) for public in publics]
        raws = [raw(value) for value in values]

        # The typed leaf and its precursor-like hashes are never authority.
        for raw_value, public in zip(raws, publics):
            with self.assertRaisesRegex(
                    ValueError, 'c1-v2-requires-paired-source-authority'):
                capture.colluder_wallet(raw_value, public)
        with self.assertRaises(ValueError):
            capture.colluder_wallet_v2_pair(raws, publics, [True, True])

        legacy = [capture.colluder_wallet(
            raw(colluder_fixture(public)), public) for public in publics]
        legacy_models = [codec.assignments(public, artifact['constraints'])
                         for public, artifact in zip(publics, legacy)]
        self.assertEqual([model['joint_candidates'] for model in legacy_models],
                         [12, 12])

        authorities = [c1_contact_value_source_authority(value)
                       for value in values]
        modeled = capture.colluder_wallet_v2_pair(
            raws, publics, authorities)
        models = [codec.assignments(public, artifact['constraints'])
                  for public, artifact in zip(publics, modeled)]
        self.assertEqual([model['joint_candidates'] for model in models],
                         [6, 6])
        self.assertEqual([artifact['inventory'][
            'candidate_count_before_contact_value'] for artifact in modeled],
            [12, 12])
        self.assertEqual([artifact['inventory'][
            'candidate_count_after_contact_value'] for artifact in modeled],
            [6, 6])
        self.assertTrue(all(len(artifact['constraints']['creator_edges']) == 3
                            for artifact in modeled))
        for artifact in modeled:
            ledger = {(row['category'], row['field_path']): row
                      for row in artifact['leakage_ledger']}
            for key in (
                    ('colluder-original', 'original.source'),
                    ('colluder-invoices', 'invoices[].source'),
                    ('colluder-invoices', 'invoices[].value'),
                    ('colluder-decrypted-receipts',
                     'decrypted_receipts[].source'),
                    ('colluder-decrypted-receipts',
                     'decrypted_receipts[].value')):
                self.assertEqual(ledger[key]['status'], 'constraint_modeled')
                self.assertGreater(ledger[key]['constraint_count'], 0)

        terminals = [capture.terminal(raw(terminal_fixture(public)), public)
                     for public in publics]
        self.assertEqual(capture.workload_candidates(
            legacy_models, terminals)['workload_joint_candidates'], 144)
        self.assertEqual(capture.workload_candidates(
            models, terminals)['workload_joint_candidates'], 36)

        # The global role closure is intentionally common. Per-round process,
        # child-exit and contact-value identities must remain distinct.
        same_process = 'ab' * 32
        with self.assertRaisesRegex(ValueError, 'c1-distinct-process'):
            capture.colluder_wallet_v2_pair(
                raws, publics,
                [c1_contact_value_source_authority(
                     value, process=same_process) for value in values])
        same_exit = 'ac' * 32
        with self.assertRaisesRegex(ValueError, 'c1-distinct-child-exit'):
            capture.colluder_wallet_v2_pair(
                raws, publics,
                [c1_contact_value_source_authority(
                     value, child_exit=same_exit) for value in values])
        duplicate_contact = 'ad' * 32
        duplicate_contact_values = [qualified_colluder_fixture(
            public, contact_authority=duplicate_contact)
            for public in publics]
        with self.assertRaisesRegex(
                ValueError, 'c1-distinct-contact-value-authority'):
            capture.colluder_wallet_v2_pair(
                [raw(value) for value in duplicate_contact_values], publics,
                [c1_contact_value_source_authority(value)
                 for value in duplicate_contact_values])
        with self.assertRaisesRegex(ValueError, 'c1-common-source-closure'):
            capture.colluder_wallet_v2_pair(
                raws, publics,
                [c1_contact_value_source_authority(values[0]),
                 c1_contact_value_source_authority(
                     values[1], role_closure='d1' * 32)])

        # Replaying either consumed authority and a body/event rebind both fail.
        with self.assertRaisesRegex(ValueError, 'c1-source-authority-replay'):
            capture.colluder_wallet_v2_pair(raws, publics, authorities)
        changed = copy.deepcopy(values)
        changed[0]['invoices'][0]['source'][
            'source_event_binding_sha256'] = 'ff' * 32
        rows = ([{'stream': 'original', **changed[0]['original']}]
            + [{'stream': 'invoice', **row} for row in changed[0]['invoices']]
            + [{'stream': 'decrypted-receipt', **row}
               for row in changed[0]['decrypted_receipts']])
        changed[0]['closure'] = closure(
            rows, sum(len(codec.encoded(row['value'])) for row in rows),
            cohort=changed[0]['cohort_sha256'],
            attempt=changed[0]['closure']['attempt_id'])
        changed_raws = [raw(value) for value in changed]
        with self.assertRaisesRegex(ValueError, 'c1-source-event-binding'):
            capture.colluder_wallet_v2_pair(
                changed_raws, publics,
                [c1_contact_value_source_authority(value)
                 for value in changed])

    def test_colluder_retry_stage_is_preserved_but_not_yet_qualified(self):
        _, public = projection(1)
        value = colluder_fixture(public)
        retry = {'source': {
            'observer_stage': 'invoice', 'stage_sequence': 0,
            'operation_id_sha256': '66' * 32,
            'contact_owner_component': 0,
            'contact_binding_qualified': False,
            'source_event_sequence': 1, 'observed_monotonic_ns': 101,
        }, 'value': {
            'attempt_id': 'invoice_retry_0', 'start_monotonic_ns': 10,
            'complete_monotonic_ns': 11, 'outcome': 'disconnected',
        }}
        value['retry_history'] = [retry]
        records = ([{'stream': 'original', **value['original']}]
            + [{'stream': 'invoice', **row} for row in value['invoices']]
            + [{'stream': 'decrypted-receipt', **row}
               for row in value['decrypted_receipts']]
            + [{'stream': 'retry', **row} for row in value['retry_history']])
        value['closure'] = closure(
            records, sum(len(codec.encoded(row['value'])) for row in records))
        modeled = capture.colluder_wallet(raw(value), public)
        self.assertEqual(modeled['inventory']['retry_count'], 1)
        self.assertIn({
            'category': 'retry-history',
            'field_path': 'retry_history[].source_and_value',
            'status': 'unmodeled', 'constraint_count': 0,
            'assumption_sha256': None,
        }, modeled['leakage_ledger'])
        self.assertEqual(capture._unmodeled_resolution(
            'colluder-wallet-capture', 'retry-history',
            'retry_history[].source_and_value'), {
                'status': 'unmodeled',
                'proposed_resolution':
                    'measured_failure_mapping_dependent',
                'evidence_requirement':
                    'COMPLETE_MULTIATTEMPT_WORKLOAD_JOIN',
                'mapping_dependent': True,
                'coverage_relabel_allowed': False,
            })

    def test_colluder_source_envelope_cannot_be_dropped_or_relabelled(self):
        _, public = projection(1)
        base = colluder_fixture(public)

        def reclose(value):
            records = ([{'stream': 'original', **value['original']}]
                + [{'stream': 'invoice', **row}
                   for row in value['invoices']]
                + [{'stream': 'decrypted-receipt', **row}
                   for row in value['decrypted_receipts']]
                + [{'stream': 'retry', **row}
                   for row in value['retry_history']])
            value['closure'] = closure(
                records,
                sum(len(codec.encoded(row['value'])) for row in records))

        mutations = (
            ('legacy-no-source', lambda row: row['invoices'][0].pop('source')),
            ('missing-stage', lambda row: row['invoices'][0]['source'].pop(
                'observer_stage')),
            ('stage', lambda row: row['invoices'][0]['source'].__setitem__(
                'observer_stage', 'scan')),
            ('stage-sequence', lambda row: row['invoices'][0]['source']
                .__setitem__('stage_sequence', 2)),
            ('operation', lambda row: row['invoices'][0]['source'].__setitem__(
                'operation_id_sha256', '65' * 32)),
            ('contact', lambda row: row['invoices'][0]['source'].__setitem__(
                'contact_owner_component', 2)),
            ('qualification', lambda row: row['invoices'][0]['source']
                .__setitem__('contact_binding_qualified', True)),
            ('source-sequence', lambda row: row['invoices'][0]['source']
                .__setitem__('source_event_sequence', 3)),
            ('time-order', lambda row: row['invoices'][0]['source'].__setitem__(
                'observed_monotonic_ns', 202)),
            ('accepted-operation', lambda row: row['invoices'][1]['value']
                .__setitem__('operation_id_sha256', '77' * 32)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                changed = copy.deepcopy(base)
                mutate(changed)
                reclose(changed)
                with self.assertRaises(ValueError):
                    capture.colluder_wallet(raw(changed), public)

    def test_corrupt_server_unknown_or_missing_lane_never_becomes_modeled(self):
        projection_bytes, public = projection(1)
        missing = corrupt_fixture(public, projection_bytes)
        missing['records'] = [row for row in missing['records']
                              if row['semantic'] != 'mac-share']
        for index, row in enumerate(missing['records']): row['sequence'] = index
        with self.assertRaises(ValueError):
            capture.corrupt_server(raw(missing), public, projection_bytes)
        unknown = corrupt_fixture(public, projection_bytes)
        unknown['records'][0]['semantic'] = 'opaque-new-lane'
        with self.assertRaises(ValueError):
            capture.corrupt_server(raw(unknown), public, projection_bytes)

    def test_terminal_whole_aggregate_vs_transparent_nf_pair_grouping(self):
        _, public = projection(1)
        hidden = capture.terminal(raw(terminal_fixture(public)), public)
        self.assertTrue(hidden['terminal_modeled'])
        self.assertEqual(set(hidden['categories']), capture.TERMINAL_CATEGORIES)
        self.assertEqual(hidden['constraints'], codec.empty_constraints())
        transparent = capture.terminal(
            raw(terminal_fixture(public, transparent=True)), public)
        self.assertEqual(len(transparent['constraints']['nf_pair_edges']), 3)
        self.assertEqual(len(transparent['constraints']['input_edges']), 3)
        self.assertEqual(len(transparent['constraints']['creator_edges']), 6)
        model = codec.assignments(public, transparent['constraints'])
        self.assertEqual(model['joint_candidates'], 1)

    def test_terminal_incomplete_grouping_or_history_refuses(self):
        _, public = projection(1)
        missing = terminal_fixture(public)
        missing['groups'][0]['tuple_sha256'].pop()
        with self.assertRaises(ValueError): capture.terminal(raw(missing), public)
        missing = terminal_fixture(public); missing['events'].pop(1)
        missing['events'][1]['sequence'] = 1
        with self.assertRaises(ValueError): capture.terminal(raw(missing), public)
        amount = terminal_fixture(public)
        amount['amount_observations'] = [{'amount_sompi': 5_000_000}]
        with self.assertRaises(ValueError): capture.terminal(raw(amount), public)
        retry = terminal_fixture(public)
        retry['retry_history'] = [{'attempt_id': 'changed-cohort',
            'outcome': 'refused', 'candidate_sha256': '88' * 32}]
        retry['rejected_or_orphaned'] = [{
            'candidate_sha256': '88' * 32, 'status': 'rejected'}]
        with self.assertRaises(ValueError): capture.terminal(raw(retry), public)

    def test_view_union_is_derived_not_caller_selected(self):
        projection_bytes, public = projection(1)
        artifacts = [
            capture.public_projection(projection_bytes, public),
            capture.terminal(raw(terminal_fixture(public)), public),
            capture.dispatcher(raw(dispatcher_fixture(public)), public),
            capture.corrupt_server(raw(corrupt_fixture(
                public, projection_bytes)), public, projection_bytes),
            capture.colluder_wallet(raw(colluder_fixture(public)), public),
        ]
        derived = capture.derive_view_artifacts(public, artifacts)
        views = derived['views']
        self.assertEqual(len(views['public']['artifact_sha256']), 2)
        self.assertEqual(len(views['dispatcher']['artifact_sha256']), 3)
        self.assertEqual(len(views['corrupt-server-plus-wallet'][
            'artifact_sha256']), 4)
        self.assertEqual(len(views['union']['artifact_sha256']), 5)
        self.assertEqual(set(views['union']['categories']),
            capture.PUBLIC_CATEGORIES | capture.DISPATCHER_CATEGORIES
            | capture.SERVER_CATEGORIES | capture.COLLUDER_CATEGORIES)
        self.assertTrue(derived['lattice_attestation'][
            'exact_union_artifact_set'])
        with self.assertRaises(ValueError):
            capture.derive_view_artifacts(public, artifacts[:-1])
        selected = copy.deepcopy(artifacts)
        selected[-1]['categories'].remove('colluder-original')
        with self.assertRaises(ValueError):
            capture.derive_view_artifacts(public, selected)

    def test_every_unmodeled_field_has_a_private_fail_closed_resolution(self):
        projection_bytes, public = projection(1)
        artifacts = [
            capture.public_projection(projection_bytes, public),
            capture.terminal(raw(terminal_fixture(public)), public),
            capture.dispatcher(raw(dispatcher_fixture(public)), public),
            capture.corrupt_server(raw(corrupt_fixture(
                public, projection_bytes)), public, projection_bytes),
            capture.colluder_wallet(raw(colluder_fixture(public)), public),
        ]
        derived = capture.derive_view_artifacts(public, artifacts)
        for view, modeled in derived['views'].items():
            inventory = modeled['unmodeled_inventory']
            self.assertEqual(inventory['schema'],
                'kpb-private-unmodeled-field-inventory/v1')
            self.assertEqual(inventory['view'], view)
            self.assertEqual(inventory['missing_artifacts'], [])
            self.assertEqual(inventory['missing_artifact_count'], 0)
            self.assertEqual(inventory['unmodeled_artifact_count'],
                             modeled['unmodeled_artifact_count'])
            rows = [field for artifact in inventory['unmodeled_artifacts']
                    for field in artifact['fields']]
            self.assertEqual(inventory['unmodeled_field_count'], len(rows))
            self.assertEqual(len(inventory['unmodeled_artifacts']),
                             modeled['unmodeled_artifact_count'])
            for artifact in inventory['unmodeled_artifacts']:
                self.assertIn(artifact['raw_typed_leaf_kind'],
                              capture.ARTIFACT_CATEGORIES)
                self.assertEqual(artifact['typed_artifact_schema'],
                                 'kpb-typed-capture-artifact-model/v2')
                self.assertTrue(artifact['fields'])
                for field in artifact['fields']:
                    self.assertEqual(field['status'], 'unmodeled')
                    self.assertIn(field['proposed_resolution'], (
                        'direct_constraint_pending_source_authority',
                        'source_assumption_pending_selection',
                        'measured_failure_mapping_dependent'))
                    self.assertFalse(field['coverage_relabel_allowed'])
                    self.assertRegex(field['evidence_requirement'],
                                     r'^[A-Z0-9_]+$')
                    self.assertEqual(
                        field['mapping_dependent'],
                        field['proposed_resolution'] ==
                            'measured_failure_mapping_dependent')

        union = derived['views']['union']['unmodeled_inventory']
        by_path = {(artifact['raw_typed_leaf_kind'], field['field_path']):
                   field
                   for artifact in union['unmodeled_artifacts']
                   for field in artifact['fields']}
        self.assertEqual(by_path[(
            'dispatcher-capture',
            'events[outbound-route].route_sha256')][
                'proposed_resolution'],
            'direct_constraint_pending_source_authority')
        self.assertEqual(by_path[(
            'corrupt-server-capture',
            'records[mascot-message].payload.nonliteral_implications')][
                'proposed_resolution'],
            'source_assumption_pending_selection')
        self.assertEqual(by_path[(
            'terminal-history',
            'groups[].owner_nf_tuple_membership')][
                'proposed_resolution'],
            'measured_failure_mapping_dependent')

    def test_private_completion_summary_refuses_any_open_field(self):
        publics = []; artifact_rounds = []
        for number in (1, 2):
            projection_bytes, public = projection(number)
            publics.append(public)
            artifact_rounds.append([
                capture.public_projection(projection_bytes, public),
                capture.terminal(raw(terminal_fixture(public)), public),
                capture.dispatcher(raw(dispatcher_fixture(public)), public),
                capture.corrupt_server(raw(corrupt_fixture(
                    public, projection_bytes)), public, projection_bytes),
                capture.colluder_wallet(raw(colluder_fixture(public)), public),
            ])
        summary = capture._private_completion_coverage_summary(
            publics, artifact_rounds)
        self.assertEqual(summary['schema'],
                         'kpb-private-four-view-coverage-summary/v1')
        self.assertTrue(summary['exact_ten_typed_leaves'])
        self.assertTrue(summary['exhaustive_lattice'])
        self.assertFalse(summary['completion_ready'])
        self.assertEqual([row['view_index'] for row in summary['views']],
                         [0, 1, 2, 3])
        for row in summary['views']:
            self.assertGreaterEqual(row['candidate_count'], 1)
            self.assertLessEqual(row['candidate_count'], 540 * 540)
            self.assertEqual(row['missing_artifact_count'], 0)
            self.assertGreater(row['unmodeled_field_count'], 0)
            self.assertEqual(row['source_assumption_mask'], 0)
            self.assertFalse(row['all_candidate_edges_covered'])
        self.assertEqual(set(summary), {
            'schema', 'views', 'exact_ten_typed_leaves',
            'exhaustive_lattice', 'completion_ready'})
        with self.assertRaisesRegex(
                ValueError, 'private-completion-unmodeled-or-missing'):
            capture.require_private_completion_coverage(
                publics, artifact_rounds)

        # Public counts/booleans and opaque caller values cannot stand in for
        # the one-shot child-memory authority returned only by the exact gate.
        substitutes = (
            summary,
            True,
            {'completion_ready': True,
             'exact_ten_typed_leaves': True,
             'exhaustive_lattice': True,
             'views': [{'all_candidate_edges_covered': True}] * 4},
            'ab' * 32,
            object(),
        )
        for substitute in substitutes:
            with self.subTest(substitute=type(substitute).__name__):
                with self.assertRaisesRegex(
                        ValueError, 'private-completion-authority-type'):
                    capture.consume_private_completion_coverage_for_prediction(
                        substitute, publics, artifact_rounds)
        with self.assertRaisesRegex(
                ValueError, 'private-completion-authority-constructor'):
            capture._PrivateCompletionCoverageAuthority(
                object(), 'aa' * 32)
        # Even hostile Python reflection that manufactures the exact runtime
        # type cannot bypass the fresh ten-leaf recomputation or turn public
        # completion booleans/counts into authority.
        forged = object.__new__(capture._PrivateCompletionCoverageAuthority)
        forged._input_identity = hashlib.sha256(
            codec.encoded(summary)).hexdigest()
        forged._live = True
        with self.assertRaisesRegex(
                ValueError, 'private-completion-authority-binding'):
            capture.consume_private_completion_coverage_for_prediction(
                forged, publics, artifact_rounds)

    def test_private_open_fields_are_grouped_by_exact_missing_authority(self):
        import privacy_capture_producer as producer
        from test_privacy_capture_producer import p1_channel, selection

        selected = selection()
        roles = selected['role_launch_closure']
        roles_sha256 = hashlib.sha256(codec.encoded(roles)).hexdigest()
        projection_raws, publics = continuous_projection_pair()
        for financial, public in zip(selected['financial_rounds'], publics):
            financial['retained_projection_sha256'] = \
                public['projection_sha256']
        structural = capture.public_projection_pair(projection_raws, publics)
        artifact_rounds = []
        colluder_values = []
        for number in (1, 2):
            round_row = selected['rounds'][number - 1]
            attempt = round_row['attempt_id']
            cohort = round_row['cohort_sha256']
            projection_bytes = projection_raws[number - 1]
            public = publics[number - 1]
            wire = c03_with_projection(
                p1_channel(number, selected), projection_bytes)
            with tempfile.TemporaryFile() as channel:
                channel.write(wire)
                channel.seek(0)
                _, closure_value = producer._consume_p1(
                    channel.fileno(), selected, number)
            authority = producer._p1_capture_authority(
                selected, number, closure_value)
            terminal_value = terminal_fixture(public)
            colluder_value = qualified_colluder_fixture(
                public, cohort_sha256=cohort, attempt_id=attempt)
            for value in (terminal_value,):
                value['closure']['attempt_id'] = attempt
                value['closure']['cohort_sha256'] = cohort
                if 'cohort_sha256' in value:
                    value['cohort_sha256'] = cohort
            dispatcher_value = dispatcher_fixture(
                public, cohort_sha256=cohort,
                run_sha256=selected['financial_rounds'][number - 1][
                    'financial_run_id'])
            dispatcher_value['closure']['attempt_id'] = attempt
            artifact_rounds.append([
                structural[number - 1],
                capture.terminal(raw(terminal_value), public),
                capture.dispatcher(
                    raw(dispatcher_value), public,
                    dispatcher_source_authority(dispatcher_value)),
                capture.corrupt_server_c03(
                    wire, public, projection_bytes, authority,
                    roles, roles_sha256),
            ])
            colluder_values.append(colluder_value)

        colluder_models = capture.colluder_wallet_v2_pair(
            [raw(value) for value in colluder_values], publics,
            [c1_contact_value_source_authority(
                 value, role_closure=roles_sha256)
             for value in colluder_values])
        for artifacts, colluder_model in zip(artifact_rounds,
                                             colluder_models):
            artifacts.append(colluder_model)

        summary = capture._private_completion_coverage_summary(
            publics, artifact_rounds)
        self.assertEqual(
            [row['unmodeled_field_count'] for row in summary['views']],
            [46, 58, 102, 114])
        self.assertEqual([row['candidate_count'] for row in summary['views']],
                         [291600, 291600, 36, 36])
        self.assertFalse(summary['completion_ready'])
        grouped = capture._private_open_fields_by_missing_authority(
            publics, artifact_rounds)
        self.assertEqual(grouped['open_field_occurrence_count'], 114)
        self.assertFalse(grouped['authorizes_coverage'])
        by_requirement = {
            row['missing_authority_or_assumption']: row['open_fields']
            for row in grouped['groups']}
        self.assertEqual(len(by_requirement[
            'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PRIVATE_V2_LEAF'
        ]), 2)
        self.assertEqual(len(by_requirement[
            'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PUBLIC_CONTINUITY_JOIN'
        ]), 2)
        self.assertEqual(len(by_requirement[
            'WITHIN_RUN_PUBLIC_CIPHERTEXT_CANDIDATE_FILTER']), 8)
        self.assertEqual(len(by_requirement[
            'AUTHENTICATED_HONEST_OUTPUT_ENCRYPTION_PRODUCER_AUTHORITY']), 2)
        self.assertEqual(len(by_requirement[
            'COMPLETE_PUBLIC_MULTIATTEMPT_NF_EQUALITY_JOIN']), 2)
        self.assertEqual(len(by_requirement[
            'PUBLIC_NF_HISTORY_EDGE_CANDIDATE_FILTER']), 2)
        self.assertEqual(len(by_requirement[
            'COMPLETE_PUBLIC_MULTIATTEMPT_HISTORY_EQUALITY_JOIN']), 2)
        self.assertEqual(len(by_requirement[
            'LIVE_STRUCTURAL_PROJECTION_CONTINUITY_RESIDUAL_AND_WORKLOAD_JOIN'
        ]), 4)
        self.assertEqual(len(by_requirement[
            'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY']), 4)
        self.assertNotIn(
            'AUTHENTICATED_C1_CONTACT_AND_VALUE_BINDING', by_requirement)
        self.assertNotIn(
            'AUTHENTICATED_C1_SOURCE_PROVENANCE', by_requirement)
        self.assertNotIn(
            'AUTHENTICATED_CONSTRUCTION_POLICY_MAPPING', by_requirement)
        self.assertTrue(all(
            field['field_path'] !=
                'release_order_policy_and_direct_exports'
            for group in grouped['groups']
            for field in group['open_fields']))

    def test_two_round_join_recomputes_models_and_applies_cross_round_link(self):
        _, first = projection(1); _, second = projection(2)
        models = [codec.assignments(first, codec.empty_constraints()),
                  codec.assignments(second, codec.empty_constraints())]
        terminals = [capture.terminal(raw(terminal_fixture(first)), first),
                     capture.terminal(raw(terminal_fixture(second)), second)]
        unconstrained = capture.workload_candidates(models, terminals)
        self.assertEqual(unconstrained['workload_joint_candidates'], 540 * 540)
        self.assertEqual(len(unconstrained['joint']), 540 * 540)
        self.assertEqual(unconstrained['full_workload_candidates'],
                         len(unconstrained['joint']))
        link = {'input_round': 2, 'nf_hex32': second['nfs_hex32'][0],
                'output_round': 1, 'tuple_sha256': first['tuple_sha256'][0],
                'provenance': 'terminal-linkage'}
        second_terminal = terminal_fixture(second)
        second_terminal['cross_round_links'] = [link]
        records = ([{'stream': 'event', 'value': row}
                    for row in second_terminal['events']]
            + [{'stream': 'group', 'value': row}
               for row in second_terminal['groups']]
            + [{'stream': 'cross-round-link', 'value': link}])
        second_terminal['closure'] = closure(
            records, sum(len(codec.encoded(row['value'])) for row in records))
        linked_terminals = [terminals[0], capture.terminal(
            raw(second_terminal), second)]
        constrained = capture.workload_candidates(models, linked_terminals)
        self.assertLess(constrained['workload_joint_candidates'],
                        unconstrained['workload_joint_candidates'])
        self.assertNotEqual(constrained['candidate_set_commitment_sha256'],
                            unconstrained['candidate_set_commitment_sha256'])
        changed = copy.deepcopy(models); changed[0]['joint'].pop()
        with self.assertRaises(ValueError):
            capture.workload_candidates(changed, terminals)
        with self.assertRaises(ValueError):
            capture.workload_candidates(models, [link])

    def test_unqualified_contact_is_not_injected_as_a_creator_fact(self):
        publics = [projection(1)[1], projection(2)[1]]
        models = [codec.assignments(public, capture.colluder_wallet(
            raw(colluder_fixture(public)), public)['constraints'])
            for public in publics]
        truth_inputs = ([0, 1, 2], [0, 1, 2])
        truth_outputs = ([0, 0, 1, 1, 2, 2],
                         [2, 2, 1, 1, 0, 0])
        alternative_indices = []
        for model, inputs, outputs in zip(models, truth_inputs, truth_outputs):
            truth = {'inputs': list(inputs), 'outputs': list(outputs)}
            self.assertIn(truth, model['joint'])
            global_swap = {'inputs': [2 - label if label != 1 else 1
                                      for label in inputs],
                           'outputs': [2 - label if label != 1 else 1
                                       for label in outputs]}
            # The current C1 source explicitly says its contact label is only a
            # controller instruction.  It may not collapse the candidate set
            # until an authenticated peer endpoint binds the contact.
            self.assertIn(global_swap, model['joint'])
            truth_pairs = {
                owner: tuple(index for index, label in enumerate(outputs)
                             if label == owner) for owner in (0, 2)}
            eligible = []
            for index, candidate in enumerate(model['joint']):
                if not all(candidate['inputs'][inputs.index(owner)] == 2 - owner
                           for owner in (0, 2)):
                    continue
                if not all(tuple(index for index, label in
                                 enumerate(candidate['outputs'])
                                 if label == 2 - owner) != truth_pairs[owner]
                           for owner in (0, 2)):
                    continue
                eligible.append(index)
            self.assertTrue(eligible)
            alternative_indices.append(set(eligible))

        terminals = [capture.terminal(raw(terminal_fixture(public)), public)
                     for public in publics]
        workload = capture.workload_candidates(models, terminals)
        self.assertTrue(any(left in alternative_indices[0]
                            and right in alternative_indices[1]
                            for left, right in workload['joint']))

    def test_observer_collect_models_only_the_exact_typed_capture_chain(self):
        projection_bytes, public = projection(1)
        dispatcher_bytes = raw(dispatcher_fixture(public))
        terminal_bytes = raw(terminal_fixture(public))
        model, coverage = observer.collect(public, [
            ('public-projection', projection_bytes, None),
            ('dispatcher-capture', dispatcher_bytes, None),
            ('terminal-history', terminal_bytes, None),
        ])
        self.assertEqual(coverage, {'modeled_artifacts': 3,
            'unmodeled_artifacts': 0, 'missing_artifacts': 0,
            'terminal_modeled': True})
        self.assertEqual(model['constraints'], codec.empty_constraints())

        _, legacy = observer.collect(public, [
            ('public-projection', projection_bytes, None),
            ('dispatcher-metadata', dispatcher_bytes, None),
            ('terminal-raw', terminal_bytes, None),
        ])
        self.assertEqual(legacy['unmodeled_artifacts'], 2)
        self.assertFalse(legacy['terminal_modeled'])


if __name__ == '__main__':
    unittest.main()

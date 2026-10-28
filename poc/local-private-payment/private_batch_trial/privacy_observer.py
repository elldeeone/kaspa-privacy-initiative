"""Direct-fact observer adapters; never an opaque-transcript privacy proof.

The colluder adapter reuses the existing scorer's legitimate incoming receipt
and authenticated invoice knowledge. Unsupported metadata/private transcripts
are explicitly unmodeled, even when no literal direct leak was recognized.
"""
import hashlib

import privacy_codec as codec


def batch_from_projection(round_number, raw):
    codec.need(type(raw) is bytes and len(raw) == 10685 and raw[:8] == b'KPBAFX01'
               and raw[193:201] == b'KPBAEF01', 'privacy-selected-actual-public-projection')
    body = raw[193:]
    value = {'round': round_number, 'projection_sha256': hashlib.sha256(raw).hexdigest(),
        'context_sha256': hashlib.sha256(body[8:284]).hexdigest(),
        'nfs_hex32': [body[404 + i * 96:436 + i * 96].hex() for i in range(3)],
        'cms_hex32': [body[692 + i * 520:724 + i * 520].hex() for i in range(6)],
        'tuple_sha256': [hashlib.sha256(body[692 + i * 520:692 + (i + 1) * 520]).hexdigest() for i in range(6)]}
    return codec.batch(value)


def merge(*values):
    result = codec.empty_constraints()
    for value in values:
        for name in ('input_edges', 'creator_edges', 'pair_edges'):
            result[name].extend(edge for edge in value[name] if edge not in result[name])
        result['individual_delta_exports'] += value['individual_delta_exports']
    return result


def route_record(value):
    codec.fields(value, ('schema', 'round', 'source_owner_component', 'target_owner_component',
        'invoice_leaf_path', 'source_operation_id', 'target_invoice_operation_id',
        'launch_monotonic_ns', 'complete_monotonic_ns', 'worker_returncode'))
    codec.need(value['schema'] == 'kpb-observed-invoice-route/v1' and type(value['round']) is int
               and value['round'] in (1, 2), 'privacy-actual-invoice-route-schema')
    codec.owner(value['source_owner_component']); codec.owner(value['target_owner_component'])
    codec.need(type(value['invoice_leaf_path']) is str and value['invoice_leaf_path'].endswith('/INVOICE208.bin')
               and type(value['source_operation_id']) is str and bool(value['source_operation_id'])
               and type(value['target_invoice_operation_id']) is str and bool(value['target_invoice_operation_id']),
               'privacy-retained-actual-route-metadata')
    codec.need(type(value['launch_monotonic_ns']) is int and value['launch_monotonic_ns'] >= 0
               and type(value['complete_monotonic_ns']) is int
               and value['complete_monotonic_ns'] >= value['launch_monotonic_ns']
               and type(value['worker_returncode']) is int, 'privacy-actual-route-timing-and-outcome')
    return value


def colluder_facts(receiver, own_record, round_number, raw_projection, actual_routes):
    """Call inside the colluder role with its actual Original and own record.

    No honest record, key or truth is accepted. Source-selected trusted invoice
    routing, not ciphertext alone, supplies the fixed counterparty identity.
    """
    import wallet_profile as wallet
    codec.need(own_record.get('owner_component') == 1 and type(round_number) is int
               and round_number in (1, 2), 'privacy-actual-declared-colluder')
    codec.need(type(actual_routes) is list and len(actual_routes) == 3, 'privacy-complete-actual-IPC-routes')
    routes = [route_record(value) for value in actual_routes]
    codec.need(all(route['round'] == round_number for route in routes)
               and sorted(route['source_owner_component'] for route in routes) == [0, 1, 2]
               and all(route['target_owner_component'] == (route['source_owner_component'] + round_number) % 3
                       for route in routes), 'privacy-actual-route-matches-frozen-workload')
    incoming_sender = next(route['source_owner_component'] for route in routes if route['target_owner_component'] == 1)
    public = batch_from_projection(round_number, raw_projection)
    nf = own_record['input']['nf_hex32']
    codec.word(nf); codec.need(nf in public['nfs_hex32'], 'privacy-colluder-input-in-actual-batch')
    result = codec.empty_constraints()
    result['input_edges'].append({'owner_component': 1, 'slot_id': nf, 'provenance': 'colluder-knowledge'})
    body = raw_projection[193:]
    rows = [body[692 + i * 520:692 + (i + 1) * 520] for i in range(6)]
    own_outputs = own_record['outputs']
    codec.need(type(own_outputs) is list and len(own_outputs) == 2, 'privacy-two-real-colluder-created-outputs')
    created = []
    for own in own_outputs:
        row = bytes.fromhex(own['tuple_hex520'])
        codec.need(len(row) == 520 and rows.count(row) == 1, 'privacy-colluder-created-tuple-join')
        # Payment to another owner need not decrypt. The complete tuple itself
        # is authentic local creation knowledge in this selected private record.
        digest = hashlib.sha256(row).hexdigest(); created.append(digest)
        result['creator_edges'].append({'owner_component': 1, 'slot_id': digest, 'provenance': 'colluder-knowledge'})
    codec.need(len(set(created)) == 2, 'privacy-distinct-colluder-created-pair')
    received = 0
    for row in rows:
        try:
            receipt = receiver.open(row[96:360])
        except wallet.Invalid as error:
            # The selected wallet exposes only its fixed unseal refusal here;
            # any malformed owned descriptor is not silently ignored.
            if str(error) == 'crypto-unseal':
                continue
            raise
        codec.need(receipt.commitment() == row[:32], 'privacy-colluder-decrypted-CM')
        if receipt.index == 2 * round_number - 1:
            received += 1
            result['creator_edges'].append({'owner_component': incoming_sender,
                'slot_id': hashlib.sha256(row).hexdigest(), 'provenance': 'colluder-knowledge'})
        else:
            codec.need(receipt.index == 2 * round_number
                       and hashlib.sha256(row).hexdigest() in created, 'privacy-colluder-selected-receipt-schedule')
    codec.need(received == 1, 'privacy-complete-actual-incoming-colluder-view')
    codec.constraints(result, public)
    return result


def extract_json(raw, public, *, route_owner=None, legitimate_colluder_view=False):
    """Recognize literal labelled NF/tuple/pair/Delta exports.

    Recognizing a leak does not make an otherwise unknown artifact completely
    modeled. The returned Boolean denotes the narrow complete schema below.
    """
    result = codec.empty_constraints()
    try:
        value = codec.parse(raw)
    except (ValueError, TypeError, UnicodeError):
        return result, False
    pair_tags = {}
    def visit(item, inherited=None):
        if type(item) is list:
            for child in item: visit(child, inherited)
            return
        if type(item) is not dict:
            return
        component = item.get('owner_component', item.get('owner_slot', item.get('creator_component', inherited)))
        valid_owner = type(component) is int and component in codec.OWNERS
        if valid_owner:
            for key in ('nf_hex32', 'input_nf_hex32'):
                if item.get(key) in public['nfs_hex32']:
                    result['input_edges'].append({'owner_component': component, 'slot_id': item[key], 'provenance': 'direct-export'})
            digest = item.get('tuple_sha256')
            if type(item.get('tuple_hex520')) is str:
                try:
                    row = bytes.fromhex(item['tuple_hex520'])
                    if len(row) == 520: digest = hashlib.sha256(row).hexdigest()
                except ValueError:
                    pass
            if digest in public['tuple_sha256']:
                result['creator_edges'].append({'owner_component': component, 'slot_id': digest, 'provenance': 'direct-export'})
        if any(key in item for key in ('private_delta_hex32', 'individual_delta_hex32', 'delta_i_hex32')) \
                and not (legitimate_colluder_view and component == 1):
            result['individual_delta_exports'] += 1
        digest = item.get('tuple_sha256')
        if digest in public['tuple_sha256']:
            for key in ('pair_tag', 'pair_tag_hex32', 'creator_pair_tag'):
                tag = item.get(key)
                if type(tag) is str:
                    pair_tags.setdefault(tag, set()).add(digest)
        pair = item.get('pair_tuple_sha256')
        if type(pair) is list and all(type(part) is str for part in pair) and len(pair) == len(set(pair)) == 2 and all(part in public['tuple_sha256'] for part in pair):
            result['pair_edges'].append({'tuple_sha256': pair, 'provenance': 'pair-tag-export'})
        for child in item.values(): visit(child, component if valid_owner else inherited)
    visit(value, route_owner)
    for grouped in pair_tags.values():
        if len(grouped) == 2:
            result['pair_edges'].append({'tuple_sha256': sorted(grouped), 'provenance': 'pair-tag-export'})
    # Only the exact public control format is complete here. Actual unknown
    # dispatcher schemas still get useful leak extraction plus UNQUALIFIED.
    complete = False
    if type(value) is dict and value.get('schema') == 'kpb-direct-export-model-control/v1':
        codec.fields(value, ('schema', 'scope', 'exports'))
        codec.need(value['scope'] == 'SYNTHETIC_OBSERVER_CONTROL' and type(value['exports']) is list,
                   'privacy-explicit-model-control-scope')
        complete = True
    if type(value) is dict and value.get('schema') == 'kpb-observed-invoice-route/v1':
        route_record(value)
        complete = True
    codec.constraints(result, public)
    return result, complete


def collect(public, artifacts, colluder=None):
    """Artifacts are actual selected bytes read inside the observer role.

    Each tuple is (kind, rawbytes, optional routed owner). The launcher must
    mount the full declared captured view. Unknown raw server and terminal
    material remains unqualified; no ``complete`` caller flag is accepted.
    """
    result = codec.empty_constraints() if colluder is None else colluder
    modeled = unmodeled = 0
    for kind, raw, route_owner in artifacts:
        if kind == 'public-projection':
            codec.need(batch_from_projection(public['round'], raw) == public, 'privacy-exact-public-view-batch')
            modeled += 1
            continue
        if kind in ('colluder-original', 'colluder-own-record', 'colluder-raw'):
            # These secrets are legitimately supplied by the declared colluder.
            # The qualified owner adapter records their direct knowledge. Their
            # remaining cryptographic implications are unmodeled, not forbidden
            # honest-owner exports merely because their keys/fields exist.
            unmodeled += 1
            continue
        extracted, complete = extract_json(raw, public, route_owner=route_owner,
                                            legitimate_colluder_view=kind == 'corrupt-server-raw')
        if kind == 'corrupt-server-raw' and colluder is not None:
            for name in ('input_edges', 'creator_edges'):
                for edge in extracted[name]:
                    if any(edge['owner_component'] == known['owner_component'] and edge['slot_id'] == known['slot_id']
                           for known in colluder[name]):
                        edge['provenance'] = 'colluder-knowledge'
        result = merge(result, extracted)
        if kind in ('synthetic-control', 'invoice-route') and complete:
            modeled += 1
        else:
            # Actual corrupt-server transcripts/MAC state and terminal economic
            # constraints are not qualified by this literal JSON strategy.
            unmodeled += 1
    return codec.assignments(public, result), {'modeled_artifacts': modeled, 'unmodeled_artifacts': unmodeled,
        'missing_artifacts': int(not artifacts), 'terminal_modeled': False}

"""Closed METHOD02 view observation and post-seal scoring.

Only the trusted source-pinned launcher may invoke these network-off roles.
CONTACT never receives the labelled release catalog. Private contacts, salts and
model assignments stay in protected leaves; public outputs contain commitments
and counts only. This finite linkage experiment supplies no cryptographic,
chain/backing or complete dispatcher/server privacy qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

import payout_privacy_attack as attack

METHOD = 'dc5026741ccc3bf8d19105a1528257d6934ed76877ec1fc3fe19e3e2b586834d'
ATTACK = '06282c791f5c8ca6ddb90e1ca0147a4bc0dc90639efb887bbd621b3a7d677089'
VIEWS = ('CONTACT', 'DISPATCHER', 'UNION')
ARMS = ('A', 'B')
OPERATIONS = ('contact-observe', 'dispatcher-observe', 'union-observe', 'postseal-score')
TAG = b'KPB_METHOD02_PAYOUT_PREDICTION_V1\0'
need = attack.need


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'method02-exact-fields')


def word(value):
    need(type(value) is str and len(value) == 64
         and all(c in '0123456789abcdef' for c in value), 'method02-sha256')
    return value


def hexbytes(value, size):
    need(type(value) is str and len(value) == size * 2
         and all(c in '0123456789abcdef' for c in value), 'method02-canonical-fixed-hex')
    return bytes.fromhex(value)


def binding(value):
    fields(value, ('method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'))
    need(value['method_sha256'] == METHOD and value['phase'] == 'private-payout-linkage-02'
         and all(type(value[k]) is str and bool(value[k]) for k in ('trial_id', 'attempt_id')),
         'method02-frozen-binding')
    word(value['selection_sha256'])
    return value


def stable_read(path, expected=None, private_mode=None):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'method02-finite-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(),
             'method02-owned-single-link-regular-leaf')
        if private_mode is not None:
            need(stat.S_IMODE(before.st_mode) == private_mode, 'method02-private-leaf-mode')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        need(identity(before) == identity(after) and len(raw) == before.st_size, 'method02-stable-leaf')
    if expected is not None:
        need(hashlib.sha256(raw).hexdigest() == word(expected), 'method02-selected-public-leaf')
    return raw


def parse(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'method02-no-duplicate-json-fields')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('method02-json-number')))


def write_new(path, value, mode=0o400):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'method02-nonsymlink-output')
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return raw


def require_namespace(operation):
    marker = parse(stable_read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-method02-observer-namespace/v1', 'operation': operation,
                    'network': 'disabled', 'Original_slots': 0}, 'method02-closed-observer-role')
    interfaces = [line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'] and all(not Path(p).exists() for p in (
        '/original', '/truth', '/home/luke/.codex', '/home/luke/.ssh',
        '/var/tmp/kpi-owner-private-lifecycle-01/private')), 'method02-no-network-Original-or-truth')
    if operation == 'contact-observe':
        need(not Path('/public/DISPATCHER.json').exists() and not Path('/predictions').exists()
             and not Path('/seals').exists(), 'method02-contact-without-labelled-release')
    if operation == 'dispatcher-observe':
        need(not Path('/contact').exists(), 'method02-dispatcher-without-private-contact')
    if operation == 'postseal-score':
        need(not Path('/contact').exists(), 'method02-score-without-raw-contact')
    config = parse(stable_read('/CONFIG.json'))
    fields(config, ('schema', 'operation', 'binding', 'source_members', 'exits_sha256',
                    'dispatcher_sha256', 'public_facts', 'seals_sha256'))
    need(config['schema'] == 'kpb-method02-payout-role-config/v1'
         and config['operation'] == operation, 'method02-exact-role-config')
    binding(config['binding'])
    word(config['exits_sha256'])
    need(type(config['source_members']) is list and bool(config['source_members']),
         'method02-source-closure')
    selected = {}
    for row in config['source_members']:
        fields(row, ('path', 'sha256'))
        need(row['path'] not in selected, 'method02-distinct-source-members')
        stable_read(row['path'], row['sha256'])
        selected[row['path']] = row['sha256']
    need(selected.get(str(Path(attack.__file__).absolute())) == ATTACK
         and str(Path(__file__).absolute()) in selected
         and str(Path(attack.exit_wire.__file__).absolute()) in selected
         and str(Path(attack.exit_wire.old.__file__).absolute()) in selected,
         'method02-executed-transitive-source-closure')
    fields(config['public_facts'], ARMS)
    for facts in config['public_facts'].values():
        fields(facts, ('economic', 'timing', 'public_identifier_edges', 'unmodeled'))
        need(all(type(v) is list for v in facts.values()), 'method02-public-fact-lists')
    if operation == 'contact-observe':
        need(config['dispatcher_sha256'] is None and config['seals_sha256'] is None,
             'method02-contact-no-truth-selection')
    elif operation == 'postseal-score':
        word(config['dispatcher_sha256'])
        fields(config['seals_sha256'], VIEWS)
        for digest in config['seals_sha256'].values():
            word(digest)
    else:
        word(config['dispatcher_sha256'])
        need(config['seals_sha256'] is None, 'method02-observer-no-scoring-seals')
    return config


def exits(config):
    value = parse(stable_read('/public/EXITS.json', config['exits_sha256']))
    fields(value, ('schema', 'binding', 'arms'))
    need(value['schema'] == 'kpb-method02-unlabelled-exits/v1'
         and value['binding'] == config['binding'], 'method02-actual-unlabelled-exit-binding')
    fields(value['arms'], ARMS)
    raw_arms, universes, nfs, identities = {}, {}, set(), set()
    for arm in ARMS:
        rows = value['arms'][arm]
        need(type(rows) is list and len(rows) == 3, 'method02-three-selected-exits')
        raw_arms[arm], universes[arm], contexts = [], [], set()
        for row in rows:
            fields(row, ('projection_hex', 'proof_hex128', 'statement_hex152', 'exit_id'))
            raw = hexbytes(row['projection_hex'], 1844)
            hexbytes(row['proof_hex128'], 128)
            statement = hexbytes(row['statement_hex152'], 152)
            key = hashlib.sha256(raw).hexdigest()
            need(row['exit_id'] == key and attack.exit_wire.statement(raw) == statement,
                 'method02-exact-projection-statement')
            effect = attack.exit_wire.validate_public(raw)
            need(effect.context.cm_count == 3 and effect.context.nf_count == 1
                 and effect.context.reserve == 6_000_000_000
                 and effect.payout == 199_999_999 and effect.fee == 1,
                 'method02-frozen-economic-and-head-shape')
            identities.add((effect.context.chain, effect.context.pool, effect.context.profile,
                            effect.context.domain, effect.context.service))
            need(effect.nf not in nfs, 'method02-independent-main-arm-nullifiers')
            nfs.add(effect.nf)
            contexts.add(effect.context.encode())
            raw_arms[arm].append(raw); universes[arm].append(key)
        need(len(set(universes[arm])) == 3 and len(contexts) == 1,
             'method02-distinct-exits-common-arm-head')
    need(len(identities) == 1, 'method02-same-public-identity-across-independent-arms')
    return raw_arms, universes


def contact(config):
    value = parse(stable_read('/contact/CONTACT.json', private_mode=0o600))
    fields(value, ('schema', 'binding', 'arms'))
    need(value['schema'] == 'kpb-method02-private-contact-view/v1'
         and value['binding'] == config['binding'], 'method02-private-contact-binding')
    fields(value['arms'], ARMS)
    result = {}
    for arm in ARMS:
        part = value['arms'][arm]
        fields(part, ('contacts', 'own_payouts', 'known_receipts', 'unmodeled'))
        need(type(part['unmodeled']) is list and all(type(x) is str for x in part['unmodeled']),
             'method02-explicit-private-view-coverage')
        converted = []
        for row in part['contacts']:
            fields(row, ('owner', 'native_pk_hex32', 'delivery_pk_hex32', 'invoice_index',
                         'domain_hex32', 'profile_hex32'))
            converted.append({'owner': row['owner'], 'native_pk': hexbytes(row['native_pk_hex32'], 32),
                'delivery_pk': hexbytes(row['delivery_pk_hex32'], 32), 'invoice_index': row['invoice_index'],
                'domain': hexbytes(row['domain_hex32'], 32), 'profile': hexbytes(row['profile_hex32'], 32)})
        need(sorted((r['owner'], r['invoice_index']) for r in converted)
             == [(owner, index) for owner in range(3) for index in (7, 9)],
             'method02-all-six-actual-contact-records')
        own, receipts = [], []
        for row in part['own_payouts']:
            fields(row, ('owner', 'spk_hex36', 'nf_hex32'))
            own.append({'owner': row['owner'], 'spk': hexbytes(row['spk_hex36'], 36),
                        'nf': hexbytes(row['nf_hex32'], 32)})
        need(len(own) == 1 and own[0]['owner'] == 1, 'method02-one-corrupt-own-payout')
        for row in part['known_receipts']:
            fields(row, ('owner', 'rho_hex32', 'cm_hex32', 'value', 'known_consumed'))
            receipts.append({'owner': row['owner'], 'rho': hexbytes(row['rho_hex32'], 32),
                'cm': hexbytes(row['cm_hex32'], 32), 'value': row['value'],
                'known_consumed': row['known_consumed']})
        need(len(receipts) == 1, 'method02-actual-own-created-receipt-retained')
        result[arm] = {'contacts': converted, 'own_payouts': own, 'known_receipts': receipts,
                       'unmodeled': part['unmodeled']}
    return result


def dispatcher(config, universes):
    value = parse(stable_read('/public/DISPATCHER.json', config['dispatcher_sha256']))
    fields(value, ('schema', 'binding', 'arms'))
    need(value['schema'] == 'kpb-method02-actual-release-routes/v1'
         and value['binding'] == config['binding'], 'method02-actual-route-binding')
    fields(value['arms'], ARMS)
    result, truth = {}, {}
    for arm in ARMS:
        rows = value['arms'][arm]
        need(type(rows) is list and len(rows) == 3, 'method02-complete-release-routes')
        routes, by_owner = [], {}
        for row in rows:
            fields(row, ('owner', 'exit_id', 'provenance', 'actual_release_route_ref'))
            need(type(row['owner']) is int and row['owner'] in (0, 1, 2)
                 and row['owner'] not in by_owner and row['exit_id'] in universes[arm]
                 and type(row['provenance']) is str and bool(row['provenance'])
                 and type(row['actual_release_route_ref']) is str and bool(row['actual_release_route_ref']),
                 'method02-complete-actual-release-reference')
            by_owner[row['owner']] = row['exit_id']
            routes.append({'owner': row['owner'], 'exit_id': row['exit_id'],
                           'provenance': row['provenance'] + ':' + row['actual_release_route_ref']})
        need(set(by_owner.values()) == set(universes[arm]), 'method02-exact-route-projection-universe')
        result[arm] = routes
        truth[arm] = [by_owner[owner] for owner in range(3)]
    return result, truth


def model_universe(prediction, universe):
    need(type(prediction['models']) is list
         and all(type(row) in (list, tuple) and len(row) == 3
                 and set(row) == set(universe) for row in prediction['models']),
         'method02-every-model-exact-selected-projection-universe')


def capsule_seal(payload, salt):
    need(type(salt) is bytes and len(salt) == 32, 'method02-private-seal-salt')
    return hashlib.sha256(TAG + salt + encoded(payload)).hexdigest()


def intersect_public_cross_arm_order(raw_arms, universes, facts, initial):
    """The selected generator publishes A/B in the same owner order.

    This is public source knowledge, not withheld owner truth. A native-key
    lookup in A therefore also labels the corresponding B array position.
    Never compare separate-arm counts while omitting this actual join.
    """
    position = {arm: {key: i for i, key in enumerate(universes[arm])} for arm in ARMS}
    joint = [(a, b) for a in initial['A']['models'] for b in initial['B']['models']
             if all(position['A'][a[owner]] == position['B'][b[owner]] for owner in range(3))]
    result = {}
    for arm, policy, index in (('A', 'invoice-native', 0), ('B', 'fresh-self', 1)):
        enriched = dict(facts[arm])
        enriched['public_identifier_edges'] = list(enriched['public_identifier_edges']) + [
            {'owner': owner, 'compatible_exit_ids': sorted({pair[index][owner] for pair in joint}),
             'provenance': 'selected-generator.publish:shared-owner-array-order-across-A-and-B'}
            for owner in range(3)]
        result[arm] = attack.candidates(raw_arms[arm], policy, enriched)
        model_universe(result[arm], universes[arm])
        need({tuple(row) for row in result[arm]['models']}
             == {tuple(pair[index]) for pair in joint},
             'method02-exact-joint-projection-no-marginal-relaxation')
    return result


def observe(config, view):
    raw_arms, universes = exits(config)
    write_new('/state/OBSERVATION-CLOSED', {'binding': config['binding'], 'view': view})
    contacts = contact(config) if view in ('CONTACT', 'UNION') else None
    routes = dispatcher(config, universes)[0] if view in ('DISPATCHER', 'UNION') else None
    predictions, all_facts, diagnostics = {}, {}, {}
    for arm, policy in (('A', 'invoice-native'), ('B', 'fresh-self')):
        facts = {'contacts': [], 'own_payouts': [], 'known_receipts': [], 'routes': [],
                 **config['public_facts'][arm]}
        facts['unmodeled'] = list(facts['unmodeled'])
        if contacts is not None:
            for name in ('contacts', 'own_payouts', 'known_receipts'):
                facts[name] = contacts[arm][name]
            facts['unmodeled'] += contacts[arm]['unmodeled']
        if routes is not None:
            facts['routes'] = routes[arm]
        all_facts[arm] = facts
        predictions[arm] = attack.candidates(raw_arms[arm], policy, facts)
        model_universe(predictions[arm], universes[arm])
        public_scope = attack.public_exit(raw_arms[arm][0])
        applicable_keys = {attack.native_spk(row['native_pk']) for row in facts['contacts']
                           if row['invoice_index'] == (7 if arm == 'A' else 9)
                           and row['domain'] == public_scope['domain']
                           and row['profile'] == public_scope['profile']}
        diagnostics[arm] = {'candidate_counts': predictions[arm]['candidate_counts'],
            'honest_honest_edges': predictions[arm]['honest_honest_edges'],
            'direct_known_invoice_native_key_matches':
                sum(attack.public_exit(raw)['spk'] in applicable_keys for raw in raw_arms[arm])
                if contacts is not None else None}
    predictions = intersect_public_cross_arm_order(raw_arms, universes, all_facts, predictions)
    payload = {'schema': 'kpb-method02-private-view-predictions/v1', 'binding': config['binding'],
               'view': view, 'selected_exit_ids': universes, 'arms': predictions,
               'arm_local_diagnostics_before_order_intersection': diagnostics,
               'same_position_cross_arm_linkage_included': True}
    salt = secrets.token_bytes(32)
    commitment = capsule_seal(payload, salt)
    write_new('/private-output/PREDICTIONS.json', {'schema': 'kpb-method02-private-capsule/v1',
               'salt_hex32': salt.hex(), 'payload': payload})
    write_new('/out/SEAL.json', {'schema': 'kpb-method02-public-prediction-seal/v1',
              'binding': config['binding'], 'view': view, 'commitment_sha256': commitment,
              'exits_sha256': config['exits_sha256'], 'predictions_frozen_before_truth': True,
              'private_contact_or_prediction_records_exported': False})


def contact_observe(config):
    observe(config, 'CONTACT')


def dispatcher_observe(config):
    observe(config, 'DISPATCHER')


def union_observe(config):
    observe(config, 'UNION')


def frozen_seals(config):
    seals = {}
    for view in VIEWS:
        seal = parse(stable_read('/seals/' + view + '.json', config['seals_sha256'][view]))
        fields(seal, ('schema', 'binding', 'view', 'commitment_sha256', 'exits_sha256',
                      'predictions_frozen_before_truth', 'private_contact_or_prediction_records_exported'))
        need(seal['schema'] == 'kpb-method02-public-prediction-seal/v1'
             and seal['binding'] == config['binding'] and seal['view'] == view
             and seal['exits_sha256'] == config['exits_sha256']
             and seal['predictions_frozen_before_truth'] is True
             and seal['private_contact_or_prediction_records_exported'] is False,
             'method02-all-view-public-pretruth-seals')
        word(seal['commitment_sha256'])
        seals[view] = seal
    return seals


def postseal_score(config):
    # Missing public barriers consume no score slot. All three fixed public
    # seals must be admitted before any capsule or labelled truth body is read.
    seals = frozen_seals(config)
    _, universes = exits(config)
    write_new('/state/SCORING-CLOSED', {'binding': config['binding'],
              'seals_sha256': config['seals_sha256']})
    predictions, diagnostics = {}, {}
    for view in VIEWS:
        capsule = parse(stable_read('/predictions/' + view + '.json', private_mode=0o400))
        fields(capsule, ('schema', 'salt_hex32', 'payload'))
        payload = capsule['payload']
        fields(payload, ('schema', 'binding', 'view', 'selected_exit_ids', 'arms',
                         'arm_local_diagnostics_before_order_intersection',
                         'same_position_cross_arm_linkage_included'))
        need(capsule['schema'] == 'kpb-method02-private-capsule/v1'
             and payload['schema'] == 'kpb-method02-private-view-predictions/v1'
             and payload['binding'] == config['binding'] and payload['view'] == view
             and payload['selected_exit_ids'] == universes
             and payload['same_position_cross_arm_linkage_included'] is True
             and capsule_seal(payload, hexbytes(capsule['salt_hex32'], 32))
                 == seals[view]['commitment_sha256'], 'method02-original-presealed-capsule')
        fields(payload['arms'], ARMS)
        fields(payload['arm_local_diagnostics_before_order_intersection'], ARMS)
        for arm in ARMS:
            model_universe(payload['arms'][arm], universes[arm])
            predicted = payload['arms'][arm]
            need(predicted['schema'] == 'kpb-private-payout-linkage-predictions/v2'
                 and predicted['policy'] == ('invoice-native' if arm == 'A' else 'fresh-self')
                 and predicted['owner_order'] == [0, 1, 2] and predicted['truth_was_input'] is False
                 and type(predicted['unmodeled']) is list
                 and all(type(x) is str for x in predicted['unmodeled'])
                 and predicted['matching_model_complete'] is (not predicted['unmodeled']),
                 'method02-original-frozen-model-scope')
            diagnostic = payload['arm_local_diagnostics_before_order_intersection'][arm]
            fields(diagnostic, ('candidate_counts', 'honest_honest_edges',
                                'direct_known_invoice_native_key_matches'))
            counts = diagnostic['candidate_counts']
            direct = diagnostic['direct_known_invoice_native_key_matches']
            need(type(counts) is list and len(counts) == 3
                 and all(type(x) is int and 0 <= x <= 3 for x in counts)
                 and diagnostic['honest_honest_edges'] == counts[0] + counts[2]
                 and (direct is None if view == 'DISPATCHER'
                      else type(direct) is int and 0 <= direct <= 3),
                 'method02-arm-local-diagnostic-counts-only')
        predictions[view] = payload['arms']
        diagnostics[view] = payload['arm_local_diagnostics_before_order_intersection']
    # This is the first read of the label/ground-truth catalog in this role.
    _, truth = dispatcher(config, universes)
    results = {}
    for view in VIEWS:
        results[view] = {}
        for arm in ARMS:
            predicted = predictions[view][arm]
            scored = attack.score_sealed(predicted, truth[arm])
            # Private view diagnostics may contain arbitrary strings. Export
            # their count, never their bodies, even after public label release.
            safe_score = {key: value for key, value in scored.items() if key != 'unmodeled'}
            results[view][arm] = {**safe_score, 'unmodeled_count': len(scored['unmodeled']),
                'compatible_assignments': predicted['compatible_assignments'],
                'candidate_counts': predicted['candidate_counts'],
                'honest_honest_edges': predicted['honest_honest_edges']}
    retained = all(part['true_assignment_retained'] for view in results.values() for part in view.values())
    contact_a, contact_b = results['CONTACT']['A'], results['CONTACT']['B']
    gain = retained and contact_b['honest_honest_edges'] > contact_a['honest_honest_edges']
    complete = all(predictions['CONTACT'][arm]['matching_model_complete'] for arm in ARMS)
    write_new('/out/RESULT.json', {'schema': 'kpb-method02-public-paired-linkage-result/v1',
        'binding': config['binding'], 'views': results, 'all_true_assignments_retained': retained,
        'arm_local_diagnostics_before_order_intersection': diagnostics,
        'same_position_cross_arm_linkage_included': True,
        'finite_contact_candidate_increase': gain,
        'contact_matching_model_complete': complete,
        'status': ('INVALID MODEL' if not retained else 'UNQUALIFIED' if not complete
                   else 'BOUNDED CONTACT CANDIDATE GAIN' if gain else 'NO MEASURED GAIN'),
        'all_predictions_sealed_before_truth': True,
        'all_models_bound_to_exact_selected_exit_universes': True,
        'private_contacts_salts_models_or_keys_exported': False,
        'overall_crypto_dispatcher_or_terminal_privacy_qualified': False,
        'chain_or_native_backing_qualified': False})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=OPERATIONS)
    operation = parser.parse_args().operation
    try:
        config = require_namespace(operation)
        {'contact-observe': contact_observe, 'dispatcher-observe': dispatcher_observe,
         'union-observe': union_observe, 'postseal-score': postseal_score}[operation](config)
    except BaseException:
        # No private exception, value or traceback leaves the role.
        if Path('/out').is_dir() and not Path('/out/INCOMPLETE.json').exists():
            write_new('/out/INCOMPLETE.json', {'schema': 'kpb-method02-role-incomplete/v1',
                                            'operation': operation})
        raise SystemExit(2)


if __name__ == '__main__':
    main()


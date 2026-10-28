"""Frozen method-02 finite matching attack; call only inside the selected view role.

This module reads no files and receives no truth. The role extractor must supply
actual complete declared facts; caller assertions are not evidence provenance.
Its candidate assignments stay in private prediction capsules until sealed.
"""
import hashlib
import itertools

import exit_wire

OWNERS = (0, 1, 2)


def need(value, category):
    if not value:
        raise ValueError(category)


def native_spk(native_pk):
    need(type(native_pk) is bytes and len(native_pk) == 32, 'native-xonly-public-key')
    return b'\0\0\x20' + native_pk + b'\xac'


def public_exit(raw):
    body = exit_wire.validate_public(raw)
    return {'id': hashlib.sha256(raw).hexdigest(), 'spk': body.payout_spk,
            'nf': body.nf, 'action': body.action, 'payout': body.payout,
            'fee': body.fee, 'context': body.context.encode(),
            'domain': body.context.domain, 'profile': body.context.profile}


def candidates(raw_exits, policy, facts):
    """Return all compatible owner->exit bijections, never an imported PASS.

    facts schema is deliberately closed. Extractors preserve all raw public
    projections separately and mark unknown/unmodeled observations explicitly.
    known_receipts retains rho/CM knowledge, but CM is not a public spent-note
    identifier; only an actually known consumed-receipt value constrains value.
    """
    need(policy in ('invoice-native', 'fresh-self'), 'declared-arm-policy')
    need(type(raw_exits) is list and len(raw_exits) == 3, 'three-actual-exits')
    need(set(facts) == {'contacts', 'own_payouts', 'known_receipts', 'routes',
                       'economic', 'timing', 'public_identifier_edges', 'unmodeled'},
         'complete-declared-view-fact-fields')
    exits = [public_exit(raw) for raw in raw_exits]
    by_id = {row['id']: row for row in exits}
    need(len(by_id) == 3, 'distinct-public-projections')
    allowed = {owner: set(by_id) for owner in OWNERS}

    def owner(value):
        need(type(value) is int and value in OWNERS, 'known-owner-label')
        return value

    def restrict(who, ids):
        allowed[owner(who)] &= set(ids)

    domains = {row['domain'] for row in exits}
    profiles = {row['profile'] for row in exits}
    need(len(domains) == len(profiles) == 1, 'selected-common-domain-profile')
    contact_keys, retained_contacts = {}, []
    required_index = 7 if policy == 'invoice-native' else 9
    for row in facts['contacts']:
        need(set(row) == {'owner', 'native_pk', 'delivery_pk', 'invoice_index', 'domain', 'profile'},
             'actual-contact-fields')
        spk = native_spk(row['native_pk'])
        who = owner(row['owner'])
        need(type(row['delivery_pk']) is bytes and len(row['delivery_pk']) == 32,
             'retained-known-delivery-key')
        need(type(row['invoice_index']) is int and row['invoice_index'] >= 0
             and type(row['domain']) is bytes and len(row['domain']) == 32
             and type(row['profile']) is bytes and len(row['profile']) == 32,
             'actual-contact-public-scope')
        reason = ('different-frozen-arm-index' if row['invoice_index'] != required_index
                  else 'different-public-domain-profile'
                  if row['domain'] not in domains or row['profile'] not in profiles else None)
        retained_contacts.append({'owner': who, 'invoice_index': row['invoice_index'],
                                  'native_lookup_applicable': reason is None,
                                  'inapplicability_reason': reason})
        if reason is None:
            contact_keys.setdefault(who, set()).add(spk)
    for who, alternatives in contact_keys.items():
        # Multiple genuinely applicable keys are alternatives, never a false
        # conjunction. The fresh policy rejects the selected invoice key, so
        # union the possibilities for each applicable selected-key alternative.
        restrict(who, [key for key, item in by_id.items()
                       if (item['spk'] in alternatives if policy == 'invoice-native'
                           else any(item['spk'] != spk for spk in alternatives))])

    for row in facts['own_payouts']:
        need(set(row) == {'owner', 'spk', 'nf'} and owner(row['owner']) == 1,
             'only-corrupt-wallet-own-private-payout-facts')
        need(type(row['spk']) is bytes and len(row['spk']) == 36
             and type(row['nf']) is bytes and len(row['nf']) == 32,
             'actual-own-payout-identifiers')
        restrict(1, [key for key, item in by_id.items()
                     if item['spk'] == row['spk'] and item['nf'] == row['nf']])

    for row in facts['known_receipts']:
        need(set(row) == {'owner', 'rho', 'cm', 'value', 'known_consumed'},
             'retain-legitimate-sender-receipt-facts')
        need(type(row['rho']) is bytes and len(row['rho']) == 32
             and type(row['cm']) is bytes and len(row['cm']) == 32
             and type(row['value']) is int and type(row['known_consumed']) is bool,
             'actual-known-receipt-types')
        owner(row['owner'])
        if row['known_consumed']:
            restrict(row['owner'], [key for key, item in by_id.items()
                                   if item['payout'] + item['fee'] == row['value']])

    for row in facts['economic']:
        need(set(row) == {'owner', 'allowed_payout_fee'}, 'actual-economic-facts')
        pairs = {tuple(pair) for pair in row['allowed_payout_fee']}
        need(all(len(pair) == 2 and all(type(value) is int for value in pair)
                 for pair in pairs), 'integer-sompi-economic-pairs')
        restrict(row['owner'], [key for key, item in by_id.items()
                               if (item['payout'], item['fee']) in pairs])

    for name in ('timing', 'public_identifier_edges'):
        for row in facts[name]:
            need(set(row) == {'owner', 'compatible_exit_ids', 'provenance'},
                 'actual-identifier-or-timing-fact')
            need(type(row['provenance']) is str and bool(row['provenance']),
                 'fact-source-reference-required')
            need(set(row['compatible_exit_ids']) <= set(by_id), 'selected-exit-identifiers-only')
            restrict(row['owner'], row['compatible_exit_ids'])

    for row in facts['routes']:
        need(set(row) == {'owner', 'exit_id', 'provenance'}, 'actual-observed-release-route')
        need(row['exit_id'] in by_id and bool(row['provenance']), 'actual-release-target')
        restrict(row['owner'], [row['exit_id']])

    models = []
    for assignment in itertools.permutations(sorted(by_id)):
        if all(assignment[who] in allowed[who] for who in OWNERS):
            models.append(assignment)
    compatible = [sorted({row[who] for row in models}) for who in OWNERS]
    need(type(facts['unmodeled']) is list and all(type(item) is str for item in facts['unmodeled']),
         'unmodeled-observations-explicit')
    return {'schema': 'kpb-private-payout-linkage-predictions/v2', 'policy': policy,
            'owner_order': list(OWNERS), 'models': models,
            'compatible_exits': compatible, 'compatible_assignments': len(models),
            'honest_honest_edges': sum(len(compatible[who]) for who in (0, 2)),
            'candidate_counts': [len(compatible[who]) for who in OWNERS],
            'unique_predictions': [{'owner': who, 'exit_id': ids[0]}
                                   for who, ids in enumerate(compatible) if len(ids) == 1],
            'retained_contact_records': retained_contacts,
            'unmodeled': list(facts['unmodeled']), 'matching_model_complete': not facts['unmodeled'],
            'truth_was_input': False}


def score_sealed(prediction, actual_owner_exit):
    """Post-seal scorer only; the selected launcher enforces the seal/budget."""
    need(type(actual_owner_exit) is list and len(actual_owner_exit) == 3
         and len(set(actual_owner_exit)) == 3, 'three-actual-truth-owners')
    assignment = tuple(actual_owner_exit)
    models = [tuple(row) for row in prediction['models']]
    need(all(len(row) == len(set(row)) == 3 and all(type(key) is str for key in row)
             for row in models) and len(models) == len(set(models)), 'sealed-distinct-bijections')
    compatible = [sorted({row[who] for row in models}) for who in OWNERS]
    unique_rows = [{'owner': who, 'exit_id': ids[0]}
                   for who, ids in enumerate(compatible) if len(ids) == 1]
    need(prediction['compatible_exits'] == compatible
         and prediction['candidate_counts'] == [len(ids) for ids in compatible]
         and prediction['compatible_assignments'] == len(models)
         and prediction['unique_predictions'] == unique_rows
         and prediction['honest_honest_edges'] == sum(len(compatible[who]) for who in (0, 2)),
         'sealed-model-derived-fields-consistent')
    model_ok = assignment in models
    ranks = []
    for who in OWNERS:
        ids = prediction['compatible_exits'][who]
        ranks.append({'owner': who, 'candidate_count': len(ids), 'rank_interval': [1, len(ids)],
                      'digest_tie_rank': ids.index(assignment[who]) + 1 if assignment[who] in ids else None})
    unique = {row['owner']: row['exit_id'] for row in prediction['unique_predictions']}
    return {'schema': 'kpb-payout-linkage-score/v2', 'true_assignment_retained': model_ok,
            'ranks': ranks, 'correct_unique': sum(unique.get(who) == assignment[who]
                                                for who in OWNERS),
            'wrong_unique': sum(value != assignment[who]
                                for who, value in unique.items()),
            'unmodeled': prediction['unmodeled'],
            'overall_crypto_or_dispatcher_privacy_qualified': False}

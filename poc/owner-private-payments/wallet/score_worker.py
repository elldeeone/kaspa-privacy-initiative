#!/usr/bin/env python3
"""One frozen diagnostic exception: salted observer seal or bounded own counts.

The financial worker/barrier is unchanged. This has no transaction, retry,
reveal, decryption-result export or per-row scoring endpoint.
"""
import argparse
import os
from pathlib import Path
import secrets
import stat

from paths import checked, digest, encoded, fields, hx, need, parse, stable_read, write_new
from support import DOMAIN, MIN_NOTE, MAX_VALUE, Q, recipient
import worker as financial
import score_codec as codec


def strategy_digest():
    return digest(b'KPX7 frozen colluder strategy\0' + stable_read(Path(__file__))
                  + stable_read(Path(codec.__file__)))


def public_json(path, expected):
    raw = stable_read(path)
    need(digest(raw) == hx(expected, 32).hex(), 'externally-selected-public-diagnostic-input')
    return parse(raw)


def completed_attempt(a, session, session_sha):
    need(type(a.attempt) is str and len(a.attempt) == 6 and a.attempt.isascii()
         and a.attempt.isdigit() and int(a.attempt) > 0, 'generic-selected-attempt')
    selected = checked(a.owner / 'attempts' / a.attempt)
    need(selected in financial.attempt_directories(a), 'existing-own-attempt')
    for name, mode in (('DISCLOSURE-CLOSED', 0o400), ('AUTHORIZATION.json', 0o600)):
        info = checked(selected / name).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == mode, 'completed-own-financial-authorization')
    # Own metadata only until the scoring reservation is durable.
    return selected


def selected_public(a):
    need(a.experiment_sha256 == codec.EXPERIMENT, 'hard-selected-frozen-experiment')
    assets, relation, crypto, construction, wire = financial.load_assets(a, 'diagnostic')
    session, session_sha = financial.session_context(a, construction)
    need(session['circuit_profile_sha256'] == assets['component_profile_sha256'], 'same-financial-component-profile')
    raw = stable_read(a.projection)
    need(digest(raw) == hx(a.projection_sha256, 32).hex(), 'genuine-final-projection-selected-before-seal')
    wire.validate_public(raw); body = wire.parse_projection(raw).body
    need(body.session.hex() == session_sha
         and body.roster == wire.sha(b'KPX7RO01', *(hx(v, 32) for v in session['roster'])),
         'same-final-pool-session-and-roster')
    effects = wire.effects_digest(raw)
    for output in body.outputs:
        relation.output(output.tuple_bytes)
    for spend in body.spends:
        relation.verify('spend', b'KPX7SP01' + DOMAIN + body.old_state.cm_root
                        + spend.nf + spend.cv + effects, spend.proof)
    relation.balance([s.cv for s in body.spends], [o.cv for o in body.outputs], body.fee, body.delta)
    return session, session_sha, body, relation, crypto, effects


def reserve(a, name, record):
    directory = checked(a.owner / 'diagnostics'); directory.mkdir(mode=0o700, exist_ok=True)
    # Commit the new diagnostics directory entry itself before committing a
    # CLOSED child. Fsyncing only the child directory cannot preserve its
    # name in the owner's parent across power loss.
    owner_fd = os.open(checked(a.owner), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(owner_fd)
    finally:
        os.close(owner_fd)
    # One record per OWNER, not a caller-selected per-experiment namespace.
    # Any error after this reservation is INCOMPLETE and cannot be re-queried.
    write_new(directory / name, encoded(record) + b'\n', 0o400)
    return directory


def own_truth(selected, session, session_sha, body, effects):
    need(financial.private_json(selected / 'SESSION.json') ==
         {'session': session, 'session_sha256': session_sha}, 'same-original-own-session')
    auth = financial.private_json(selected / 'AUTHORIZATION.json')
    fields(auth, ('schema', 'session_sha256', 'effects_digest_hex32', 'nf_hex32',
                  'cv_hex64', 'statement_hex200', 'proof_hex128'), 'own-original-financial-auth-fields')
    nf, cv = hx(auth['nf_hex32'], 32), hx(auth['cv_hex64'], 64)
    statement = b'KPX7SP01' + DOMAIN + body.old_state.cm_root + nf + cv + effects
    need(auth['schema'] == 'kpx7-owner-spend-authorization/v1' and auth['session_sha256'] == session_sha
         and auth['effects_digest_hex32'] == effects.hex() and hx(auth['statement_hex200'], 200) == statement
         and sum(spend.nf == nf and spend.cv == cv for spend in body.spends) == 1,
         'same-own-original-authorized-financial-effects')
    hx(auth['proof_hex128'], 128)  # Same-statement witness rerandomization is allowed.
    truth = financial.private_json(selected / 'TRUTH.json')
    fields(truth, ('schema', 'session_sha256', 'creator_participant_id_hex32', 'outputs'), 'own-truth-fields')
    need(truth['schema'] == 'kpx7-private-owner-output-truth/v1'
         and truth['session_sha256'] == session_sha and type(truth['outputs']) is list
         and len(truth['outputs']) == 2, 'own-two-output-truth-context')
    owner_id = truth['creator_participant_id_hex32']
    hx(owner_id, 32); need(session['roster'].count(owner_id) == 1, 'truth-public-participant-context')
    hashes = [digest(output.tuple_bytes) for output in body.outputs]
    positions, records = [], {}
    for record in truth['outputs']:
        fields(record, ('tuple_sha256', 'cm_hex32', 'recipient_id_hex32', 'value_hex8', 'kind'),
               'fixed-private-truth-record')
        hx(record['tuple_sha256'], 32)
        need(hashes.count(record['tuple_sha256']) == 1, 'own-truth-in-genuine-final-pool')
        position = hashes.index(record['tuple_sha256'])
        need(body.outputs[position].cm == hx(record['cm_hex32'], 32), 'own-truth-CM-join')
        need(record['recipient_id_hex32'] in session['roster'] and record['kind'] in ('payment', 'change')
             and (record['recipient_id_hex32'] == owner_id) == (record['kind'] == 'change')
             and MIN_NOTE <= int.from_bytes(hx(record['value_hex8'], 8), 'little') <= MAX_VALUE,
             'own-original-payment-change-record')
        positions.append(position); records[position] = record
    need(len(set(positions)) == 2 and sorted(record['kind'] for record in records.values()) == ['change', 'payment'],
         'two-distinct-private-created-outputs')
    return session['roster'].index(owner_id), tuple(positions), records


def observer(a):
    session, session_sha, body, relation, crypto, effects = selected_public(a)
    selected = completed_attempt(a, session, session_sha)
    strategy = strategy_digest()
    public_owners = public_json(a.registry, a.registry_sha256)
    fields(public_owners, ('schema', 'owners', 'classification'), 'public-owner-registry-fields')
    need(public_owners['schema'] == 'kpx7-public-owner-registry/v1'
         and public_owners['classification'] == 'UNFUNDED_SUPPLIED_CONTEXTS_NOT_ACCEPTED'
         and type(public_owners['owners']) is list and len(public_owners['owners']) == 3,
         'actual-public-admission-priors')
    admissions = []
    for index, owner in enumerate(public_owners['owners']):
        fields(owner, ('schema', 'domain_hex32', 'participant_id_hex32', 'initial_cm_hex32',
                       'initial_position', 'admission_sompi'), 'public-init-registry-record')
        need(owner['schema'] == 'kpx7-unfunded-owner-public/v1' and owner['domain_hex32'] == DOMAIN.hex()
             and owner['participant_id_hex32'] == session['roster'][index]
             and type(owner['initial_position']) is int and owner['initial_position'] == index
             and type(owner['admission_sompi']) is int and MIN_NOTE <= owner['admission_sompi'] <= MAX_VALUE,
             'public-original-roster-and-admission')
        hx(owner['initial_cm_hex32'], 32); admissions.append(owner['admission_sompi'])
    directory = reserve(a, 'OBSERVER-CLOSED', {'experiment_sha256': codec.EXPERIMENT,
        'session_sha256': session_sha, 'projection_sha256': a.projection_sha256, 'strategy_sha256': strategy})
    colluder, positions, _ = own_truth(selected, session, session_sha, body, effects)
    context_raw = stable_read(selected / 'CONTEXT.json', private=True)
    need(digest(context_raw) == session['public_effects_context_sha256'], 'same-frozen-public-fee-priors')
    context = parse(context_raw)
    need(context['fee_sompi'] == body.fee and len(context['fee_shares_sompi']) == 3
         and sum(context['fee_shares_sompi']) == body.fee
         and sum(admissions) == body.old_reserve, 'public-prior-fee-and-reserve-join')
    available = [value - share for value, share in zip(admissions, context['fee_shares_sompi'])]
    state = financial.private_json(selected / 'STATE.json')
    owner, original = financial.owner_state(a)
    need(owner['participant_id_hex32'] == session['roster'][colluder]
         and original.value_sompi == admissions[colluder], 'authentic-one-colluder-owner-view')
    wallet = recipient().Receiver(hx(owner['seed_hex32'], 32), DOMAIN, crypto)
    own_nf = wallet.nullifier(original, owner['initial_position'])
    own_cv = relation.commit(original.value_sompi, hx(state['rin_hex32'], 32))
    need(any(s.nf == own_nf and s.cv == own_cv for s in body.spends), 'authentic-colluder-input-opening')
    known = {}
    need(type(state['outputs']) is list and len(state['outputs']) == 2, 'colluder-contributed-view')
    blind_sum = 0
    for output in state['outputs']:
        row = hx(output['tuple_hex520'], 520)
        need(sum(o.tuple_bytes == row for o in body.outputs) == 1, 'authentic-colluder-created-row')
        receipt = recipient().Receipt.parse(hx(output['receipt_hex216'], 216))
        blind = hx(output['blind_hex32'], 32); blind_sum += int.from_bytes(blind, 'little')
        need(receipt.commitment() == row[:32] and relation.commit(receipt.value_sompi, blind) == row[32:96],
             'colluder-local-value-and-randomness-view')
        known[next(i for i, o in enumerate(body.outputs) if o.tuple_bytes == row)] = receipt.value_sompi
    need(set(positions) == set(known) and sum(known.values()) == available[colluder],
         'colluder-original-two-creator-facts')
    # Exercise authentic beta/local randomness without exposing any private
    # scalar, point, tuple or view-derived hash. It does not label honest rows.
    beta = (int.from_bytes(hx(state['rin_hex32'], 32), 'little') - blind_sum) % Q
    need(0 <= beta < Q, 'colluder-private-beta-view')
    known_creators = {position: colluder for position in positions}
    for index, output in enumerate(body.outputs):
        try:
            receipt = wallet.open(output.cf)
        except recipient().Invalid:
            continue
        need(receipt.commitment() == output.cm, 'legitimate-incoming-note-value-view')
        known[index] = receipt.value_sompi
        if 1 <= receipt.index <= 3:
            # This is actual private issuance knowledge + the selected honest
            # sender-worker behavior, NOT cryptographic sender authentication.
            sender = receipt.index - 1
            issued = stable_read(a.owner / ('RECEIVE-INVOICE-' + str(sender) + '.bin'), private=True)
            need(len(issued) == 240 and issued[:32] == hx(owner['participant_id_hex32'], 32)
                 and issued[32:] == wallet.invoice(receipt.index).encode(), 'authentic-private-invoice-issuance')
            need(index not in known_creators or known_creators[index] == sender,
                 'consistent-issued-invoice-creator-knowledge')
            known_creators[index] = sender
        else:
            need(receipt.index == 4 and index in positions, 'selected-honest-worker-receipt-namespace')
    proposed, assignments, partitions = codec.infer(positions, known, known_creators, available, colluder,
                                                   hx(a.projection_sha256, 32))
    packed = codec.capsule(session_sha, a.projection_sha256, strategy, secrets.token_bytes(32), colluder,
                           [i not in known_creators for i in range(6)], proposed)
    write_new(directory / 'OBSERVER-CAPSULE.bin', packed, 0o400)
    public = {'schema': 'kpx7-colluder-observer-seal/v1', 'experiment_sha256': codec.EXPERIMENT,
        'session_sha256': session_sha, 'projection_sha256': a.projection_sha256, 'strategy_sha256': strategy,
        'capsule_seal_sha256': digest(packed), 'excluded_known_creator_count': len(known_creators),
        'unknown_creator_target_count': 6 - len(known_creators),
        'candidate_creator_assignments': assignments, 'candidate_partitions': partitions,
        'hash_tie_break_used': assignments > 1, 'unique_partition_from_constraints': partitions == 1,
        'scope': 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION'}
    write_new(a.output / 'PUBLIC.json', encoded(public) + b'\n', 0o400)


def score(a):
    session, session_sha, body, _, _, effects = selected_public(a)
    selected = completed_attempt(a, session, session_sha)
    predictions = public_json(a.predictions, a.predictions_sha256)
    coordinator = codec.prediction(predictions, session_sha, a.projection_sha256)
    observer_public = public_json(a.observer_receipt, a.observer_receipt_sha256)
    strategy = strategy_digest()
    codec.observer_receipt(observer_public, session_sha, a.projection_sha256, strategy)
    sealed = public_json(a.bundle, a.bundle_sha256)
    codec.bundle(sealed, session_sha, a.projection_sha256, a.predictions_sha256, a.observer_receipt_sha256)
    need(sealed['colluder_capsule_seal_sha256'] == observer_public['capsule_seal_sha256'],
         'same-presealed-permitted-colluder-view')
    directory = reserve(a, 'SCORING-CLOSED', {'experiment_sha256': codec.EXPERIMENT,
        'session_sha256': session_sha, 'projection_sha256': a.projection_sha256, 'bundle_sha256': a.bundle_sha256})
    # The salt and exclusion mask remain inside restricted namespaces. This is
    # not a public hash of a low-entropy ownership map.
    packed = stable_read(a.capsule, private=True)
    need(digest(packed) == sealed['colluder_capsule_seal_sha256'], 'presealed-private-prediction-capsule')
    colluder, eligible, proposed = codec.parse_capsule(packed, session_sha, a.projection_sha256, strategy)
    need(sum(eligible) == observer_public['unknown_creator_target_count'], 'same-presealed-known-target-count')
    owner, positions, records = own_truth(selected, session, session_sha, body, effects)
    for position in positions:
        record = records[position]
        known_creator = owner == colluder or (record['kind'] == 'payment'
            and record['recipient_id_hex32'] == session['roster'][colluder])
        need(eligible[position] == (not known_creator)
             and (not known_creator or proposed[position] == owner), 'exclude-only-actual-known-creator-facts')
    result = codec.counts(session_sha, a.projection_sha256, a.bundle_sha256, 2,
        sum(coordinator[i] == owner for i in positions), sum(eligible[i] for i in positions),
        sum(eligible[i] and proposed[i] == owner for i in positions),
        int(len({coordinator[i] for i in positions}) == 1),
        int(any(eligible[i] for i in positions) and len({proposed[i] for i in positions}) == 1))
    write_new(directory / 'COUNTS.bin', result, 0o400)
    # NO per-owner counts, output IDs, record digest or truth are exported here.


def aggregate(a):
    need(a.experiment_sha256 == codec.EXPERIMENT, 'hard-selected-frozen-experiment')
    observer_public = public_json(a.observer_receipt, a.observer_receipt_sha256)
    codec.observer_receipt(observer_public, a.session_sha256, a.projection_sha256, strategy_digest())
    sealed = public_json(a.bundle, a.bundle_sha256)
    codec.bundle(sealed, a.session_sha256, a.projection_sha256, sealed['coordinator_predictions_sha256'],
                 a.observer_receipt_sha256)
    need(sealed['colluder_capsule_seal_sha256'] == observer_public['capsule_seal_sha256'],
         'same-final-sealed-ambiguity-report')
    records = [stable_read(path, private=True) for path in a.count_file]
    result = codec.aggregate(records, a.session_sha256, a.projection_sha256, a.bundle_sha256)
    need(result['one_colluder']['eligible_count'] == observer_public['unknown_creator_target_count'],
         'all-own-counts-match-sealed-colluder-knowledge')
    result['one_colluder']['presealed_ambiguity'] = {key: observer_public[key] for key in
        ('candidate_creator_assignments', 'candidate_partitions', 'hash_tie_break_used',
         'unique_partition_from_constraints')}
    result['interpretation'] = 'A_CORRECT_TIE_BREAK_GUESS_IS_NOT_BY_ITSELF_A_RECOVERED_LEAK'
    write_new(a.output / 'PUBLIC.json', encoded(result) + b'\n', 0o400)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('observe', 'score', 'aggregate'))
    for name in ('owner', 'mpc', 'output', 'assets', 'session', 'projection', 'registry',
                 'predictions', 'observer-receipt', 'bundle', 'capsule'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'session-sha256', 'projection-sha256', 'registry-sha256',
                 'predictions-sha256', 'observer-receipt-sha256', 'bundle-sha256', 'experiment-sha256'):
        p.add_argument('--' + name)
    p.add_argument('--attempt')
    p.add_argument('--count-file', type=Path, action='append')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        a = p.parse_args()
        if a.operation == 'aggregate':
            aggregate(a)
        else:
            with financial.owner_lock(a):
                {'observe': observer, 'score': score}[a.operation](a)
        print(encoded({'operation': a.operation, 'completed': True}).decode())
    except Exception:
        p.exit(2, 'diagnostic INCOMPLETE; private material not disclosed\n')

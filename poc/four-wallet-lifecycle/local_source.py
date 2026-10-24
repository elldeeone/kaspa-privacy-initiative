"""Explicit unfunded GN2/native rehearsal, never accepted-chain authority."""
import copy

from compat import core
from contracts import genesis
from paths import outside

SCHEMA = 'kpx6-four-wallet-local-history/v1'
CLASSIFICATION = 'UNFUNDED_SUPPLIED_GN2_CONTEXTS_NOT_ACCEPTED'


def replay_local(raw, external_sha256, profile, runtime, output):
    c = core(); p = c.primitives; g = genesis()
    p.need(p.h(raw).hex() == external_sha256, 'external-local-history-byte-pin')
    data = p.parse(raw)
    p.need(type(data) is dict and set(data) == {'schema', 'classification',
        'financial_profile_sha256', 'trial_id', 'funding_case', 'records', 'head_context'}
        and data['schema'] == SCHEMA and data['classification'] == CLASSIFICATION
        and data['financial_profile_sha256'] == profile.profile_sha256,
        'strict-unfunded-local-source-scope')
    selected = g.EntrySelection(profile.profile_sha256, profile.domain, profile.w_tail)
    # Shared historical financial shape; its function name grants no accepted
    # authority here. Fresh Full follows and this path remains explicitly local.
    initial = g.validate_accepted_genesis(data['funding_case'], selected, data['trial_id'])
    output = outside(output)
    p.need(not output.exists(), 'fresh-local-replay-output')
    output.mkdir(parents=True, mode=0o700)
    funding = data['funding_case']
    contexts = [{'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
        'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': row['isCoinbase'],
        'covenant_id': row['covenantId']} for row in funding['entries']]
    body, metrics = runtime.normalize(funding['transaction'], contexts, output / 'GN2-normalize')
    p.need(body == funding['transaction'], 'canonical-local-GN2-ID-and-mass')
    runtime.sdk(body, contexts)
    report, checked = runtime.validate(body, contexts, output / 'GN2-Full')
    p.need(metrics == checked and metrics['actual_fee_sompi'] == initial['fee_sompi'],
           'local-GN2-native-allocation-conformance')
    derived = runtime.replay_cases(initial['snapshot'], initial['founding_outpoint'],
        initial['reserve_sompi'], data['records'], output / 'W-prefix')
    head = data['head_context']
    if derived['point'] is None:
        p.need(head is None, 'no-current-head-after-terminal')
    else:
        p.need(type(head) is dict and set(head) == {'amount_sompi', 'script_public_key',
            'block_daa_score', 'is_coinbase', 'covenant_id'}
            and head['amount_sompi'] == str(derived['reserve'])
            and head['script_public_key'] == c.native_runtime.p2sh(
                runtime.emit(derived['snapshot'].state(profile.domain)))
            and type(head['block_daa_score']) is str and head['block_daa_score'].isdigit()
            and str(int(head['block_daa_score'])) == head['block_daa_score']
            and 0 <= int(head['block_daa_score']) < 1 << 64
            and head['is_coinbase'] is False and head['covenant_id'] is None,
            'exact-supplied-current-local-context')
    return {**derived, 'schema': 'kpx6-four-wallet-local-replay/v1',
        'classification': CLASSIFICATION, 'trial_id': data['trial_id'],
        'entry': initial, 'entry_fee_sompi': initial['fee_sompi'],
        'head_context': copy.deepcopy(head), 'GN2_native_report': report,
        'accepted_chain_backing_verified': False, 'currentness_verified': False,
        'spend_authorized': False, 'provided_public_prefix_validated': True}

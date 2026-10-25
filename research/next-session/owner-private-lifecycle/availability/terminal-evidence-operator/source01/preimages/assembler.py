#!/usr/bin/env python3
"""Finite public terminal metadata assembly; no fetch, private read, page decode or payload copy."""
import argparse
import ast
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat

D = 'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
PROFILE = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
REPO = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
ASSETS = Path('/var/tmp/kpi-owner-private-lifecycle-01/assets')
REPLAY_SOURCE = 'poc/owner-private-lifecycle/chain/replay.py'
REPLAY_SHA = '1bb5c89fd64454aa79b081b659b232c55c881ae7cd8240a857539813d2528048'
STATIC_SHA = 'f163bff74e538ad553ffcb7b942586c5871df172c40139f0d087c7b7ad1f0af7'
R2_SHA = '106f850e04cfafab896c9f2c6d17a71779534f9c7da26612dcaf947a870ddaa5'
TOP_SELECTION_SHA = 'ea50ce2c0d06d5ebb534c7e8730aaaa54110d7a733880cdc59c2c37654f77566'
TOP_CLOSURE_SHA = 'e7fdc78f74cbe6f17f82deab97d683aa5aadc3e7abbef624c3ed0dde7cf640ab'
AUDITOR_SHA = 'c9c7b593bc12690e105158f01a9bd39fd99d0a029fca2883f70a69a6a1d47aa7'
TAIL_SHA = '2e9e00aa4ba7d9a25db4aff5246d58213b336e7a0c7689de8cc36498bcd09bf6'
FILE_ROLES = {'handoff', 'sdk', 'accounting', 'terminal', 'outage', 'observed',
              'static', 'r2', 'top-selection', 'top-closure'}
SELECTORS = {
    'selection': ('chain-selection', 'inputs/selection.json'),
    'descriptor': ('founding-descriptor', 'inputs/descriptor.json'),
    'fetch.json': ('terminal-fetch', 'inputs/fetch.json'),
    'parameters': ('native-parameters', 'inputs/parameters.json'),
    'sessions': ('public-sessions', 'inputs/sessions.json'),
    'source_pins': ('replay-source-pins', 'inputs/source-pins.json'),
    'HISTORY.json': ('terminal-history', 'expected/HISTORY.json'),
    'CHECKPOINT.json': ('terminal-checkpoint', 'expected/CHECKPOINT.json'),
    'CURRENT-ENTRY.json': ('terminal-current-entry', 'expected/CURRENT-ENTRY.json'),
    'RESULTS.json': ('terminal-replay-report', 'expected/RESULTS.json'),
}
HANDOFF_FIELDS = {'accepted_transactions', 'automatic_resubmission_permitted', 'checkpoint',
    'expected_transaction_id', 'fetch_wall_seconds', 'financial_profile_sha256', 'full_prefix_pages',
    'independent_consensus_or_continuous_currentness', 'native_payouts_observed',
    'observed_total_fee_sompi', 'schema', 'selectors', 'status', 'submission_performed',
    'terminal', 'total_wall_seconds', 'trial_id'}
REPLAY_FIELDS = {'all_native_Full_and_input_engines_executed', 'current_checkpoint',
    'descriptor_sha256', 'fetch_sha256', 'financial_profile_sha256',
    'genesis_rederived_from_public_notes_and_native_backing', 'history_sha256',
    'independent_consensus_or_continuous_currentness', 'observed_total_fee_sompi',
    'payouts', 'schema', 'selection_file_sha256', 'spend_authorized', 'status', 'transactions', 'trust'}
SDK_FIELDS = {'schema', 'status', 'financial_profile_sha256', 'selection_file_sha256',
    'descriptor_file_sha256', 'fetch_file_sha256', 'sdk_pins', 'selected_transaction_ids',
    'discovered_head', 'terminal_candidate', 'transaction_ids_and_full_body_context_locators_recomputed',
    'header_hashes_and_prefix_paths_recomputed', 'current_view_and_delta_consistent',
    'chain_inclusion_pow_or_independent_consensus_verified',
    'no_GN3_or_W_semantic_native_verification_in_this_SDK_stage'}
FETCH_FIELDS = {'accepted_backing_currentness_or_spend_authorized', 'attempts', 'coverage',
    'current_view', 'descriptor', 'descriptor_canonical_sha256', 'descriptor_file_sha256',
    'financial_profile_sha256', 'genesis_hash_hex', 'network_id', 'observed_at',
    'owner_backup_or_signing_key_read', 'pages', 'public_parameter_blob_read', 'rpc_views_are_atomic',
    'schema', 'sdk_pins', 'selection_file_sha256', 'source', 'status',
    'terminal_candidate_not_yet_replay_verified', 'transactions', 'trust'}
OUTAGE_FIELDS = {'schema', 'trial_id', 'financial_profile_sha256', 'accepted_R2_handoff_sha256',
    'all_recorded_owned_prover_process_identities_gone',
    'all_six_original_submission_processes_and_last_confirmation_exited',
    'all_three_original_MPC_parties_and_coordinator_completed',
    'client_owner_NF_or_payout_associations_exported', 'durable_retention_guarantee_demonstrated',
    'independent_machine_or_administrator_demonstrated', 'original_pool_writer_authority_relinquished',
    'original_protected_contents_read_or_hashed_for_this_summary',
    'owned_MPC_containers_or_integration_units_running',
    'owned_prover_GPU_processes_sockets_or_construction_containers_running',
    'owned_shared_prover_units_stopped', 'public_read_only_chain_observer_remains_available',
    'same_physical_host_isolated_replacement_namespaces', 'scope', 'source_receipt_sha256',
    'summarized_at_utc'}
ACCOUNT_INTS = {'GN3_fee_sompi', 'accepted_payment_round_count', 'accepted_pool_transaction_count',
    'acquisition_fees_sompi', 'complete_fee_sompi_so_far', 'confirmed_payout_count',
    'fee_ratio_denominator', 'fee_ratio_numerator', 'fixed_useful_payment_sompi',
    'independent_exit_total_fee_sompi', 'mined_source_sompi', 'mixed_batch_total_fee_sompi',
    'native_payout_sompi', 'ordinary_GN3_change_sompi', 'ordinary_acquisition_transaction_count',
    'pool_fees_sompi', 'remaining_reserve_sompi'}
ACCOUNT_BOOLS = {'complete_requested_lifecycle', 'denominator_is_frozen_workload_not_decrypted_by_auditor',
    'financial_chain_terminal', 'independent_consensus_or_crypto_proof_verified',
    'privacy_or_separate_administration_qualified', 'terminal_claims_and_payout_keys_reconciled_locally',
    'terminal_scan_cohort_equality_checked_locally', 'three_original_seed_terminal_scans',
    'whole_trial_sompi_conservation'}
STATIC_VERIFY_IDS = {'financial-profile', 'component-profile', 'native-policy', 'native-codec',
    'software-archive', 'software-inventory', 'software-members', 'software-archive-metadata'}


def need(ok, label):
    if not ok:
        raise ValueError(label)


def fields(value, names, label='exact-metadata-fields'):
    need(type(value) is dict and set(value) == set(names), label)


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'canonical-unsigned-metadata-integer')
    return value


def hx(value, size=None):
    need(type(value) is str and len(value) % 2 == 0
         and re.fullmatch('[0-9a-f]*', value) is not None, 'canonical-lowercase-hex')
    raw = bytes.fromhex(value)
    need(size is None or len(raw) == size, 'exact-hex-width')
    return raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate-public-JSON-key')
            value[key] = item
        return value
    def no_constant(_):
        raise ValueError('nonfinite-public-JSON-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=no_constant)


def logical(value):
    need(type(value) is str and value not in ('', '.') and '\\' not in value, 'logical-path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == value, 'logical-path')
    return value


def public_path(value):
    need(type(value) is str, 'public-path-string')
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == value, 'absolute-public-path')
    need(not any(p in {'private', 'owner', 'controller', 'local-bookkeeping'}
                 or p.startswith(('party-', 'scan-attempt-', 'restore-attempt-')) for p in path.parts),
         'owner-client-private-path-forbidden')
    return path


def load_converter(raw):
    """Reuse only the fixed pure RPC->native representation conversion, without importing a runtime."""
    need(digest(raw) == REPLAY_SHA, 'fixed-replay-conversion-source')
    nodes = [n for n in ast.parse(raw, REPLAY_SOURCE).body
             if isinstance(n, ast.FunctionDef) and n.name in {'decimals', 'native_case'}]
    need({n.name for n in nodes} == {'decimals', 'native_case'}, 'fixed-pure-conversion-functions')
    scope = {'copy': copy, 'need': need, 'uint': uint}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), REPLAY_SOURCE, 'exec'), scope)
    return scope['native_case']


def point(value):
    fields(value, {'transactionId', 'index'}, 'exact-public-outpoint')
    hx(value['transactionId'], 32)
    uint(value['index'], 32)
    return value['transactionId'], value['index']


class Assembler:
    def __init__(self, reader, metadata, converter, output):
        self.reader, self.metadata, self.converter = reader, metadata, converter
        self.output = Path(output)
        self.objects, self.generated, self.receipts = [], {}, {}
        self.observed = {}
        self.release_base = None

    def read(self, row):
        fields(row, {'path', 'bytes', 'sha256'}, 'exact-selected-public-file')
        path = public_path(row['path']); uint(row['bytes']); hx(row['sha256'], 32)
        raw = self.reader(path, row['sha256'])
        need(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'whole-selected-metadata')
        return raw

    def selected(self, row):
        return parse(self.read(row))

    def add(self, identifier, source, size, pin, placement, suffix='.json', kind='public_history'):
        need(re.fullmatch('[a-z][a-z0-9-]*', identifier) is not None, 'asset-id')
        public_path(str(source)); logical(placement); uint(size); hx(pin, 32)
        need(identifier not in {o['id'] for o in self.objects}, 'distinct-asset-id')
        matches = self.observed.get((pin, size), [])
        row = {'id': identifier, 'kind': kind, 'source_path': str(source), 'bytes': size,
               'sha256': pin, 'placement': placement,
               'release_filename': identifier + '-' + pin + suffix,
               'existing_public_urls': sorted({m['url'] for m in matches}),
               'upload_required': not bool(matches)}
        row['public_urls'] = row['existing_public_urls'] or [self.release_base + '/' + row['release_filename']]
        self.objects.append(row)
        return row

    def new_json(self, identifier, filename, value, placement):
        raw = encoded(value); path = self.output / filename
        self.generated[filename] = raw
        return self.add(identifier, path, len(raw), digest(raw), placement)

    def plan(self, selected):
        fields(selected, {'schema', 'domain_hex32', 'financial_profile_sha256', 'trial_id', 'files', 'cases'})
        need(selected['schema'] == 'kpx8-root-terminal-evidence-inputs/v1'
             and selected['domain_hex32'] == D and selected['financial_profile_sha256'] == PROFILE,
             'root-selected-terminal-profile')
        fields(selected['files'], FILE_ROLES); trial = selected['trial_id']
        need(type(trial) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', trial), 'trial-id')
        files = selected['files']; docs = {name: self.selected(row) for name, row in files.items()}
        need(files['static']['sha256'] == STATIC_SHA and files['r2']['sha256'] == R2_SHA,
             'unchanged-initial-inventories')
        need(files['top-selection']['sha256'] == TOP_SELECTION_SHA
             and files['top-closure']['sha256'] == TOP_CLOSURE_SHA
             and docs['top-closure']['transport_selection_sha256'] == TOP_SELECTION_SHA
             and docs['top-closure']['profile_reference_sha256'] == PROFILE,
             'unchanged-full-recovery-top-manifests')
        observed = docs['observed']
        need(type(observed['objects']) is list and len(observed['objects']) >= 64, 'observed-release-assets')
        for row in observed['objects']:
            fields(row, {'bytes', 'github_reported_digest', 'id', 'name', 'url'})
            uint(row['bytes']); need(row['github_reported_digest'].startswith('sha256:'), 'observed-digest')
            pin = row['github_reported_digest'][7:]; hx(pin, 32)
            need(row['url'].startswith('https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/')
                 and row['url'].endswith('/' + row['name']), 'actual-public-release-url')
            self.observed.setdefault((pin, row['bytes']), []).append(row)
        bases = {row['url'].rsplit('/', 1)[0] for row in observed['objects']}
        need(len(bases) == 1, 'one-observed-release-for-upload-delta')
        self.release_base = next(iter(bases))
        h = docs['handoff']; fields(h, HANDOFF_FIELDS)
        need(h['schema'] == 'kpx8-confirmed-transition-handoff/v1' and h['trial_id'] == trial
             and h['financial_profile_sha256'] == PROFILE and h['accepted_transactions'] == 12
             and type(h['accepted_transactions']) is int and h['terminal'] is True
             and h['status'] == 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
             and h['automatic_resubmission_permitted'] is False and h['submission_performed'] is False
             and h['independent_consensus_or_continuous_currentness'] is False, 'actual-terminal-handoff')
        fields(h['selectors'], SELECTORS)
        protocol, raw_protocol = {}, {}
        initial_rows = {o['id']:o for o in [*docs['static']['objects'], *docs['r2']['objects']]}
        for name, selector in h['selectors'].items():
            fields(selector, {'path', 'sha256'}); public_path(selector['path']); hx(selector['sha256'], 32)
            raw = self.reader(Path(selector['path']), selector['sha256'])
            need(digest(raw) == selector['sha256'], 'selector-whole-sha256')
            protocol[name], raw_protocol[name] = parse(raw), raw
            identifier, placement = SELECTORS[name]
            if name in {'selection','descriptor','parameters','sessions','source_pins'}:
                need(initial_rows[identifier]['sha256'] == selector['sha256']
                     and initial_rows[identifier]['bytes'] == len(raw), 'unchanged-R2-public-protocol-inputs')
            self.add(identifier, selector['path'], len(raw), selector['sha256'], 'data/' + placement)
        history, checkpoint, report, fetch = (protocol[n] for n in
             ('HISTORY.json', 'CHECKPOINT.json', 'RESULTS.json', 'fetch.json'))
        fields(checkpoint, {'outpoint_hex36', 'reserve_sompi', 'state_hex112'})
        need(checkpoint == h['checkpoint'] == history['head'] and checkpoint['outpoint_hex36'] is None
             and type(checkpoint['reserve_sompi']) is int and checkpoint['reserve_sompi'] == 0
             and protocol['CURRENT-ENTRY.json'] is None, 'terminal-null-point-and-zero-reserve')
        state = hx(checkpoint['state_hex112'], 112)
        need(state[:8] == b'KPX8ST01' and state[8:40].hex() == D
             and int.from_bytes(state[72:76], 'little') == 15
             and int.from_bytes(state[108:112], 'little') == 16, 'terminal-CM15-NF16')
        fields(history, {'schema', 'domain_hex32', 'genesis', 'head', 'transitions'})
        need(history['schema'] == 'kpx8-owner-private-history/v1' and history['domain_hex32'] == D
             and [t['kind'] for t in history['transitions']] == ['batch'] * 2 + ['exit'] * 9,
             'exact-two-mixed-nine-exit-history')
        fields(report, REPLAY_FIELDS)
        need(report['schema'] == 'kpx8-accepted-native-replay/v1' and report['financial_profile_sha256'] == PROFILE
             and report['status'] == h['status'] and report['current_checkpoint'] == checkpoint
             and report['all_native_Full_and_input_engines_executed'] is True
             and report['genesis_rederived_from_public_notes_and_native_backing'] is True
             and report['spend_authorized'] is False and report['independent_consensus_or_continuous_currentness'] is False,
             'strict-recorded-replay-report')
        for report_key, role in [('history_sha256', 'HISTORY.json'), ('fetch_sha256', 'fetch.json'),
             ('selection_file_sha256', 'selection'), ('descriptor_sha256', 'descriptor')]:
            need(report[report_key] == h['selectors'][role]['sha256'], 'replay-input-output-sha-join')
        fields(fetch, FETCH_FIELDS | ({'incremental_acquisition'} if 'incremental_acquisition' in fetch else set()),
               'exact-full-or-incremental-observer-schema')
        need(fetch['schema'] == 'kpx8-gn3-network-fetch/v1' and fetch['financial_profile_sha256'] == PROFILE
             and fetch['terminal_candidate_not_yet_replay_verified'] is True
             and fetch['coverage']['complete'] is True and fetch['coverage']['frontier_seen'] is True
             and fetch['coverage']['missing'] == [] and fetch['coverage']['pruned'] == [],
             'complete-selected-observer-prefix')
        rows = fetch['transactions']; need(type(rows) is list and len(rows) == 12, 'twelve-accepted-cases')
        ids = [r['transaction']['id'] for r in rows]
        need(len(set(ids)) == 12 and ids[-1] == h['expected_transaction_id'], 'distinct-current-accepted-txids')
        for value in ids: hx(value, 32)
        sdk = docs['sdk']; fields(sdk, SDK_FIELDS)
        need(sdk['schema'] == 'kpx8-gn3-public-sdk-verification/v1' and sdk['status'] == 'PUBLIC_EVIDENCE_CONSISTENCY_PASS'
             and sdk['financial_profile_sha256'] == PROFILE and sdk['selected_transaction_ids'] == ids
             and sdk['discovered_head'] is None and sdk['terminal_candidate'] is True
             and sdk['transaction_ids_and_full_body_context_locators_recomputed'] is True
             and sdk['header_hashes_and_prefix_paths_recomputed'] is True
             and sdk['current_view_and_delta_consistent'] is True
             and sdk['no_GN3_or_W_semantic_native_verification_in_this_SDK_stage'] is True
             and sdk['chain_inclusion_pow_or_independent_consensus_verified'] is False,
             'actual-complete-SDK-stage')
        for key, role in [('selection_file_sha256', 'selection'), ('descriptor_file_sha256', 'descriptor'),
                          ('fetch_file_sha256', 'fetch.json')]:
            need(sdk[key] == h['selectors'][role]['sha256'], 'SDK-selector-join')
        need(type(selected['cases']) is list and len(selected['cases']) == 12, 'twelve-explicit-case-rows')
        need(len(report['transactions']) == 12, 'twelve-native-report-rows')
        fee_total, case_rows, native_cases = 0, [], []
        for index, (chosen, row, result) in enumerate(zip(selected['cases'], rows, report['transactions'])):
            fields(row, {'transaction','accepted_input_contexts','accepting_block_header','confirmation_policy',
                'genesis_hash_hex','network_id','sdk_transaction_id_recomputed','source_group_index',
                'source_page_index','source_transaction_index'}, 'exact-accepted-transaction-row')
            fields(row['transaction'], {'gas','id','inputs','lockTime','outputs','payload','storageMass',
                                       'subnetworkId','version'}, 'exact-accepted-transaction-body')
            for item in row['transaction']['inputs']:
                fields(item, {'computeBudget','previousOutpoint','sequence','signatureScript'}, 'exact-accepted-input')
            for item in row['transaction']['outputs']:
                fields(item, {'covenant','scriptPublicKey','value'}, 'exact-accepted-output')
            for item in row['accepted_input_contexts']:
                fields(item, {'amount_sompi','block_daa_score','covenant_id','is_coinbase','outpoint','script_public_key'},
                       'exact-accepted-input-context')
            fields(chosen, {'case', 'validation', 'metrics'}); values = {k: self.selected(v) for k, v in chosen.items()}
            case, validation, metrics = (values[k] for k in ('case', 'validation', 'metrics'))
            native_cases.append(case)
            fields(case, {'entries', 'transaction'})
            need(case == self.converter(row), 'entire-accepted-case-witness-budget-and-context-preserved')
            fields(validation, {'Full', 'ScriptEngine', 'all_input_engines_accepted', 'isolation', 'per_input_ScriptEngine'})
            fields(validation['Full'], {'accepted', 'fee_sompi'})
            fields(metrics, {'P2SH_sigop_counts', 'actual_fee_sompi', 'compute_mass', 'estimated_bytes',
                'mining_mass', 'quotes', 'relay_mass', 'source_adapted_block_mass_caps',
                'source_adapted_default_relay_fee', 'source_adapted_sigop_policy', 'standard_script_classes',
                'storage_mass', 'transient_mass'}, 'exact-public-native-metrics')
            need(validation['Full']['accepted'] is True and validation['all_input_engines_accepted'] is True
                 and validation['isolation'] == 'PASS' and len(validation['per_input_ScriptEngine']) == len(case['entries'])
                 and all(v['accepted'] is True for v in validation['per_input_ScriptEngine']), 'actual-native-Full-every-input')
            for input_index, engine in enumerate(validation['per_input_ScriptEngine']):
                fields(engine, {'accepted','allowed_script_units','input_index','units'}, 'exact-native-script-result')
                need(type(engine['input_index']) is int and engine['input_index'] == input_index
                     and uint(engine['units']) <= uint(engine['allowed_script_units']), 'native-input-metrics-join')
            need(validation['ScriptEngine'] == validation['per_input_ScriptEngine'][0], 'first-script-result-join')
            fields(result, {'transaction_id', 'metrics', 'native_full_and_all_input_engines_passed'})
            need(result['transaction_id'] == ids[index] and result['metrics'] == metrics
                 and result['native_full_and_all_input_engines_passed'] is True, 'case-report-metrics-join')
            fee = uint(metrics['actual_fee_sompi']); need(validation['Full']['fee_sompi'] == fee, 'native-fee-join')
            fee_total += fee
            payload = hx(case['transaction']['payload'])
            need(payload[:8] == (b'KPX8GN01' if index == 0 else b'KPX8PB01' if index < 3 else b'KPX8XB01'),
                 'GN3-two-mixed-nine-exit-modes')
            group = {}
            for key, selector in chosen.items():
                obj = self.add('accepted-case-%02d-%s' % (index, key), selector['path'], selector['bytes'],
                               selector['sha256'], 'cases/%02d/%s.json' % (index, key))
                group[key] = obj['id']
            case_rows.append({'transaction_id': ids[index], 'kind': 'genesis' if index == 0 else 'batch' if index < 3 else 'exit',
                              'objects': group})
        need(fee_total == uint(report['observed_total_fee_sompi']) == uint(h['observed_total_fee_sompi']),
             'exact-all-pool-fees')
        payouts = report['payouts']; observations = h['native_payouts_observed']
        need(type(payouts) is list and len(payouts) == 9 and type(observations) is list and len(observations) == 9,
             'nine-actual-payout-observations')
        seen = set(); payout_total = 0
        query_sets = [fetch['current_view']['queries'], fetch['current_view']['final_requery']['queries']]
        for query_set in query_sets:
            need(len({point(r['outpoint']) for r in query_set}) == len(query_set), 'unique-public-query-points')
            queries = {point(q['outpoint']):q for q in query_set}
            for row in rows:
                for item in row['transaction']['inputs']:
                    q = queries.get(point(item['previousOutpoint']))
                    need(q is not None and q['queried'] is True and q['entry'] is None,
                         'all-accepted-inputs-absent-in-both-query-rounds')
        for ordinal, (payout, observed) in enumerate(zip(payouts, observations)):
            fields(payout, {'output_index', 'payout_sompi', 'script_public_key', 'transaction_id'})
            fields(observed, {'entry', 'outpoint'}); fields(observed['entry'], {'amount', 'blockDaaScore', 'covenantId', 'isCoinbase', 'scriptPublicKey'})
            at = (payout['transaction_id'], uint(payout['output_index'], 32)); value = uint(payout['payout_sompi'])
            need(at not in seen and at[0] == ids[ordinal + 3] and point(observed['outpoint']) == at, 'nine-distinct-exit-payouts')
            seen.add(at); payout_total += value
            output = native_cases[ordinal + 3]['transaction']['outputs'][at[1]]
            need(output['value'] == value and output['scriptPublicKey'] == payout['script_public_key'],
                 'actual-case-output-payout-join')
            need(observed['entry']['amount'] == value and observed['entry']['scriptPublicKey'] == payout['script_public_key']
                 and observed['entry']['isCoinbase'] is False and observed['entry']['covenantId'] is None,
                 'exact-public-native-payout')
            uint(observed['entry']['blockDaaScore']); hx(payout['script_public_key'], 36)
            for query_set in query_sets:
                match = [r for r in query_set if point(r['outpoint']) == at]
                need(len(match) == 1 and match[0]['queried'] is True and match[0]['entry'] is not None,
                     'payout-present-in-initial-and-final-requery')
                q = match[0]['entry']
                fields(q, {'outpoint', 'amount_sompi', 'script_public_key', 'block_daa_score', 'is_coinbase', 'covenant_id'})
                need(point(q['outpoint']) == at and q['amount_sompi'] == str(value)
                     and q['block_daa_score'] == str(observed['entry']['blockDaaScore'])
                     and q['script_public_key'] == payout['script_public_key'] and q['is_coinbase'] is False
                     and q['covenant_id'] is None, 'exact-retained-payout-query-join')
        terminal = docs['terminal']
        fields(terminal, {'schema', 'accepted_history', 'all_three_terminal_seed_scans_passed',
            'all_historical_native_payout_keys_rederived', 'reserve_sompi', 'terminal_seed_scans_completed',
            'client_associations_exported', 'read_context_placeholder_fee_is_a_ledger_charge'})
        need(type(terminal['accepted_history']) is list and len(terminal['accepted_history']) == 2,
             'aggregate-selected-history-reference')
        public_path(terminal['accepted_history'][0])
        need(terminal['schema'] == 'kpx8-confirmed-terminal-seed-reconciliation/v1'
             and terminal['accepted_history'][1] == h['selectors']['HISTORY.json']['sha256']
             and terminal['all_three_terminal_seed_scans_passed'] is True
             and terminal['all_historical_native_payout_keys_rederived'] is True
             and type(terminal['reserve_sompi']) is int and terminal['reserve_sompi'] == 0
             and type(terminal['terminal_seed_scans_completed']) is int and terminal['terminal_seed_scans_completed'] == 3
             and terminal['client_associations_exported'] is False
             and terminal['read_context_placeholder_fee_is_a_ledger_charge'] is False, 'aggregate-three-original-seed-terminal-scans')
        account = docs['accounting']
        fields(account, ACCOUNT_INTS | ACCOUNT_BOOLS | {'schema', 'auditor_sha256', 'scope',
            'accepted_prefix_evidence_sha256', 'two_percent_target_verdict'})
        for key in ACCOUNT_INTS: uint(account[key])
        for key in ACCOUNT_BOOLS: need(type(account[key]) is bool, 'accounting-exact-booleans')
        need(account['schema'] == 'kpx8-neutral-recorded-live-accounting/v1'
             and account['auditor_sha256'] == AUDITOR_SHA
             and account['accepted_pool_transaction_count'] == 12 and account['accepted_payment_round_count'] == 2
             and account['confirmed_payout_count'] == 9 and account['remaining_reserve_sompi'] == 0
             and account['pool_fees_sompi'] == fee_total and account['native_payout_sompi'] == payout_total
             and account['fixed_useful_payment_sompi'] == 2100000000
             and all(account[k] is True for k in ['complete_requested_lifecycle', 'financial_chain_terminal',
                 'three_original_seed_terminal_scans', 'whole_trial_sompi_conservation',
                 'terminal_claims_and_payout_keys_reconciled_locally', 'terminal_scan_cohort_equality_checked_locally'])
             and account['independent_consensus_or_crypto_proof_verified'] is False
             and account['privacy_or_separate_administration_qualified'] is False, 'complete-neutral-terminal-accounting')
        fields(account['accepted_prefix_evidence_sha256'], {'fetch', 'replay', 'history', 'checkpoint', 'native-tail'})
        for key, role in [('fetch', 'fetch.json'), ('replay', 'RESULTS.json'), ('history', 'HISTORY.json'), ('checkpoint', 'CHECKPOINT.json')]:
            need(account['accepted_prefix_evidence_sha256'][key] == h['selectors'][role]['sha256'], 'accounting-terminal-prefix-join')
        need(account['accepted_prefix_evidence_sha256']['native-tail'] == TAIL_SHA, 'selected-native-tail')
        need(account['complete_fee_sompi_so_far'] == account['pool_fees_sompi'] + account['acquisition_fees_sompi'], 'all-in-fee-scope')
        ratio = math.gcd(account['complete_fee_sompi_so_far'], account['fixed_useful_payment_sompi'])
        need((account['fee_ratio_numerator'], account['fee_ratio_denominator']) ==
             (account['complete_fee_sompi_so_far'] // ratio, account['fixed_useful_payment_sompi'] // ratio), 'exact-fee-ratio')
        need(account['two_percent_target_verdict'] == ('PASS' if account['complete_fee_sompi_so_far'] * 100 <= 2 * account['fixed_useful_payment_sompi'] else 'FAIL'), 'unchanged-two-percent-target')
        outage = docs['outage']; fields(outage, OUTAGE_FIELDS)
        need(outage['schema'] == 'kpx8-observed-original-service-outage-aggregate/v1'
             and outage['trial_id'] == trial and outage['financial_profile_sha256'] == PROFILE,
             'neutral-outage-profile')
        need(outage['accepted_R2_handoff_sha256'] == docs['r2']['handoff_sha256'], 'outage-accepted-R2-join')
        for key in ['all_recorded_owned_prover_process_identities_gone',
                    'all_six_original_submission_processes_and_last_confirmation_exited',
                    'all_three_original_MPC_parties_and_coordinator_completed',
                    'original_pool_writer_authority_relinquished',
                    'public_read_only_chain_observer_remains_available', 'same_physical_host_isolated_replacement_namespaces']:
            need(outage[key] is True, 'actual-original-service-quiescence')
        for key in ['client_owner_NF_or_payout_associations_exported', 'durable_retention_guarantee_demonstrated',
                    'independent_machine_or_administrator_demonstrated', 'original_protected_contents_read_or_hashed_for_this_summary']:
            need(outage[key] is False, 'bounded-outage-claims')
        need(type(outage['owned_shared_prover_units_stopped']) is int and outage['owned_shared_prover_units_stopped'] > 0
             and type(outage['owned_MPC_containers_or_integration_units_running']) is int
             and outage['owned_MPC_containers_or_integration_units_running'] == 0
             and type(outage['owned_prover_GPU_processes_sockets_or_construction_containers_running']) is int
             and outage['owned_prover_GPU_processes_sockets_or_construction_containers_running'] == 0, 'no-original-owned-services-running')
        fields(outage['source_receipt_sha256'], {'coordinator_mpc', 'original_writer', 'shared_prover'})
        for pin in outage['source_receipt_sha256'].values(): hx(pin, 32)
        # Everything above is metadata validation. No output is created until all inputs pass.
        for name in ['sdk', 'accounting', 'outage', 'top-selection', 'top-closure']:
            row = files[name]
            self.add({'sdk':'terminal-sdk','accounting':'terminal-accounting','outage':'original-service-outage',
                'top-selection':'initial-recovery-selection','top-closure':'initial-recovery-closure'}[name],
                row['path'], row['bytes'], row['sha256'], 'metadata/' + name + '.json')
        self.add('terminal-observer-handoff', files['handoff']['path'], files['handoff']['bytes'],
                 files['handoff']['sha256'], 'observations/HANDOFF.json')
        initial = [*docs['static']['objects'], *docs['r2']['objects']]
        for row in initial:
            if row['id'] in STATIC_VERIFY_IDS | {'closed-replay-bootstrap'}:
                need((row['sha256'], row['bytes']) in self.observed, 'existing-verification-dependency-public')
                self.add(row['id'], row['source_path'], row['bytes'], row['sha256'], row['placement'], kind=row['kind'])
        need(STATIC_VERIFY_IDS | {'closed-replay-bootstrap'} <= {o['id'] for o in self.objects}, 'complete-public-replay-bootstrap')
        prefix = Path(h['selectors']['fetch.json']['path']).parent
        records = [*fetch['pages'], *fetch['current_view']['post_query_delta']['pages']]
        need(records, 'complete-prefix-pages-required')
        selected_pages = {}
        for page in h['full_prefix_pages']:
            fields(page, {'path', 'bytes', 'sha256'}); public_path(page['path']); uint(page['bytes']); hx(page['sha256'], 32)
            need(page['path'] not in selected_pages, 'distinct-handoff-pages')
            selected_pages[page['path']] = (page['bytes'], page['sha256'])
        need(len(records) == len(selected_pages), 'all-main-and-postquery-pages-selected')
        packet_pages, new_gzip = [], []
        logical_pages = set()
        for index, record in enumerate(records):
            fields(record, {'path', 'request', 'decoded_sha256', 'decoded_bytes', 'gzip_sha256',
                            'gzip_bytes', 'encoding'}, 'exact-retained-page-metadata')
            relative = logical(record['path']); need(relative not in logical_pages, 'distinct-logical-page-paths')
            logical_pages.add(relative); source = prefix / relative; public_path(str(source))
            for name in ['gzip_bytes', 'decoded_bytes']: uint(record[name])
            for name in ['gzip_sha256', 'decoded_sha256']: hx(record[name], 32)
            need(selected_pages.get(str(source)) == (record['gzip_bytes'], record['gzip_sha256']), 'every-page-exact-handoff-join')
            self.metadata(source, record['gzip_bytes'])
            obj = self.add('terminal-prefix-page-%05d' % index, source, record['gzip_bytes'], record['gzip_sha256'],
                           'data/' + relative, '.json.gz')
            packet_pages.append({'path': relative, 'bytes': record['gzip_bytes'], 'sha256': record['gzip_sha256']})
            if obj['upload_required']:
                new_gzip.append({'path': relative, 'source': str(source), **{k:record[k] for k in
                    ['gzip_bytes','gzip_sha256','decoded_bytes','decoded_sha256']}})
        packet_inputs = {}
        for role, normalized in [('selection','selection'),('descriptor','descriptor'),('fetch.json','fetch'),
                                 ('parameters','parameters'),('sessions','sessions'),('source_pins','source-pins')]:
            packet_inputs[normalized] = {'path': SELECTORS[role][1], 'bytes': len(raw_protocol[role]),
                                         'sha256': h['selectors'][role]['sha256']}
        self.new_json('terminal-replay-packet', 'REPLAY-PACKET.json', {
            'schema':'kpx8-closed-replay-public-inputs/v1','financial_profile_sha256':PROFILE,
            'inputs':packet_inputs,'pages':packet_pages,
            'expected':{'history_sha256':h['selectors']['HISTORY.json']['sha256'],
                        'checkpoint_sha256':h['selectors']['CHECKPOINT.json']['sha256']}}, 'data/REPLAY-PACKET.json')
        self.new_json('terminal-payout-observations', 'PAYOUTS.json', {
            'schema':'kpx8-terminal-public-payout-observations/v1','financial_profile_sha256':PROFILE,
            'trial_id':trial,'fetch_sha256':h['selectors']['fetch.json']['sha256'],
            'recorded_queries_not_independent_consensus':True,'native_payouts':observations}, 'observations/PAYOUTS.json')
        self.new_json('terminal-seed-aggregate', 'TERMINAL-AGGREGATE.json', {
            'schema':'kpx8-neutral-terminal-seed-aggregate/v1','financial_profile_sha256':PROFILE,
            'history_sha256':h['selectors']['HISTORY.json']['sha256'],'original_seed_scans_completed':3,
            'all_owned_claims_spent':True,'all_historical_native_payout_keys_rederived':True,
            'accepted_cohort_equality_checked_locally':True,'client_associations_exported':False,
            'independent_ownership_proof_claimed':False}, 'observations/TERMINAL-AGGREGATE.json')
        index = {'schema':'kpx8-terminal-public-evidence-index/v1','domain_hex32':D,'financial_profile_sha256':PROFILE,
            'trial_id':trial,'accepted_pool_transaction_ids':ids,'accepted_cases':case_rows,
            'checkpoint_sha256':h['selectors']['CHECKPOINT.json']['sha256'],
            'initial_R2_inventory_sha256':R2_SHA,'initial_R2_snapshot_changed':False,
            'owner_client_associations_selected':False,'financial_verifier_or_consensus_claimed_by_packager':False,
            'availability_claimed_by_manifest':False,
            'objects':[{k:o[k] for k in ['id','kind','bytes','sha256','placement','release_filename','public_urls']}
                       for o in self.objects]}
        self.new_json('terminal-evidence-index', 'INDEX.json', index, 'metadata/TERMINAL-EVIDENCE-INDEX.json')
        gzip_map = {'schema':'owner-private-lifecycle-root-gzip-audit-map/v1','dataset_id':'terminal-public-evidence-01',
                    'domain_hex32':D,'financial_profile_sha256':PROFILE,'pages':new_gzip}
        self.generated['GZIP-AUDIT-MAP.json'] = encoded(gzip_map)
        new = [o for o in self.objects if o['upload_required']]
        candidate = {'schema':'kpx8-public-terminal-evidence-candidate/v1',
            'status':'TERMINAL_METADATA_VALIDATED_PENDING_WHOLE_OBJECT_AUDIT_AND_PUBLICATION',
            'domain_hex32':D,'financial_profile_sha256':PROFILE,'trial_id':trial,
            'objects':self.objects,'new_upload_object_ids':[o['id'] for o in new],
            'object_count':len(self.objects),'new_upload_object_count':len(new),
            'new_upload_bytes':sum(o['bytes'] for o in new),
            'reused_object_count':len(self.objects)-len(new),
            'new_gzip_audit_map_sha256':digest(self.generated['GZIP-AUDIT-MAP.json']),
            'new_gzip_audit_only_decoded_bytes':sum(r['decoded_bytes'] for r in new_gzip),
            'root_input_selection_sha256':digest(encoded(selected)),
            'initial_R2_snapshot_changed':False,'payloads_copied_or_fetched':False,
            'owner_client_associations_selected':False,'page_payload_hash_audit_still_required':True}
        candidate['new_public_URLs_require_actual_upload_observation_and_HTTPS_verification'] = True
        self.generated['CANDIDATE-OBJECTS.json'] = encoded(candidate)
        return candidate


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(args.output.is_absolute() and args.output.is_relative_to(ASSETS) and not args.output.exists()
         and not args.output.is_symlink() and all(not p.is_symlink() for p in args.output.parents), 'fresh-assets-output')
    h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    source = h['read'](REPO / REPLAY_SOURCE, REPLAY_SHA)
    converter = load_converter(source)
    raw = h['read'](args.selection, args.selection_sha256)
    need(digest(raw) == args.selection_sha256, 'external-root-input-selection')
    def metadata(path, size):
        _, value = h['m'].GUARD.metadata(path)
        need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_size == size, 'regular-single-link-public-page')
    assembler = Assembler(h['read'], metadata, converter, args.output)
    candidate = assembler.plan(parse(raw))
    # Preserve the exact externally selected byte identity rather than JSON reserialization.
    candidate['root_input_selection_sha256'] = digest(raw)
    assembler.generated['CANDIDATE-OBJECTS.json'] = encoded(candidate)
    args.output.mkdir(parents=True, mode=0o700)
    for name, payload in assembler.generated.items(): write_new(args.output / name, payload)
    print(json.dumps({k:candidate[k] for k in ['status','object_count','new_upload_object_count',
        'new_upload_bytes','reused_object_count','new_gzip_audit_only_decoded_bytes']}, sort_keys=True))


if __name__ == '__main__':
    main()

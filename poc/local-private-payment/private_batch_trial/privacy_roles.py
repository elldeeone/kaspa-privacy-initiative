#!/usr/bin/env python3
"""Network-off observer, one-owner scorer and clean count aggregator workers.

Invoke only through a trusted finite namespace launcher. Each operation checks
its role marker and cannot run directly on the host. Private capsules, truth,
count leaves and diagnostic logs are never controller body/hash inputs.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import stat

import privacy_codec as codec
import privacy_capture_model as capture_model
import privacy_observer as observer
import privacy_owner
import privacy_source_closure as source_closure


def stable_read(path, *, expected=None, private_mode=None):
    path = Path(path)
    codec.need(not any(part.is_symlink() for part in (path, *path.parents)), 'privacy-selected-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        codec.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'privacy-single-link-regular-leaf')
        if private_mode is not None:
            codec.need(stat.S_IMODE(before.st_mode) == private_mode, 'privacy-private-leaf-mode')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        codec.need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'privacy-stable-leaf')
    if expected is not None:
        codec.need(hashlib.sha256(raw).hexdigest() == codec.word(expected), 'privacy-exact-selected-public-or-sealed-input')
    return raw


def write_new(path, value, mode=0o400):
    path = Path(path)
    raw = value if type(value) is bytes else codec.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def selected_json(row):
    codec.fields(row, ('path', 'sha256'))
    return codec.parse(stable_read(row['path'], expected=row['sha256']))


def validate_v2_worker_identity(config, root_guard_source):
    """Validate only identities explicitly mounted for this worker role."""
    selected = {
        'schema': 'kpb-transitive-source-closure/v1',
        'role': 'observer',
        'members': [{
            'name': row['name'],
            'sha256': row['sha256'],
        } for row in config['source_members']],
    }
    for row in config['source_members']:
        codec.fields(row, ('name', 'path', 'sha256'))
        codec.need(Path(row['path']) ==
                   (source_closure.NAMESPACE_SOURCE_ROOT /
                    row['name']).resolve(),
                   'privacy-v2-exact-role-source-route')
    source_closure.validate_manifest(selected, 'observer')
    runtime = source_closure.runtime_identity(root_guard_source)
    codec.need(
        type(config['source_closure_sha256']) is dict
        and config['source_closure_sha256'].get('observer') ==
            source_closure.digest('observer')
        and config['runtime_identity_sha256'] == hashlib.sha256(
            source_closure.encoded(runtime)).hexdigest()
        and config['python_runtime_sha256'] ==
            runtime['python_runtime_sha256']
        and config['namespace_tool_sha256'] ==
            runtime['namespace_tool_sha256']
        and config['root_guard_helper_sha256'] ==
            runtime['root_guard_helper_sha256']
        and config['host_runtime_trust_boundary'] ==
            runtime['host_runtime_trust_boundary']
        and config['step3_terminal_gate'] ==
            'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3',
        'privacy-v2-source-runtime-terminal-freeze')


def require_namespace(operation):
    marker = codec.parse(stable_read('/NAMESPACE.json'))
    codec.need(marker == {'schema': 'kpb-private-diagnostic-namespace/v1', 'operation': operation,
        'network': 'disabled', 'truth_owner_slots': 1 if operation == 'score' else 0,
        'colluder_owner_slots': 1 if operation == 'observe' else 0,
        'corrupt_server_slots': 1 if operation == 'observe' else 0}, 'privacy-exact-diagnostic-role')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    codec.need(interfaces == ['lo'] and not Path('/home/luke/.codex').exists()
        and not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists()
        and not Path('/home/luke/.ssh').exists(), 'privacy-network-off-no-host-private-roots')
    if operation != 'observe':
        codec.need(not Path('/colluder').exists() and not Path('/corrupt-server').exists(), 'privacy-score-no-observer-secrets')
        codec.need(not Path('/original').exists(), 'privacy-diagnostics-no-Original-needed')
    else:
        codec.need(not Path('/truth').exists() and not Path('/original').exists(), 'privacy-observer-no-honest-truth-mount')
    if operation == 'aggregate':
        codec.need(not Path('/truth').exists() and not Path('/original').exists(), 'privacy-aggregate-no-truth-or-Original')
    config = codec.parse(stable_read('/CONFIG.json'))
    codec.binding(config['binding'])
    for row in config['source_members']:
        stable_read(row['path'], expected=row['sha256'])
    if config.get('schema') == 'kpb-private-diagnostic-role-config/v2':
        validate_v2_worker_identity(
            config, source_closure.NAMESPACE_SOURCE_ROOT /
            'root_guard_helper.py')
    return config


def _candidate_lattice(models_by_view, workloads):
    edges = (('public', 'dispatcher'),
             ('public', 'corrupt-server-plus-wallet'),
             ('dispatcher', 'union'),
             ('corrupt-server-plus-wallet', 'union'))

    def round_set(model):
        return {codec.encoded(row) for row in model['joint']}

    def workload_set(view):
        models = models_by_view[view]
        return {codec.encoded([
            models[0]['joint'][pair[0]],
            models[1]['joint'][pair[1]],
        ]) for pair in workloads[view]['joint']}

    round_ok = all(
        round_set(models_by_view[stronger][index]).issubset(
            round_set(models_by_view[weaker][index]))
        for weaker, stronger in edges for index in range(2))
    workload_ok = all(workload_set(stronger).issubset(
        workload_set(weaker)) for weaker, stronger in edges)
    codec.need(round_ok and workload_ok,
               'privacy-source-derived-candidate-lattice')
    return {
        'exact_union_artifact_set': True,
        'exact_union_constraints': True,
        'candidate_subset_lattice_verified': True,
        'full_workload_subset_lattice_verified': True,
    }


def observe_v2(config):
    codec.fields(config, (
        'schema', 'binding', 'comparison_selection_sha256',
        'run_selection_sha256', 'diagnostic_selection_sha256',
        'source_members', 'source_closure_sha256',
        'runtime_identity_sha256', 'python_runtime_sha256',
        'namespace_tool_sha256', 'root_guard_helper_sha256',
        'host_runtime_trust_boundary', 'step3_terminal_gate',
        'capture_receipt', 'capture_models',
        'construction_classification'))
    for name in ('comparison_selection_sha256', 'run_selection_sha256',
                 'diagnostic_selection_sha256'):
        codec.word(config[name])
    capture_receipt = selected_json(config['capture_receipt'])
    construction = selected_json(config['construction_classification'])
    models_value = codec.parse(stable_read(config['capture_models'],
                                           private_mode=0o600))
    codec.fields(models_value, ('schema', 'binding', 'rounds'))
    codec.need(models_value['schema'] ==
               'kpb-private-actual-capture-models/v1'
               and models_value['binding'] == config['binding']
               and type(models_value['rounds']) is list
               and len(models_value['rounds']) == 2,
               'privacy-v2-capture-models')
    codec.need(capture_receipt['schema'] ==
               'kpb-privacy-actual-capture-receipt/v2'
               and capture_receipt['binding'] == config['binding']
               and capture_receipt['comparison_selection_sha256'] ==
                    config['comparison_selection_sha256']
               and capture_receipt['run_selection_sha256'] ==
                    config['run_selection_sha256']
               and capture_receipt['source_closure_sha256'] ==
                    config['source_closure_sha256']
               and capture_receipt['runtime_identity_sha256'] ==
                    config['runtime_identity_sha256']
               and capture_receipt['step3_terminal_gate'] ==
                    config['step3_terminal_gate']
               and construction['schema'] ==
                    'kpb-financial-construction-classification/v1'
               and construction['comparison_selection_sha256'] ==
                    config['comparison_selection_sha256']
               and construction['run_selection_sha256'] ==
                    config['run_selection_sha256']
               and hashlib.sha256(codec.encoded(construction)).hexdigest() ==
                    capture_receipt[
                        'construction_classification_receipt_sha256'],
               'privacy-v2-capture-chain')
    models_by_view = {view: [] for view in codec.VIEWS}
    terminal_by_round = []
    for round_number, private_round in enumerate(models_value['rounds'], 1):
        codec.fields(private_round,
                     ('round', 'public', 'typed_artifacts', 'derived'))
        public = private_round['public']
        codec.need(private_round['round'] == round_number
                   and public['round'] == round_number,
                   'privacy-v2-private-round-order')
        derived = capture_model.derive_view_artifacts(
            public, private_round['typed_artifacts'])
        codec.need(derived == private_round['derived'],
                   'privacy-v2-recomputed-view-inventory')
        terminal = [artifact for artifact in
                    private_round['typed_artifacts']
                    if artifact['kind'] == 'terminal-history']
        codec.need(len(terminal) == 1,
                   'privacy-v2-one-terminal-artifact')
        terminal_by_round.extend(terminal)
        for view in codec.VIEWS:
            models_by_view[view].append(codec.assignments(
                public, derived['views'][view]['constraints']))
    workloads = {view: capture_model.workload_candidates(
        models_by_view[view], terminal_by_round) for view in codec.VIEWS}
    lattice = _candidate_lattice(models_by_view, workloads)
    write_new('/state/OBSERVATION-CLOSED', {
        'binding': config['binding'], 'operation': 'observe',
        'capture_receipt_sha256': config['capture_receipt']['sha256']})
    capture_views = {row['view']: row for row in capture_receipt['views']}
    codec.need(set(capture_views) == set(codec.VIEWS),
               'privacy-v2-capture-four-views')
    receipts = []
    for view in codec.VIEWS:
        captured = capture_views[view]
        categories = {}
        for row in captured['rounds']:
            for category, counts in row['category_coverage'].items():
                total = categories.setdefault(
                    category, {name: 0 for name in counts})
                codec.need(set(total) == set(counts),
                           'privacy-v2-category-field-set')
                for name in total:
                    total[name] += counts[name]
        predicted = codec.prediction(
            config['binding'], view, models_by_view[view],
            captured['coverage'], category_coverage=categories,
            workload=workloads[view], lattice_attestation=lattice)
        capsule, seal = codec.seal(predicted, secrets.token_bytes(32))
        write_new('/state/PREDICTIONS-' + view + '.bin', capsule)
        receipts.append({
            'view': view,
            'capsule_seal_sha256': seal,
            'capsule_bytes': len(capsule),
            'rounds': [{
                'round': model['public']['round'],
                **{name: model[name] for name in (
                    'input_owner_assignments',
                    'output_creator_assignments',
                    'output_pair_partitions', 'joint_candidates',
                    'nf_to_created_pair_relations',
                    'nf_pair_candidate_count_histogram',
                    'forbidden_exports')},
            } for model in models_by_view[view]],
            'coverage': captured['coverage'],
            'category_coverage': categories,
            'workload': {name: workloads[view][name] for name in (
                'full_workload_candidates',
                'cross_round_constraints_modeled',
                'terminal_constraints_modeled',
                'candidate_set_commitment_sha256')},
            'lattice_attestation': lattice,
        })
    write_new('/out/PUBLIC.json', {
        'schema': 'kpb-direct-observation-receipt/v2',
        'binding': config['binding'],
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'run_selection_sha256': config['run_selection_sha256'],
        'capture_receipt_sha256': config['capture_receipt']['sha256'],
        'capture_manifest_seal_sha256':
            capture_receipt['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            capture_receipt[
                'construction_classification_receipt_sha256'],
        'capture_producer_receipt_sha256':
            capture_receipt['capture_producer_receipt_sha256'],
        'source_closure_sha256': capture_receipt['source_closure_sha256'],
        'runtime_identity_sha256':
            capture_receipt['runtime_identity_sha256'],
        'terminal_scope': capture_receipt['terminal_scope'],
        'step3_terminal_gate': capture_receipt['step3_terminal_gate'],
        'views': receipts,
        'predictions_frozen_before_truth': True,
        'private_view_or_prediction_records_exported': False,
    })


def observe(config):
    if config.get('schema') == 'kpb-private-diagnostic-role-config/v2':
        return observe_v2(config)
    codec.need([view['view'] for view in config['views']] == list(codec.VIEWS), 'privacy-all-declared-views')
    write_new('/state/OBSERVATION-CLOSED', {'binding': config['binding'], 'operation': 'observe'})
    receipts = []
    for view in config['views']:
        codec.fields(view, ('view', 'rounds'))
        codec.need([part['round'] for part in view['rounds']] == [1, 2], 'privacy-complete-observed-rounds')
        models, totals = [], {'modeled_artifacts': 0, 'unmodeled_artifacts': 0, 'missing_artifacts': 0, 'terminal_modeled': True}
        for part in view['rounds']:
            codec.fields(part, ('round', 'projection', 'artifacts', 'colluder_constraints'))
            raw = stable_read(part['projection']['path'], expected=part['projection']['sha256'])
            public = observer.batch_from_projection(part['round'], raw)
            artifacts = [('public-projection', raw, None)]
            kinds, actual_routes = set(), []
            for artifact in part['artifacts']:
                codec.fields(artifact, ('kind', 'path', 'sha256', 'route_owner'))
                kinds.add(artifact['kind'])
                # Private view bytes are read only inside this role. A null
                # public hash is expected for a private captured artifact.
                data = stable_read(artifact['path'], expected=artifact['sha256'])
                if artifact['kind'] == 'invoice-route':
                    actual_routes.append(observer.route_record(codec.parse(data)))
                artifacts.append((artifact['kind'], data, artifact['route_owner']))
            facts = None
            if part['colluder_constraints'] is not None:
                facts = codec.parse(stable_read(part['colluder_constraints'], private_mode=0o600))
                codec.fields(facts, ('schema', 'binding', 'round', 'context_sha256', 'constraints'))
                codec.need(facts['schema'] == 'kpb-private-colluder-constraints/v1' and facts['binding'] == config['binding']
                    and facts['round'] == part['round'] and facts['context_sha256'] == public['context_sha256'],
                    'privacy-own-derived-colluder-facts')
                facts = codec.constraints(facts['constraints'], public)
            model, coverage = observer.collect(public, artifacts, facts)
            required = {'terminal-history'}
            if view['view'] in ('dispatcher', 'union'): required |= {'dispatcher-capture', 'invoice-route'}
            if view['view'] in ('dispatcher', 'union'):
                routed = {row['source_owner_component'] for row in actual_routes if row['round'] == part['round']}
                coverage['missing_artifacts'] += len(set(codec.OWNERS) - routed)
            if view['view'] in ('corrupt-server-plus-wallet', 'union'):
                required |= {'corrupt-server-capture',
                             'colluder-wallet-capture'}
                coverage['missing_artifacts'] += int(facts is None)
            coverage['missing_artifacts'] += len(required - kinds)
            for name in ('modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts'):
                totals[name] += coverage[name]
            totals['terminal_modeled'] = (totals['terminal_modeled']
                                          and coverage['terminal_modeled'])
            models.append(model)
        predicted = codec.prediction(config['binding'], view['view'], models, totals)
        capsule, seal = codec.seal(predicted, secrets.token_bytes(32))
        write_new('/state/PREDICTIONS-' + view['view'] + '.bin', capsule)
        receipts.append({'view': view['view'], 'capsule_seal_sha256': seal, 'capsule_bytes': len(capsule),
            'rounds': [{name: model[name] for name in ('input_owner_assignments', 'output_creator_assignments',
                'output_pair_partitions', 'joint_candidates', 'nf_to_created_pair_relations',
                'nf_pair_candidate_count_histogram', 'forbidden_exports')} for model in models], 'coverage': totals})
    write_new('/out/PUBLIC.json', {'schema': 'kpb-direct-observation-receipt/v1', 'binding': config['binding'],
        'views': receipts, 'predictions_frozen_before_truth': True, 'private_view_or_prediction_records_exported': False})


def frozen_predictions(config):
    barrier = selected_json(config['barrier'])
    if config.get('schema') == 'kpb-private-diagnostic-role-config/v2':
        codec.fields(barrier, (
            'schema', 'binding', 'comparison_selection_sha256',
            'run_selection_sha256', 'capture_receipt_sha256',
            'capture_manifest_seal_sha256',
            'construction_classification_receipt_sha256',
            'terminal_scope', 'observation_receipt_sha256', 'capsules'))
        receipt = selected_json(config['observation_receipt'])
        codec.fields(receipt, (
            'schema', 'binding', 'comparison_selection_sha256',
            'run_selection_sha256', 'capture_receipt_sha256',
            'capture_manifest_seal_sha256',
            'construction_classification_receipt_sha256',
            'capture_producer_receipt_sha256', 'source_closure_sha256',
            'runtime_identity_sha256', 'terminal_scope',
            'step3_terminal_gate', 'views',
            'predictions_frozen_before_truth',
            'private_view_or_prediction_records_exported'))
        expected = [{'view': row['view'],
                     'capsule_seal_sha256': row['capsule_seal_sha256']}
                    for row in receipt['views']]
        codec.need(
            receipt['schema'] == 'kpb-direct-observation-receipt/v2'
            and receipt['binding'] == config['binding']
            and receipt['comparison_selection_sha256'] ==
                config['comparison_selection_sha256']
            and receipt['run_selection_sha256'] ==
                config['run_selection_sha256']
            and receipt['predictions_frozen_before_truth'] is True
            and receipt['private_view_or_prediction_records_exported']
                is False
            and [row['view'] for row in receipt['views']] ==
                list(codec.VIEWS)
            and barrier == {
                'schema': 'kpb-direct-prediction-barrier/v2',
                'binding': config['binding'],
                'comparison_selection_sha256':
                    config['comparison_selection_sha256'],
                'run_selection_sha256': config['run_selection_sha256'],
                'capture_receipt_sha256':
                    receipt['capture_receipt_sha256'],
                'capture_manifest_seal_sha256':
                    receipt['capture_manifest_seal_sha256'],
                'construction_classification_receipt_sha256':
                    receipt[
                        'construction_classification_receipt_sha256'],
                'capture_producer_receipt_sha256':
                    receipt['capture_producer_receipt_sha256'],
                'source_closure_sha256':
                    receipt['source_closure_sha256'],
                'runtime_identity_sha256':
                    receipt['runtime_identity_sha256'],
                'terminal_scope': receipt['terminal_scope'],
                'step3_terminal_gate': receipt['step3_terminal_gate'],
                'observation_receipt_sha256':
                    config['observation_receipt']['sha256'],
                'capsules': expected,
            }, 'privacy-v2-fixed-pretruth-barrier')
        return receipt, expected
    codec.fields(barrier, ('schema', 'binding', 'observation_receipt_sha256', 'capsules'))
    codec.need(barrier['schema'] == 'kpb-direct-prediction-barrier/v1' and barrier['binding'] == config['binding']
        and barrier['observation_receipt_sha256'] == config['observation_receipt']['sha256'], 'privacy-fixed-pretruth-barrier')
    receipt = selected_json(config['observation_receipt'])
    codec.fields(receipt, ('schema', 'binding', 'views', 'predictions_frozen_before_truth', 'private_view_or_prediction_records_exported'))
    codec.need(receipt['schema'] == 'kpb-direct-observation-receipt/v1' and receipt['binding'] == config['binding']
        and receipt['predictions_frozen_before_truth'] is True and receipt['private_view_or_prediction_records_exported'] is False
        and [row['view'] for row in receipt['views']] == list(codec.VIEWS), 'privacy-observer-receipt-before-truth')
    expected = [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in receipt['views']]
    codec.need(barrier['capsules'] == expected, 'privacy-all-four-capsules-presealed')
    return receipt, expected


def private_capsules(config, expected):
    codec.need([row['view'] for row in config['capsules']] == list(codec.VIEWS), 'privacy-all-four-original-capsule-leaves')
    values = []
    for selected, frozen in zip(config['capsules'], expected):
        codec.fields(selected, ('view', 'path'))
        predicted = codec.unseal(stable_read(selected['path'], private_mode=0o400), frozen['capsule_seal_sha256'])
        codec.need(predicted['binding'] == config['binding'] and predicted['view'] == selected['view'], 'privacy-original-capsule-context')
        values.append(predicted)
    return values


def score(config):
    _, frozen = frozen_predictions(config)
    codec.owner(config['owner_component'])
    # Fixed state leaf must be mounted from this Original owner's one persistent
    # diagnostics directory. The trusted launcher verifies that exact routing.
    write_new('/state/SCORING-CLOSED', {'binding': config['binding'], 'barrier_sha256': config['barrier']['sha256']})
    predictions = private_capsules(config, frozen)
    codec.need(len(config['truth_commitments']) == 2, 'privacy-own-two-original-public-commitments')
    truth = []
    for round_number, selected in enumerate(config['truth_commitments'], 1):
        public = selected_json(selected)
        raw = stable_read('/truth/round' + str(round_number) + '.json', private_mode=0o600)
        truth.append(privacy_owner.open_truth(raw, public, config['binding'], config['owner_component'], round_number))
    leaves = [codec.score_owner(predicted, truth, frozen[index]['capsule_seal_sha256'])
              for index, predicted in enumerate(predictions)]
    if config.get('schema') == 'kpb-private-diagnostic-role-config/v2':
        write_new('/state/COUNTS.json', {
            'schema': 'kpb-private-all-view-count-leaves/v2',
            'binding': config['binding'],
            'run_selection_sha256': config['run_selection_sha256'],
            'owner_component': config['owner_component'],
            'views': leaves,
        })
        write_new('/out/PUBLIC.json', {
            'schema': 'kpb-private-score-completed/v2',
            'binding': config['binding'],
            'comparison_selection_sha256':
                config['comparison_selection_sha256'],
            'run_selection_sha256': config['run_selection_sha256'],
            'barrier_sha256': config['barrier']['sha256'],
            'owner_component': config['owner_component'],
            'source_closure_sha256': config['source_closure_sha256'],
            'runtime_identity_sha256': config['runtime_identity_sha256'],
            'step3_terminal_gate': config['step3_terminal_gate'],
            'per_owner_counts_or_truth_exported': False,
        })
        return
    write_new('/state/COUNTS.json', {'schema': 'kpb-private-all-view-count-leaves/v1',
        'binding': config['binding'], 'owner_component': config['owner_component'], 'views': leaves})
    write_new('/out/PUBLIC.json', {'schema': 'kpb-private-score-completed/v1',
        'binding': config['binding'], 'per_owner_counts_or_truth_exported': False})


def aggregate(config):
    _, frozen = frozen_predictions(config)
    predictions = private_capsules(config, frozen)
    codec.need(len(config['count_files']) == 3, 'privacy-all-three-original-count-leaves')
    bundles = [codec.parse(stable_read(path, private_mode=0o400)) for path in config['count_files']]
    codec.need(sorted(bundle['owner_component'] for bundle in bundles) == [0, 1, 2], 'privacy-three-original-owner-counts')
    v2 = config.get('schema') == 'kpb-private-diagnostic-role-config/v2'
    for bundle in bundles:
        expected_fields = ('schema', 'binding', 'owner_component',
                           'views') + (('run_selection_sha256',) if v2 else ())
        codec.fields(bundle, expected_fields)
        codec.need(bundle['schema'] ==
                   ('kpb-private-all-view-count-leaves/v2' if v2 else
                    'kpb-private-all-view-count-leaves/v1')
            and bundle['binding'] == config['binding']
            and (not v2 or bundle['run_selection_sha256'] ==
                 config['run_selection_sha256'])
            and [leaf['view'] for leaf in bundle['views']] == list(codec.VIEWS), 'privacy-all-view-private-count-contexts')
    result = [codec.aggregate(predicted, [bundle['views'][index] for bundle in bundles], frozen[index]['capsule_seal_sha256'])
              for index, predicted in enumerate(predictions)]
    if v2:
        lattice = predictions[0]['lattice_attestation']
        codec.need(all(predicted['lattice_attestation'] == lattice
                       for predicted in predictions),
                   'privacy-v2-common-lattice-attestation')
        observation = selected_json(config['observation_receipt'])
        write_new('/out/PUBLIC.json', {
            'schema': 'kpb-public-all-view-direct-counts/v2',
            'binding': config['binding'],
            'comparison_selection_sha256':
                config['comparison_selection_sha256'],
            'run_selection_sha256': config['run_selection_sha256'],
            'capture_receipt_sha256':
                observation['capture_receipt_sha256'],
            'barrier_sha256': config['barrier']['sha256'],
            'capture_producer_receipt_sha256':
                observation['capture_producer_receipt_sha256'],
            'source_closure_sha256': config['source_closure_sha256'],
            'runtime_identity_sha256': config['runtime_identity_sha256'],
            'step3_terminal_gate': config['step3_terminal_gate'],
            'lattice_attestation': lattice,
            'views': result,
            'private_records_masks_or_per_owner_counts_exported': False,
        })
        return
    write_new('/out/PUBLIC.json', {'schema': 'kpb-public-all-view-direct-counts/v1', 'binding': config['binding'],
        'views': result, 'private_records_masks_or_per_owner_counts_exported': False})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('observe', 'score', 'aggregate'))
    operation = parser.parse_args().operation
    try:
        config = require_namespace(operation)
        {'observe': observe, 'score': score, 'aggregate': aggregate}[operation](config)
    except BaseException:
        # No private exception category/value, source-local object or traceback
        # enters the public diagnostic export.
        if Path('/out').is_dir() and not Path('/out/PUBLIC-FAILURE.json').exists():
            write_new('/out/PUBLIC-FAILURE.json', {'schema': 'kpb-private-diagnostic-incomplete/v1', 'operation': operation})
        raise SystemExit(2)


if __name__ == '__main__':
    main()

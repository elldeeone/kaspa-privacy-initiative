#!/usr/bin/env python3
"""Synthetic container/selector controls and known PUBLIC owner namespaces only.

No actual-original metadata function is permitted to run. The twelve-role
envelope uses synthetic transaction IDs/reports, explicitly NOT accepted-node
evidence. Separate unchanged workers replay an existing genuine-component public
fixture; that is supplied-context evidence, never actual trial acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
import subprocess

HERE = Path('/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01')
ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
READ = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
SOURCE = HERE / 'final_publication_launch.py'
FIXTURE = Path('/var/tmp/kpi-local-private-payment-01/results/public/wallet-matched21-fixture-01')
CLASS = 'KNOWN_PUBLIC_SYNTHETIC_PROVENANCE_ENVELOPE_NOT_ACCEPTED_NODE_EVIDENCE'
STATUS = 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
    path.chmod(mode)


def load_source():
    raw = READ(str(SOURCE))
    scope = {'__name__': 'known_public_final_scope_controls', '__file__': str(SOURCE)}
    exec(compile(raw, str(SOURCE), 'exec'), scope)
    return scope, sha(raw)


def synthetic_envelope(api, hraw, craw, rows):
    history, context = json.loads(hraw), json.loads(craw)
    trial = '00000000-0000-4000-8000-000000000001'
    ids = [sha(b'KNOWN PUBLIC SYNTHETIC TX ID ' + bytes([i])) for i in range(16)]
    documents = {role: encoded({'fixture_classification': CLASS, 'role': role}) for role in api['ROLES']}
    documents.update({'history': hraw, 'context': craw, 'currententry': b'null\n',
        'descriptor': encoded({'trial_id': trial, 'fixture_classification': CLASS}),
        'fetch': encoded({'schema': 'kpxa-gn3-network-fetch/v1', 'status': 'FETCHED_PENDING_REPLAY',
             'descriptor': {'trial_id': trial}, 'transactions': [{'transaction': {'id': v}} for v in ids],
             'fixture_classification': CLASS})})
    replay = {'schema': 'kpxa-accepted-native-replay/v1', 'status': STATUS, 'trial_id': trial,
        'accepted_transactions': 16, 'terminal': True, 'current_checkpoint': history['head'],
        'whole_CASE_native_Full_reports': [{'transaction_id': v, 'fixture_classification': CLASS} for v in ids],
        'wall_seconds': 0.125, 'fixture_classification': CLASS}
    for role, field in [('history', 'history_sha256'), ('context', 'context_sha256'),
                        ('fetch', 'fetch_sha256'), ('selection', 'selection_sha256')]:
        replay[field] = sha(documents[role])
    documents['replayresults'] = encoded(replay)
    observed = []
    for transition in history['transitions'][6:]:
        body = bytes.fromhex(transition['projection_hex'])[-1632:]
        observed.append({'amount_sompi': str(int.from_bytes(body[396:404], 'little')),
                         'script_public_key': body[404:440].hex(), 'fixture_classification': CLASS})
    handoff = {'schema': 'kpxa-confirmed-transition-handoff/v1', 'status': STATUS,
        'expected_transaction_id': ids[-1], 'trial_id': trial, 'accepted_transactions': 16,
        'terminal': True, 'accepted_whole_CASE_equals_expected': True,
        'checkpoint': history['head'], 'native_payouts_observed': observed,
        'selectors': {}, 'wall_seconds': 0.125, 'fixture_classification': CLASS}
    for role, name in [('history', 'HISTORY.json'), ('context', 'CONTEXT.json'),
                       ('currententry', 'CURRENT-ENTRY.json'), ('replayresults', 'RESULTS.json'),
                       ('fetch', 'fetch.json')]:
        handoff['selectors'][name] = {'sha256': sha(documents[role])}
    documents['terminalhandoff'] = encoded(handoff)
    sources = {api['ROLE_MOUNTS'][role]: raw for role, raw in documents.items()}
    scope = {'schema': 'kpxa-canary-final-accepted-history-context/v1',
        'classification': 'CANARY_ONLY_ROOT_SELECTED_ACCEPTED_HISTORY_AND_OWN_PAYOUT_KEYS',
        'original_cohort': 'actual02', 'candidate_manifest_sha256': sha(encoded(rows)),
        'roles': {role: {'mount': api['ROLE_MOUNTS'][role], 'sha256': sha(raw)}
                  for role, raw in documents.items()},
        'accepted_backing_or_recovery_authority': False,
        'own_historical_payout_keys_required': True, 'future_material_covered': False}
    sources['/public/CANARY-CONTEXT-SCOPE.json'] = encoded(scope)
    return sources


def alter_document(api, sources, role, change):
    sources = dict(sources)
    mount = api['ROLE_MOUNTS'][role]
    value = json.loads(sources[mount])
    change(value)
    sources[mount] = encoded(value)
    scope = json.loads(sources['/public/CANARY-CONTEXT-SCOPE.json'])
    scope['roles'][role]['sha256'] = sha(sources[mount])
    sources['/public/CANARY-CONTEXT-SCOPE.json'] = encoded(scope)
    return sources


def known_public_closure(output):
    root = HERE / 'public-controls-02'
    selection = json.loads(READ(str(root / 'SOURCE.json')))
    files, pins = {}, []
    for row in selection['finite_public_mounts']:
        mount = row['path']
        source = root / 'software' / mount.removeprefix('/public/')
        raw = READ(str(source), row['sha256'])
        target = output / 'software' / mount.removeprefix('/public/')
        save(target, raw, 0o500 if raw[:4] == b'\x7fELF' else 0o400)
        files[mount] = target
        pins.append({'mount': mount, 'bytes': len(raw), 'sha256': sha(raw)})
    for name, pin in [('publication_literal.py', '0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52'),
                      ('publication_derived.py', 'e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489')]:
        raw = READ(str(ROOT / 'poc/local-private-payment/recovery' / name), pin)
        mount = '/public/recovery/' + name
        target = output / 'software/recovery' / name
        if mount not in files:
            save(target, raw)
            files[mount] = target
            pins.append({'mount': mount, 'bytes': len(raw), 'sha256': pin})
        else:
            assert sha(READ(str(files[mount]))) == pin
    save(output / 'PUBLIC-SOURCE-CLOSURE.json', encoded({'schema': 'kpxa-known-public-scope-closure/v1',
        'fixture_classification': CLASS, 'files': pins}))
    return files


def base_command(files, out):
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8']
    for mount, source in sorted(files.items()):
        command += ['--ro-bind', str(source), mount]
    return command + ['--bind', str(out), '/out']


def namespace_controls(files, output, rows, candidate):
    manifest_rows = [{key: row[key] for key in ('path', 'bytes', 'sha256')} for row in rows]
    cases = []
    for lane in range(3):
        seed = hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED ' + bytes([lane])).digest()
        lane_root = output / ('known-public-%d' % lane)
        lane_root.mkdir(mode=0o700)
        backup = lane_root / 'PUBLIC-FIXTURE-BACKUP.json'
        save(backup, encoded({'schema': 'kpxa-original-seed-backup/v1', 'domain_hex32': DOMAIN,
                             'seed_hex32': seed.hex()}), 0o600)
        for kind, schema in [('literal', 'kpx8-new-owner-seed-export-allowlist/v1'),
                             ('derived', 'kpxa-derived-export-candidates/v1')]:
            allowlist = encoded({'schema': schema, 'files': manifest_rows})
            manifest = lane_root / (kind + '-ALLOWLIST.json')
            save(manifest, allowlist)
            out = lane_root / (kind + '-out')
            out.mkdir(mode=0o700)
            command = base_command(files, out) + ['--ro-bind', str(backup), '/BACKUP.json',
                '--ro-bind', str(manifest), '/ALLOWLIST.json', '--ro-bind', str(candidate), '/candidates/0.bin',
                '/usr/bin/python3', '-B', '/public/recovery/publication_' + kind + '.py',
                '--owner', '/BACKUP.json', '--allowlist', '/ALLOWLIST.json', '--allowlist-sha256', sha(allowlist),
                '--candidates', '/candidates', '--output', '/out/RESULTS.json']
            if kind == 'derived':
                for name, mount in [('assets', '/public/ASSETS.json'), ('history', '/public/HISTORY.json'),
                                    ('context', '/public/CONTEXT.json')]:
                    command += ['--' + name, mount, '--' + name + '-sha256', sha(READ(str(files[mount])))]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=CLEAN)
            assert result.returncode == 0, (lane, kind)
            value = json.loads(READ(str(out / 'RESULTS.json')))
            expected = {'schema', 'status', 'candidate_count', 'candidate_bytes', 'matched_candidate_count', 'scope'}
            if kind == 'derived':
                expected.add('literal_seed_coverage')
            assert set(value) == expected and value['status'] == 'PASS'
            assert value['matched_candidate_count'] == 0 and type(value['matched_candidate_count']) is int
            assert value['candidate_count'] == 2 and value['candidate_bytes'] == rows[0]['bytes'] + len(allowlist)
            assert value['scope'] == ('FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF'
                if kind == 'derived' else 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF')
            if kind == 'derived':
                assert value['literal_seed_coverage'] is False
            cases.append({'control': 'known-public-%d-%s-zero-match' % (lane, kind), 'passed': True})
    out = output / 'namespace-probe'
    out.mkdir(mode=0o700)
    code = "from pathlib import Path; import json; names=['/home','/var','/root','/owner','/private','/SIBLING.json','/BACKUP.json']; assert not any(Path(n).exists() for n in names); Path('/out/RESULTS.json').write_text(json.dumps({'absent':len(names)}))"
    result = subprocess.run(base_command(files, out) + ['/usr/bin/python3', '-B', '-c', code],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN)
    assert result.returncode == 0 and json.loads(READ(str(out / 'RESULTS.json'))) == {'absent': 7}
    cases.append({'control': 'seven-private-parent-sibling-root-paths-absent', 'passed': True})
    return cases


def run(output):
    assert not output.exists()
    output.mkdir(mode=0o700)
    api, source_sha = load_source()
    hraw = READ(str(FIXTURE / 'HISTORY.json'), '1c27c3fc86b69684cbb696e606d4b21c13bc4f1ed018f9880ea5bc3375103038')
    craw = READ(str(FIXTURE / 'CONTEXT.json'), 'edc36fd73bc88da7e62a122c7e6becdf04fcbd6ece4bfa0911067925d81bbadb')
    payload = b'KNOWN PUBLIC FINITE DATA CANDIDATE\n'
    rows = [{'path': 'release/known-public-data.bin', 'bytes': len(payload), 'sha256': sha(payload)}]
    candidate_sha = sha(encoded(rows))
    good = synthetic_envelope(api, hraw, craw, rows)
    cases = []
    def positive(name, sources):
        value = api['final_scope'](sources, candidate_sha)
        assert value['accepted_backing_or_recovery_authority'] is False
        assert value['own_historical_payout_keys_checked'] is False
        cases.append({'control': name, 'passed': True})
    def refused(name, sources, pin=candidate_sha):
        try:
            api['final_scope'](sources, pin)
        except Exception:
            cases.append({'control': name, 'passed': True})
            return
        raise AssertionError(name)
    positive('synthetic-twelve-role-terminal-envelope-only', good)
    for role in ('history', 'context'):
        changed = dict(good)
        value = json.loads(changed[api['ROLE_MOUNTS'][role]])
        value['fixture_stale_bytes'] = True
        changed[api['ROLE_MOUNTS'][role]] = encoded(value)
        refused('stale-' + role + '-source-pin', changed)
    changed = json.loads(hraw); changed['domain_hex32'] = '00' * 32
    refused('wrong-history-domain-with-rebound-role-pins', synthetic_envelope(api, encoded(changed), craw, rows))
    changed = json.loads(craw); changed['domain_hex32'] = '00' * 32
    refused('wrong-context-domain-with-rebound-role-pins', synthetic_envelope(api, hraw, encoded(changed), rows))
    for name, amount in [('zero-payout-spoof', '0'), ('float-payout-spoof', 0.5), ('bool-payout-spoof', True),
                         ('noncanonical-payout-spoof', '010000000')]:
        refused(name, alter_document(api, good, 'terminalhandoff',
            lambda value, amount=amount: value['native_payouts_observed'][0].update(amount_sompi=amount)))
    refused('wrong-payout-destination', alter_document(api, good, 'terminalhandoff',
        lambda value: value['native_payouts_observed'][0].update(script_public_key='00' * 36)))
    refused('wrong-final-protocol-transaction-count', alter_document(api, good, 'terminalhandoff',
        lambda value: value.update(accepted_transactions=15)))
    refused('nonterminal-scope-spoof', alter_document(api, good, 'terminalhandoff', lambda value: value.update(terminal=False)))
    refused('wrong-native-report-ID-order', alter_document(api, good, 'replayresults',
        lambda value: value['whole_CASE_native_Full_reports'].reverse()))
    changed = dict(good)
    changed[api['ROLE_MOUNTS']['currententry']] = b'{}\n'
    scope = json.loads(changed['/public/CANARY-CONTEXT-SCOPE.json'])
    scope['roles']['currententry']['sha256'] = sha(b'{}\n')
    changed['/public/CANARY-CONTEXT-SCOPE.json'] = encoded(scope)
    refused('wrong-terminal-current-entry', changed)
    for name, change in [('role-path-alias', lambda value: value['roles']['history'].update(mount='/public/CONTEXT.json')),
                         ('role-wrong-source-pin', lambda value: value['roles']['parameters'].update(sha256='00' * 32)),
                         ('missing-final-role', lambda value: value['roles'].pop('accounting')),
                         ('wrong-original-cohort', lambda value: value.update(original_cohort='smoke01')),
                         ('own-payout-check-disabled', lambda value: value.update(own_historical_payout_keys_required=False)),
                         ('audit-as-recovery-authority', lambda value: value.update(accepted_backing_or_recovery_authority=True))]:
        changed = dict(good)
        scope = json.loads(changed['/public/CANARY-CONTEXT-SCOPE.json']); change(scope)
        changed['/public/CANARY-CONTEXT-SCOPE.json'] = encoded(scope)
        refused(name, changed)
    refused('different-common-candidate-manifest', good, '00' * 32)
    nonchain_scope = {'schema': 'kpxa-canary-nonchain-creation-context/v1',
        'classification': 'CANARY_ONLY_NONCHAIN_GENUINE_CREATION_OUTPUTS', 'creation_output_count': 9,
        'deposit_sompi': 2_000_000_000, 'accepted_backing': False, 'recovery_or_signing_authority': False,
        'actual_payout_key_material_covered': 0, 'future_material_covered': False}
    nonchain = {'/public/CANARY-CONTEXT-SCOPE.json': encoded(nonchain_scope),
        '/public/HISTORY.json': encoded({'transitions': [], 'genesis': {
            'outputs_hex520': ['KNOWN_PUBLIC_OPAQUE_SHAPE_ONLY_NOT_OUTPUT_PROOFS'] * 9, 'deposit_sompi': 2_000_000_000}})}
    positive('unchanged-NONCHAIN-shape-and-zero-payout-coverage', nonchain)
    changed = dict(nonchain); changed['/public/HISTORY.json'] = hraw
    refused('accepted-history-cannot-use-NONCHAIN-scope', changed)
    files = known_public_closure(output)
    for mount, raw in good.items():
        if mount in ('/public/HISTORY.json', '/public/CONTEXT.json'):
            assert sha(READ(str(files[mount]))) == sha(raw)
        else:
            target = output / 'scope-sources' / mount.removeprefix('/public/')
            save(target, raw)
            files[mount] = target
    candidate = output / 'candidate.bin'; save(candidate, payload)
    release = {'schema': 'kpxa-publication-audit-release/v1', 'domain_hex32': DOMAIN,
        'files': [{'source': str(candidate), **rows[0]}], 'sources': []}
    for mount, source in sorted(files.items()):
        raw = READ(str(source))
        release['sources'].append({'source': str(source), 'mount': mount, 'bytes': len(raw),
            'sha256': sha(raw), 'mode': '0500' if raw[:4] == b'\x7fELF' else '0400'})
    class MetadataBoundary(Exception):
        pass
    def forbidden_metadata(_):
        raise MetadataBoundary()
    api['original_metadata'] = forbidden_metadata
    def release_control(name, value, expect_boundary=False):
        path = output / ('selector-' + name + '.json'); raw = encoded(value); save(path, raw)
        args = SimpleNamespace(release=path, release_sha256=sha(raw), execute=False)
        try:
            api['execute'](args)
        except MetadataBoundary:
            assert expect_boundary, name
        except Exception:
            assert not expect_boundary, name
        else:
            raise AssertionError(name)
        cases.append({'control': name, 'passed': True})
    release_control('all-public-authentication-before-forbidden-original-metadata-boundary', release, True)
    for name, change in [('mount-parent-alias', lambda value: value['sources'][0].update(mount='/public/../escape')),
                         ('wrong-public-source-pin', lambda value: value['sources'][0].update(sha256='00' * 32)),
                         ('unsupported-source-mode', lambda value: value['sources'][0].update(mode='0600')),
                         ('duplicate-candidate-path', lambda value: value['files'].append(copy.deepcopy(value['files'][0]))),
                         ('duplicate-source-mount', lambda value: value['sources'].append(copy.deepcopy(value['sources'][0])))]:
        changed = copy.deepcopy(release); change(changed); release_control(name, changed)
    namespace = namespace_controls(files, output, rows, candidate)
    report = {'schema': 'kpxa-final-scope-known-public-controls/v1', 'status': 'PASS',
        'fixture_classification': CLASS, 'source_sha256': source_sha,
        'scope_and_selector_controls': cases, 'namespace_controls': namespace,
        'actual_original_metadata_selected_or_read': False, 'protected_originals_read_or_mounted': False,
        'actual_original_workers_executed': False, 'genuine_component_history_is_supplied_context_only': True,
        'synthetic_provenance_is_accepted_node_evidence': False, 'publication_or_network_performed': False}
    save(output / 'RESULTS.json', encoded(report))
    save(output / 'FIXTURE-CLASSIFICATION.json', encoded({'classification': CLASS,
        'existing_genuine_component_fixture_history_sha256': sha(hraw),
        'existing_genuine_component_fixture_context_sha256': sha(craw),
        'synthetic_transaction_ids_handoff_native_reports': True,
        'financial_or_chain_acceptance_attested_by_scope_controls': False}))
    print(json.dumps({'status': 'PASS', 'scope_and_selector_controls': len(cases),
        'namespace_controls': len(namespace), 'protected_originals_read_or_mounted': False}, sort_keys=True))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args().output)

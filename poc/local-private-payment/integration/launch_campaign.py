#!/usr/bin/env python3
"""Frozen public config producer and detached Restart=no campaign launcher.

Proposal/materialization read public files only. Launch delegates private plan
creation and use to the reviewed caller; this producer never opens or hashes a
plan, original backup, invoice, witness or private worker/controller log.
"""
from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
from support import DOMAIN, checked, digest, encoded, fields, hx, need, parse, write_new
import campaign

CALLER_SHA = '1af6c2ccd34839e36dba724781bff1801d5505fb5b973c09d39d09fe7108080e'
NATIVE_JOB = {'path': '/var/tmp/kpi-local-private-payment-01/results/public/outer-fee-correct-01/NATIVE-SELECTION.json',
              'sha256': '7a968271d3c3a20747c7926e30e4ae014dc350064a41ee50e302d018f350a9f4'}
OUTER_JOB = {'path': '/var/tmp/kpi-local-private-payment-01/results/public/outer-fee-correct-01/EXECUTE-PROVE-SELECTION.json',
             'sha256': 'e69d695c05668a37f713113b1aec24cd1632b00ea00ea09f8ee280baf846f138'}
FEES = {'path': '/var/tmp/kpi-local-private-payment-01/assets/wallet-public-fixture-stage-03/NATIVE-FEE-POLICY.json',
        'sha256': '30a009f709857e929c3a71c594cde328c99346b721c46e63ba28b2150438c307'}
NODE = {'path': '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node',
        'sha256': 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'}


class Producer:
    def __init__(self):
        self.h = runpy.run_path(campaign.HELPER)

    def read(self, row):
        fields(row, ('path', 'sha256'), 'selected-public-row')
        return self.h['read'](str(row['path']), row['sha256'])

    def row(self, path):
        path = checked(path)
        return {'path': str(path), 'sha256': digest(self.h['read'](str(path)))}

    def save(self, path, value):
        path = checked(path)
        need(not path.is_relative_to(campaign.PRIVATE), 'public-producer-output')
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        write_new(path, encoded(value) + b'\n')
        return self.row(path)

    def closure(self, roots):
        """Finite static driver imports plus explicit dynamically loaded files."""
        directories = [BASE / name for name in ('integration', 'wallet', 'recovery', 'chain', 'bootstrap',
                                                'execution', 'verification', 'verification/native')]
        queue, pins = list(map(Path, roots)), {}
        while queue:
            path = checked(queue.pop())
            if str(path) in pins:
                continue
            raw = self.h['read'](str(path))
            pins[str(path)] = digest(raw)
            dependencies = []
            if path.suffix == '.py':
                for node in ast.walk(ast.parse(raw, str(path))):
                    names = ([alias.name.split('.')[0] for alias in node.names] if isinstance(node, ast.Import)
                             else [node.module.split('.')[0]] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        match = next((parent / (name + '.py') for parent in (path.parent, *directories)
                                      if (parent / (name + '.py')).is_file()), None)
                        if match is not None:
                            dependencies.append(match)
            elif path.suffix == '.mjs':
                dependencies = [Path(os.path.normpath(str(path.parent / relative))) for relative in
                    re.findall(r"(?:from\s*|import\s*)['\"](\.[^'\"]+\.mjs)['\"]", raw.decode())]
            queue.extend(dependencies)
        return [{'path': path, 'sha256': pin} for path, pin in sorted(pins.items())]

    def proposal(self, activation_row, output):
        activation = parse(self.read(activation_row))
        need(activation['schema'] == 'kpxa-activation-handoff/v1'
             and activation['status'] == 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
             and activation['checkpoint']['reserve_sompi'] == 6_000_000_000
             and activation['confirmed_history_observed_total_fee_includes_genesis'] is True,
             'actual-confirmed-GEN3-required')
        self.read({'path': str(BASE / 'integration/campaign.py'), 'sha256': CALLER_SHA})
        for row in activation['selectors'].values():
            self.read(row)
        context = parse(self.read(activation['selectors']['CONTEXT.json']))
        need(context['domain_hex32'] == DOMAIN.hex() and context['checkpoint'] == activation['checkpoint'],
             'exact-confirmed-GEN3-context')
        outer, native = parse(self.read(OUTER_JOB)), parse(self.read(NATIVE_JOB))
        native_files = native['files']
        rows = {name: native_files[name] for name in ('engine', 'codec', 'component', 'selection')}
        rows.update({name: outer['files'][name] for name in ('host', 'program')})
        scripts = {name: self.row(BASE / relative) for name, relative in {
            'worker': 'wallet/worker.py', 'outer': 'execution/outer.py', 'native': 'execution/native.py',
            'submit': 'chain/submit.mjs', 'confirm': 'chain/confirm.py'}.items()}
        for row in (*rows.values(), NODE, FEES, activation['assets']):
            self.read(row)
        selected = {'schema': 'kpxa-matched21-campaign-selection/v1', 'domain_hex32': DOMAIN.hex(),
            'trial_id': activation['trial_id'], 'activation': activation_row, 'wallet_assets': activation['assets'],
            'native_fee_policy': FEES, 'node': NODE, 'scripts': scripts,
            'wallet_source_sha256': {name: self.row(BASE / name)['sha256'] for name in campaign.SOURCES},
            'native': rows, 'fee_cap_sompi': 50_000_000,
            'cold': {'schema': 'PENDING_REAL_DOWNLOADED_COLD_SELECTOR_ONLY'}}
        frozen = self.closure([BASE / 'integration/campaign.py', *[row['path'] for row in scripts.values()],
            BASE / 'verification/native_case.py', BASE / 'verification/wire.py',
            BASE / 'verification/native/validate_selected_case.py', *[BASE / name for name in campaign.SOURCES]])
        result = {'schema': 'kpxa-campaign-public-proposal/v1',
            'classification': 'CONFIRMED_GEN3_STATIC_INPUTS_FROZEN_COLD_DOWNLOAD_PENDING_NOT_LAUNCHED',
            'caller_source': {'path': str(BASE / 'integration/campaign.py'), 'sha256': CALLER_SHA},
            'producer_source': self.row(Path(__file__)), 'driver_source_closure': frozen,
            'qualified_outer_job': OUTER_JOB, 'qualified_native_job': NATIVE_JOB,
            'campaign_selection_template': selected, 'private_inputs_read_or_hashed': False,
            'network_or_owner_or_GPU_or_submission_executed': False,
            'only_pending_inputs': ['actual_download_receipt', 'materialized_cold_selector']}
        return self.save(output, result)

    def frozen_proposal(self, row):
        proposal = parse(self.read(row))
        need(proposal['schema'] == 'kpxa-campaign-public-proposal/v1'
             and proposal['caller_source']['sha256'] == CALLER_SHA, 'reviewed-caller-proposal')
        for source in (*proposal['driver_source_closure'], proposal['caller_source'], proposal['producer_source']):
            self.read(source)
        return proposal

    def materialize(self, proposal_row, cold_row, output):
        proposal = self.frozen_proposal(proposal_row)
        cold = parse(self.read(cold_row))
        need(type(cold) is dict and 'files' in cold and 'download_receipt' in cold
             and 'cold' not in cold and 'classification' not in cold, 'actual-materialized-cold-selector-required')
        selected = dict(proposal['campaign_selection_template'], cold=cold)
        # The reviewed caller parses the actual acquisition receipt, hashes
        # retained archive/ExitPK, binds all24leaves to inventory, and admits
        # exact owner/native closures. No private file is touched here.
        raw = encoded(selected) + b'\n'
        candidate = checked(output)
        need(not candidate.exists(), 'fresh-materialized-public-selection')
        temporary = candidate.with_name(candidate.name + '.candidate')
        self.save(temporary, selected)
        c = campaign.Campaign(temporary, digest(raw), campaign.PRIVATE / 'public-validation-interface-only',
                              candidate.parent / 'public-validation-interface-only')
        c.cold_entries()
        c.cold_entries(native_only=True)
        c.cold_case_tools()
        for _, row, _ in c.cold_entries():
            c.row(row)
        # Keep the successfully validated candidate as the final exact bytes.
        temporary.rename(candidate)
        final = self.row(candidate)
        receipt = {'schema': 'kpxa-campaign-materialization/v1', 'proposal': proposal_row,
            'cold_selector': cold_row, 'campaign_selection': final, 'caller_source': proposal['caller_source'],
            'actual_download_and_inventory_and_finite_closures_verified': True,
            'private_inputs_read_or_hashed': False, 'owner_or_GPU_or_submission_executed': False}
        self.save(candidate.with_name(candidate.name + '.VALIDATED.json'), receipt)
        return final

    def launch(self, proposal_row, materialization_row, private, output, trial_private, unit, *, execute=False, resume=False):
        proposal = self.frozen_proposal(proposal_row)
        materialized = parse(self.read(materialization_row))
        need(materialized['schema'] == 'kpxa-campaign-materialization/v1'
             and materialized['proposal'] == proposal_row
             and materialized['actual_download_and_inventory_and_finite_closures_verified'] is True,
             'actual-materialization-must-match-frozen-proposal')
        selected = materialized['campaign_selection']
        selected_value = parse(self.read(selected))
        expected = dict(proposal['campaign_selection_template'], cold=parse(self.read(materialized['cold_selector'])))
        need(selected_value == expected, 'only-frozen-cold-inputs-may-be-filled')
        private, output, trial_private = checked(private), checked(output), checked(trial_private)
        trial_label = Path(selected_value['activation']['path']).parents[1].name
        need(trial_private == campaign.PRIVATE / trial_label, 'original-owner-metadata-must-belong-to-confirmed-trial')
        need(private.is_relative_to(campaign.PRIVATE) and trial_private.is_relative_to(campaign.PRIVATE)
             and not output.is_relative_to(campaign.PRIVATE) and private != trial_private
             and not trial_private.is_relative_to(private) and not private.is_relative_to(trial_private),
             'separate-authorized-trial-and-private-caller-namespaces')
        need(re.fullmatch(r'[a-z][a-z0-9-]{0,62}', unit), 'neutral-service-unit-name')
        c = campaign.Campaign(selected['path'], selected['sha256'], private, output)
        c.cold_entries()
        c.cold_entries(native_only=True)
        caller = proposal['caller_source']
        command = ['/usr/bin/python3', '-B', caller['path'], 'run', '--selection', selected['path'],
            '--selection-sha256', selected['sha256'], '--private-directory', str(private), '--output', str(output), '--execute']
        if not execute:
            return {'schema': 'kpxa-campaign-launch-preflight/v1', 'unit': unit + '.service',
                'restart_policy': 'no', 'actual_download_gates_passed': True,
                'private_inputs_read_or_hashed': False, 'owner_plan_or_service_started': False}
        probe = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit + '.service',
            '--property=LoadState', '--value'], capture_output=True, text=True)
        need(probe.stdout.strip() == 'not-found', 'fresh-service-unit-required-never-auto-restart')
        if not resume:
            need(not private.exists() and not output.exists(), 'fresh-private-caller-and-public-output')
            prepare = ['/usr/bin/python3', '-B', caller['path'], 'prepare', '--selection', selected['path'],
                '--selection-sha256', selected['sha256'], '--private-directory', str(private), '--output', str(output)]
            for index in range(3):
                backup = trial_private / ('party-' + str(index)) / 'owner/BACKUP.json'
                campaign.backup_metadata(backup)  # metadata only, never bytes/hash
                prepare += ['--owner-backup', str(backup)]
            prepared = subprocess.run(prepare, capture_output=True)
            need(prepared.returncode == 0, 'private-caller-plan-preparation-refused')
            # This is the public, fixed-shape preparation receipt only.
            public_ready = parse(self.h['read'](str(output / 'PREPARED.json')))
            need(public_ready['payments'] == 6 and public_ready['independent_exits'] == 9
                 and public_ready['useful_payment_sompi'] == 2_100_000_000, 'exact-public-preparation-receipt')
        else:
            need(private.is_dir() and output.is_dir(), 'existing-caller-required-for-confirmation-safe-resume')
        detached = ['/usr/bin/systemd-run', '--user', '--unit', unit, '--property=Restart=no',
            '--property=UMask=0077', '--property=WorkingDirectory=' + str(BASE.parents[1]),
            '--property=StandardOutput=append:' + str(private / 'CONTROLLER.stdout'),
            '--property=StandardError=append:' + str(private / 'CONTROLLER.stderr'),
            '--setenv=PATH=/usr/bin:/bin', '--setenv=LANG=C.UTF-8', '--setenv=TZ=UTC', *command]
        started = subprocess.run(detached, capture_output=True)
        need(started.returncode == 0, 'detached-Restart-no-unit-start-refused-private-state-retained')
        receipt = {'schema': 'kpxa-campaign-detached-launch/v1', 'unit': unit + '.service', 'restart_policy': 'no',
            'campaign_selection': selected, 'caller_source': caller, 'resume': resume,
            'actual_download_gates_passed': True, 'private_inputs_read_or_hashed_by_launcher': False,
            'one_sequential_GPU_pipeline': True, 'confirmed_payment_or_exit_claimed_at_launch': False}
        self.save(output / ('RESUME-LAUNCH.json' if resume else 'LAUNCH.json'), receipt)
        return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('proposal', 'materialize', 'launch'))
    for name in ('activation', 'proposal', 'cold-selector', 'materialization'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--' + name + '-sha256')
    for name in ('output', 'private-directory', 'trial-private-directory'):
        p.add_argument('--' + name, type=Path)
    p.add_argument('--unit')
    p.add_argument('--execute', action='store_true')
    p.add_argument('--resume', action='store_true')
    a = p.parse_args()
    producer = Producer()
    row = lambda name: {'path': str(getattr(a, name)), 'sha256': getattr(a, name + '_sha256')}
    if a.operation == 'proposal':
        result = producer.proposal(row('activation'), a.output)
    elif a.operation == 'materialize':
        result = producer.materialize(row('proposal'), row('cold_selector'), a.output)
    else:
        result = producer.launch(row('proposal'), row('materialization'), a.private_directory,
            a.output, a.trial_private_directory, a.unit, execute=a.execute, resume=a.resume)
    print(encoded(result).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('campaign producer/launcher refused; no private inputs disclosed')

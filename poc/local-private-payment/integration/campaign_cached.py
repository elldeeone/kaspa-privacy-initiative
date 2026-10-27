#!/usr/bin/env python3
"""Private matched21 campaign caller: six local payments, nine cold exits.

The caller owns its new private schedule/current-head state. It never opens or
hashes a backup, receipt, invoice, witness, private worker log or owner scan map.
Only isolated owner workers read their single original backup. No network or
financial operation runs unless the operator invokes ``run --execute``.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import random
import runpy
import stat
import subprocess
import sys
import time

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
from support import DOMAIN, checked, digest, encoded, fields, hx, need, parse, read, selected_module, uint, write_new

PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
HELPER = '/var/tmp/kpi-root-guard-helper-09.py'
SOURCES = ('wallet/worker.py', 'wallet/payment.py', 'wallet/support.py', 'recovery/history.py',
           'integration/native_fees.py')


def private_save(path, value):
    """Durable caller state, never hashed or exported by the supervisor."""
    path = checked(path)
    temporary = path.with_name(path.name + '.new')
    write_new(temporary, encoded(value) + b'\n', 0o600)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def backup_metadata(path):
    path = checked(path)
    need(path.is_relative_to(PRIVATE), 'only-new-original-backup-interface')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600, 'single-own-original-backup-metadata')
    return path, (info.st_dev, info.st_ino)


def submission_journal(private):
    """Match the frozen submitter's literal controller namespace before proof."""
    journal = checked(private) / 'controller' / 'submission-journal'
    need(journal.is_relative_to(PRIVATE) and journal != PRIVATE
         and 'controller' in journal.parts, 'declared-private-submit-controller-directory')
    return checked(journal)


def make_plan(backups, *, rng=None):
    """SystemRandom order stays private; no schedule or schedule hash export."""
    rng = random.SystemRandom() if rng is None else rng
    need(len(backups) == 3, 'three-original-owner-interfaces')
    direction = rng.choice((1, 2))
    actions = []
    for round_number, amount in enumerate((500_000_000, 200_000_000)):
        order = list(range(3))
        rng.shuffle(order)
        for owner in order:
            actions.append({'operation': 'payment', 'owner': owner,
                'recipient': (owner + direction) % 3, 'payment_sompi': amount,
                'selection_kind': 'any' if round_number == 0 else
                    ('change' if owner == 1 else 'received-preferred')})
    exits = [owner for owner in range(3) for _ in range(3)]
    rng.shuffle(exits)
    actions.extend({'operation': 'exit', 'owner': owner} for owner in exits)
    return {'schema': 'kpxa-private-matched21-campaign-plan/v1',
            'owner_backups': [str(path) for path in backups], 'actions': actions}


def validate_plan(plan):
    fields(plan, ('schema', 'owner_backups', 'actions'), 'private-campaign-plan-fields')
    need(plan['schema'] == 'kpxa-private-matched21-campaign-plan/v1'
         and type(plan['owner_backups']) is list and len(plan['owner_backups']) == 3
         and len(set(plan['owner_backups'])) == 3 and type(plan['actions']) is list
         and len(plan['actions']) == 15, 'private-matched21-plan-shape')
    recipients = []
    for round_number, amount in enumerate((500_000_000, 200_000_000)):
        group = plan['actions'][round_number * 3:round_number * 3 + 3]
        for action in group:
            fields(action, ('operation', 'owner', 'recipient', 'payment_sompi', 'selection_kind'),
                   'private-payment-action-fields')
            need(action['operation'] == 'payment' and type(action['owner']) is int
                 and type(action['recipient']) is int and type(action['payment_sompi']) is int
                 and action['payment_sompi'] == amount and action['owner'] != action['recipient'],
                 'exact-approved-private-payment')
            expected = 'any' if round_number == 0 else ('change' if action['owner'] == 1 else 'received-preferred')
            need(action['selection_kind'] == expected, 'original-seed-private-selection-policy')
        need(sorted(action['owner'] for action in group) == [0, 1, 2]
             and sorted(action['recipient'] for action in group) == [0, 1, 2], 'one-payment-per-owner-per-round')
        recipients.append({action['owner']: action['recipient'] for action in group})
    need(recipients[0] == recipients[1], 'same-private-recipient-cycle')
    exits = plan['actions'][6:]
    for action in exits:
        fields(action, ('operation', 'owner'), 'private-exit-action-fields')
        need(action['operation'] == 'exit' and type(action['owner']) is int, 'private-direct-exit-action')
    need(sorted(action['owner'] for action in exits) == [0, 0, 0, 1, 1, 1, 2, 2, 2], 'nine-original-owner-exits')
    return plan


def canonical_reserve_entry(value, checkpoint, expected_spk):
    """Convert only the selected reserve UTXO's canonical SDK boundary fields.

    In particular this is the UTXO birth DAA, never the latest virtual tip DAA.
    This public context is shared by payment and downloaded cold-exit builders.
    """
    fields(value, ('outpoint', 'amount_sompi', 'script_public_key', 'block_daa_score',
                   'is_coinbase', 'covenant_id'), 'selected-current-reserve-entry-fields')
    fields(value['outpoint'], ('transactionId', 'index'), 'selected-current-reserve-outpoint-fields')
    fields(checkpoint, ('state_hex112', 'reserve_sompi', 'outpoint_hex36'), 'selected-reserve-checkpoint-fields')

    def decimal(text):
        need(type(text) is str and text.isascii() and text.isdecimal()
             and str(int(text)) == text, 'canonical-current-entry-u64-boundary')
        return uint(int(text))

    amount = decimal(value['amount_sompi'])
    birth = decimal(value['block_daa_score'])
    point = hx(value['outpoint']['transactionId'], 32) + uint(value['outpoint']['index'], 32).to_bytes(4, 'little')
    script = hx(value['script_public_key'], 37)
    need(point == hx(checkpoint['outpoint_hex36'], 36)
         and amount == uint(checkpoint['reserve_sompi'])
         and value['script_public_key'] == expected_spk
         and script[:4] == b'\0\0\xaa\x20' and script[-1:] == b'\x87'
         and value['is_coinbase'] is False and value['covenant_id'] is None,
         'current-entry-must-match-exact-checkpoint-point-amount-policy-and-kind')
    return {'amount': amount, 'scriptPublicKey': value['script_public_key'],
            'blockDaaScore': birth, 'isCoinbase': False, 'covenantId': None}


def current_baseline_args(head):
    """Use only the caller's retained current head, never the initial anchor."""
    fetch = head['fetch.json']
    fields(fetch, ('path', 'sha256'), 'current-confirmed-fetch-selector')
    hx(fetch['sha256'], 32)
    path = checked(fetch['path'])
    argv = ['--baseline-fetch', str(path), '--baseline-fetch-sha256', fetch['sha256'],
            '--baseline-bundle-directory', str(path.parent)]
    if 'CACHE.json' in head:
        cache = head['CACHE.json']
        fields(cache, ('path', 'sha256'), 'retained-local-controller-cache-selector')
        hx(cache['sha256'], 32)
        argv += ['--baseline-cache', str(checked(cache['path'])), '--baseline-cache-sha256', cache['sha256']]
    return argv


def cache_policy_args(policy):
    """Select trusted local admission; the chain verifier checks cache validity."""
    fields(policy, ('admission', 'runtime_source'), 'selected-local-cache-policy')
    argv = ['--trusted-local-cache']
    for name, flag in (('admission', '--cache-admission'), ('runtime_source', '--runtime-source')):
        row = policy[name]
        fields(row, ('path', 'sha256'), 'selected-cache-authority-file')
        hx(row['sha256'], 32)
        argv += [flag, str(checked(row['path'])), flag + '-sha256', row['sha256']]
    return argv


class Campaign:
    def __init__(self, selection, selection_sha256, private, output):
        self.h = runpy.run_path(HELPER)
        self.public_read = self.h['read']
        self.m = self.h['m']
        self.private, self.output = checked(private), checked(output)
        need(self.private.is_relative_to(PRIVATE) and not self.output.is_relative_to(PRIVATE),
             'separate-new-private-caller-and-public-artifacts')
        submission_journal(self.private)
        self.selection_raw = self.public_read(str(selection), selection_sha256)
        self.selection = parse(self.selection_raw)
        fields(self.selection, ('schema', 'domain_hex32', 'trial_id', 'activation', 'wallet_assets',
            'native_fee_policy', 'node', 'scripts', 'wallet_source_sha256', 'native', 'cold', 'fee_cap_sompi',
            'cache_policy'), 'campaign-public-selection-fields')
        need(self.selection['schema'] == 'kpxa-matched21-campaign-selection/v1'
             and self.selection['domain_hex32'] == DOMAIN.hex(), 'selected-campaign-domain')
        need(0 < uint(self.selection['fee_cap_sompi']) <= 2_870_000_000_000_000_000, 'explicit-approved-fee-cap')
        self.cache_policy = self.selection['cache_policy']
        cache_policy_args(self.cache_policy)
        for row in self.cache_policy.values():
            self.row(row)
        self.assets = parse(self.row(self.selection['wallet_assets']))
        self.fees = parse(self.row(self.selection['native_fee_policy']))
        self.activation = parse(self.row(self.selection['activation']))
        need(self.activation['schema'] == 'kpxa-activation-handoff/v1'
             and self.activation['trial_id'] == self.selection['trial_id']
             and self.activation['confirmed_history_observed_total_fee_includes_genesis'] is True,
             'actual-confirmed-genesis-activation-required')
        need(self.activation['checkpoint']['reserve_sompi'] == 6_000_000_000
             and self.activation['checkpoint']['outpoint_hex36'] is not None, 'confirmed-native-sixty-KAS-head')
        self.native = self.selection['native']
        fields(self.native, ('host', 'program', 'engine', 'codec', 'component', 'selection'), 'native-program-selection')
        fields(self.selection['scripts'], ('worker', 'outer', 'native', 'submit', 'confirm'), 'campaign-script-selection')
        fields(self.selection['wallet_source_sha256'], SOURCES, 'exact-owner-source-closure-pins')
        need(self.selection['scripts']['worker'] == {'path': str(BASE / 'wallet/worker.py'),
            'sha256': self.selection['wallet_source_sha256']['wallet/worker.py']}, 'selected-owner-worker-source')
        self.native_module = selected_module(self.fees['native_case'], '_kpxa_campaign_native_case')
        self.codec = self.native_module.NativeCodec(Path(self.native['codec']['path']), self.native['codec']['sha256'])
        self.image = hx(self.fees['outer_image_hex32'], 32)
        self.profile = hx(self.fees['component_profile_sha256'], 32)
        manifest = parse(self.public_read(self.assets['exit']['manifest'], self.assets['exit']['manifest_sha256']))
        self.exit_vk = hx(manifest['vk_hex328'], 328)
        self.counter = 0

    def row(self, row):
        fields(row, ('path', 'sha256'), 'selected-public-file-row')
        return self.public_read(str(row['path']), row['sha256'])

    def file(self, path):
        raw = self.public_read(str(path))
        return {'path': str(path), 'sha256': digest(raw)}

    def save_public(self, path, value):
        write_new(path, encoded(value) + b'\n')
        return self.file(path)

    def call(self, argv, *, label):
        """Private invocation logs; no secret-bearing command is printed."""
        self.counter += 1
        logs = self.private / 'logs'
        logs.mkdir(mode=0o700, exist_ok=True)
        process = subprocess.run(list(map(str, argv)), capture_output=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'})
        suffix = str(time.time_ns())
        write_new(logs / (suffix + '.stdout'), process.stdout, 0o600)
        write_new(logs / (suffix + '.stderr'), process.stderr, 0o600)
        need(process.returncode == 0, label)

    def finite_mounts(self, entries, stage):
        """Authenticate finite public leaves before binding the one backup."""
        stage.mkdir(mode=0o700)
        mounts = []
        for i, (target, row, executable) in enumerate(entries):
            target = checked(target)
            raw = self.row(row)
            # Large public PKs stay selected read-only leaves. The owner
            # authenticates whole PK bytes again before opening its backup.
            if len(raw) >= 16 * 1024 * 1024:
                source = Path(row['path'])
            else:
                source = stage / ('public-' + str(i).zfill(3))
                write_new(source, raw, 0o500 if executable else 0o400)
            mounts += ['--ro-bind', str(source), str(target)]
        return mounts

    def live_entries(self, roles):
        entries = []
        for relative in SOURCES:
            source = BASE / relative
            row = {'path': str(source), 'sha256': self.selection['wallet_source_sha256'][relative]}
            self.row(row)
            entries.append((source, row, False))
        for name in ('relation', 'crypto', 'recipient', 'wire', 'trees'):
            row = self.assets[name]
            entries.append((row['path'], row, name in ('relation', 'crypto')))
        for role in ('spend', 'output', 'exit'):
            row = self.assets[role]
            entries.append((row['manifest'], {'path': row['manifest'], 'sha256': row['manifest_sha256']}, False))
            if role in roles:
                entries.append((row['pk'], {'path': row['pk'], 'sha256': row['pk_sha256']}, False))
        for name in ('native_case', 'codec', 'template_projection'):
            row = self.fees[name]
            entries.append((row['path'], row, name == 'codec'))
        entries += [('/assets.json', self.selection['wallet_assets'], False),
                    ('/fees.json', self.selection['native_fee_policy'], False)]
        return entries, str(BASE / 'wallet/worker.py'), '/assets.json', self.selection['wallet_assets']['sha256'], '/fees.json', self.selection['native_fee_policy']['sha256']

    def cold_entries(self, *, native_only=False):
        cold = self.selection['cold']
        downloaded = self.downloaded_files()
        selected = cold['native_files'] if native_only else cold['files']
        if native_only:
            fields(cold['native_targets'], ('validator', 'engine', 'codec', 'component', 'selection'),
                   'downloaded-native-target-fields')
            expected = {'/public/verification/native_case.py', '/public/verification/wire.py',
                        *cold['native_targets'].values()}
            need(len(expected) == 7 and {row['target'] for row in selected} == expected
                 and len(selected) == 7, 'native-exit-mounts-exact-verifier-closure-no-PK-or-prover')
        entries = []
        for row in selected:
            fields(row, ('target', 'path', 'sha256', 'executable'), 'finite-downloaded-release-file')
            need(Path(row['target']).is_relative_to('/public') and '..' not in Path(row['target']).parts,
                 'downloaded-release-public-namespace')
            need(type(row['executable']) is bool, 'downloaded-file-mode-selection')
            need((str(checked(row['path'])), row['sha256']) in downloaded,
                 'cold-mount-not-in-selected-actual-download-inventory')
            entries.append((row['target'], {'path': row['path'], 'sha256': row['sha256']}, row['executable'] is True))
        return entries

    def downloaded_files(self):
        """Bind every cold leaf to retained acquisitions and exact inventory."""
        if hasattr(self, '_downloaded_files'):
            return self._downloaded_files
        receipt = parse(self.row(self.selection['cold']['download_receipt']))
        fields(receipt, ('schema', 'classification', 'transport', 'inventory', 'artifacts', 'files'),
               'actual-downloaded-recovery-receipt-fields')
        need(receipt['schema'] == 'kpxa-downloaded-recovery-receipt/v1'
             and receipt['classification'] == 'ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED'
             and receipt['transport'] == 'TOR_SOCKS5H_TLS', 'actual-download-acquisition-boundary')
        need(type(receipt['artifacts']) is list and len(receipt['artifacts']) == 2,
             'downloaded-software-archive-and-ExitPK-required')
        artifacts = set()
        for row in receipt['artifacts']:
            fields(row, ('path', 'sha256', 'bytes', 'origin_url'), 'downloaded-artifact-fields')
            need(type(row['origin_url']) is str and row['origin_url'].startswith('https://')
                 and type(row['bytes']) is int and row['bytes'] > 0, 'retained-HTTPS-acquisition')
            raw = self.row({'path': row['path'], 'sha256': row['sha256']})
            need(len(raw) == row['bytes'], 'downloaded-artifact-size')
            artifacts.add((str(checked(row['path'])), row['sha256']))
        inventory_raw = self.row(receipt['inventory'])
        inventory = parse(inventory_raw)
        need(inventory['schema'] == 'kpxa-recovery-software-inventory/v1'
             and inventory['domain_hex32'] == DOMAIN.hex() and inventory['PKs_included'] is False,
             'selected-downloaded-software-inventory')
        files = {}
        for row in receipt['files']:
            fields(row, ('path', 'sha256', 'bytes'), 'downloaded-unpacked-file-fields')
            need(type(row['bytes']) is int and row['bytes'] > 0, 'downloaded-file-size')
            key = (str(checked(row['path'])), hx(row['sha256'], 32).hex())
            need(key not in files, 'distinct-downloaded-file-leaves')
            files[key] = row['bytes']
        root = checked(receipt['inventory']['path']).parent
        expected = {(str(root / row['path']), row['sha256']): row['bytes'] for row in inventory['files']}
        expected[(str(root / 'INVENTORY.json'), receipt['inventory']['sha256'])] = len(inventory_raw)
        exit_role = self.assets['exit']
        exit_manifest = parse(self.public_read(exit_role['manifest'], exit_role['manifest_sha256']))
        pk = [key for key in artifacts if key[1] == exit_manifest['pk_sha256']]
        need(len(pk) == 1, 'actual-downloaded-selected-ExitPK-artifact')
        expected[pk[0]] = exit_manifest['pk_bytes']
        need(files == expected, 'exact-unpacked-inventory-plus-downloaded-ExitPK')
        self._downloaded_files = set(files)
        return self._downloaded_files

    def owner(self, backup, operation, head, *, output=None, request=None, invoice=None, cold=False):
        backup, identity = backup_metadata(backup)  # metadata only
        runtime = self.private / 'workers' / ('worker-' + str(time.time_ns()))
        runtime.mkdir(parents=True, mode=0o700)
        own = runtime / 'owner'
        own.mkdir(mode=0o700)
        if cold:
            cold_selection = self.selection['cold']
            entries = self.cold_entries()
            worker, assets, assets_sha, fees, fees_sha = (cold_selection[name] for name in
                ('worker_target', 'wallet_assets_target', 'wallet_assets_sha256',
                 'native_fee_policy_target', 'native_fee_policy_sha256'))
        else:
            entries, worker, assets, assets_sha, fees, fees_sha = self.live_entries(
                ('spend', 'output') if operation == 'campaign-pay' else ())
        entries += [('/history.json', head['HISTORY.json'], False), ('/context.json', head['CONTEXT.json'], False)]
        mounts = self.finite_mounts(entries, runtime / 'stage')
        need(backup_metadata(backup)[1] == identity, 'original-backup-metadata-changed')
        mounts += ['--ro-bind', str(backup), '/backup/BACKUP.json', '--bind', str(own), '/owner']
        if invoice is not None:
            path = checked(invoice)
            info = path.lstat()
            need(path.is_relative_to(self.private) and stat.S_ISREG(info.st_mode)
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o400,
                 'single-recipient-worker-private-invoice-leaf')
            mounts += ['--ro-bind', str(path), '/invoice/INVOICE208.bin']
        if request is not None:
            write_new(own / 'REQUEST.json', encoded(request) + b'\n', 0o600)
        common = ['--owner', '/owner', '--assets', assets, '--assets-sha256', assets_sha,
            '--native-fee-policy', fees, '--native-fee-policy-sha256', fees_sha,
            '--history', '/history.json', '--history-sha256', head['HISTORY.json']['sha256'],
            '--context', '/context.json', '--context-sha256', head['CONTEXT.json']['sha256']]
        phases = ('restore', 'scan') if operation == 'scan' else ('restore', 'scan', operation)
        for phase in phases:
            destination = output if phase == operation and output is not None else runtime / ('status-' + phase)
            destination.mkdir(mode=0o700)
            argv = self.m.bubble() + mounts + ['--bind', str(destination), '/out',
                '/usr/bin/python3', '-B', worker, phase, '--public-output', '/out', *common]
            if phase == 'restore':
                argv += ['--backup', '/backup/BACKUP.json']
            elif phase == operation and request is not None:
                argv += ['--request', '/owner/REQUEST.json']
            self.call(argv, label='isolated-owner-stage-refused')
        return own / 'INVOICE208.bin' if operation == 'invoice' else output

    def outer(self, directory, projection, journal):
        script = self.selection['scripts']['outer']
        self.row(script)
        receipt = None
        for operation, output_name in (('prove', 'receipt.bin'), ('compress', 'groth16-receipt.bin'),
                                       ('native-proof', 'native-proof.bin')):
            files = {'host': self.native['host'], 'program': self.native['program'], 'journal': journal}
            files['projection' if receipt is None else 'receipt'] = projection if receipt is None else receipt
            job = {'schema': 'local-private-payment-outer-job/v1', 'domain_hex32': DOMAIN.hex(),
                'component_profile_sha256': self.profile.hex(), 'image_id_hex32': self.image.hex(), 'files': files}
            selected = self.save_public(directory / (operation + '-SELECTION.json'), job)
            output = directory / operation
            argv = ['/usr/bin/python3', '-B', script['path'], operation,
                '--selection', selected['path'], '--selection-sha256', selected['sha256'],
                '--output', output, '--threads', '14', '--execute']
            for excluded in self.m.GUARD.directories:
                argv += ['--exclude-private-directory', excluded]
            self.call(argv, label='selected-sequential-outer-stage-incomplete')
            self.row(self.file(output / 'RESULT.json'))
            receipt = self.file(output / 'public-output/result' / output_name)
        return receipt

    def qualify_native(self, directory, case, projection, journal, *, proof=None):
        script = self.selection['scripts']['native']
        self.row(script)
        files = {'engine': self.native['engine'], 'codec': self.native['codec'], 'case': case,
            'projection': projection, 'journal': journal, 'component': self.native['component'],
            'selection': self.native['selection']}
        if proof is not None:
            files['proof'] = proof
        job = {'schema': 'local-private-payment-native-job/v1', 'mode': 'mixed-attach' if proof else 'direct-exit',
            'financial_profile_sha256': self.profile.hex(), 'compute_budget': 1800 if proof else 1500,
            'fee_rate_sompi_per_mass': 100, 'files': files}
        selected = self.save_public(directory / 'NATIVE-SELECTION.json', job)
        output = directory / 'native'
        argv = ['/usr/bin/python3', '-B', script['path'], '--selection', selected['path'],
                '--selection-sha256', selected['sha256'], '--output', output, '--execute']
        for excluded in self.m.GUARD.directories:
            argv += ['--exclude-private-directory', excluded]
        self.call(argv, label='actual-native-Full-qualification-incomplete')
        return self.file(output / 'public-output/CASE.json')

    def cold_native(self, directory, case, projection, journal):
        """Downloaded finite verifier/engine only; no prover, PK or service."""
        entries = self.cold_entries(native_only=True)
        entries += [('/public/case', case, False), ('/public/projection', projection, False),
                    ('/public/journal', journal, False)]
        stage = self.private / 'cold-native-stages' / ('stage-' + str(time.time_ns()))
        stage.parent.mkdir(mode=0o700, exist_ok=True)
        mounts = self.finite_mounts(entries, stage)
        output = directory / 'native'
        output.mkdir(mode=0o700)
        targets = self.selection['cold']['native_targets']
        argv = self.m.bubble() + mounts + ['--bind', str(output), '/out', '/usr/bin/python3', '-B',
            targets['validator'], '--mode', 'direct-exit', '--financial-profile-sha', self.profile.hex(),
            '--compute-budget', '1500', '--fee-rate-sompi-per-mass', '100', '--out', '/out']
        for name, row in {'case': case, 'projection': projection, 'journal': journal,
                          **{name: self.selection['cold']['native_selectors'][name]
                             for name in ('engine', 'codec', 'component', 'selection')}}.items():
            argv += ['--' + name, '/public/' + name if name in ('case', 'projection', 'journal') else targets[name],
                     '--' + name + '-sha', row['sha256']]
        self.call(argv, label='downloaded-direct-exit-native-Full-incomplete')
        result = parse(self.public_read(str(output / 'RESULT.json')))
        need(result['native_Full_accepted'] is True and result['all_input_scripts_accepted'] is True,
             'downloaded-exit-native-Full-required')
        return self.file(output / 'CASE.json')

    def cold_case_tools(self):
        """Public case construction also uses downloaded software/codec."""
        if hasattr(self, '_cold_tools'):
            return self._cold_tools
        cold = self.selection['cold']
        rows = {target: row for target, row, _ in self.cold_entries(native_only=True)}
        source = rows['/public/verification/native_case.py']
        module = selected_module(source, '_kpxa_campaign_downloaded_native_case')
        selected = cold['native_selectors']
        for row in selected.values():
            self.row(row)
        component = parse(self.row(selected['component']))
        selection = parse(self.row(selected['selection']))
        need(selected['component']['sha256'] == self.profile.hex()
             and selection['image_id_hex32'] == self.image.hex(), 'same-downloaded-financial-policy')
        codec = module.NativeCodec(Path(selected['codec']['path']), selected['codec']['sha256'])
        exit_vk = hx(component['exit']['vk_hex328'], 328)
        need(exit_vk == self.exit_vk, 'same-downloaded-direct-exit-VK')
        self._cold_tools = module, codec, exit_vk
        return self._cold_tools

    def build(self, directory, head, action, plan, *, invoice=None):
        native_module, codec, exit_vk = (self.native_module, self.codec, self.exit_vk) if action['operation'] == 'payment' else self.cold_case_tools()
        context = parse(self.row(head['CONTEXT.json']))
        need(context['domain_hex32'] == DOMAIN.hex(), 'current-reserve-context-domain')
        checkpoint = context['checkpoint']
        state = hx(checkpoint['state_hex112'], 112)
        emitted = native_module.emit(codec, state, self.image, self.profile, exit_vk)
        # Bind the actual current UTXO before asking any owner for authority.
        expected_entry = canonical_reserve_entry(parse(self.row(head['CURRENT-ENTRY.json'])),
                                                 checkpoint, emitted['script_public_key'])
        backup = plan['owner_backups'][action['owner']]
        component = directory / 'component'
        if action['operation'] == 'payment':
            need(invoice is not None, 'previously-authenticated-private-invoice-required')
            request = {'schema': 'kpxa-private-campaign-payment-request/v1',
                'payment_sompi': action['payment_sompi'], 'fee_cap_sompi': self.selection['fee_cap_sompi'],
                'selection_kind': action['selection_kind']}
            self.owner(backup, 'campaign-pay', head, output=component, request=request, invoice=invoice)
        else:
            request = {'schema': 'kpxa-private-recovery-exit-request/v1',
                       'fee_cap_sompi': self.selection['fee_cap_sompi']}
            self.owner(backup, 'recovery-exit', head, output=component, request=request, cold=True)
        projection = self.file(component / 'PROJECTION.bin')
        raw = self.row(projection)
        wire = native_module._wire
        body = (wire.parse_projection(raw).body if action['operation'] == 'payment'
                else wire.parse_exit_projection(raw).body)
        budget = 1800 if action['operation'] == 'payment' else 1500
        need(body.point == hx(checkpoint['outpoint_hex36'], 36)
             and body.old_state.raw == state and body.old_reserve == checkpoint['reserve_sompi'],
             'owner-projection-must-use-exact-selected-current-reserve')
        case, independent, journal, report = native_module.make_case(
            codec, body.raw, self.image, self.profile, exit_vk, budget,
            block_daa_score=expected_entry['blockDaaScore'])
        need(case['entries'] == [expected_entry], 'whole-CASE-entry-must-equal-selected-actual-UTXO-context')
        need(independent == raw and report['metrics']['actual_fee_sompi']
             >= report['metrics']['mining_mass'] * 100, 'actual-current-case-native-fee-and-projection')
        if action['operation'] == 'exit':
            own_proof = self.row(self.file(component / 'EXIT-PROOF.bin'))
            case, after, after_journal, _ = native_module.replace_proof(
                codec, case, own_proof, self.image, self.profile, exit_vk)
            need(after == raw and after_journal == journal, 'only-selected-direct-proof-attached')
        selected_case = self.save_public(directory / 'CASE.json', case)
        journal_path = directory / 'JOURNAL.bin'
        write_new(journal_path, journal)
        selected_journal = self.file(journal_path)
        if action['operation'] == 'payment':
            proof = self.outer(directory, projection, selected_journal)
            return self.qualify_native(directory, selected_case, projection, selected_journal, proof=proof)
        return self.cold_native(directory, selected_case, projection, selected_journal)

    def settle(self, directory, action_label, case, state):
        original = parse(self.row(case))
        txid = original['transaction']['id']
        chain = {name: self.activation[name] for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec')}
        fetch = state['head']['fetch.json']
        submit = self.selection['scripts']['submit']
        confirm = self.selection['scripts']['confirm']
        self.row(submit)
        self.row(confirm)
        node = self.selection['node']
        self.row(node)
        if not state.get('submission_consumed'):
            # Persist before calling the once-only submitter. An unknown result
            # can only enter fresh confirmation; it can never retransmit.
            state['submission_consumed'] = True
            state['qualified_case'] = case
            private_save(self.private / 'STATE.json', state)
            argv = [node['path'], submit['path'], '--mode', 'lifecycle', '--stage', action_label,
                '--trial-id', self.selection['trial_id'], '--case', case['path'], '--case-sha256', case['sha256'],
                '--output', directory / 'submission', '--journal', submission_journal(self.private),
                '--fetch', fetch['path'], '--fetch-sha256', fetch['sha256'],
                '--bundle-directory', str(Path(fetch['path']).parent), '--execute']
            argv += cache_policy_args(self.cache_policy) + current_baseline_args(state['head'])
            for name, row in chain.items():
                argv += ['--' + name, row['path'], '--' + name + '-sha256', row['sha256']]
            try:
                self.call(argv, label='submission-consumed-confirmation-only')
            except ValueError:
                pass
        # Fresh read-only attempts are allowed while the accepted prefix catches
        # up. Each failure remains retained; there is no timeout-based broadcast.
        while True:
            destination = directory / ('confirmation-' + str(time.time_ns()))
            argv = ['/usr/bin/python3', '-B', confirm['path'], '--expected-transaction-id', txid,
                '--expected-case', case['path'], '--expected-case-sha256', case['sha256'], '--output', destination]
            argv += cache_policy_args(self.cache_policy) + current_baseline_args(state['head'])
            for name, row in chain.items():
                argv += ['--' + name, row['path'], '--' + name + '-sha256', row['sha256']]
            try:
                self.call(argv, label='read-only-confirmation-incomplete-never-resubmit')
                handoff = parse(self.public_read(str(destination / 'HANDOFF.json')))
                need(handoff['accepted_whole_CASE_equals_expected'] is True
                     and handoff['expected_transaction_id'] == txid, 'whole-case-confirmation-required')
                return handoff
            except ValueError:
                time.sleep(5)

    def prepare(self, backups):
        need(not self.private.exists() and not self.output.exists(), 'fresh-unused-campaign-namespace')
        identities = [backup_metadata(path) for path in backups]
        need(len({identity for _, identity in identities}) == 3, 'three-distinct-new-original-backups')
        self.private.mkdir(parents=True, mode=0o700)
        self.output.mkdir(parents=True, mode=0o700)
        plan = validate_plan(make_plan([path for path, _ in identities]))
        write_new(self.private / 'PLAN.json', encoded(plan) + b'\n', 0o600)
        private_save(self.private / 'STATE.json', {'schema': 'kpxa-private-campaign-state/v1',
            'next_action': 0, 'head': self.activation['selectors'], 'confirmed': [], 'submission_consumed': False})
        self.save_public(self.output / 'PREPARED.json', {'schema': 'kpxa-campaign-prepared/v1',
            'payments': 6, 'independent_exits': 9, 'useful_payment_sompi': 2_100_000_000,
            'private_schedule_or_hash_exported': False, 'backup_contents_or_hashes_read': False,
            'network_funding_or_broadcast': False, 'testnet_readiness_claimed': False})

    def run(self):
        plan = validate_plan(parse(read(self.private / 'PLAN.json', private=True)))
        state = parse(read(self.private / 'STATE.json', private=True))
        need(plan['schema'] == 'kpxa-private-matched21-campaign-plan/v1'
             and state['schema'] == 'kpxa-private-campaign-state/v1', 'own-private-campaign-state')
        # Check actual downloaded recovery closure before the first payment.
        # Missing availability stops safely before new financial authority.
        for _, row, _ in self.cold_entries():
            self.row(row)
        invoice_file = self.private / 'INVOICES.json'
        if not invoice_file.exists():
            need(state['next_action'] == 0, 'private-invoice-intent-required-before-campaign')
            # Finish all recipient workers before any actual payment proof.
            # Thereafter construction requires only the payer plus its already
            # authenticated invoice, and never another owner's live process.
            invoices = [str(self.owner(plan['owner_backups'][action['recipient']], 'invoice', state['head']))
                        for action in plan['actions'][:6]]
            write_new(invoice_file, encoded({'schema': 'kpxa-private-campaign-invoice-intent/v1',
                'paths': invoices}) + b'\n', 0o600)
        invoice_intent = parse(read(invoice_file, private=True))
        fields(invoice_intent, ('schema', 'paths'), 'private-invoice-intent-fields')
        need(invoice_intent['schema'] == 'kpxa-private-campaign-invoice-intent/v1'
             and type(invoice_intent['paths']) is list and len(invoice_intent['paths']) == 6
             and len(set(invoice_intent['paths'])) == 6, 'six-private-authenticated-invoice-leaves')
        while state['next_action'] < 15:
            index = state['next_action']
            label = 'action-' + str(index + 1).zfill(4)
            directory = self.output / label
            if state.get('submission_consumed'):
                qualified = state['qualified_case']
            else:
                need(not directory.exists(), 'retain-incomplete-action-start-fresh-trial-if-not-resumable')
                directory.mkdir(mode=0o700)
                qualified = self.build(directory, state['head'], plan['actions'][index], plan,
                    invoice=invoice_intent['paths'][index] if index < 6 else None)
            handoff = self.settle(directory, label, qualified, state)
            state['head'] = handoff['selectors']
            state['confirmed'].append({'action': label, 'transaction_id': handoff['expected_transaction_id']})
            state['next_action'] += 1
            state['submission_consumed'] = False
            state.pop('qualified_case', None)
            state['observed_total_fee_sompi'] = handoff['observed_total_fee_sompi']
            private_save(self.private / 'STATE.json', state)
            self.save_public(directory / 'CONFIRMED.json', state['confirmed'][-1])
            print(encoded({'action': label, 'status': 'WHOLE_CASE_CONFIRMED',
                           'transaction_id': handoff['expected_transaction_id']}).decode(), flush=True)
        context = parse(self.row(state['head']['CONTEXT.json']))
        need(context['checkpoint']['reserve_sompi'] == 0 and context['checkpoint']['outpoint_hex36'] is None,
             'nine-confirmed-payouts-and-zero-terminal-reserve-required')
        # Restore and scan every original seed again using only the downloaded
        # finite package and complete final accepted public history.
        for backup in plan['owner_backups']:
            self.owner(backup, 'scan', state['head'], cold=True)
        all_fees = (uint(self.activation['ordinary_pre_genesis_paid_fee_sompi'])
                    + uint(state['observed_total_fee_sompi']))
        self.save_public(self.output / 'RESULTS.json', {'schema': 'kpxa-confirmed-matched21-campaign/v1',
            'payments': 6, 'independent_exits': 9, 'useful_payment_sompi': 2_100_000_000,
            'all_in_paid_fee_sompi': all_fees, 'terminal_reserve_sompi': 0,
            'whole_case_confirmed_actions': state['confirmed'], 'downloaded_finite_recovery_used': True,
            'original_seed_terminal_scans_completed': True, 'backup_contents_or_hashes_read_by_caller': False,
            'payer_or_role_or_scan_index_or_schedule_hash_exported': False,
            'independent_consensus_global_privacy_or_production_safety_claimed': False,
            'prior_frozen_fee_and_privacy_verdicts_unchanged': True})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('prepare', 'run'))
    p.add_argument('--selection', type=Path, required=True)
    p.add_argument('--selection-sha256', required=True)
    p.add_argument('--private-directory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--owner-backup', type=Path, action='append', default=[])
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    os.umask(0o077)
    c = Campaign(a.selection, a.selection_sha256, a.private_directory, a.output)
    if a.operation == 'prepare':
        need(not a.execute, 'prepare-never-funds-or-broadcasts')
        c.prepare(a.owner_backup)
    else:
        need(a.execute, 'operator-execution-release-required')
        lock = os.open(c.private / 'CALLER-LOCK', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            c.run()
        finally:
            os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('campaign incomplete; private details retained; never retransmit a consumed action')

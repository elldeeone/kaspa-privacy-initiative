"""Compose downloaded-software owner and public Exit builders, without RPC.

All seed/proof work uses cold_owner's fixed restored worker. All public native
financial construction and Full validation use cold_case's restored /work child.
The host only schedules selected commands and checks typed public exports.
"""
from pathlib import Path
import secrets
import stat
import sys

from campaign import restore_public
from backend import path, write
from codec import canonical_json, parse_json, sha
from exits import auth_export
from public import DOMAIN, fields, need, load_wire
from rounds import selected
from runner import StageRunner
from ingress import Ingress, PRIVATE

HERE = Path(__file__).resolve().parent
RECOVERY = HERE.parent / 'recovery'
sys.path.insert(0, str(RECOVERY))
from cold_owner import retained_private_roots
from run_restore import PublicPolicy


class _PublicGuard:
    def __init__(self, policy):
        self.policy = policy
        self.directories = policy.roots
        self.forbidden = policy.identities

    def metadata(self, value):
        self.policy.refresh()
        target = self.policy.public_path(Path(value))
        info = target.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and (info.st_dev, info.st_ino) not in self.policy.identities,
             'closed-public-producer-private-alias-or-type')
        return target, info

    def read(self, value, expected):
        return self.policy.read(Path(value), expected)


class ClosedIngress(Ingress):
    """Keep exact producer promotion without requiring foreign trial fixtures."""
    def __init__(self, retained_private):
        self.policy = PublicPolicy(retained_private)
        need(PRIVATE in self.policy.roots
             and all(any(root.is_relative_to(excluded) for excluded in self.policy.roots)
                     for root in retained_private_roots()), 'all-existing-private-parents-excluded')
        self.forbidden, self.producers = set(), {}
        self.refresh()

    def refresh(self):
        self.policy.refresh()
        self.forbidden.update(self.policy.identities)
        self.guard = _PublicGuard(self.policy)
        return self.guard


class ClosedStageRunner(StageRunner):
    """Reuse resource scheduling with a portable, metadata-only public ingress."""
    def __init__(self, private_base, public_base, retained_private, source_manifest):
        self.private = path(private_base)
        self.public = path(public_base)
        need(self.private.is_relative_to(PRIVATE) and self.private != PRIVATE,
             'closed-runtime-within-reserved-private-parent')
        self.old, self.retained = [], list(retained_private)
        self.ingress = ClosedIngress(self.retained)
        need(all(not self.public.is_relative_to(root) for root in self.ingress.policy.roots),
             'closed-public-runtime-outside-private')
        self.source_manifest = source_manifest


def private_order(runner, label):
    """Fresh OS randomness; the permutation is never exported or reread."""
    order = secrets.SystemRandom().sample(range(3), 3)
    write(runner.private / 'controller' / (label + '-private-order.json'),
          canonical_json({'schema': 'kpx8-private-client-order/v1', 'order': order}))
    runner.ingress.refresh()
    return order


def consume_owner(runner, output, label, validator):
    """Validate one registered export, then retain associations only privately."""
    temporary = output.parent / (label + '-associated-result.json')
    archive = runner.private / 'controller' / (label + '-associated-outputs')
    need(not archive.exists(), 'fresh-private-associated-output-archive')
    archive.mkdir(mode=0o700)
    try:
        value, _ = runner.ingress.promote(output, temporary, validator)
        return value
    finally:
        # The only public producer leaves are fixed by cold_owner. Stable
        # guarded public reads permit cross-filesystem retention without
        # following or opening any private inode. Never read these archives.
        members = list(output.iterdir())
        need(all(member.name in ('PUBLIC.json', 'ISOLATION.json') for member in members),
             'closed-owner-fixed-public-leaves')
        for member in members + ([temporary] if temporary.exists() else []):
            raw = runner.ingress.refresh().policy.read(member)
            write(archive / member.name, raw)
            member.unlink()
        output.rmdir()
        runner.ingress.refresh()


def common(selection, runner):
    result = ['--software-root', selection['software_root'],
        '--software-inventory', selection['software_inventory'][0],
        '--software-inventory-sha256', selection['software_inventory'][1],
        '--assets', selection['assets'][0], '--assets-sha256', selection['assets'][1]]
    for root in runner.retained:
        result += ['--exclude-private-directory', str(root)]
    return result


def replay_for_owner(runner, selection, accepted, output, label):
    """Each owner independently executes the complete downloaded public replay."""
    command = ['/usr/bin/python3', '-B', str(RECOVERY / 'replay_closed.py'),
        '--software-root', selection['software_root'],
        '--software-inventory', selection['software_inventory'][0],
        '--data-root', selection['data_root'], '--packet', selection['replay_packet'][0],
        '--packet-sha256', selection['replay_packet'][1], '--codec', selection['codec'],
        '--output', str(output)]
    for root in runner.retained:
        command += ['--exclude-private-directory', str(root)]
    runner.stage(label, [command], cpu=8, memory=12 * 1024**3)
    replayed = output / 'public/replayed'
    history_selector = selected(runner, replayed / 'HISTORY.json')
    checkpoint_selector = selected(runner, replayed / 'CHECKPOINT.json')
    history = parse_json(runner.ingress.read(*history_selector))
    checkpoint = parse_json(runner.ingress.read(*checkpoint_selector))
    receipt = parse_json(runner.ingress.read(*selected(runner, output / 'RESULT.json')))
    need(history_selector[1] == accepted['history_selector'][1]
         and history == accepted['history'] and checkpoint == accepted['checkpoint']
         and receipt['packet_sha256'] == selection['replay_packet'][1]
         and receipt['result']['history_sha256'] == history_selector[1]
         and receipt['result']['checkpoint_sha256'] == checkpoint_selector[1]
         and receipt['result']['all_native_Full_and_input_engines_executed'] is True
         and receipt['result']['all_original_paths_absent'] is True,
         'owner-independent-closed-full-prefix-replay-at-current-selected-checkpoint')
    current_raw = runner.ingress.read(*selection['current_entry'])
    need(selection['current_entry'][1] == accepted['current_entry_selector'][1]
         and parse_json(current_raw) == accepted['current_entry'], 'byte-identical-downloaded-current-entry')
    own = dict(accepted)
    own['history_selector'] = history_selector
    own['current_entry_selector'] = selection['current_entry']
    return own


def owner_command(runner, selection, operation, index, output, label, extra):
    parent = runner.private / ('party-%d' % index)
    return ['/usr/bin/python3', '-B', str(RECOVERY / 'cold_owner.py'), operation,
        *common(selection, runner), '--owner-directory', str(parent / 'owner'),
        '--mpc-directory', str(parent / 'mpc'), '--private-run-directory',
        str(runner.private / 'controller' / label), '--output', str(output), *extra]


def public_command(runner, selection, accepted, operation, output, label, extra=()):
    return ['/usr/bin/python3', '-B', str(RECOVERY / 'cold_case.py'), operation,
        *common(selection, runner), '--codec', selection['codec'],
        '--parameters', selection['parameters'][0], '--parameters-sha256', selection['parameters'][1],
        '--history', accepted['history_selector'][0], '--history-sha256', accepted['history_selector'][1],
        '--current-entry', accepted['current_entry_selector'][0],
        '--current-entry-sha256', accepted['current_entry_selector'][1],
        '--private-run-directory', str(runner.private / 'controller' / label),
        '--output', str(output), *extra]


def restore_clients(runner, selection, owners, original_private):
    runner.initialize_directories()
    order = private_order(runner, 'restore')
    outputs = [runner.public / ('restore-attempt-%d' % (attempt + 1)) for attempt in range(3)]
    for output in outputs:
        runner.ingress.register(output, 'restore')
    commands = [owner_command(runner, selection, 'restore', index, outputs[attempt],
        'restored-software-seed-attempt-%d' % (attempt + 1), ['--backup', str(Path(original_private) /
            ('party-%d' % index) / 'owner/BACKUP.json')]) for attempt, index in enumerate(order)]
    runner.stage('restored-software-seeds', commands, cpu=12, memory=12 * 1024**3)
    for attempt, index in enumerate(order):
        consume_owner(runner, outputs[attempt], 'restore-attempt-%d' % (attempt + 1),
            lambda raw, kind, index=index: restore_public(raw, kind, owners[index]['participant_id_hex32']))
    result = {'schema': 'kpx8-neutral-restored-client-completion/v1', 'fresh_clients': 3,
              'all_seed_only_restores_passed': True, 'client_associations_exported': False}
    write(runner.public / 'RESTORES.json', canonical_json(result))
    return result


def prepare_next(runner, sequence, selection, owners):
    """Return one genuine candidate; caller must confirm it before another call."""
    runner.authenticate()
    need(sequence.pending is None and len(sequence.completed) < 9, 'accepted-head-ready-for-next-exit')
    accepted = sequence.accepted
    ordinal = len(sequence.completed) + 1
    label = 'exit-%02d' % ordinal
    folder = runner.public / label
    need(not folder.exists(), 'one-fresh-live-exit-candidate-directory')
    folder.mkdir(mode=0o700)
    ready_selector = None
    for attempt, index in enumerate(private_order(runner, label)):
        attempt_label = label + '-attempt-%d' % (attempt + 1)
        own = replay_for_owner(runner, selection, accepted, folder / ('replay-attempt-%d' % (attempt + 1)),
                               attempt_label + '-closed-replay')
        context_output = folder / ('read-context-attempt-%d' % (attempt + 1))
        runner.stage(attempt_label + '-restored-context', [public_command(runner, selection, own,
            'context', context_output, attempt_label + '-restored-context')])
        context = selected(runner, context_output / 'CONTEXT.json')
        base_owner = ['--history', own['history_selector'][0], '--history-sha256', own['history_selector'][1]]
        output = folder / ('ready-attempt-%d' % (attempt + 1))
        runner.ingress.register(output, 'exit-ready')
        runner.stage(attempt_label + '-restored-ready', [owner_command(runner, selection,
            'exit-ready', index, output, attempt_label + '-restored-ready',
            [*base_owner, '--context', context[0], '--context-sha256', context[1], '--note-kind', 'any'])])
        value = consume_owner(runner, output, attempt_label + '-ready',
            lambda raw, kind, index=index: sequence.owner_ready(raw,
                owners[index]['participant_id_hex32'], index))
        if value:
            # The restored public quote needs only fields already present in
            # a public native Exit. Participant identity is deliberately absent.
            ready = {key: value for key, value in sequence.pending['ready'].items()
                     if key != 'participant_id_hex32'}
            write(folder / 'PUBLIC-QUOTE-INPUT.json', canonical_json(ready))
            ready_selector = selected(runner, folder / 'PUBLIC-QUOTE-INPUT.json')
            accepted = own
            break
    need(ready_selector is not None, 'all-nine-authenticated-claims-must-remain-available')
    quoted = folder / 'quote'
    runner.stage(label + '-restored-quote', [public_command(runner, selection, accepted,
        'quote', quoted, label + '-restored-quote',
        ['--ready', ready_selector[0], '--ready-sha256', ready_selector[1]])])
    body = selected(runner, quoted / 'BODY.bin')
    projection = selected(runner, quoted / 'PROJECTION.bin')
    context = selected(runner, quoted / 'CONTEXT.json')
    output = folder / 'authorization'
    runner.ingress.register(output, 'exit')
    runner.stage(label + '-restored-proof', [owner_command(runner, selection, 'exit', index,
        output, label + '-restored-proof', [*base_owner, '--context', context[0],
        '--context-sha256', context[1], '--projection', projection[0],
        '--projection-sha256', projection[1]])], cpu=14, memory=20 * 1024**3)
    raw_projection = runner.ingress.read(*projection)
    nf = load_wire().parse_exit_projection(raw_projection).body.nf.hex()
    def checked_authorization(raw, kind):
        auth_export(raw, kind, accepted['history_selector'][1], raw_projection, nf)
        return parse_json(raw)

    authorization_public = consume_owner(runner, output, label + '-proof', checked_authorization)
    # This checked public authorization contains no owner identifier.
    write(folder / 'AUTHORIZATION.json', canonical_json(authorization_public))
    authorization = selected(runner, folder / 'AUTHORIZATION.json')
    final = folder / 'final'
    runner.stage(label + '-restored-final', [public_command(runner, selection, accepted,
        'finalize', final, label + '-restored-final', ['--body', body[0], '--body-sha256', body[1],
        '--projection', projection[0], '--projection-sha256', projection[1], '--authorization', authorization[0],
        '--authorization-sha256', authorization[1]])], cpu=8, memory=12 * 1024**3)
    case = parse_json(runner.ingress.read(*selected(runner, final / 'CASE.json')))
    final_projection = selected(runner, final / 'PROJECTION.bin')
    need(final_projection[1] == projection[1], 'genuine-restored-proof-preserves-approved-effects')
    txid = case['transaction']['id']
    sequence.candidate(txid, final_projection)
    result = {'schema': 'kpx8-restored-live-exit-candidate/v1', 'ordinal': ordinal,
        'transaction_id': txid, 'accepted_predecessor_history_sha256': accepted['history_selector'][1],
        'case': selected(runner, final / 'CASE.json'), 'projection': final_projection,
        'journal': selected(runner, final / 'JOURNAL.bin'),
        'restored_native_Full': selected(runner, final / 'native/native-validation.json'),
        'genuine_Exit_and_restored_native_Full_passed': True,
        'broadcast_or_chain_acceptance': False}
    write(folder / 'CANDIDATE.json', canonical_json(result))
    return result


def terminal_scans(runner, sequence, selection, owners):
    """Reconcile every seed-derived claim and rederive historical payout keys."""
    runner.authenticate()
    accepted = sequence.accepted
    need(len(sequence.completed) == 9 and sequence.pending is None
         and accepted['history']['head']['reserve_sompi'] == 0
         and accepted['history']['head']['outpoint_hex36'] is None
         and accepted['current_entry'] is None, 'nine-actual-confirmed-exits-before-final-scan')
    folder = runner.public / 'terminal'
    need(not folder.exists(), 'fresh-terminal-reconciliation')
    folder.mkdir(mode=0o700)
    order = private_order(runner, 'terminal')
    outputs = [folder / ('scan-attempt-%d' % (attempt + 1)) for attempt in range(3)]
    for output in outputs:
        runner.ingress.register(output, 'scan')
    commands = []
    for attempt, index in enumerate(order):
        attempt_label = 'terminal-attempt-%d' % (attempt + 1)
        own = replay_for_owner(runner, selection, accepted, folder / ('replay-attempt-%d' % (attempt + 1)),
                               attempt_label + '-closed-replay')
        context_output = folder / ('context-attempt-%d' % (attempt + 1))
        runner.stage(attempt_label + '-restored-context', [public_command(runner, selection, own,
            'context', context_output, attempt_label + '-restored-context')])
        context = selected(runner, context_output / 'CONTEXT.json')
        commands.append(owner_command(runner, selection, 'scan', index, outputs[attempt],
            attempt_label + '-restored-scan', ['--history', own['history_selector'][0],
            '--history-sha256', own['history_selector'][1], '--context', context[0],
            '--context-sha256', context[1]]))
    runner.stage('terminal-restored-scans', commands, cpu=12, memory=12 * 1024**3)

    def validate(raw, kind, participant):
        value = parse_json(raw)
        fields(value, ('schema', 'domain_hex32', 'participant_id_hex32', 'history_sha256',
            'seed_only', 'scan_completed', 'private_claims_exported', 'terminal_reconciled',
            'native_payout_keys_rederived'), 'exact-final-cold-scan')
        need(value['schema'] == 'kpx8-owner-scan-complete/v1' and value['domain_hex32'] == DOMAIN.hex()
             and value['participant_id_hex32'] == participant
             and value['history_sha256'] == accepted['history_selector'][1]
             and value['seed_only'] is True and value['scan_completed'] is True
             and value['private_claims_exported'] is False
             and value['terminal_reconciled'] is True and value['native_payout_keys_rederived'] is True,
             'all-seed-claims-spent-and-historical-payout-keys-rederived')
        return value

    bookkeeping = folder / 'local-bookkeeping'
    bookkeeping.mkdir(mode=0o700)
    for attempt, index in enumerate(order):
        value = consume_owner(runner, outputs[attempt], 'terminal-attempt-%d' % (attempt + 1),
            lambda raw, kind, index=index: validate(raw, kind, owners[index]['participant_id_hex32']))
        # Root-selected LOCAL accountant input only: these closed fields have
        # no claim/NF/value/payout/exit/index association. Never include these
        # files, selectors or hashes in shared release/repository reports.
        raw = canonical_json(value)
        write(bookkeeping / (sha(raw) + '.json'), raw)
    result = {'schema': 'kpx8-confirmed-terminal-seed-reconciliation/v1',
        'accepted_history': accepted['history_selector'], 'all_three_terminal_seed_scans_passed': True,
        'all_historical_native_payout_keys_rederived': True, 'reserve_sompi': 0,
        'terminal_seed_scans_completed': 3, 'client_associations_exported': False,
        'read_context_placeholder_fee_is_a_ledger_charge': False}
    write(folder / 'TERMINAL.json', canonical_json(result))
    return result

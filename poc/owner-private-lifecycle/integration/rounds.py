"""One genuine mixed round through independent nine-proof verification.

Root separately supplies the outer receipt, native Full and chain confirmation.
No wallet content or MPC stream is opened by this trusted scheduler.
"""
from pathlib import Path
import stat

from driver import authorize_public, native_module, produced, ready_public
from backend import write
from codec import canonical_json, parse_json, sha
from public import current_entry_context, fields, hx, need, reconstruct
import quote

HERE = Path(__file__).resolve().parent


def selected(runner, path):
    raw = produced(runner.ingress.refresh(), path)
    return [str(path), sha(raw)]


def public_json(runner, path):
    return parse_json(produced(runner.ingress.refresh(), path))


def run(runner, label, history_selector, assets_selector, native_selection, owners,
        engine_root, payment_sompi, note_kinds, *, current_entry=None):
    need(type(label) is str and label.replace('-', '').isalnum(), 'round-label')
    need(type(note_kinds) is list and len(note_kinds) == 3 and len(owners) == 3, 'three-owner-policies')
    runner.authenticate()
    root = runner.public / label
    need(not root.exists(), 'fresh-round-output')
    root.mkdir(mode=0o700)
    assets = public_json(runner, assets_selector[0])
    history = public_json(runner, history_selector[0])
    need(sha(canonical_json(assets)) == assets_selector[1], 'canonical-selected-assets')
    need(sha(canonical_json(history)) == history_selector[1], 'canonical-selected-history')
    reconstruct(history)
    module = native_module()
    codec = module.NativeCodec(Path(native_selection['codec']['path']), native_selection['codec']['sha256'])
    guard = runner.ingress.refresh()
    guard.read(codec.executable, codec.sha256)
    vk = guard.read(native_selection['exit_vk']['path'], native_selection['exit_vk']['sha256'])
    identity = (hx(native_selection['image_hex32'], 32), hx(assets['component_profile_sha256'], 32), vk)
    roster = [row['participant_id_hex32'] for row in owners]
    block_daa = 0 if current_entry is None else current_entry_context(history,
        native_selection['immutable_tail_hex'], current_entry)
    *_, sizing = quote.batch(history, roster, module, codec, identity, block_daa_score=block_daa)
    write(root / 'QUOTE.json', canonical_json(sizing))
    fee = sizing['fee_sompi']

    def one(phase, operation, extra):
        target = root / phase
        runner.stage(label + '-' + phase, [runner.driver(operation, target, extra)])
        return target

    context_root = one('context', 'context', ['--history', *history_selector,
        '--component-profile-sha256', assets['component_profile_sha256'], '--fee-sompi', fee,
        '--native-tail-hex', native_selection['immutable_tail_hex']])
    context = selected(runner, context_root / 'CONTEXT.json')
    session_root = one('session', 'session', ['--history', *history_selector, '--context', *context,
        '--program-sha256', assets['program_source_sha256'],
        *[value for participant in roster for value in ('--participant-id', participant)]])
    session = selected(runner, session_root / 'SESSION.json')
    common_owner = ['--assets', assets_selector[0], '--assets-sha256', assets_selector[1],
        '--context', context[0], '--context-sha256', context[1], '--history', history_selector[0],
        '--history-sha256', history_selector[1], '--session', session[0], '--session-sha256', session[1]]

    def owners_phase(phase, operation, extras, validator, proving=False):
        outputs = [root / (phase + '-%d' % index) for index in range(3)]
        for output in outputs:
            runner.ingress.register(output, operation)
        commands = [runner.wallet_command(operation, index, outputs[index],
            runner.private / 'controller' / (label + '-' + phase + '-%d' % index),
            [*common_owner, *extras(index)]) for index in range(3)]
        runner.stage(label + '-' + phase, commands, cpu=14 if proving else 4,
                     memory=(20 if proving else 4) * 1024**3)
        promoted = []
        for index, output in enumerate(outputs):
            _, selector = runner.ingress.promote(output, root / (phase.upper() + '-%d.json' % index),
                lambda raw, kind, index=index: validator(parse_json(raw), index))
            promoted.append([selector['path'], selector['sha256']])
        return promoted

    def invoice_validator(value, index):
        fields(value, ('schema', 'session_sha256', 'participant_id_hex32', 'private_invoice_count'),
               'exact-public-invoice-completion')
        need(value['schema'] == 'kpx8-owner-invoices-ready/v1'
             and value['session_sha256'] == session[1] and value['participant_id_hex32'] == roster[index]
             and type(value['private_invoice_count']) is int and value['private_invoice_count'] == 3,
             'same-session-three-private-invoices')
        return value

    owners_phase('invoice', 'invoice', lambda _: [], invoice_validator)
    current = [runner.private / ('party-%d' % index) for index in range(3)]
    common_mpc = []
    for old in runner.old:
        common_mpc += ['--exclude-private-root', old]
    for parent in current:
        common_mpc += ['--exclude-owner-private-directory', str(parent)]
    for parent in runner.retained:
        common_mpc += ['--exclude-retained-private-directory', str(parent)]
    guard = runner.ingress.refresh()
    pins = {name: sha(produced(guard, HERE / 'construction' / name)) for name in
            ('backend.py', 'codec.py', 'party.py', 'coordinator.py', 'kpx7_mix.mpc')}
    prepared = root / 'mpc-prepared'
    command = ['/usr/bin/python3', '-B', str(HERE / 'construction/backend.py'), 'prepare', *common_mpc,
        '--output', str(prepared), '--engine-root', str(engine_root), '--session', session[0],
        '--session-sha256', session[1], '--program-sha256', pins['kpx7_mix.mpc'],
        '--codec-sha256', pins['codec.py'], '--party-sha256', pins['party.py'],
        '--coordinator-sha256', pins['coordinator.py']]
    runner.stage(label + '-compile', [command])
    ready = owners_phase('ready', 'prepare', lambda index: ['--party', index,
        '--note-kind', note_kinds[index], '--payment-sompi', payment_sompi],
        lambda value, index: ready_public(value, roster[index], session[1]), proving=True)
    before_reports = [set((parent / 'mpc').glob('mpc-private-*/OWN-MPC-PROJECTION.json')) for parent in current]
    mixed = root / 'mpc-mixed'
    command = ['/usr/bin/python3', '-B', str(HERE / 'construction/backend.py'), 'run', *common_mpc,
        '--output', str(mixed), '--prepared-root', str(prepared),
        '--prepared-sha256', selected(runner, prepared / 'PREPARED.json')[1],
        '--owner-input-directory', *[str(parent / 'mpc') for parent in current], '--execute']
    runner.stage(label + '-mix', [command], cpu=1, memory=512 * 1024**2)
    reports = []
    for index, parent in enumerate(current):
        new = set((parent / 'mpc').glob('mpc-private-*/OWN-MPC-PROJECTION.json')) - before_reports[index]
        need(len(new) == 1, 'one-fresh-own-engine-result')
        report, = new
        before = report.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'own-report-metadata-only')
        report.chmod(0o400)
        after = report.lstat()
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'own-report-bytes-unchanged')
        reports.append(str(report.relative_to(parent / 'mpc')))
    args = ['--history', *history_selector, '--context', *context, '--session', *session,
            '--mixed', *selected(runner, mixed / 'MIXED.json')]
    args += [value for selector in ready for value in ('--ready', *selector)]
    core = one('core', 'build', args)
    native_args = ['--native-codec', native_selection['codec']['path'], native_selection['codec']['sha256'],
        '--exit-vk', native_selection['exit_vk']['path'], native_selection['exit_vk']['sha256'],
        '--outer-image-hex32', native_selection['image_hex32'],
        '--component-profile-sha256', assets['component_profile_sha256'], '--compute-budget', 1800,
        '--block-daa-score', block_daa]
    pre = one('pre', 'native-project', ['--body', *selected(runner, core / 'BODY.bin'), *native_args])
    quote.exact_final(public_json(runner, pre / 'NATIVE-CODEC.json'), fee)
    projection = selected(runner, pre / 'PROJECTION.bin')
    raw_projection = runner.ingress.read(*projection)
    authorized = owners_phase('authorize', 'authorize', lambda index: [
        '--projection', projection[0], '--projection-sha256', projection[1], '--own-mpc-result', reports[index]],
        lambda value, index: authorize_public(value, raw_projection, index), proving=True)
    final_body = one('final-body', 'finalize', ['--projection', *projection,
        *[value for selector in authorized for value in ('--spend-public', *selector)]])
    final = one('final', 'native-project', ['--body', *selected(runner, final_body / 'BODY.bin'), *native_args])
    quote.exact_final(public_json(runner, final / 'NATIVE-CODEC.json'), fee)
    one('crosscheck', 'verify', ['--projection', *selected(runner, final / 'PROJECTION.bin'),
        '--verifier-host', native_selection['host']['path'], native_selection['host']['sha256'], '--execute'])
    result = {'schema': 'kpx8-genuine-mixed-round/v1', 'label': label,
        'projection': selected(runner, final / 'PROJECTION.bin'), 'case': selected(runner, final / 'CASE.json'),
        'journal': selected(runner, final / 'JOURNAL.bin'), 'session': session, 'fee_sompi': fee,
        'nine_genuine_component_proofs_independently_verified': True,
        'outer_receipt_native_Full_or_chain_acceptance': False}
    write(root / 'ROUND.json', canonical_json(result))
    return result

"""One current-head Exit candidate, with genuine proof and native Full.

This function never broadcasts or appends an accepted history. The live
controller must independently confirm/replay the exact case before preparing
another head. No caller boolean can establish chain acceptance here.
"""
from pathlib import Path
import secrets

from driver import native_module
from backend import path, write
from codec import canonical_json, sha
from exits import auth_export, read_context, ready_export
from public import current_entry_context, hx, need
from rounds import public_json, selected
from validation import VALIDATOR, native_full
import quote


def prepare(runner, output, party, participant_id, history_selector, assets_selector,
            native_selection, current_entry):
    runner.authenticate()
    need(type(party) is int and 0 <= party < 3, 'selected-live-exit-owner')
    output = path(output)
    need(not output.exists() and all(not output.is_relative_to(root)
         for root in runner.ingress.guard.directories), 'fresh-public-live-exit-output')
    history = public_json(runner, history_selector[0])
    assets = public_json(runner, assets_selector[0])
    need(sha(canonical_json(history)) == history_selector[1]
         and sha(canonical_json(assets)) == assets_selector[1], 'selected-live-history-and-assets')
    daa = current_entry_context(history, native_selection['immutable_tail_hex'], current_entry)
    output.mkdir(mode=0o700)
    prefix = output.name
    probe = output / 'READ-CONTEXT.json'
    write(probe, canonical_json(read_context(history, assets['component_profile_sha256'],
                                            native_selection['immutable_tail_hex'])))

    def owner_job(operation, target, extra, proving=False):
        runner.ingress.register(target, operation)
        common = ['--assets', assets_selector[0], '--assets-sha256', assets_selector[1],
            '--history', history_selector[0], '--history-sha256', history_selector[1]]
        command = runner.wallet_command(operation, party, target,
            runner.private / 'controller' / (prefix + '-' + operation), [*common, *extra])
        runner.stage(prefix + '-' + operation, [command], cpu=8 if proving else 4,
                     memory=(12 if proving else 4) * 1024**3)

    ready_output = output / 'ready'
    owner_job('exit-ready', ready_output, ['--context', str(probe), '--context-sha256',
        selected(runner, probe)[1], '--note-kind', 'any'])
    ready, _ = runner.ingress.promote(ready_output, output / 'READY.json',
        lambda raw, kind: ready_export(raw, kind, participant_id, history_selector[1]))
    if ready['schema'] == 'kpx8-owner-no-unspent-claim/v1':
        result = {'schema': 'kpx8-single-live-exit-candidate/v1', 'status': 'AUTHENTICATED_OWNER_EMPTY',
                  'history_sha256': history_selector[1], 'financial_authorization_or_broadcast': False}
        write(output / 'RESULT.json', canonical_json(result))
        return result
    module = native_module()
    codec = module.NativeCodec(Path(native_selection['codec']['path']), native_selection['codec']['sha256'])
    runner.ingress.read(codec.executable, codec.sha256)
    vk = runner.ingress.read(native_selection['exit_vk']['path'], native_selection['exit_vk']['sha256'])
    identity = (hx(native_selection['image_hex32'], 32), hx(assets['component_profile_sha256'], 32), vk)
    body, _, projection, _, _, sizing = quote.exit(history, hx(ready['nf_hex32'], 32),
        hx(ready['payout_spk_hex36'], 36), ready['gross_claim_sompi'], secrets.token_hex(32),
        module, codec, identity, block_daa_score=daa)
    write(output / 'QUOTE.json', canonical_json(sizing))
    write(output / 'BODY.bin', body)
    write(output / 'UNPROVED-PROJECTION.bin', projection)
    context = output / 'CONTEXT.json'
    write(context, canonical_json(read_context(history, assets['component_profile_sha256'],
        native_selection['immutable_tail_hex'], sizing['fee_sompi'])))
    authorization = output / 'authorization'
    owner_job('exit', authorization, ['--context', str(context), '--context-sha256', selected(runner, context)[1],
        '--projection', str(output / 'UNPROVED-PROJECTION.bin'), '--projection-sha256', sha(projection)], proving=True)
    proof, _ = runner.ingress.promote(authorization, output / 'AUTHORIZATION.json',
        lambda raw, kind: auth_export(raw, kind, history_selector[1], projection, ready['nf_hex32']))
    case, final, journal, report = module.make_case(codec, body, *identity, 1800,
        outer_proof=proof, block_daa_score=daa)
    need(final == projection and case['entries'][0] == current_entry['entry'],
         'genuine-exit-preserves-exact-selected-chain-context-and-projection')
    quote.exact_final(report, sizing['fee_sompi'])
    for name, value in (('CASE.json', case), ('PROJECTION.bin', final),
                        ('JOURNAL.bin', journal), ('NATIVE-CODEC.json', report)):
        write(output / name, canonical_json(value) if type(value) is dict else value)
    validator = native_selection.get('validator', {'path': str(VALIDATOR)})['path']
    full = native_full(runner, selected(runner, output / 'CASE.json'), output / 'Full', validator=validator)
    write(output / 'FULL-CHECK.json', canonical_json(full))
    result = {'schema': 'kpx8-single-live-exit-candidate/v1', 'status': 'GENUINE_NATIVE_CANDIDATE',
        'case': selected(runner, output / 'CASE.json'), 'projection': selected(runner, output / 'PROJECTION.bin'),
        'journal': selected(runner, output / 'JOURNAL.bin'), 'selected_block_daa_score': daa,
        'fee_sompi': sizing['fee_sompi'], 'native_Full_and_all_input_engines': True,
        'broadcast_accepted_history_or_chain_confirmation': False}
    write(output / 'RESULT.json', canonical_json(result))
    return result

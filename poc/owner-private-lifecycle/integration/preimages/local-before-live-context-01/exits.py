"""Independent direct exits; local functional evidence, no shutdown claim."""
from pathlib import Path
import secrets
from backend import write
from codec import canonical_json, parse_json, sha
from driver import native_module
from public import DOMAIN, fields, hx, load_wire, need, reconstruct
from rounds import public_json, selected
from validation import native_full
import quote


def read_context(history, component, tail, fee=1):
    _, head = reconstruct(history)
    need(type(fee) is int and fee > 0, 'positive-read-context-fee')
    return {'schema': 'kpx8-wallet-premix-context/v1', 'domain_hex32': DOMAIN.hex(),
        'component_profile_sha256': component, 'prior_state_hex112': head['state_hex112'],
        'previous_outpoint_hex36': head['outpoint_hex36'], 'reserve_sompi': head['reserve_sompi'],
        'fee_sompi': fee, 'fee_shares_sompi': [fee // 3, fee // 3, fee - 2 * (fee // 3)],
        'native_tail_hex': tail}


def ready_export(raw, kind, participant, history_sha):
    value = parse_json(raw)
    if value.get('schema') == 'kpx8-owner-no-unspent-claim/v1':
        fields(value, ('schema', 'participant_id_hex32', 'history_sha256', 'empty'), 'exact-empty-exit-result')
        need(value['empty'] is True, 'typed-empty-not-missing-data')
    else:
        fields(value, ('schema', 'domain_hex32', 'participant_id_hex32', 'history_sha256', 'nf_hex32',
            'gross_claim_sompi', 'payout_spk_hex36', 'financial_authorization'), 'exact-exit-ready-fields')
        need(value['schema'] == 'kpx8-owner-exit-ready/v1' and value['domain_hex32'] == DOMAIN.hex()
             and value['financial_authorization'] is False, 'unproved-current-exit-ready')
        hx(value['nf_hex32'], 32); hx(value['payout_spk_hex36'], 36)
        need(type(value['gross_claim_sompi']) is int and value['gross_claim_sompi'] > 0, 'integer-gross-claim')
    need(value['participant_id_hex32'] == participant and value['history_sha256'] == history_sha,
         'same-owner-current-history-result')
    return value


def auth_export(raw, kind, history_sha, projection, nf):
    value = parse_json(raw)
    fields(value, ('schema', 'history_sha256', 'projection_sha256', 'effects_digest_hex32',
        'nf_hex32', 'statement_hex152', 'proof_hex128'), 'exact-exit-authorization')
    wire = load_wire()
    need(value['schema'] == 'kpx8-owner-exit-authorization/v1' and value['history_sha256'] == history_sha
         and value['projection_sha256'] == sha(projection) and value['nf_hex32'] == nf
         and value['effects_digest_hex32'] == wire.exit_effects_digest(projection).hex()
         and hx(value['statement_hex152'], 152) == wire.exit_statement(projection),
         'exact-current-native-effects-exit-statement')
    return hx(value['proof_hex128'], 128)


def run(runner, history_selector, assets_selector, native_selection, owners):
    """Drain nine notes without private maps or assuming three claims each."""
    runner.authenticate()
    root = runner.public / 'independent-exits'
    need(not root.exists(), 'fresh-direct-exit-campaign')
    root.mkdir(mode=0o700)
    assets = public_json(runner, assets_selector[0])
    history = public_json(runner, history_selector[0])
    need(sha(canonical_json(assets)) == assets_selector[1], 'selected-exit-assets')
    need(sha(canonical_json(history)) == history_selector[1], 'selected-pre-exit-history')
    state, _ = reconstruct(history)
    need((len(state.cms), len(state.entries)) == (15, 7), 'two-round-nine-claim-state')
    module = native_module()
    codec = module.NativeCodec(Path(native_selection['codec']['path']), native_selection['codec']['sha256'])
    runner.ingress.read(codec.executable, codec.sha256)
    vk = runner.ingress.read(native_selection['exit_vk']['path'], native_selection['exit_vk']['sha256'])
    identity = (hx(native_selection['image_hex32'], 32), hx(assets['component_profile_sha256'], 32), vk)
    native_args = ['--native-codec', str(codec.executable), codec.sha256, '--exit-vk',
        native_selection['exit_vk']['path'], native_selection['exit_vk']['sha256'],
        '--outer-image-hex32', native_selection['image_hex32'],
        '--component-profile-sha256', assets['component_profile_sha256']]
    completed, candidate = [], 0

    def owner_job(label, operation, party, output, extra, proving=False):
        runner.ingress.register(output, operation)
        common = ['--assets', assets_selector[0], '--assets-sha256', assets_selector[1],
            '--history', history_selector[0], '--history-sha256', history_selector[1]]
        command = runner.wallet_command(operation, party, output, runner.private / 'controller' / label,
                                       [*common, *extra])
        runner.stage(label, [command], cpu=8 if proving else 4, memory=(12 if proving else 4) * 1024**3)

    for ordinal in range(9):
        label = 'exit-%02d' % (ordinal + 1)
        folder = root / label
        folder.mkdir(mode=0o700)
        context = folder / 'READ-CONTEXT.json'
        write(context, canonical_json(read_context(history, assets['component_profile_sha256'],
                                                  native_selection['immutable_tail_hex'])))
        ready, party = None, None
        for offset in range(3):
            index = (candidate + offset) % 3
            output = folder / ('ready-%d' % index)
            owner_job(label + '-ready-%d' % index, 'exit-ready', index, output,
                ['--context', str(context), '--context-sha256', selected(runner, context)[1], '--note-kind', 'any'])
            value, _ = runner.ingress.promote(output, folder / ('READY-%d.json' % index),
                lambda raw, kind, index=index: ready_export(raw, kind, owners[index]['participant_id_hex32'],
                                                          history_selector[1]))
            if value['schema'] == 'kpx8-owner-exit-ready/v1':
                ready, party = value, index
                candidate = (index + 1) % 3
                break
        need(ready is not None, 'nine-required-claims-cannot-disappear')
        body, _, projection, _, _, sizing = quote.exit(history, hx(ready['nf_hex32'], 32),
            hx(ready['payout_spk_hex36'], 36), ready['gross_claim_sompi'], secrets.token_hex(32), module, codec, identity)
        write(folder / 'QUOTE.json', canonical_json(sizing))
        write(folder / 'BODY.bin', body)
        write(folder / 'UNPROVED-PROJECTION.bin', projection)
        context = folder / 'CONTEXT.json'
        write(context, canonical_json(read_context(history, assets['component_profile_sha256'],
            native_selection['immutable_tail_hex'], sizing['fee_sompi'])))
        output = folder / 'authorization'
        owner_job(label + '-prove', 'exit', party, output, ['--context', str(context), '--context-sha256',
            selected(runner, context)[1], '--projection', str(folder / 'UNPROVED-PROJECTION.bin'),
            '--projection-sha256', sha(projection)], proving=True)
        proof, _ = runner.ingress.promote(output, folder / 'AUTHORIZATION.json',
            lambda raw, kind: auth_export(raw, kind, history_selector[1], projection, ready['nf_hex32']))
        case, final, journal, report = module.make_case(codec, body, *identity, 1800, outer_proof=proof)
        need(final == projection, 'Exit-proof-preserves-native-projection')
        quote.exact_final(report, sizing['fee_sompi'])
        for name, value in (('CASE.json', case), ('PROJECTION.bin', final),
                            ('JOURNAL.bin', journal), ('NATIVE-CODEC.json', report)):
            write(folder / name, canonical_json(value) if type(value) is dict else value)
        full = native_full(runner, selected(runner, folder / 'CASE.json'), folder / 'Full')
        write(folder / 'FULL-CHECK.json', canonical_json(full))
        following = folder / 'history'
        runner.stage(label + '-history', [runner.driver('append', following, ['--history', *history_selector,
            '--case', *selected(runner, folder / 'CASE.json'), '--projection', *selected(runner, folder / 'PROJECTION.bin'),
            *native_args])])
        history_selector = selected(runner, following / 'HISTORY.json')
        history = public_json(runner, history_selector[0])
        completed.append({'ordinal': ordinal + 1, 'case': selected(runner, folder / 'CASE.json'),
                          'native_Full': full, 'fee_sompi': sizing['fee_sompi']})
        write(folder / 'COMPLETE.json', canonical_json(completed[-1]))
    state, head = reconstruct(history)
    need(head['reserve_sompi'] == 0 and head['outpoint_hex36'] is None
         and (len(state.cms), len(state.entries)) == (15, 16), 'all-nine-exits-terminal-state')
    result = {'schema': 'kpx8-nine-local-independent-exits/v1', 'completed_exits': completed,
        'final_history': history_selector, 'terminal_reserve_sompi': 0,
        'all_nine_genuine_Exit_proofs_and_native_Full_passed': True,
        'accepted_chain_literal_prover_shutdown_or_independent_storage': False}
    write(root / 'RESULT.json', canonical_json(result))
    return result

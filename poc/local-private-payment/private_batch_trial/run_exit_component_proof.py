#!/usr/bin/env python3
"""Fresh real AuthExit proofs for explicitly unfunded native-branch probes.

Reuse selected parameters. Payment image/component metadata are intentionally
unselected; this does not select a complete financial profile or broadcast.
"""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import component_run
import exit_wire
import wallet_profile as wallet

CLASSIFICATION = 'UNFUNDED_EXIT_COMPONENT_ONLY_UNSELECTED_PAYMENT_METADATA'


class ProbeRun(component_run.Run):
    def __init__(self, args):
        super().__init__(args)
        self.parameter_manifest = Path(args.parameter_manifest).absolute()
        self.parameter_manifest_sha256 = args.parameter_manifest_sha256
        self.parameter_key = Path(args.proving_key).absolute()
        manifest_raw = self.read(self.parameter_manifest, self.parameter_manifest_sha256)
        self.parameter_metadata = json.loads(manifest_raw)
        self.read(self.parameter_key, self.parameter_metadata['pk_sha256'])
        emission_raw = self.read(Path(args.emission).absolute(), args.emission_sha256)
        self.emission = json.loads(emission_raw)
        parameters_raw = self.read(Path(args.native_parameters).absolute(), args.native_parameters_sha256)
        parameters = json.loads(parameters_raw)
        for value in (self.emission, parameters):
            component_run.need(value['classification'] == CLASSIFICATION
                and value['payment_profile_selected'] is False, 'unfunded-unselected-payment-probe')
        component_run.need(self.emission['aggregate_proof_selected'] is False,
                           'no-aggregate-proof-substitution')
        component_run.need(parameters['auth_exit']['parameter_manifest_sha256'] == self.parameter_manifest_sha256
            and parameters['auth_exit']['vk_sha256'] == self.parameter_metadata['vk_sha256']
            and parameters['auth_exit']['vk_hex328'] == self.parameter_metadata['vk_hex328'],
            'exact-real-exit-parameters')
        component_run.need(parameters['domain_hex32'] == self.profile.domain.hex()
            and parameters['profile_hex32'] == self.profile.profile_id.hex()
            and parameters['chain_hex32'] == self.descriptor['chain_genesis_hex32']
            and parameters['service_hex32'] == self.descriptor['service_policy_hex32'],
            'exact-probe-profile-context')
        for fee in (args.terminal_fee_sompi, args.continuing_fee_sompi):
            component_run.need(type(fee) is int and 0 < fee <= 190_000_000, 'selected-component-fee')
        self.terminal_fee = args.terminal_fee_sompi
        self.continuing_fee = args.continuing_fee_sompi
        self.tail = bytes.fromhex(self.emission['immutable_tail_hex'])
        self.redeem = bytes.fromhex(self.emission['redeem_hex'])
        component_run.need(self.redeem[:2] == b'\x4c\x70'
            and self.redeem[114:] == self.tail
            and self.redeem[2:114].hex() == self.emission['state_hex112'], 'actual-probe-policy-tail')
        self.save('PROBE-SELECTION.json', component_run.encoded({
            'schema': 'kpb-real-exit-proof-probe-selection/v1', 'classification': CLASSIFICATION,
            'source_sha256': hashlib.sha256(self.read(Path(__file__).resolve())).hexdigest(),
            'emission_sha256': args.emission_sha256,
            'native_parameters_sha256': args.native_parameters_sha256,
            'parameter_manifest_sha256': self.parameter_manifest_sha256,
            'fresh_setup': False, 'cases': ['terminal-200M', 'continuing-260M-overcollateralized'],
            'terminal_fee_sompi': self.terminal_fee,
            'continuing_fee_sompi': self.continuing_fee,
            'fee_rate_source_sompi_per_mass': 100,
            'actual_node_or_network_minimum_fee_claimed': False,
            'accepted_ledger_or_financial_profile_selected': False}))

    def native(self, label, request):
        argv = self.isolation() + ['--ro-bind', str(self.binary), '/public/relation',
            '--ro-bind', str(self.output), str(self.output),
            '--ro-bind', str(self.parameter_manifest), '/parameters/MANIFEST.json']
        if request['operation'] == 'prove':
            argv += ['--ro-bind', str(self.parameter_key), '/parameters/parameters.pk']
        argv += ['/public/relation']
        return json.loads(self.call(label, argv, request))

    def prove_projection(self, label, claim, raw_body, context, approved_fee):
        projection = exit_wire.projection(raw_body, self.tail)
        approved = wallet.authorize_exit(self.receiver, claim, projection, context, self.tail,
                                         approved_fee_sompi=approved_fee)
        signature = self.normalize(label, self.authority.signature_inputs(approved.statement, approved.authorization))
        request = {**approved.private_request, 'signature': signature}
        matrix = self.native(label + '-actual-joined-matrix', {**request, 'operation': 'check-joined'})
        component_run.need(all(matrix['counts'][field] == 0 for field in (
            'native_residual_failures', 'signature_residual_failures', 'link_residual_failures')),
            'actual-exit-probe-matrix-SAT')
        selected = {'manifest': '/parameters/MANIFEST.json',
                    'manifest_sha256': self.parameter_manifest_sha256}
        proof = self.native(label + '-genuine-existing-key-proof', {**request, 'operation': 'prove',
            'parameters': {**selected, 'pk': '/parameters/parameters.pk',
                           'pk_sha256': self.parameter_metadata['pk_sha256']}})
        verify = self.native(label + '-separate-public-verification', {
            'operation': 'verify', 'role': 'new-auth-exit', 'profile': request['profile'],
            'statement_hex': approved.statement.hex(), 'proof_hex128': proof['proof_hex128'],
            'parameters': selected})
        component_run.need(verify['accepted'] is True, 'real-exit-probe-public-verification')
        body = exit_wire.parse_body(raw_body)
        record = {'schema': 'kpb-genuine-exit-native-probe-input/v1', 'classification': CLASSIFICATION,
            'id': label, 'projection_hex': projection.hex(), 'body_hex1604': raw_body.hex(),
            'statement_hex152': approved.statement.hex(), 'proof_hex128': proof['proof_hex128'],
            'old_state_hex112': context.state().hex(), 'new_state_hex112': body.next_state().hex(),
            'old_reserve_sompi': context.reserve, 'new_reserve_sompi': body.new_reserve,
            'payout_sompi': body.payout, 'fee_sompi': body.fee,
            'fresh_owner_authorization': True, 'fresh_proof_with_existing_parameters': True,
            'actual_proof_public_verification': True, 'native_VM_or_chain_confirmation': False}
        self.save(label + '-PROOF-INPUT.json', component_run.encoded(record))
        return {'id': label, 'actual_matrix': matrix, 'proof_input': str(self.output / (label + '-PROOF-INPUT.json')),
                'actual_proof_public_verification': True}

    def probes(self):
        _, context, claim, raw, _, _, _ = self.fixture()
        component_run.need(context.state().hex() == self.emission['state_hex112'], 'exact-probe-old-state')
        component_run.need(exit_wire.state_spk(context.state(), self.tail).hex() == self.emission['script_public_key'],
                           'exact-probe-input-SPK')
        original = exit_wire.parse_body(raw)
        terminal = replace(context, point=hashlib.sha256(b'UNFUNDED TERMINAL EXIT BRANCH 2026-10-28').digest()
                           + (3).to_bytes(4, 'little'))
        raw_terminal = exit_wire.body(terminal, bytes([5]) * 32, original.new_nf_root,
            original.new_nf_count, 0, self.terminal_fee, 200_000_000 - self.terminal_fee,
            original.payout_spk, original.nf, original.witness)
        results = [self.prove_projection('terminal-200M', claim, raw_terminal, terminal, self.terminal_fee)]
        # Separate hypothetical UTXO/context. The excess60M reserve is explicit;
        # there is no claim of an accepted liability/deposit ledger for it.
        continuing = replace(context,
            point=hashlib.sha256(b'UNFUNDED CONTINUING EXIT BRANCH 2026-10-28').digest() + (7).to_bytes(4, 'little'),
            reserve=260_000_000)
        raw_continuing = exit_wire.body(continuing, bytes([7]) * 32, original.new_nf_root,
            original.new_nf_count, 60_000_000, self.continuing_fee, 200_000_000 - self.continuing_fee,
            original.payout_spk, original.nf, original.witness)
        results.append(self.prove_projection('continuing-260M', claim, raw_continuing, continuing, self.continuing_fee))
        result = {'schema': 'kpb-real-exit-native-probe-proofs-result/v1', 'classification': CLASSIFICATION,
                  'cases': results, 'fresh_setup': False, 'funding_or_broadcast': False,
                  'accepted_backing_chain_or_payment_profile': False, 'native_VM_executed': False}
        self.save('EVENTS.json', component_run.encoded(self.events))
        self.save('PROOF-RESULT.json', component_run.encoded(result))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'binary', 'binary-sha256', 'profile', 'profile-sha256',
                 'parameter-manifest', 'parameter-manifest-sha256', 'proving-key',
                 'emission', 'emission-sha256', 'native-parameters', 'native-parameters-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--terminal-fee-sompi', type=int, required=True)
    parser.add_argument('--continuing-fee-sompi', type=int, required=True)
    args = parser.parse_args()
    args.operation = 'unfunded-native-exit-branch-proof'
    run = None
    try:
        run = ProbeRun(args)
        result = run.probes()
        print(json.dumps({'status': 'GENUINE_EXIT_BRANCH_PROOFS_COMPLETED',
                          'case_count': len(result['cases']), 'native_VM_executed': False}))
    except BaseException as error:
        if run is not None:
            run.save('FIRST-FAILURE.json', component_run.encoded({'type': type(error).__name__,
                     'category': str(error), 'events': run.events}))
        raise
    finally:
        if run is not None:
            run.authority.close()


if __name__ == '__main__':
    main()

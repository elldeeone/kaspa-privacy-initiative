#!/usr/bin/env python3
"""Strict explicit new-profile GEN3 public admission; no signing or broadcast.

Reuse the old three-owner funding/value/fee predicates under a new payload tag,
actual new Output key and KPBAST01 reserve policy. NativeFull, SDK transaction-ID
validation and actual accepted-chain acquisition remain separate requirements.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import uuid

import exit_wire
import new_private_trial as bootstrap
import output_verifier
import private_worker
import wallet_history
import wallet_profile as wallet

MAGIC = b'KPBGN301'
WIDTH = 1648
ADMISSION = 2_000_000_000
RESERVE = 6_000_000_000
POOL_HEX = 'd68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf'
EXPECTED_IDENTITY = tuple(bytes.fromhex(value) for value in (
    'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370', POOL_HEX,
    'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700',
    'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0',
    'ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5'))
need, fields, hx = wallet_history.need, wallet_history.fields, wallet_history.hx


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'GEN3-canonical-unsigned-integer')
    return value


def amount(value, *, zero=False):
    uint(value)
    need((0 if zero else 1) <= value <= exit_wire.MAX, 'GEN3-integer-sompi-range')
    return value


class GenesisVerifier(output_verifier.OutputVerifier):
    def _derive_public(self, request):
        argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(self.binary), '/public/relation', '/public/relation']
        result = subprocess.run(argv, input=private_worker.encoded(request), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=bootstrap.CLEAN)
        need(result.returncode == 0, 'GEN3-established-public-commitment-refused')
        return private_worker.parse(result.stdout)

    def known_initial_cv(self):
        """Evaluate the established native Commit(20KAS,0), with public inputs.

        The deterministic dummy receipt is public, never a wallet Original or
        funded claim. The existing derive-output operation calls exactly the
        mature relation::value_commitment implementation; it makes no proof.
        """
        values = [hashlib.sha256(b'PUBLIC GEN3 COMMITMENT ONLY ' + bytes([i])).digest() for i in range(5)]
        invoice = wallet.Invoice(self.profile.domain, 0, values[0], values[1], values[2],
            bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), values[3])
        receipt = wallet.Receipt.for_invoice(invoice, ADMISSION, values[4])
        cf_hash = hashlib.sha256(b'PUBLIC COMMITMENT DERIVATION; NO ENCRYPTED NOTE').digest()
        request = {'operation': 'derive-output', 'role': 'new-output',
            'profile': {'domain_hex32': self.profile.domain.hex(), 'profile_id_hex32': self.profile.profile_id.hex()},
            'statement_hex': '', 'note_hex168': receipt.note_bytes().hex(),
            'blinding_hex32': bytes(32).hex(), 'cf_hash_hex32': cf_hash.hex()}
        value = self._derive_public(request)
        fields(value, ('schema', 'statement_hex168', 'proof_or_ciphertext_validity_established'))
        statement = hx(value['statement_hex168'], 168)
        need(value['schema'] == 'kpb-new-output-public-statement/v1'
             and value['proof_or_ciphertext_validity_established'] is False
             and statement[:8] == b'KPXAOU01' and statement[8:40] == self.profile.domain
             and statement[40:72] == receipt.commitment() and statement[136:] == cf_hash,
             'GEN3-independent-known20KAS-commitment')
        return statement[72:136]


class NamespaceGenesisVerifier(GenesisVerifier):
    """Direct transport after the caller establishes its outer public sandbox.

    The caller admits the binary/manifest read-only and authenticates that
    namespace before constructing this adapter. This public-only adapter has no
    Original/seed API, private derivation input or proving-key fallback.
    """
    def _derive_public(self, request):
        need(request['operation'] == 'derive-output', 'GEN3-public-derivation-only')
        result = subprocess.run([str(self.binary)], input=private_worker.encoded(request),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=bootstrap.CLEAN)
        need(result.returncode == 0, 'GEN3-namespace-public-derivation-refused')
        return private_worker.parse(result.stdout)

    def _call(self, operation, statement, private=None):
        need(operation == 'verify' and set(private or {}) == {'proof_hex128'}, 'GEN3-public-verification-only')
        request = {'operation': 'verify', 'role': 'new-output',
            'profile': {'domain_hex32': self.profile.domain.hex(), 'profile_id_hex32': self.profile.profile_id.hex()},
            'statement_hex': statement.hex(), **private,
            'parameters': {'manifest': str(self.manifest), 'manifest_sha256': self.manifest_sha256}}
        result = subprocess.run([str(self.binary)], input=private_worker.encoded(request),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=bootstrap.CLEAN)
        need(result.returncode == 0, 'GEN3-namespace-public-verification-refused')
        return private_worker.parse(result.stdout)


@dataclass(frozen=True, repr=False)
class Selection:
    component_sha: bytes
    identity: tuple
    tail: bytes
    verifier: GenesisVerifier
    initial_cv: bytes

    @classmethod
    def from_component(cls, raw, expected_sha256, tail, verifier):
        need(hashlib.sha256(raw).hexdigest() == expected_sha256, 'GEN3-selected-component-file')
        value = private_worker.parse(raw)
        fields(value, ('schema', 'selected', 'classification', 'chain_genesis_hex32', 'pool_lineage_hex32',
            'profile_id_hex32', 'domain_hex32', 'service_policy_hex32', 'aggregate', 'output', 'auth_exit',
            'value_generator_hex64', 'blinding_generator_hex64', 'curve_parameters_sha256',
            'input_count', 'output_count', 'note_floor_sompi', 'max_value_sompi', 'body_core_bytes',
            'body_bytes', 'journal_bytes', 'auth_exit_statement_bytes'))
        need(value['schema'] == 'private-batch-component-profile/v1' and value['selected'] is True
             and value['classification'] == 'RESEARCH_TESTNET_ONLY'
             and value['input_count'] == 3 and value['output_count'] == 6
             and value['note_floor_sompi'] == exit_wire.NOTE_FLOOR and value['max_value_sompi'] == exit_wire.MAX
             and value['body_core_bytes'] == 10364 and value['body_bytes'] == 10492
             and value['journal_bytes'] == 104 and value['auth_exit_statement_bytes'] == 152,
             'GEN3-actual-new-financial-component-profile')
        identity = tuple(hx(value[key], 32) for key in ('chain_genesis_hex32', 'pool_lineage_hex32',
            'profile_id_hex32', 'domain_hex32', 'service_policy_hex32'))
        need(identity == EXPECTED_IDENTITY
             and identity[2] == verifier.profile.profile_id and identity[3] == verifier.profile.domain,
             'GEN3-selected-new-chain-pool-profile-domain')
        keys = []
        for role in ('aggregate', 'output', 'auth_exit'):
            fields(value[role], ('vk_hex328', 'vk_sha256', 'parameter_manifest_sha256'))
            key = hx(value[role]['vk_hex328'], 328)
            digest = hx(value[role]['vk_sha256'], 32)
            need(hashlib.sha256(key).digest() == digest and hx(value[role]['parameter_manifest_sha256'], 32) != bytes(32),
                 'GEN3-actual-role-key-digest')
            keys.append(digest)
        need(len(set(keys)) == 3 and value['output']['vk_sha256'] == verifier.vk_sha256
             and value['output']['parameter_manifest_sha256'] == verifier.manifest_sha256,
             'GEN3-same-real-Output-parameters')
        hx(value['value_generator_hex64'], 64); hx(value['blinding_generator_hex64'], 64)
        need(value['curve_parameters_sha256'] == '401abafb0b375aa71159c6f4fff4002985f02a29acf0dfe03d89991734d3eeef',
             'GEN3-established-CV-curve-parameters')
        need(type(tail) is bytes and 0 < len(tail) <= 65535 - 114, 'GEN3-exact-native-policy-tail')
        return cls(bytes.fromhex(expected_sha256), identity, tail, verifier, verifier.known_initial_cv())


def trial_uuid(value):
    need(type(value) is str and str(uuid.UUID(value)) == value, 'GEN3-canonical-fresh-trial-UUID')
    return uuid.UUID(value).bytes


def records(payload, selected, trial_id):
    need(type(payload) is bytes and len(payload) == WIDTH and payload[:8] == MAGIC
         and payload[8:40] == selected.component_sha and payload[40:72] == selected.identity[3]
         and payload[72:88] == trial_uuid(trial_id), 'GEN3-new-codec-component-domain-trial')
    rows = [payload[88 + index * 520:88 + (index + 1) * 520] for index in range(3)]
    need(len({row[:32] for row in rows}) == 3, 'GEN3-three-distinct-initial-CMs')
    need(all(row[32:96] == selected.initial_cv and selected.verifier.verify(row) for row in rows),
         'GEN3-real-Output-and-independent20KAS-zero-blind-CV')
    state = wallet_history.trees.PublicState([row[:32] for row in rows])
    return rows, state


def encode_payload(selected, trial_id, rows):
    need(type(rows) in (list, tuple) and len(rows) == 3
         and all(type(row) is bytes and len(row) == 520 for row in rows), 'GEN3-complete-three-row-frame')
    raw = MAGIC + selected.component_sha + selected.identity[3] + trial_uuid(trial_id) + b''.join(rows)
    records(raw, selected, trial_id)
    return raw


def validate_case(case, selected, trial_id, *, quoted_fee_sompi=None, signed=False):
    """Derive exact public entry effects. This returns no acceptance authority."""
    fields(case, ('transaction', 'entries'))
    body, entries = case['transaction'], case['entries']
    fields(body, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId', 'gas', 'payload', 'mass'))
    need(type(body['version']) is int and body['version'] == 1 and type(body['lockTime']) is int
         and body['lockTime'] == 0 and type(body['gas']) is int and body['gas'] == 0
         and body['subnetworkId'] == '00' * 20, 'GEN3-canonical-native-header')
    hx(body['id'], 32); uint(body['mass'])
    need(type(body['inputs']) is list and len(body['inputs']) == 3
         and type(entries) is list and len(entries) == 3 and type(body['outputs']) is list
         and 1 <= len(body['outputs']) <= 4, 'GEN3-three-funding-inputs-output-count')
    points, scripts, amounts = [], [], []
    for source, entry in zip(body['inputs'], entries):
        fields(source, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'))
        fields(source['previousOutpoint'], ('transactionId', 'index'))
        point = source['previousOutpoint']; hx(point['transactionId'], 32); uint(point['index'], 32)
        need(uint(source['sequence']) == (1 << 64) - 1, 'GEN3-exact-source-sequence')
        uint(source['computeBudget'], 16)
        need(signed or source['computeBudget'] == 10, 'GEN3-unsigned-campaign-budget')
        signature = hx(source['signatureScript'], 66)
        need(signature[:1] == b'\x41' and signature[-1:] == b'\x01'
             and (signed or signature == b'\x41' + bytes(64) + b'\x01'), 'GEN3-canonical-ALL-signature-frame')
        fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'))
        amount(entry['amount']); uint(entry['blockDaaScore'])
        need(entry['isCoinbase'] is False and entry['covenantId'] is None, 'GEN3-ordinary-mature-context')
        script = hx(entry['scriptPublicKey'], 36)
        need(script[:3] == b'\0\0\x20' and script[-1:] == b'\xac', 'GEN3-ordinary-funding-P2PK')
        points.append((point['transactionId'], point['index'])); scripts.append(entry['scriptPublicKey']); amounts.append(entry['amount'])
    need(len(set(points)) == 3 and len(set(scripts)) == 3, 'GEN3-distinct-funding-points-and-keys')
    payload_hex = body['payload']
    rows, state = records(hx(payload_hex, WIDTH), selected, trial_id)
    state_raw = wallet_history.state_bytes(state, selected.identity[3])
    reserve_spk = exit_wire.state_spk(state_raw, selected.tail).hex()
    for output in body['outputs']:
        fields(output, ('value', 'scriptPublicKey', 'covenant'))
        amount(output['value']); need(type(output['scriptPublicKey']) is str, 'GEN3-output-script')
        hx(output['scriptPublicKey'], len(output['scriptPublicKey']) // 2)
        need(output['covenant'] is None, 'GEN3-no-output-covenant')
    need(body['outputs'][0] == {'value': RESERVE, 'scriptPublicKey': reserve_spk, 'covenant': None},
         'GEN3-exact60KAS-new-policy-reserve')
    changes, previous = [0, 0, 0], -1
    for output in body['outputs'][1:]:
        need(output['scriptPublicKey'] in scripts, 'GEN3-no-foreign-change')
        index = scripts.index(output['scriptPublicKey'])
        need(index > previous, 'GEN3-ordered-distinct-change')
        changes[index], previous = output['value'], index
    fee = amount(sum(amounts) - sum(output['value'] for output in body['outputs']))
    if quoted_fee_sompi is not None:
        need(fee == amount(quoted_fee_sompi), 'GEN3-exact-independently-quoted-native-fee')
    base = fee // 3
    shares = [base, base, fee - 2 * base]
    need(all(amounts[i] == ADMISSION + changes[i] + shares[i] for i in range(3)), 'GEN3-exact-per-owner-contribution')
    return {'schema': 'kpb-three-owner-genesis-admission/v1',
        'classification': 'SUPPLIED_CASE_AND_OUTPUT_PROOFS_NOT_NATIVE_OR_CHAIN_ACCEPTANCE',
        'component_profile_sha256': selected.component_sha.hex(), 'trial_id': trial_id,
        'chain_hex32': selected.identity[0].hex(), 'pool_hex32': selected.identity[1].hex(),
        'profile_hex32': selected.identity[2].hex(), 'domain_hex32': selected.identity[3].hex(),
        'service_hex32': selected.identity[4].hex(), 'state_hex112': state_raw.hex(),
        'reserve_sompi': RESERVE, 'outpoint_hex36': body['id'] + '00000000',
        'outputs_hex520': [row.hex() for row in rows], 'initial_cv_hex64': selected.initial_cv.hex(),
        'fee_sompi': fee, 'owner_fee_shares_sompi': shares, 'owner_changes_sompi': changes,
        'canonical_case_sha256': hashlib.sha256(private_worker.encoded(case)).hexdigest(),
        'native_Full_SDK_id_and_accepted_chain_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('component-profile', 'component-profile-sha256', 'tail', 'tail-sha256', 'case', 'case-sha256', 'trial-id', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--quoted-fee-sompi', type=int)
    parser.add_argument('--signed', action='store_true')
    args = parser.parse_args()
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    try:
        descriptor = private_worker.parse(read(bootstrap.PROFILE, bootstrap.PROFILE_SHA))
        profile = wallet.Profile(bytes.fromhex(descriptor['profile_descriptor']['domain_hex32']), bytes.fromhex(descriptor['profile_id_hex32']))
        verifier = GenesisVerifier(profile, bootstrap.BINARY, bootstrap.BINARY_SHA,
            bootstrap.PARAMETERS / 'MANIFEST.json', bootstrap.MANIFEST_SHA, read_public=read)
        selected = Selection.from_component(read(Path(args.component_profile).absolute(), args.component_profile_sha256),
            args.component_profile_sha256, read(Path(args.tail).absolute(), args.tail_sha256), verifier)
        case = private_worker.parse(read(Path(args.case).absolute(), args.case_sha256))
        result = validate_case(case, selected, args.trial_id, quoted_fee_sompi=args.quoted_fee_sompi, signed=args.signed)
        bootstrap.save(Path(args.output).absolute(), result)
        print(json.dumps({'status': 'GEN3_PUBLIC_PREDICATES_PASSED', 'native_or_chain_acceptance': False}))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit('new-profile GEN3 public admission incomplete')


if __name__ == '__main__':
    main()

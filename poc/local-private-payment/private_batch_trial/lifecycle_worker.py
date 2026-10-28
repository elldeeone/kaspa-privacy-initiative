#!/usr/bin/env python3
"""Original-only new-profile owner operations inside one network-off namespace.

Output tuples, private notes, signatures, normalized witnesses and MPC input
files never enter the public status receipt. This first facade accepts only
supplied unfunded histories; it cannot claim accepted backing or broadcast.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import sys

import exit_wire
import output_producer
import output_verifier
import private_worker as boundary
import wallet_history
import wallet_profile as wallet

HERE = Path(__file__).absolute().parent
_spec = importlib.util.spec_from_file_location('_kpb_owner_restricted_intent', HERE.parent / 'private_batch/intent.py')
intent_codec = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = intent_codec
_spec.loader.exec_module(intent_codec)
MATRIX_SHA = 'b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11'
MAP_SHA = 'dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712'
need, read, write, parse, encoded = boundary.need, boundary.read, boundary.write, boundary.parse, boundary.encoded


class NamespaceOutputVerifier(output_verifier.OutputVerifier):
    """Public verification/private CV derivation inside the existing sandbox.

    Neither operation needs an Output proving key. Actual payment creation uses
    the separately selected NamespaceProver with its proving key instead.
    """
    def _call(self, operation, statement, private=None):
        need(operation in ('verify', 'derive-output'), 'owner-no-Output-proving-key-fallback')
        request = {'operation': operation, 'role': 'new-output',
            'profile': {'domain_hex32': self.profile.domain.hex(), 'profile_id_hex32': self.profile.profile_id.hex()},
            'statement_hex': statement.hex(), **(private or {})}
        if operation == 'verify':
            need(set(private or {}) == {'proof_hex128'}, 'owner-public-Output-verifier-only')
            request['parameters'] = {'manifest': str(self.manifest), 'manifest_sha256': self.manifest_sha256}
        else:
            need(set(private or {}) == {'note_hex168', 'blinding_hex32', 'cf_hash_hex32'},
                 'owner-private-CV-derivation-only')
        return parse(private_call([str(self.binary)], request))


def private_call(argv, value=None):
    result = subprocess.run(list(map(str, argv)), input=None if value is None else encoded(value),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'RAYON_NUM_THREADS': '2'})
    need(result.returncode == 0, 'owner-private-selected-tool-refused')
    return result.stdout


def normalize(inputs):
    """Run the pinned stock signature generator and normalizer in this sandbox."""
    write('/owner/SIGNATURE-INPUT.json', inputs)
    private_call(['/generator/private_authorization', '/owner/SIGNATURE-INPUT.json', '/owner/SIGNATURE.wtns'])
    artifacts = {name: read('/signature/' + name) for name in ('ordinary.r1cs', 'cpp0.r1cs', 'ordinary.sym')}
    request = {'mode': 'witness', 'ordinaryR1csHex': artifacts['ordinary.r1cs'].hex(),
        'cpp0R1csHex': artifacts['cpp0.r1cs'].hex(), 'symHex': artifacts['ordinary.sym'].hex(),
        'wtnsHex': read('/owner/SIGNATURE.wtns').hex(),
        'frozen': {'mappingSha256': MAP_SHA, 'normalizedMatrixSha256': MATRIX_SHA}}
    normalized = parse(private_call(['/runtime/node', '/src/harness/worker.mjs'], request))
    for name, pin in (('matrix', MATRIX_SHA), ('mapping', MAP_SHA)):
        need(normalized[name]['sha256'] == pin, 'owner-selected-signature-layout')
        raw = bytes.fromhex(normalized[name]['hex'])
        need(hashlib.sha256(raw).hexdigest() == pin, 'owner-signature-layout-bytes')
        write('/owner/SIGNATURE-' + name.upper() + '.json', raw)
    witness = bytes.fromhex(normalized['witness']['hex'])
    witness_sha = hashlib.sha256(witness).hexdigest()
    need(witness_sha == normalized['witness']['sha256'], 'owner-signature-witness-bytes')
    write('/owner/SIGNATURE-WITNESS.json', witness)
    return {'matrix': '/owner/SIGNATURE-MATRIX.json', 'matrix_sha256': MATRIX_SHA,
        'mapping_sha256': MAP_SHA, 'witness': '/owner/SIGNATURE-WITNESS.json', 'witness_sha256': witness_sha}


def own_initial_cv(receiver, prover, history):
    genesis = history['genesis']['outputs_hex520']
    owned = []
    for text in genesis:
        row = wallet_history.hx(text, 520)
        need(prover.verify(row), 'owner-real-initial-output-proof')
        try:
            receipt = receiver.open(row[96:360])
        except wallet.Invalid as error:
            if str(error) == 'crypto-unseal':
                continue
            raise
        need(receipt.index == 0 and receipt.value_sompi == 2_000_000_000
             and receipt.commitment() == row[:32], 'owner-exact20KAS-original-admission')
        # Every admission CV must equal this independently derived public
        # CV(20KAS,0). The existing Output relation proves each opening.
        derived = prover._call('derive-output', b'', {'note_hex168': receipt.note_bytes().hex(),
            'blinding_hex32': bytes(32).hex(), 'cf_hash_hex32': row[360:392].hex()})
        cv = bytes.fromhex(derived['statement_hex168'])[72:136]
        need(cv == row[32:96], 'owner-original-zero-blind-public-CV')
        owned.append(cv)
    need(len(owned) == 1, 'owner-exactly-one-original-admission')
    return owned[0]


def prepare_payment(receiver, prover, history, config):
    round_number, component = config['round'], config['owner_component']
    claim = wallet_history.select_for_round(history.recover(receiver), round_number, component)
    invoice = wallet.Invoice.parse(read('/invoice/INVOICE208.bin', private=True))
    need(invoice.domain == receiver.profile.domain and invoice.index == 2 * round_number - 1,
         'owner-authenticated-benchmark-recipient-invoice')
    payment = 500_000_000 if round_number == 1 else 200_000_000
    fee = config['approved_fee_sompi']
    need(type(fee) is int and 1 <= fee <= exit_wire.MAX, 'owner-exact-approved-integer-fee')
    change = claim.receipt.value_sompi - payment - fee
    need(exit_wire.NOTE_FLOOR <= change <= exit_wire.MAX, 'owner-value-conserving-change-range')
    created = [prover.create(receiver.crypto, invoice, payment),
               prover.create(receiver.crypto, receiver.invoice(2 * round_number), change)]
    # Incoming CVs are freshly rerandomized. No creator's old blinding is a
    # recovery prerequisite; value is bound to the CM-proved recovered note.
    blind = secrets.randbelow(output_producer.Q).to_bytes(32, 'little')
    derived = prover._call('derive-output', b'', {'note_hex168': claim.receipt.note_bytes().hex(),
        'blinding_hex32': blind.hex(), 'cf_hash_hex32': history.rows[claim.position][360:392].hex()})
    input_cv = bytes.fromhex(derived['statement_hex168'])[72:136]
    head = history.head
    nonce = secrets.token_bytes(32)
    raw_intent = intent_codec.RestrictedIntent(head.chain, head.pool, head.profile, head.domain, head.service,
        head.point, head.cm_root, head.nf_root, head.cm_count, head.nf_count, head.reserve,
        claim.nf, input_cv, fee, nonce, tuple(item.row for item in created)).encode()
    keys = receiver.keys(claim.receipt.index)
    signature = receiver.authority.sign(keys.signing_seed, raw_intent)
    need(receiver.authority.verify(raw_intent, signature), 'owner-actual-restricted-intent-signature')
    inputs = receiver.authority.signature_inputs(raw_intent, signature)
    normalized = normalize(inputs)
    record = {'schema': 'kpb-private-original-owner-record/v1', 'owner_component': component,
        'input': {'note_hex168': claim.receipt.note_bytes().hex(), 'nk_hex32': keys.nf_secret.hex(),
            'position': claim.position, 'path_hex32': [part.hex() for part in claim.path],
            'cv_hex64': input_cv.hex(), 'blind_hex32': blind.hex(), 'ak_hex64': keys.owner_key.hex(),
            'nf_hex32': claim.nf.hex()}, 'fee_sompi': fee, 'nonce_hex32': nonce.hex(),
        'outputs': [{'tuple_hex520': item.row.hex(), 'note_hex168': item.receipt.note_bytes().hex(),
                     'blind_hex32': item.blind.hex()} for item in created],
        'private_delta_hex32': ((int.from_bytes(blind, 'little')
            - sum(int.from_bytes(item.blind, 'little') for item in created)) % output_producer.Q).to_bytes(32, 'little').hex(),
        'intent_hex1460': raw_intent.hex(),
        'signature': {key: signature[key] for key in ('owner_key_hex64', 'R8', 'S')},
        'signature_inputs': inputs}
    write('/owner/OWNER-LOCAL-RECORD.json', record)
    # The prospective method is fixed before this operation. Truth stays in
    # this owner role; only a fresh salted commitment leaves it. No controller
    # reads/hashes the truth body or learns the creator correspondence.
    import privacy_owner
    privacy_owner.write_truth(config['privacy_binding'], component, round_number,
                              head.encode(), claim.nf, [item.row for item in created])
    request = {'schema': 'kpi-owner-local-aux-request/v1', 'owner_component': component,
        'context_hex': head.encode().hex(), 'owner_record_path': 'OWNER-LOCAL-RECORD.json',
        'signature_matrix_path': 'SIGNATURE-MATRIX.json', 'signature_witness_path': 'SIGNATURE-WITNESS.json',
        'expected_matrix_sha256': MATRIX_SHA, 'expected_mapping_sha256': MAP_SHA,
        'expected_witness_sha256': normalized['witness_sha256']}
    write('/owner/OWNER-AUX-REQUEST.json', request)
    private_call(['/runtime/owner-aux', '/owner/OWNER-AUX-REQUEST.json',
                  '/owner/OWNER-PRIVATE-INPUT.txt', '/owner/OWNER-AUX-PUBLIC.json'])
    auxiliary = parse(read('/owner/OWNER-AUX-PUBLIC.json'))
    need(auxiliary['schema'] == 'kpi-owner-local-aux-public-receipt/v1'
         and auxiliary['owner_component'] == component and auxiliary['ordered_private_values'] == 2_635_409
         and auxiliary['native_edges'] == 66 and auxiliary['signature_rows_checked'] is True
         and auxiliary['combined_dealer'] is False, 'owner-complete-actual-auxiliary')
    return {'actual_output_proofs': 2, 'actual_restricted_intent_signature': True,
            'actual_signature_normalization': True, 'owner_private_auxiliary_values': 2_635_409,
            'original_seed_recovered_input': True, 'input_kind_exported': False,
            'creator_output_correspondence_exported': False}


def prepare_exit(receiver, history, config, tail):
    claims = history.recover(receiver)
    available = [claim for claim in claims if not claim.spent]
    need(available, 'owner-no-unspent-exit-claim')
    claim = min(available, key=lambda item: item.position)
    fee = config['approved_fee_sompi']
    need(type(fee) is int and 1 <= fee <= exit_wire.MAX, 'owner-approved-exit-integer-fee')
    payout = claim.receipt.value_sompi - fee
    following = history.state.copy()
    witness = following.insert(claim.nf)
    raw_body = exit_wire.body(history.head, secrets.token_bytes(32), following.nf.root(),
        len(following.entries), history.reserve - claim.receipt.value_sompi, fee, payout,
        b'\0\0\x20' + receiver.keys(claim.receipt.index).invoice.native_pk + b'\xac', claim.nf, witness)
    projection = exit_wire.projection(raw_body, tail)
    approved = wallet.authorize_exit(receiver, claim, projection, history.head, tail, approved_fee_sompi=fee)
    normalized = normalize(receiver.authority.signature_inputs(approved.statement, approved.authorization))
    manifest = parse(read('/exit-parameters/MANIFEST.json', config['exit_manifest_sha256']))
    parameters = {'manifest': '/exit-parameters/MANIFEST.json', 'manifest_sha256': config['exit_manifest_sha256']}
    request = {**approved.private_request, 'signature': normalized, 'operation': 'prove',
        'parameters': {**parameters, 'pk': '/exit-parameters/parameters.pk', 'pk_sha256': manifest['pk_sha256']}}
    proof = parse(private_call(['/runtime/prover'], request))
    verified = parse(private_call(['/runtime/prover'], {'operation': 'verify', 'role': 'new-auth-exit',
        'profile': request['profile'], 'statement_hex': approved.statement.hex(),
        'proof_hex128': proof['proof_hex128'], 'parameters': parameters}))
    need(verified['accepted'] is True, 'owner-real-independent-Exit-proof')
    # Candidate release is a separate explicit action. Preparing a direct Exit
    # must not silently publish an owner-to-NF/payout correspondence.
    write('/owner/EXIT-CANDIDATE.json', {'schema': 'kpb-owner-prepared-independent-exit/v1',
        'scope': wallet_history.SCOPE, 'projection_hex': projection.hex(), 'proof_hex128': proof['proof_hex128'],
        'statement_hex152': approved.statement.hex(), 'native_or_chain_acceptance': False})
    return {'actual_AuthExit_proof': True, 'original_only_recovered_claim': True,
            'service_or_other_owner_dependency': False, 'candidate_exported': False}


def run(operation):
    marker = parse(read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                    'operation': operation, 'owner_slots': 1}, 'one-owner-lifecycle-namespace-marker')
    need(not Path('/home/luke/.codex').exists() and not Path('/home/luke/.ssh').exists()
         and not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists(), 'host-private-paths-absent')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'network-off-owner-lifecycle-namespace')
    config = parse(read('/CONFIG.json'))
    for member in config['source_members'] + config['runtime_members']:
        read(member['path'], member['sha256'])
    profile = wallet.Profile(bytes.fromhex(config['domain_hex32']), bytes.fromhex(config['profile_id_hex32']))
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['js_leaf_map_sha256'], '/runtime/js')
    crypto = wallet.Crypto('/runtime/crypto')
    with boundary.NamespaceAuthority('/runtime/node', modules) as authority:
        receiver = wallet.Receiver(boundary.load_backup('/original/BACKUP.json', profile), profile, crypto, authority)
        if operation == 'invoice':
            need(type(config['round']) is int and config['round'] in (1, 2), 'owner-benchmark-round')
            write('/owner/INVOICE208.bin', receiver.invoice(2 * config['round'] - 1).encode())
            result = {'authenticated_private_invoice_ready': True, 'invoice_exported_publicly': False}
        else:
            if operation == 'pay':
                prover = boundary.NamespaceProver(profile, '/runtime/prover', config['binary_sha256'],
                    '/parameters/MANIFEST.json', config['manifest_sha256'], '/parameters/parameters.pk', read_public=read)
            else:
                prover = NamespaceOutputVerifier(profile, '/runtime/prover', config['binary_sha256'],
                    '/parameters/MANIFEST.json', config['manifest_sha256'], read_public=read)
            value = parse(read('/history/PUBLIC-HISTORY.json', config['history_sha256']))
            identity = tuple(bytes.fromhex(config[name]) for name in
                             ('chain_hex32', 'pool_hex32', 'profile_id_hex32', 'domain_hex32', 'service_hex32'))
            tail = read('/policy/IMMUTABLE-TAIL.bin', config['tail_sha256'])
            initial_cv = own_initial_cv(receiver, prover, value)
            history = wallet_history.load_supplied(value, profile, identity, tail, prover.verify, initial_cv)
            if operation == 'pay':
                result = prepare_payment(receiver, prover, history, config)
            elif operation == 'exit':
                result = prepare_exit(receiver, history, config, tail)
            else:
                claims = history.recover(receiver)
                by_nf = {claim.nf: claim for claim in claims}
                for nf, script, payout, fee in history.exits:
                    if nf in by_nf:
                        claim = by_nf[nf]
                        need(script == b'\0\0\x20' + receiver.keys(claim.receipt.index).invoice.native_pk + b'\xac'
                             and payout + fee == claim.receipt.value_sompi, 'owner-original-historical-payout')
                need(history.reserve != 0 or all(claim.spent for claim in claims), 'owner-terminal-no-unspent-claim')
                result = {'original_only_scan_complete': True, 'private_claims_exported': False,
                          'terminal_reconciled': history.reserve == 0,
                          'history_sha256': config['history_sha256']}
    write('/out/PUBLIC.json', {'schema': 'kpb-original-lifecycle-operation/v1', 'operation': operation,
        'scope': wallet_history.SCOPE, 'private_original_or_witness_exported': False,
        'accepted_backing_or_native_settlement': False, **result}, 0o400)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('invoice', 'pay', 'scan', 'exit'))
    operation = parser.parse_args().operation
    try:
        run(operation)
    except BaseException as error:
        if Path('/out').is_dir() and not Path('/out/PUBLIC-FAILURE.json').exists():
            frame = error.__traceback__
            while frame and frame.tb_next:
                frame = frame.tb_next
            write('/out/PUBLIC-FAILURE.json', {'schema': 'kpb-owner-lifecycle-failure/v1',
                'category': type(error).__name__, 'source_site': None if frame is None else
                    {'file': Path(frame.tb_frame.f_code.co_filename).name, 'line': frame.tb_lineno}}, 0o400)
        raise


if __name__ == '__main__':
    main()

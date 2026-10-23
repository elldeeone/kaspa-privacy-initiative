#!/usr/bin/env python3
"""One-backup private full-claim cashout using own local authenticated prover.

No operator fixture/archive, hosted prover, setup, revealing fallback or RPC
broadcast is accepted here. Public replay completes before any backup read.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

import owner_selection as selection
from owner_rules import (GENESIS, Invalid, backup, canonical, digest, fresh_output,
                         hx, integer, need, outside_git, parse, write_private)
from owner_runtime import SealedExecutable
from private_action import material, payout_key, p2sh, snapshot_from_public
from receiver_tools import Crypto, recipient

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR_FIELDS = {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
    'founding_outpoint', 'birth_start_hash', 'initial_redeem_hex', 'vk_hex328',
    'immutable_policy_sha256', 'public_params_manifest_sha256'}
PUBLIC_PREPARED_FIELDS = {'schema', 'passed', 'status', 'transaction_id', 'quote_id',
    'descriptor_sha256', 'parameter_manifest_sha256', 'prover_elf_sha256', 'native_elf_sha256',
    'proof_sha256', 'authorization_sha256', 'fee_sompi', 'payout_sompi', 'reserve_after_sompi',
    'mining_mass', 'broadcast', 'automatic_revealing_fallback',
    'fresh_current_head_check_required_before_submission',
    'operator_fixture_or_expected_map_or_precomputed_exit_read',
    'independent_consensus_or_durable_availability_proved',
    'financial_privacy_or_complete_fee_target_qualified', 'output_dir'}
PUBLIC_RECOVERY_FIELDS = {'schema', 'passed', 'status', 'descriptor_sha256', 'output_dir',
                          'broadcast', 'automatic_revealing_fallback'}


def public_export(result):
    need(type(result) is dict, 'public-result-allowlist')
    allowed = PUBLIC_PREPARED_FIELDS if result.get('status') == 'PROVED_NATIVE_FULL_VALID_UNBROADCAST' else PUBLIC_RECOVERY_FIELDS
    need(set(result) == allowed
         and all(type(value) in (str, int, bool) for value in result.values()), 'public-result-allowlist')
    return result


def selected(preparing):
    names = ['CRYPTO_SHA256', 'NETWORK_REPLAY_SHA256', 'NETWORK_SOURCE_FREEZE_SHA256', 'PARAMETER_MANIFEST_SHA256',
             'DOMAIN_HEX32', 'VK_SHA256', 'COMPILED_BUILD_IDENTITY_SHA256']
    if preparing:
        names += ['NATIVE_SHA256', 'PROVER_SHA256']
    for name in names:
        value = getattr(selection, name)
        need(type(value) is str and len(hx(value, 32)) == 32, 'trusted-software-selection-required')


def public_identity(request):
    descriptor = parse(Path(request['descriptor_path']).read_bytes())
    need(type(descriptor) is dict and set(descriptor) == DESCRIPTOR_FIELDS, 'descriptor-fields')
    need(descriptor['schema'] == 'kpx3-private-network-descriptor/v1'
         and descriptor['network_id'] == 'testnet-10' and descriptor['genesis_hash_hex'] == GENESIS,
         'descriptor-network')
    need(digest(canonical(descriptor)) == request['expected_descriptor_sha256'], 'user-descriptor-pin')
    need(descriptor['domain_hex32'] == selection.DOMAIN_HEX32
         and digest(hx(descriptor['vk_hex328'], 328)) == selection.VK_SHA256
         and descriptor['public_params_manifest_sha256'] == selection.PARAMETER_MANIFEST_SHA256,
         'selected-descriptor-parameters')
    raw = Path(request['public_manifest_path']).read_bytes()
    manifest = parse(raw)
    need(raw == canonical(manifest) and digest(raw) == selection.PARAMETER_MANIFEST_SHA256,
         'selected-canonical-parameter-manifest')
    need(manifest['schema'] == 'kpx3-public-proving-parameters/v1'
         and manifest['network_id'] == 'testnet-10' and manifest['genesis_hash_hex'] == GENESIS
         and manifest['domain_hex32'] == descriptor['domain_hex32']
         and manifest['vk_hex328'] == descriptor['vk_hex328']
         and manifest['vk_sha256'] == selection.VK_SHA256
         and manifest['compiled_build_identity_sha256'] == selection.COMPILED_BUILD_IDENTITY_SHA256,
         'parameter-manifest-identity')
    return descriptor, manifest


def network_replay(descriptor, fetched, manifest, output):
    source_freeze = ROOT / 'research/next-session/private-service-loss/network/NETWORK-SOURCE-FREEZE-01.json'
    freeze_raw = source_freeze.read_bytes()
    need(digest(freeze_raw) == selection.NETWORK_SOURCE_FREEZE_SHA256, 'network-full-source-selection')
    freeze = parse(freeze_raw)
    need(freeze['schema'] == 'kpx3-private-network-source-freeze/v1', 'network-source-freeze-schema')
    for item in freeze['files'] + freeze['installed_public_software']:
        selected_path = Path(item['path'])
        if not selected_path.is_absolute():
            selected_path = ROOT / selected_path
        raw = selected_path.read_bytes()
        need(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'network-full-dependency-identity')
    path = ROOT / 'poc/private-network-recovery/network_replay.py'
    raw = path.read_bytes()
    need(digest(raw) == selection.NETWORK_REPLAY_SHA256, 'network-replay-source-identity')
    name = '_kpx3_owner_network_replay'
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        # Exact authenticated top-level bytes; its fixed imported modules and
        # base Python installation retain the documented immutable-install premise.
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        return module.replay(descriptor, fetched, manifest, output_directory=output)
    finally:
        sys.path.remove(str(path.parent))
        sys.modules.pop(name, None)


def native_call(executable, request, diagnostic=None):
    process = executable.run(input=json.dumps(request))
    if diagnostic is not None:
        # Only Auth/cipher/public updates enter this keyless helper. Preserve
        # failed native diagnostics privately; never write the private witness.
        write_private(diagnostic, {'public_native_request': request, 'returncode': process.returncode,
                                   'stdout': process.stdout, 'stderr': process.stderr})
    need(process.returncode == 0, 'public-native-helper-rejected')
    result = parse(process.stdout)
    need(type(result) is dict and result.get('schema') == 'kpx3-public-native-result/v1',
         'public-native-helper-response')
    return result


def check_body(response, descriptor, head, action, auth, proof, fee):
    """Independently check owner-visible effects, not just a helper verdict."""
    tx = response['transaction']
    need(tx['version'] == 1 and tx['payload'] == (auth + action.ciphertexts + action.public_witness).hex()
         and integer(tx['lockTime'], (1 << 64) - 1) == 0 and integer(tx['gas'], (1 << 64) - 1) == 0
         and hx(tx['subnetworkId'], 20) == bytes(20) and len(tx['inputs']) == 1, 'native-body-fields')
    need(tx['id'] == response['transaction_id'] and len(hx(tx['id'], 32)) == 32, 'native-body-id')
    entry = tx['inputs'][0]
    need(entry['previousOutpoint'] == head['outpoint']
         and integer(entry['sequence'], (1 << 64) - 1) == (1 << 64) - 1
         and entry['computeBudget'] == 1600, 'native-current-input')
    redeem = hx(head['current_redeem_hex'], 24417)
    frame = hx(entry['signatureScript'])
    need(frame == b'\x41' + bytes(65) + b'\x4c\x80' + proof
         + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem, 'native-private-proof-frame')
    need(integer(response['fee_sompi']) == fee, 'native-exact-fee')
    payout = action.claim.receipt.value_sompi - fee
    outputs = tx['outputs']
    need(len(outputs) == (2 if action.remaining else 1), 'native-output-count')
    need(integer(outputs[-1]['value']) == payout and outputs[-1]['scriptPublicKey'] == action.destination.hex()
         and outputs[-1].get('covenant') is None, 'native-owned-payout')
    if action.remaining:
        successor = redeem[:2] + action.after + redeem[114:]
        need(integer(outputs[0]['value']) == action.remaining
             and outputs[0]['scriptPublicKey'] == p2sh(successor) and outputs[0].get('covenant') is None
             and response['successor_state_hex112'] == action.after.hex(), 'native-immutable-successor')
    else:
        need(response['successor_state_hex112'] is None, 'native-terminal-no-successor')
    contexts = response['supplied_context']
    current = head['current_utxo']
    need(len(contexts) == 1 and integer(contexts[0]['amount_sompi']) == integer(current['amount_sompi'])
         and contexts[0]['script_public_key'] == current['script_public_key']
         and integer(contexts[0]['block_daa_score'], (1 << 64) - 1)
             == integer(current['block_daa_score'], (1 << 64) - 1)
         and contexts[0]['is_coinbase'] is False and contexts[0]['covenant_id'] is None,
         'native-exact-supplied-context')


def ready(process):
    line = process.stdout.readline()
    need(bool(line), 'local-prover-no-parameters-ready')
    response = parse(line)
    need(type(response) is dict and set(response) == {'event', 'parameter_manifest_sha256',
         'domain_hex32', 'vk_sha256', 'compiled_build_identity_sha256'}
         and response['event'] == 'parameters-ready', 'local-prover-ready-schema')
    expected = {'parameter_manifest_sha256': selection.PARAMETER_MANIFEST_SHA256,
                'domain_hex32': selection.DOMAIN_HEX32, 'vk_sha256': selection.VK_SHA256,
                'compiled_build_identity_sha256': selection.COMPILED_BUILD_IDENTITY_SHA256}
    need(all(response[key] == value for key, value in expected.items()), 'local-prover-ready-identity')


def recognition_summary(recovered, reserve):
    need(recovered.all_owned_unspent_sompi <= reserve, 'recognized-principal-exceeds-reserve')
    return {'recognized_valid_receipts_only': True, 'recognized_receipts': len(recovered.owned),
            'recognized_spent_receipts': sum(claim.spent for claim in recovered.owned),
            'recognized_owned_unspent_sompi': recovered.all_owned_unspent_sompi,
            'recognized_duplicate_claims': sum(claim.duplicate_invoice for claim in recovered.owned),
            'recognized_contaminated_claims': sum(claim.privacy_contaminated for claim in recovered.owned),
            'no_recognized_receipt_proves_absence_of_all_owned_liabilities': False,
            'correctly_encoded_encrypted_delivery_assumption': True}


def private_input_metadata(request, manifest):
    """Never open backup/PK bytes here or mistake a backup for public input."""
    pk_path = outside_git(request['public_pk_path'])
    backup_path = outside_git(request['backup_path'])
    pk_info, backup_info = pk_path.stat(), backup_path.stat()
    need(stat.S_ISREG(pk_info.st_mode) and pk_info.st_size == integer(manifest['pk_bytes'], (1 << 64) - 1)
         and not os.access(pk_path, os.W_OK), 'read-only-selected-public-cache-metadata')
    need(stat.S_ISREG(backup_info.st_mode) and stat.S_IMODE(backup_info.st_mode) == 0o600
         and (pk_info.st_dev, pk_info.st_ino) != (backup_info.st_dev, backup_info.st_ino),
         'separate-own-backup-and-public-cache')


def owned_native_payouts(seed, descriptor, recovered, crypto, public):
    """Rebuild default payout authority from historical own receipts.

    PRIVATE_EXIT does not publish an input CM/position. Ownership is determined
    by the recoverable destination key, not old REVEAL opening matching. The
    association and scalar never enter a public result or a persisted witness.
    """
    scripts = set()
    for claim in recovered.owned:  # Include receipts whose original NF is spent.
        secret, public_key, _ = payout_key(seed, descriptor, claim, crypto)
        del secret
        scripts.add((b'\0\0\x20' + public_key + b'\xac').hex())
    historical, current, count, seen = 0, 0, 0, set()
    for payout in public['payouts']:
        if payout['script_public_key'] not in scripts:
            continue
        outpoint = payout['outpoint']
        key = (outpoint['transactionId'], outpoint['index'])
        need(key not in seen, 'duplicate-owned-native-payout')
        seen.add(key)
        amount = integer(payout['amount_sompi'])
        need(amount >= 10_000_000 and payout['queried'] is True, 'owned-payout-current-query-required')
        historical += amount
        entry = payout['current_utxo']
        if entry is not None:
            need(entry['outpoint'] == outpoint and integer(entry['amount_sompi']) == amount
                 and entry['script_public_key'] == payout['script_public_key']
                 and entry['is_coinbase'] is False and entry['covenant_id'] is None,
                 'owned-native-payout-current-context')
            current += amount
            count += 1
    return {'historical_owned_default_private_payouts_sompi': historical,
            'current_owned_default_private_payouts_sompi': current,
            'current_owned_default_private_payout_utxos': count,
            'arbitrary_external_destination_keys_recovered': False}


def prove_and_build(request, descriptor, public, manifest, output, crypto, native, prover):
    read_fd, write_fd = os.pipe()
    process = None
    try:
        proof_output = output / 'proof'
        process = prover.popen(['prove', request['public_pk_path'], str(read_fd), str(proof_output)],
                               extra_fds=(read_fd,))
        os.close(read_fd)
        read_fd = None
        ready(process)  # Actual complete PK/VK authentication precedes backup bytes.
        seed = backup(request['backup_path'], descriptor)
        snapshot, expected = snapshot_from_public(descriptor, public)
        receiver = recipient().Receiver(seed, hx(descriptor['domain_hex32'], 32), crypto)
        recovered = recipient().recover(receiver, expected, snapshot)
        summary = recognition_summary(recovered, integer(public['head']['reserve_sompi']))
        summary.update(owned_native_payouts(seed, descriptor, recovered, crypto, public))
        claims = sorted((claim for claim in recovered.owned if claim.owner_action_available),
                        key=lambda claim: claim.position)
        need(bool(claims), 'recognized-unspent-claim-required')
        claim = claims[0]
        payout_secret, payout_public, _ = payout_key(seed, descriptor, claim, crypto)
        del payout_secret
        action = material(descriptor, public['head'], receiver, claim, snapshot, expected,
                          b'\0\0\x20' + payout_public + b'\xac')
        rate = integer(request['fee_rate_sompi_per_mass'], (1 << 64) - 1)
        need(rate > 0, 'positive-fee-rate')
        fee, attempts = 1, []
        while True:
            auth, witness, public_request = action.build(fee)
            quote = native_call(native, dict(public_request, mode='quote', fee_rate_sompi_per_mass=str(rate)),
                                output / f'native-quote-{len(attempts):04d}.json')
            need(quote['verified'] is False and quote['public_checks_reached_G16'] is True,
                 'native-quote-g16-seam')
            check_body(quote, descriptor, public['head'], action, auth, bytes(128), fee)
            mass = integer(quote['mining_mass'], (1 << 64) - 1)
            need(mass > 0 and integer(quote['required_fee_sompi']) == rate * mass,
                 'native-quote-fee-mass')
            required = rate * mass
            attempts.append({'fee_sompi': fee, 'required_fee_sompi': required, 'mining_mass': mass})
            if fee >= required:
                break
            fee = required  # Strictly increasing, bounded by claim/payout ranges.
        quote_id = quote['quote_id']
        hx(quote_id, 32)
        encoded = canonical(witness) + b'\n'
        view = memoryview(encoded)
        while view:
            written = os.write(write_fd, view)
            need(written > 0, 'local-private-witness-pipe')
            view = view[written:]
        os.close(write_fd)
        write_fd = None
        process.communicate()
        need(process.returncode == 0, 'own-local-prover-rejected')
        proof = (proof_output / 'proof128.bin').read_bytes()
        need(len(proof) == 128 and proof != bytes(128)
             and (proof_output / 'authorization528.bin').read_bytes() == auth
             and (proof_output / 'verification-key.bin').read_bytes() == hx(descriptor['vk_hex328'], 328),
             'local-proof-auth-vk-output')
        verified = native_call(native, dict(public_request, mode='verify', proof_hex128=proof.hex(),
                                             fee_rate_sompi_per_mass=str(rate), expected_quote_id=quote_id),
                               output / 'native-verify.json')
        check_body(verified, descriptor, public['head'], action, auth, proof, fee)
        normalized = parse(canonical(verified['transaction']))
        frame = bytearray(hx(normalized['inputs'][0]['signatureScript']))
        frame[68:196] = bytes(128)
        normalized['inputs'][0]['signatureScript'] = frame.hex()
        need(canonical(normalized) == canonical(quote['transaction'])
             and canonical(verified['supplied_context']) == canonical(quote['supplied_context'])
             and verified['quote_id'] == quote_id and verified['verified'] is True
             and verified['native_validation']['Full']['accepted'] is True
             and integer(verified['native_validation']['Full']['fee_sompi']) == fee
             and verified['native_validation']['all_input_engines_accepted'] is True,
             'genuine-proof-full-quote-identity')
        for key, filename in [('transaction', 'transaction.json'), ('supplied_context', 'supplied-context.json'),
                              ('native_validation', 'native-validation.json'), ('metrics', 'metrics.json')]:
            write_private(output / filename, verified[key])
        write_private(output / 'quote.json', {'fee_rate_sompi_per_mass': rate, 'attempts': attempts,
                                            'quote_id': quote_id})
        write_private(output / 'OWNER-RECOVERY.json', summary)  # Never hash/export this private report.
        result = {'schema': 'kpx3-private-owner-result/v1', 'passed': True,
                  'status': 'PROVED_NATIVE_FULL_VALID_UNBROADCAST',
                  'transaction_id': verified['transaction_id'], 'quote_id': quote_id,
                  'descriptor_sha256': digest(canonical(descriptor)),
                  'parameter_manifest_sha256': selection.PARAMETER_MANIFEST_SHA256,
                  'prover_elf_sha256': prover.sha256, 'native_elf_sha256': native.sha256,
                  'proof_sha256': digest(proof), 'authorization_sha256': digest(auth),
                  'fee_sompi': fee, 'payout_sompi': claim.receipt.value_sompi - fee,
                  'reserve_after_sompi': action.remaining, 'mining_mass': mass,
                  'broadcast': False, 'automatic_revealing_fallback': False,
                  'fresh_current_head_check_required_before_submission': True,
                  'operator_fixture_or_expected_map_or_precomputed_exit_read': False,
                  'independent_consensus_or_durable_availability_proved': False,
                  'financial_privacy_or_complete_fee_target_qualified': False,
                  'output_dir': str(output)}
        result = public_export(result)
        write_private(output / 'RESULTS.json', result)
        return result
    finally:
        for descriptor_fd in (read_fd, write_fd):
            if descriptor_fd is not None:
                os.close(descriptor_fd)
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate()


def execute(request):
    common = {'schema', 'op', 'backup_path', 'descriptor_path', 'expected_descriptor_sha256',
              'public_manifest_path', 'fetch_path', 'crypto_path', 'output_dir'}
    preparing = type(request) is dict and request.get('op') == 'prepare-private-exit'
    extra = {'public_pk_path', 'local_prover_path', 'native_helper_path', 'fee_rate_sompi_per_mass'}
    need(type(request) is dict and request.get('schema') == 'kpx3-private-owner-request/v1'
         and request.get('op') in ('recover', 'prepare-private-exit')
         and set(request) == common | (extra if preparing else set()), 'private-owner-request-fields')
    selected(preparing)
    recipient()  # Authenticate unchanged receive/tree source before backup access.
    descriptor, manifest = public_identity(request)
    output = fresh_output(request['output_dir'])
    output.mkdir(mode=0o700)
    with ExitStack() as stack:
        crypto_elf = stack.enter_context(SealedExecutable(request['crypto_path'], selection.CRYPTO_SHA256))
        native = stack.enter_context(SealedExecutable(request['native_helper_path'], selection.NATIVE_SHA256)) if preparing else None
        prover = stack.enter_context(SealedExecutable(request['local_prover_path'], selection.PROVER_SHA256)) if preparing else None
        fetched = parse(Path(request['fetch_path']).read_bytes())
        public = network_replay(descriptor, fetched, manifest, output / 'public-replay')
        snapshot, expected = snapshot_from_public(descriptor, public)  # Incompleteness before seed.
        crypto = Crypto(crypto_elf)
        if preparing:
            need(integer(public['head']['reserve_sompi']) > 0, 'terminal-pool-has-no-private-exit')
            private_input_metadata(request, manifest)
            return prove_and_build(request, descriptor, public, manifest, output, crypto, native, prover)
        seed = backup(request['backup_path'], descriptor)
        receiver = recipient().Receiver(seed, hx(descriptor['domain_hex32'], 32), crypto)
        recovered = recipient().recover(receiver, expected, snapshot)
        summary = recognition_summary(recovered, integer(public['head']['reserve_sompi']))
        summary.update(owned_native_payouts(seed, descriptor, recovered, crypto, public))
        write_private(output / 'OWNER-RECOVERY.json', summary)
        result = {'schema': 'kpx3-private-owner-result/v1', 'passed': True, 'status': 'RECOVERY_REPORT_PRIVATE',
                  'descriptor_sha256': digest(canonical(descriptor)), 'output_dir': str(output),
                  'broadcast': False, 'automatic_revealing_fallback': False}
        result = public_export(result)
        write_private(output / 'RESULTS.json', result)
        return result


if __name__ == '__main__':
    try:
        response = execute(parse(sys.stdin.read()))
    except Invalid as error:
        print(json.dumps({'passed': False, 'error': str(error)}))
        raise SystemExit(1)
    except Exception:
        print(json.dumps({'passed': False, 'error': 'private-owner-client-failed'}))
        raise SystemExit(1)
    print(json.dumps(response, sort_keys=True, separators=(',', ':')))

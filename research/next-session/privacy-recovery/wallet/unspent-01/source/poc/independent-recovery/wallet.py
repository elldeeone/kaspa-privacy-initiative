#!/usr/bin/env python3
"""One-backup KPX2 recovery and explicitly consented native reveal preparation.

No network, prover, proving key, full controller profile or broadcast interface.
Public acceptance retains the fetcher's selected-validating-node assumption.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
V2_SOURCE_SHA256 = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CRYPTO_SHA256 = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
DEFAULT_CRYPTO = ROOT.parent / 'recipient-target/debug/kpi-future-recipient-crypto'
# Selected only after the separately reviewed generic helper's immutable build.
# Unselected builds cannot accept a caller's own expected executable digest.
NATIVE_HELPER_SHA256 = 'a4c5da2c94691ba39ca9f5be1279b3243a0328481f9ba795e812483c770e1186'
DISCLOSURE_CONSENT = 'I_ACCEPT_PUBLIC_NOTE_VALUE_COMMITMENT_NULLIFIER_KEY_AND_PAYOUT_KEY_DISCLOSURE'
MAX_SOMPI = 2_870_000_000_000_000_000


class Invalid(ValueError):
    """Stable secret-free rejection category."""


def require(condition, category):
    if not condition:
        raise Invalid(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-json-field')
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=json_object)


def exact(raw, size=None):
    require(type(raw) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', raw) is not None,
            'canonical-hex')
    value = bytes.fromhex(raw)
    require(size is None or len(value) == size, 'hex-width')
    return value


def amount(value):
    require(type(value) is int or type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value),
            'integer-sompi')
    value = int(value)
    require(0 <= value <= MAX_SOMPI, 'sompi-range')
    return value


def no_symlinks(path):
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'symlink-path')


def outside_git(path):
    path = path.absolute()
    no_symlinks(path)
    # Check links before normalization; resolving first could hide a traversed
    # symlink. Git must probe a directory, never an existing backup file.
    path = Path(os.path.normpath(path))
    probe = path
    while not probe.exists():
        probe = probe.parent
    if not probe.is_dir():
        probe = probe.parent
    result = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(probe),
                             'rev-parse', '--show-toplevel'], capture_output=True)
    require(result.returncode != 0 and ROOT != path and ROOT not in path.parents,
            'private-material-inside-git')


def load_backup(path, descriptor):
    path = Path(path).absolute()
    outside_git(path)
    require(path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o600,
            'backup-permissions')
    backup = parse_json(path.read_bytes())
    require(type(backup) is dict and set(backup) == {'schema', 'network_id',
            'genesis_hash_hex', 'domain_hex32', 'seed_hex32'}, 'seed-only-backup-fields')
    require(backup['schema'] == 'kpx2-tn10-seed-backup/v1', 'backup-version')
    for name in ('network_id', 'genesis_hash_hex', 'domain_hex32'):
        require(backup[name] == descriptor[name], 'backup-descriptor-identity')
    return exact(backup['seed_hex32'], 32)


def recipient_module():
    source = ROOT / 'poc/future-recipient/v2/recipient.py'
    require(digest(source.read_bytes()) == V2_SOURCE_SHA256, 'recipient-software-identity')
    name = '_kpx2_independent_wallet_recipient'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def runtime_crypto(path):
    path = Path(path).absolute()
    no_symlinks(path)
    require(path.is_file() and os.access(path, os.X_OK), 'crypto-executable')
    require(digest(path.read_bytes()) == CRYPTO_SHA256, 'crypto-software-identity')
    return recipient_module().Crypto(path)


def descriptor_identity(descriptor):
    require(type(descriptor) is dict and set(descriptor) == {'schema', 'network_id',
        'genesis_hash_hex', 'domain_hex32', 'founding_outpoint', 'birth_start_hash',
        'initial_redeem_hex', 'immutable_policy_sha256', 'vk_hex328'}, 'descriptor-fields')
    require(descriptor['schema'] == 'kpx2-recovery-descriptor/v1'
            and descriptor['network_id'] == 'testnet-10'
            and descriptor['genesis_hash_hex'] == GENESIS, 'descriptor-network')
    exact(descriptor['domain_hex32'], 32)
    exact(descriptor['birth_start_hash'], 32)
    exact(descriptor['vk_hex328'], 328)
    exact(descriptor['immutable_policy_sha256'], 32)
    initial = exact(descriptor['initial_redeem_hex'])
    require(114 < len(initial) <= 65_535 and initial[:10] == b'\x4c\x70KPX2ST01'
            and initial[10:42].hex() == descriptor['domain_hex32'], 'initial-policy-state')
    require(digest(initial[114:]) == descriptor['immutable_policy_sha256'],
            'initial-policy-hash')
    point = descriptor['founding_outpoint']
    require(type(point) is dict and set(point) == {'transactionId', 'index'}
            and type(point['index']) is int and point['index'] == 0, 'founding-outpoint')
    exact(point['transactionId'], 32)
    return digest(canonical(descriptor))


def snapshot_from_replay(descriptor, public):
    v2 = recipient_module()
    identity = descriptor_identity(descriptor)
    require(public['schema'] == 'kpx2-independent-replay/v1'
            and public['descriptor_sha256'] == identity, 'replay-descriptor-identity')
    for name in ('network_id', 'genesis_hash_hex', 'domain_hex32'):
        require(public[name] == descriptor[name], 'replay-network-domain')
    require(public['completeness']['complete'] is True, 'incomplete-public-history')
    deliveries = []
    for row in public['deliveries']:
        require(set(row) == {'position', 'cm', 'ciphertext'}
                and type(row['position']) is int, 'delivery-fields')
        deliveries.append(v2.Delivery(row['position'], exact(row['cm'], 32),
                                      exact(row['ciphertext'], 264)))
    nullifiers = []
    for row in public['nullifiers']:
        require(set(row) == {'value', 'next_value', 'next_index'}
                and type(row['next_index']) is int, 'nullifier-fields')
        nullifiers.append(v2.NFEntry(exact(row['value'], 32), exact(row['next_value'], 32),
                                     row['next_index']))
    snapshot = v2.Snapshot(deliveries, nullifiers)
    domain = exact(descriptor['domain_hex32'], 32)
    expected = snapshot.pin(domain)
    cm, nf = snapshot.verify(expected)
    state = b'KPX2ST01' + domain + cm.root + v2.u32(len(deliveries)) + nf.root + v2.u32(len(nullifiers))
    head = public['head']
    require(exact(head['state_hex112'], 112) == state, 'replayed-current-state')
    reserve = amount(head['reserve_sompi'])
    if reserve:
        require(reserve >= 60_000_000, 'current-reserve-floor')
        require(public['completeness']['terminal'] is False, 'nonterminal-head-label')
        redeem = exact(head['current_redeem_hex'])
        initial = exact(descriptor['initial_redeem_hex'])
        require(redeem[:2] == b'\x4c\x70' and redeem[2:114] == state
                and redeem[114:] == initial[114:], 'current-immutable-policy')
        entry = head['current_utxo']
        require(type(entry) is dict and entry['outpoint'] == head['outpoint']
                and amount(entry['amount_sompi']) == reserve
                and entry['script_public_key'] == p2sh(redeem)
                and entry['is_coinbase'] is False and entry['covenant_id'] is None,
                'current-reserve-utxo')
    else:
        require(public['completeness']['terminal'] is True and head['outpoint'] is None
                and head['current_redeem_hex'] is None and head['current_utxo'] is None,
                'terminal-state-incomplete')
    return snapshot, expected


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def recognize(descriptor, public, seed, crypto):
    v2 = recipient_module()
    snapshot, expected = snapshot_from_replay(descriptor, public)
    receiver = v2.Receiver(seed, exact(descriptor['domain_hex32'], 32), crypto)
    recovered = v2.recover(receiver, expected, snapshot)
    reserve = amount(public['head']['reserve_sompi'])
    require(recovered.all_owned_unspent_sompi <= reserve, 'recognized-principal-exceeds-reserve')
    owned = {(claim.position, claim.receipt.commitment().hex()): claim for claim in recovered.owned}
    paid, current_paid, current_count = 0, 0, 0
    matched_payouts = set()
    for payout in public['payouts']:
        key = (payout['position'], payout['cm'])
        claim = owned.get(key)
        if claim is None:
            continue
        require(key not in matched_payouts, 'duplicate-owned-payout')
        matched_payouts.add(key)
        require(claim.spent and claim.receipt.note_bytes().hex() == payout['note_hex168'],
                'owned-payout-opening')
        value = amount(payout['amount_sompi'])
        require(10_000_000 <= value < claim.receipt.value_sompi
                and payout['script_public_key'] == (b'\0\0\x20' + claim.receipt.native_pk + b'\xac').hex(),
                'owned-payout-value-key')
        require(payout['queried'] is True, 'owned-payout-current-query-missing')
        paid += value
        current = payout['current_utxo']
        if current is not None:
            require(current['outpoint'] == payout['outpoint']
                    and amount(current['amount_sompi']) == value
                    and current['script_public_key'] == payout['script_public_key']
                    and current['is_coinbase'] is False and current['covenant_id'] is None,
                    'owned-payout-current-utxo')
            current_paid += value
            current_count += 1
    witnesses = 0
    for claim in recovered.owned:
        if claim.owner_action_available:
            v2.exit_witness(receiver, claim, expected, snapshot)
            witnesses += 1
    summary = {'schema': 'kpx2-independent-wallet-recovery/v1', 'passed': True,
        'descriptor_sha256': digest(canonical(descriptor)), 'domain_hex32': descriptor['domain_hex32'],
        'recognized_valid_receipts_only': True,
        'recognized_receipts': len(recovered.owned),
        'recognized_spent_receipts': sum(claim.spent for claim in recovered.owned),
        'recognized_owned_unspent_sompi': recovered.all_owned_unspent_sompi,
        'recognized_normal_credit_sompi': recovered.normal_credit_sompi,
        'recognized_duplicate_invoice_claims': sum(claim.duplicate_invoice for claim in recovered.owned),
        'recognized_privacy_contaminated_claims': sum(claim.privacy_contaminated for claim in recovered.owned),
        'current_witnesses_constructible': witnesses, 'historical_owned_payouts_sompi': paid,
        'current_owned_pool_payouts_sompi': current_paid,
        'current_owned_pool_payout_utxos': current_count,
        'validated_terminal_pool': reserve == 0,
        'no_recognized_receipt_proves_absence_of_all_owned_claims': False,
        'delivery_validity_assumption': 'Correctly encrypted and descriptor/CM-valid receipts are recognizable; foreign and maliciously undeliverable ciphertexts are indistinguishable.',
        'acceptance_trust': public['completeness'].get('acceptance_trust'),
        'as_of_frontier': public['completeness'].get('frontier'),
        'view_is_atomic': False,
        'local_native_validation': public.get('local_native_validation', False),
        'groth16_and_signatures': public.get('groth16_and_signatures', 'NOT_LOCALLY_REVALIDATED'),
        'user_authenticated_descriptor_required': True,
        'independent_consensus_verified': False,
        'orphan_disclosure_history_recovered': False,
        'invoice_issuance_state_recovered': False,
        'operator_snapshot_or_expected_payment_map_used': False,
        'payer_other_recipient_prover_or_pk_read': False,
        'revealing_fallback_automatically_selected': False}
    return summary, receiver, recovered, expected, snapshot


def reveal_payload(receiver, claim, expected, snapshot, fee):
    v2 = recipient_module()
    fee = amount(fee)
    require(fee > 0 and claim.receipt.value_sompi >= fee + 10_000_000, 'reveal-fee-payout')
    witness = v2.exit_witness(receiver, claim, expected, snapshot)
    note = claim.receipt
    predecessor = witness['predecessor']
    raw = (b'KPX2RV01\x01' + note.owner + note.incoming + v2.u64(note.value_sompi)
        + note.rho + receiver.keys(note.index).nf_secret + note.native_pk
        + v2.u32(claim.position) + note.key_commitment + note.commitment()
        + b''.join(exact(item, 32) for item in witness['cm_path'])
        + v2.u32(witness['predecessor_index']) + exact(predecessor['value'], 32)
        + exact(predecessor['next_value'], 32) + v2.u32(predecessor['next_index'])
        + b''.join(exact(item, 32) for item in witness['predecessor_path'])
        + b''.join(exact(item, 32) for item in witness['append_path_after_predecessor_update'])
        + exact(witness['nf'], 32) + exact(witness['intermediate_nf_root'], 32)
        + exact(witness['successor_nf_root'], 32) + v2.u64(fee)
        + v2.u64(note.value_sompi - fee))
    require(len(raw) == 2029, 'reveal-payload-width')
    return raw


def selected_native_helper(path):
    require(NATIVE_HELPER_SHA256 is not None, 'native-helper-not-selected')
    path = Path(path).absolute()
    no_symlinks(path)
    require(path.is_file() and os.access(path, os.X_OK)
            and digest(path.read_bytes()) == NATIVE_HELPER_SHA256, 'native-helper-software-identity')
    return path


def native_call(helper, request):
    result = subprocess.run([str(helper)], input=json.dumps(request), text=True,
                            capture_output=True)
    require(result.returncode == 0, 'native-helper-rejected')
    try:
        response = parse_json(result.stdout)
    except (ValueError, TypeError):
        raise Invalid('native-helper-response') from None
    require(type(response) is dict and 'error' not in response, 'native-helper-response')
    return response


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        file.flush()
        os.fsync(file.fileno())


def validate_signed(response, public, claim, payload, fee, quoted_id):
    """Recheck owner-visible public effects independently of helper diagnostics."""
    require(response['transaction_id'] == quoted_id and response['sighash_type'] == 1
            and amount(response['fee_sompi']) == fee, 'signed-quote-identity')
    tx = response['transaction']
    require(tx['version'] == 1 and tx['id'] == quoted_id and tx['payload'] == payload.hex()
            and amount(tx['lockTime']) == 0 and amount(tx['gas']) == 0
            and exact(tx['subnetworkId'], 20) == bytes(20)
            and len(tx['inputs']) == 1, 'signed-transaction-fields')
    inp = tx['inputs'][0]
    require(inp['previousOutpoint'] == public['head']['outpoint']
            and type(inp['sequence']) in (str, int) and type(inp['sequence']) is not bool
            and int(inp['sequence']) == (1 << 64) - 1
            and inp['computeBudget'] == 200, 'signed-current-input')
    redeem = exact(public['head']['current_redeem_hex'])
    witness = exact(inp['signatureScript'])
    require(len(witness) == 199 + len(redeem) and witness[0] == 65
            and witness[1:65] != bytes(64) and witness[65] == 1
            and witness[66:68] == b'\x4c\x80' and witness[68:196] == bytes(128)
            and witness[196] == 0x4d
            and int.from_bytes(witness[197:199], 'little') == len(redeem)
            and witness[199:] == redeem, 'signed-all-witness-frame')
    remainder = amount(public['head']['reserve_sompi']) - claim.receipt.value_sompi
    require(remainder >= 0 and len(tx['outputs']) == (2 if remainder else 1),
            'signed-reserve-output-count')
    payout = claim.receipt.value_sompi - fee
    payout_output = tx['outputs'][-1]
    require(amount(payout_output['value']) == payout
            and payout_output['scriptPublicKey'] == (b'\0\0\x20' + claim.receipt.native_pk + b'\xac').hex()
            and payout_output.get('covenant') is None, 'signed-owned-payout')
    state = bytearray(exact(public['head']['state_hex112'], 112))
    state[76:108] = payload[1981:2013]
    state[108:112] = (int.from_bytes(state[108:112], 'little') + 1).to_bytes(4, 'little')
    if remainder:
        require(amount(tx['outputs'][0]['value']) == remainder
                and tx['outputs'][0]['scriptPublicKey'] == p2sh(redeem[:2] + state + redeem[114:])
                and tx['outputs'][0].get('covenant') is None
                and response['successor_state_hex112'] == bytes(state).hex(),
                'signed-immutable-successor')
    else:
        require(response['successor_state_hex112'] is None, 'signed-terminal-successor')
    context = response['supplied_context']
    entry = public['head']['current_utxo']
    require(len(context) == 1 and amount(context[0]['amount_sompi']) == amount(entry['amount_sompi'])
            and context[0]['script_public_key'] == entry['script_public_key']
            and context[0]['is_coinbase'] is False
            and int(context[0]['block_daa_score']) == int(entry['block_daa_score']),
            'signed-current-context')
    validation = response['native_validation']
    require(validation['Full']['accepted'] is True
            and amount(validation['Full']['fee_sompi']) == fee
            and validation['all_input_engines_accepted'] is True, 'native-full-validation')


def prepare_reveal(request, descriptor, public, receiver, recovered, expected, snapshot):
    # Consent precedes any payload materialization or native helper invocation.
    require(request.get('disclosure_consent') == DISCLOSURE_CONSENT, 'explicit-reveal-consent-required')
    require(amount(public['head']['reserve_sompi']) > 0, 'terminal-pool-has-no-exit')
    position = request['position']
    require(type(position) is int and 0 <= position < 65_535, 'claim-position')
    claims = [claim for claim in recovered.owned if claim.position == position]
    require(len(claims) == 1 and claims[0].owner_action_available, 'recognized-unspent-claim-required')
    claim = claims[0]
    helper = selected_native_helper(request['native_helper_path'])
    rate = amount(request['fee_rate_sompi_per_mass'])
    require(rate > 0, 'positive-fee-rate')
    output = Path(request['output_dir']).absolute()
    outside_git(output)
    require(not output.exists() and output.parent.is_dir(), 'fresh-private-output-directory')
    head = public['head']
    base = {'domain_hex32': descriptor['domain_hex32'],
        'current_redeem_hex': head['current_redeem_hex'],
        'immutable_tail_sha256': descriptor['immutable_policy_sha256'],
        'current_script_public_key_hex': head['current_utxo']['script_public_key'],
        'previous_outpoint': head['outpoint'], 'reserve_sompi': str(amount(head['reserve_sompi'])),
        'block_daa_score': str(int(head['current_utxo']['block_daa_score']))}
    fee, attempts = 1, []
    for _ in range(256):
        payload = reveal_payload(receiver, claim, expected, snapshot, fee)
        quote = native_call(helper, dict(base, mode='quote', payload_hex2029=payload.hex()))
        require(quote['public_checks_reached_owner_signature'] is True
                and amount(quote['fee_sompi']) == fee, 'native-public-quote-validation')
        mass = amount(quote['mining_mass'])
        require(mass > 0, 'positive-native-mass')
        required = rate * mass
        attempts.append({'fee_sompi': fee, 'required_fee_sompi': required, 'mining_mass': mass})
        if fee >= required:
            break
        fee = required
    else:
        raise Invalid('native-fee-quote-incomplete')
    quoted_id = quote['transaction_id']
    exact(quoted_id, 32)
    signed = native_call(helper, dict(base, mode='sign', payload_hex2029=payload.hex(),
        native_secret_hex32=receiver.keys(claim.receipt.index).native_secret.hex(),
        expected_unsigned_txid_raw_hex=quoted_id, consent=DISCLOSURE_CONSENT))
    validate_signed(signed, public, claim, payload, fee, quoted_id)
    output.mkdir(mode=0o700)
    require(stat.S_IMODE(output.stat().st_mode) == 0o700, 'private-output-permissions')
    for key, filename in (('transaction', 'transaction.json'), ('supplied_context', 'supplied-context.json'),
                          ('native_validation', 'native-validation.json'), ('metrics', 'metrics.json')):
        write_private(output / filename, signed[key])
    write_private(output / 'quote.json', {'fee_rate_sompi_per_mass': rate, 'attempts': attempts,
                                        'quoted_transaction_id': quoted_id})
    result = {'schema': 'kpx2-independent-consented-reveal/v1', 'passed': True,
        'status': 'SIGNED_NATIVE_FULL_VALID_UNBROADCAST',
        'transaction_id': quoted_id, 'descriptor_sha256': digest(canonical(descriptor)),
        'fee_sompi': fee, 'payout_sompi': claim.receipt.value_sompi - fee,
        'native_helper_sha256': NATIVE_HELPER_SHA256, 'sighash_type': 1,
        'explicit_public_disclosure_consent': True, 'broadcast': False,
        'fresh_node_refetch_required_before_submission': True,
        'prover_or_pk_read': False, 'output_dir': str(output)}
    write_private(output / 'RESULTS.json', result)
    parent = os.open(output, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return result


def execute(request):
    require(type(request) is dict and request.get('op') in ('recover', 'prepare-reveal'), 'wallet-operation')
    if request['op'] == 'prepare-reveal':
        require(request.get('disclosure_consent') == DISCLOSURE_CONSENT, 'explicit-reveal-consent-required')
    crypto = runtime_crypto(request.get('crypto_path', DEFAULT_CRYPTO))
    descriptor = parse_json(Path(request['descriptor_path']).read_bytes())
    selected_descriptor = descriptor_identity(descriptor)
    require('expected_descriptor_sha256' in request, 'user-selected-descriptor-pin-required')
    require(exact(request['expected_descriptor_sha256'], 32).hex() == selected_descriptor,
            'user-selected-descriptor-pin-mismatch')
    fetched = parse_json(Path(request['fetch_path']).read_bytes())
    # Replay public inputs in this trusted client; caller cannot supply an
    # operator snapshot or assert a self-authenticating complete result.
    sys.path.insert(0, str(HERE))
    from replay import replay
    public = replay(descriptor, fetched)
    snapshot_from_replay(descriptor, public)  # Reject public-data gaps before seed read.
    seed = load_backup(request['backup_path'], descriptor)
    summary, receiver, recovered, expected, snapshot = recognize(descriptor, public, seed, crypto)
    if request['op'] == 'recover':
        return summary
    return prepare_reveal(request, descriptor, public, receiver, recovered, expected, snapshot)


if __name__ == '__main__':
    try:
        print(json.dumps(execute(parse_json(sys.stdin.read())), sort_keys=True))
    except Invalid as error:
        print(json.dumps({'passed': False, 'error': str(error)}))
        raise SystemExit(1)
    except (ValueError, KeyError, TypeError, OSError, IndexError, subprocess.SubprocessError):
        # Deliberately do not stringify dependencies or malformed secret input.
        print(json.dumps({'passed': False, 'error': 'WALLET_RECOVERY_REJECTED'}))
        raise SystemExit(1)

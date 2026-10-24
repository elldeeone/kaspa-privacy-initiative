#!/usr/bin/env python3
"""Provisional ADR59 PUBLIC mass skeletons, never quote/settlement authority.

Unknown roots/records and proofs are explicit fixed-width public placeholders.
No legal child, private witness, NativeFull or receipt is claimed. The exact
genuine-child body MUST be normalized/reconciled before guest execution.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

from native_adapter import NativeCodec
from policy import Head, state
from selected import child_profile, parse
from virtual import PAYLOAD_BYTES, encode_payload, push
from wire import h, hexbytes, need, p2sh

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from public_native import normalize


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def skeleton(head, emitter, payload, outputs, budget=1600):
    redeem = emitter(head.state)
    return {'transaction': {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': head.point(), 'signatureScript':
            (push(bytes(65)) + push(bytes(128)) + push(redeem)).hex(),
            'sequence': (1 << 64) - 1, 'computeBudget': budget}],
        'outputs': [{'value': value, 'scriptPublicKey': spk, 'covenant': None} for value, spk in outputs],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': payload.hex(), 'mass': 0},
        'entries': [{'amount': head.reserve, 'scriptPublicKey': p2sh(redeem),
                     'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}]}


def fixed_fee(build, rate):
    fee, history = 2, []
    for _ in range(64):
        case = build(fee)
        actual = normalize(case)
        required = rate * actual['metrics']['mining_mass']
        history.append({'provisional_fee_sompi': fee, 'required_reference_fee_sompi': required,
                        'storage_mass': actual['metrics']['storage_mass']})
        if required == fee:
            need(actual['metrics']['actual_fee_sompi'] == fee, 'official_skeleton_implicit_fee')
            return {'transaction': actual['transaction'], 'entries': case['entries']}, actual['metrics'], history
        need(required > 0, 'positive_reference_price')
        fee = required
    raise ValueError('public_mass_price_fixpoint_incomplete')


def evaluate(prestate, profile_path, profile_sha, image, raw_output, useful_each=1000000000, rate=100):
    need(not raw_output.exists() and raw_output.is_absolute()
         and not raw_output.resolve().is_relative_to(ROOT.resolve())
         and not any(part.is_symlink() for part in (raw_output, *raw_output.parents)), 'fresh_raw_public_pricing_directory')
    child, metadata = child_profile(profile_path, profile_sha, allow_no_append_exit=True)
    need(prestate['schema'] == 'kpx5-public-constructed-two-owner-prestate/v1'
         and prestate['child_profile_sha256'] == profile_sha
         and prestate['accepted_chain_backing_currentness_or_GN_claimed'] is False,
         'constructed_public_prestate_only')
    given = Head(prestate['previous_point']['transactionId'], prestate['previous_point']['index'],
                 hexbytes(prestate['state_hex112'], 112), prestate['reserve_sompi'], domain=child.domain)
    codec = NativeCodec(image, profile_sha)
    current_redeem = codec.emit(given.state)
    parsed = state(given.state, child.domain)
    final = bytearray(given.state)
    final[40:72] = bytes(32); final[76:108] = bytes(32)
    final[72:76] = (((parsed['n'] + 1) // 2 * 2) + 4).to_bytes(4, 'little')
    final[108:112] = (parsed['m'] + 4).to_bytes(4, 'little')
    final = bytes(final)
    state(final, child.domain)
    next_redeem = codec.emit(final)
    # Exact widths, deliberately invalid record contents: no fake private
    # witness or legal-candidate claim is made by these public mass skeletons.
    payload = encode_payload((bytes(4048), bytes(4048)))
    outer, outer_metrics, outer_steps = fixed_fee(lambda fee:
        skeleton(given, codec.emit, payload, [(given.reserve - fee, p2sh(next_redeem))]), rate)
    fee = outer_metrics['actual_fee_sompi']
    allocation = [fee // 2, fee - fee // 2]
    need(all(amount > 0 for amount in allocation), 'positive_exact_child_fee_allocation')
    # Public full-note cashout size; actual recipient amount/state/roots and
    # genuine private proof must be checked later against the actual candidate.
    after = Head(given.transaction_id, 0, final, given.reserve - fee, domain=child.domain)
    payout_spk = '000020' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' + 'ac'
    exit_payload = b'KPX4AU01' + child.domain + bytes(2848 - 40)
    continuing, continuing_metrics, continuing_steps = fixed_fee(lambda credit:
        skeleton(after, codec.emit, exit_payload,
            [(after.reserve - useful_each - credit, p2sh(next_redeem)), (useful_each, payout_spk)]), rate)
    credit = continuing_metrics['actual_fee_sompi']
    terminal_head = Head(given.transaction_id, 0, final, useful_each + credit, domain=child.domain)
    terminal, terminal_metrics, terminal_steps = fixed_fee(lambda tail:
        skeleton(terminal_head, codec.emit, exit_payload, [(terminal_head.reserve - tail, payout_spk)]), rate)
    terminal_fee = terminal_metrics['actual_fee_sompi']
    need(credit >= terminal_fee, 'terminal_surplus_nonnegative')
    invariance = []
    for variant in ('fixed_width_payload_bytes', 'outer_proof_slot'):
        changed = copy.deepcopy(outer)
        if variant == 'fixed_width_payload_bytes':
            changed['transaction']['payload'] = (payload[:12] + bytes([0x5a]) * (PAYLOAD_BYTES - 12)).hex()
        else:
            script = bytearray.fromhex(changed['transaction']['inputs'][0]['signatureScript'])
            script[68:196] = bytes([0x42]) * 128
            changed['transaction']['inputs'][0]['signatureScript'] = script.hex()
        metrics = normalize(changed)['metrics']
        need(metrics['mining_mass'] == outer_metrics['mining_mass']
             and metrics['storage_mass'] == outer_metrics['storage_mass'], 'fixed_width_public_mass_invariance')
        invariance.append({'variant': variant, 'same_mining_and_storage_mass': True})
    raw_output.mkdir(parents=True, mode=0o700)
    for name, value in [('outer-INVALID-public-record-skeleton.json', outer),
                        ('continuing-INVALID-public-exit-skeleton.json', continuing),
                        ('terminal-INVALID-public-exit-skeleton.json', terminal)]:
        with (raw_output / name).open('xb') as file: file.write(encoded(value) + b'\n')
    head_json = {'classification': 'EXTERNALLY_SELECTED_SYNTHETIC_HEAD',
                 'transaction_id': given.transaction_id, 'index': given.index,
                 'state_hex112': given.state.hex(), 'reserve_sompi': given.reserve}
    with (raw_output / 'selected-constructed-head.json').open('xb') as file:
        file.write(encoded(head_json) + b'\n')
    return {'schema': 'kpx5-provisional-public-mass-pricing/v1',
        'classification': 'INVALID_PUBLIC_RECORD_SIZING_SKELETON_NOT_QUOTE_AUTHORITY',
        'profile': metadata, 'outer_image_hex32': image.hex(), 'actual_W_redeem_bytes': len(current_redeem),
        'actual_W_redeem_sha256': h(current_redeem).hex(), 'reference_rate': rate,
        'constructed_initial_reserve_sompi': given.reserve, 'useful_each_requested_sompi': useful_each,
        'outer_fee_sompi': fee, 'allocated_child_fees_sompi': allocation,
        'recipient_gross_note_sompi': useful_each + credit,
        'continuing_noappend_exit_credit_sompi': credit, 'terminal_noappend_minimum_sompi': terminal_fee,
        'terminal_credit_refund_sompi': credit - terminal_fee,
        'official_outer_metrics': outer_metrics, 'official_continuing_metrics': continuing_metrics,
        'official_terminal_metrics': terminal_metrics, 'outer_fixpoint': outer_steps,
        'continuing_fixpoint': continuing_steps, 'terminal_fixpoint': terminal_steps,
        'fixed_width_invariance_controls': invariance,
        'selected_constructed_head_file_sha256': h(encoded(head_json) + b'\n').hex(),
        'genuine_child_body_and_final_outer_body_must_be_renormalized': True,
        'new_private_witness_PK_proof_native_VM_backing_currentness_or_fee_qualification': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prestate', type=Path, required=True); p.add_argument('--prestate-sha256', required=True)
    p.add_argument('--profile', type=Path, required=True); p.add_argument('--profile-sha256', required=True)
    p.add_argument('--image', required=True); p.add_argument('--raw-output', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    need(not a.output.exists(), 'fresh_public_pricing_summary')
    raw = a.prestate.read_bytes()
    need(h(raw).hex() == a.prestate_sha256, 'externally_selected_public_prestate')
    result = evaluate(parse(raw), a.profile, a.profile_sha256, hexbytes(a.image, 32), a.raw_output)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('xb') as file: file.write(encoded(result) + b'\n')
    print(json.dumps({'outer_fee_sompi': result['outer_fee_sompi'],
        'allocated_child_fees_sompi': result['allocated_child_fees_sompi'],
        'continuing_exit_credit_sompi': result['continuing_noappend_exit_credit_sompi'],
        'terminal_exit_minimum_sompi': result['terminal_noappend_minimum_sompi'],
        'quote_authority_or_financial_positive': False}))

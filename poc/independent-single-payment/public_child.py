#!/usr/bin/env python3
"""Two fresh PUBLIC unsafe owner components for the selected NEW wrapper profile.

Preparation/context commands are light and public. prove-child --execute loads
one selected compact PK, requires exact READY, derives only this actor's known
unsafe seed, and sends one own witness over one inherited pipe. It never asserts
native/chain acceptance or gives a virtual component old-UTXO spend authority.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

from payment import Request, REQUEST_SCHEMA, VIRTUAL, prepare_payment, public_component
from public_fixture import (CLASSIFICATION, VALUE, actor_wallet, load_profile, parse_snapshot,
                            read_note, save_new, snapshot_record)
from reuse import load, ROOT

CONTEXT_SCHEMA = 'kpx5-public-virtual-owner-context/v1'
SUCCESSOR_SCHEMA = 'kpx5-public-virtual-child-successor/v1'


def raw_selected(path, expected):
    c = load()
    c.history.hexbytes(expected, 32)
    raw = c.receiver.no_symlinks(path).read_bytes()
    c.primitives.need(hashlib.sha256(raw).hexdigest() == expected, 'selected-public-bytes-pin')
    return raw


def state_input(raw, profile, actor):
    c = load()
    p = c.primitives
    row = p.parse(raw)
    base = {'schema', 'classification', 'child_profile_sha256', 'domain_hex32',
            'wrapper_domain_hex32', 'previous_point', 'previous_point_kind',
            'reserve_sompi', 'state_hex112', 'snapshot'}
    if actor == 0:
        expected = base | {'accepted_chain_backing_currentness_or_GN_claimed',
                           'proof_native_PK_or_main_inputs_read'}
        p.need(type(row) is dict and set(row) == expected
               and row['schema'] == 'kpx5-public-constructed-two-owner-prestate/v1'
               and row['previous_point_kind'] == 'CONSTRUCTED_WRAPPER_HEAD_NOT_ACCEPTED'
               and row['accepted_chain_backing_currentness_or_GN_claimed'] is False
               and row['proof_native_PK_or_main_inputs_read'] is False, 'constructed-first-public-head')
    else:
        expected = base | {'genuine_child_proof_verified', 'actual_wrapper_or_chain_accepted'}
        p.need(type(row) is dict and set(row) == expected
               and row['schema'] == SUCCESSOR_SCHEMA
               and row['previous_point_kind'] == 'CANONICAL_PREVIOUS_VIRTUAL_BODY'
               and row['genuine_child_proof_verified'] is True
               and row['actual_wrapper_or_chain_accepted'] is False, 'selected-virtual-prefix')
    p.need(row['classification'] == CLASSIFICATION
           and row['child_profile_sha256'] == profile.sha256
           and row['domain_hex32'] == profile.domain.hex()
           and row['wrapper_domain_hex32'] == profile.wrapper_domain.hex(), 'public-head-profile')
    p.amount(row['reserve_sompi'])
    c.actions.point_bytes(row['previous_point'])
    snapshot = parse_snapshot(row['snapshot'], profile.domain,
                              c.history.hexbytes(row['state_hex112'], 112))
    if actor == 0:
        p.need(snapshot.cm_cursor == 2 and len(snapshot.deliveries) == 2
               and [x.position for x in snapshot.deliveries] == [0, 1]
               and len(snapshot.nullifiers) == 1 and row['reserve_sompi'] == 2 * VALUE,
               'exact-constructed-two-note-prestate')
    return row, snapshot


def validate_context(raw, profile):
    c = load()
    p = c.primitives
    value = p.parse(raw)
    p.need(type(value) is dict and set(value) == {
        'schema', 'classification', 'child_profile_sha256', 'actor', 'head',
        'recipient_public_record', 'request', 'allocated_fee_sompi',
        'fee_allocation_sompi', 'outer_fee_sompi', 'expected_exit_credit_sompi',
        'quote_reference_sha256', 'quote_reference_requires_final_confirmation'
    } and value['schema'] == CONTEXT_SCHEMA
        and value['classification'] == CLASSIFICATION
        and value['child_profile_sha256'] == profile.sha256
        and type(value['actor']) is int and value['actor'] in (0, 1)
        and value['quote_reference_requires_final_confirmation'] is True,
        'strict-public-owner-context')
    actor = value['actor']
    head, snapshot = state_input(c.native_runtime.encoded(value['head']), profile, actor)
    target, _ = read_note(c.native_runtime.encoded(value['recipient_public_record']), profile)
    p.need(target['actor_position'] == 1 - actor, 'cross-public-actor-invoice')
    request = Request.parse(c.native_runtime.encoded(value['request']), profile.domain)
    p.need(request.invoice.hex() == target['payment_invoice_hex208']
           and request.net_principal_sompi == 1_000_000_000, 'exact-one-10KAS-request')
    credit = p.amount(value['expected_exit_credit_sompi'])
    p.need(credit > 0 and request.recipient_exit_credit_sompi == credit, 'explicit-exit-credit')
    fees = value['fee_allocation_sompi']
    p.need(type(fees) is list and len(fees) == 2
           and all(type(fee) is int and 0 < fee <= p.MAX for fee in fees)
           and p.amount(value['outer_fee_sompi']) == sum(fees)
           and p.amount(value['allocated_fee_sompi']) == fees[actor], 'exact-positive-outer-fee-allocation')
    c.history.hexbytes(value['quote_reference_sha256'], 32)
    return value, head, snapshot, request


def make_context(profile, args):
    c = load()
    p = c.primitives
    p.need(type(args.actor) is int and args.actor in (0, 1), 'one-public-actor')
    head, _ = state_input(c.receiver.no_symlinks(args.head).read_bytes(), profile, args.actor)
    target, _ = read_note(c.receiver.no_symlinks(args.recipient_note).read_bytes(), profile)
    value = {'schema': CONTEXT_SCHEMA, 'classification': CLASSIFICATION,
        'child_profile_sha256': profile.sha256, 'actor': args.actor, 'head': head,
        'recipient_public_record': target,
        'request': {'schema': REQUEST_SCHEMA, 'domain_hex32': profile.domain.hex(),
                    'recipient_invoice_hex208': target['payment_invoice_hex208'],
                    'net_principal_sompi': 1_000_000_000,
                    'recipient_exit_credit_sompi': args.exit_credit_sompi},
        'allocated_fee_sompi': args.allocated_fees_sompi[args.actor],
        'fee_allocation_sompi': args.allocated_fees_sompi,
        'outer_fee_sompi': args.outer_fee_sompi, 'expected_exit_credit_sompi': args.exit_credit_sompi,
        'quote_reference_sha256': args.quote_reference_sha256,
        'quote_reference_requires_final_confirmation': True}
    validate_context(c.native_runtime.encoded(value), profile)
    save_new(args.output, value)
    return {'public_context_written': True, 'actor': args.actor,
            'allocated_fee_sompi': value['allocated_fee_sompi'],
            'private_seed_witness_PK_native_or_proof_read': False}


def selected_manifest(raw, profile):
    c = load()
    p = c.primitives
    p.need(p.h(raw).hex() == profile.data['child_parameter_manifest_sha256'], 'selected-child-manifest-pin')
    manifest = p.parse(raw)
    p.need(type(manifest) is dict and manifest['schema'] == 'kpx4-public-proving-parameters/v1'
           and manifest['role'] == 'compact2' and manifest['output_arity'] == 2
           and manifest['domain_hex32'] == profile.domain.hex()
           and manifest['vk_sha256'] == profile.data['child_vk_sha256']
           and c.history.hexbytes(manifest['vk_hex328'], 328) == profile.vk,
           'selected-child-manifest-fields')
    for key in ('compiled_build_identity_sha256', 'pk_sha256', 'vk_sha256'):
        c.history.hexbytes(manifest[key], 32)
    p.need(type(manifest['pk_bytes']) is int and manifest['pk_bytes'] > 0, 'selected-whole-PK-length')
    return manifest


def ready_expected(profile, manifest):
    return {'event': 'parameters-ready', 'role': 'compact2', 'output_arity': 2,
        'parameter_manifest_sha256': profile.data['child_parameter_manifest_sha256'],
        'domain_hex32': profile.domain.hex(), 'vk_sha256': profile.data['child_vk_sha256'],
        'compiled_build_identity_sha256': manifest['compiled_build_identity_sha256']}


def public_body(auth, payload, profile):
    c = load()
    p = c.primitives
    p.fixed(auth, 528)
    p.need(auth[:8] == b'KPX4AU01' and auth[8:40] == profile.domain
           and auth[300] == 2 and int.from_bytes(auth[484:492], 'little') == 0
           and auth[492:528] == bytes(36) and payload[:528] == auth and len(payload) == 3920,
           'selected-public-compact-P0')
    previous = {'transactionId': auth[40:72].hex(), 'index': int.from_bytes(auth[72:76], 'little')}
    redeem = b'\x4c\x70' + auth[76:188] + profile.tail
    after = b'\x4c\x70' + auth[364:476] + profile.tail
    signature = c.native_runtime.push(bytes(65)) + c.native_runtime.push(bytes(128)) + c.native_runtime.push(redeem)
    reserve = int.from_bytes(auth[188:196], 'little')
    remaining = int.from_bytes(auth[476:484], 'little')
    body = c.native_runtime.tx(previous, [(remaining, c.native_runtime.p2sh(after))], payload, signature, 1600)
    entries = [c.native_runtime.context(reserve, redeem)]
    return c.native_runtime.public_case(body, entries)


def normalize_public(case, output):
    """Official2.1 public normalization only; no old-domain emitter/Full call."""
    c = load()
    p = c.primitives
    native = c.native_runtime.Executable(c.native_runtime.NATIVE, c.native_runtime.NATIVE_SHA)
    c.native_runtime.save(output / 'public-case.json', case)
    native.run(['control-normalize-freeze', output / 'public-case.json', output / 'normalized'])
    body = p.parse((output / 'normalized/transaction.json').read_bytes())
    metrics = p.parse((output / 'normalized/metrics.json').read_bytes())
    expected = copy.deepcopy(case['transaction'])
    expected['id'], expected['mass'] = body['id'], body['mass']
    p.need(body == expected, 'normalizer-only-derived-ID-and-mass')
    fee = case['entries'][0]['amount'] - sum(row['value'] for row in body['outputs'])
    p.need(metrics['actual_fee_sompi'] == fee, 'virtual-reserve-exact-allocated-fee')
    return {'transaction': body, 'entries': case['entries']}, metrics


def prove_child(profile, args):
    c = load()
    p = c.primitives
    raw = raw_selected(args.context, args.context_sha256)
    context, head, snapshot, request = validate_context(raw, profile)
    manifest = selected_manifest(c.receiver.no_symlinks(args.manifest).read_bytes(), profile)
    prover = c.native_runtime.Executable(args.prover, args.prover_sha256)
    c.receiver.no_symlinks(args.pk)
    output = c.receiver.no_symlinks(args.output)
    p.need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-public-owner-output-outside-Git')
    p.need(args.execute is True, 'explicit-root-heavy-release-required')
    for path in args.must_be_absent:
        p.need(not path.exists() and not path.is_symlink(), 'original-operator-path-visible')
    output.mkdir(parents=True, mode=0o700)
    read_fd, write_fd = os.pipe()
    process = None
    try:
        env = dict(c.native_runtime.CLEAN, RAYON_NUM_THREADS=str(args.workers))
        process = subprocess.Popen([str(prover.path), 'prove', 'compact2', str(args.pk),
                                   str(read_fd), str(output / 'proof')],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, pass_fds=(read_fd,), env=env)
        os.close(read_fd)
        read_fd = None
        first = process.stdout.readline()
        p.need(first and p.parse(first) == ready_expected(profile, manifest),
               'exact-whole-PK-READY-before-actor-seed')
        c.native_runtime.save(output / 'PARAMETERS-READY.json', p.parse(first))
        # First known unsafe actor-seed derivation in this owner process.
        wallet = actor_wallet(profile, context['actor'])
        recovered = c.receiver.recover(wallet, snapshot, snapshot.state(profile.domain))
        claims = [claim for claim in recovered.owned if claim.position == context['actor']
                  and claim.receipt.index == 0 and claim.receipt.value_sompi == VALUE
                  and claim.owner_action_available]
        p.need(len(claims) == 1, 'one-own-original-public-2B-claim')
        prepared = prepare_payment(wallet, snapshot, claims[0], head['previous_point'],
            head['reserve_sompi'], context['allocated_fee_sompi'], request, recovered.owned,
            expected_exit_credit_sompi=context['expected_exit_credit_sompi'], fee_context=VIRTUAL,
            excluded_change_indices=(0, 1))
        candidate = prepared.candidate
        case, metrics = normalize_public(public_body(candidate.auth, candidate.payload(), profile), output)
        with os.fdopen(write_fd, 'wb') as writer:
            write_fd = None
            writer.write(c.native_runtime.encoded(candidate.private_witness()) + b'\n')
        stdout, stderr = process.communicate()
        p.need(process.returncode == 0, 'selected-public-owner-proof-failed')
        done = p.parse(stdout.strip())
        p.need(type(done) is dict, 'public-proof-completion-object')
        expected_done = {'event': 'proof-complete', 'role': 'compact2',
            'genuine_Groth16_verified': True, 'proof_sha256': done.get('proof_sha256'),
            'authorization_sha256': p.h(candidate.auth).hex(),
            'vk_sha256': profile.data['child_vk_sha256']}
        p.need(done == expected_done, 'exact-selected-public-proof-completion')
        proof = p.fixed((output / 'proof/proof128.bin').read_bytes(), 128)
        report = p.parse((output / 'proof/report.json').read_bytes())
        p.need((output / 'proof/authorization528.bin').read_bytes() == candidate.auth
               and (output / 'proof/verification-key.bin').read_bytes() == profile.vk
               and done['proof_sha256'] == p.h(proof).hex()
               and report['genuine_Groth16_verified'] is True
               and report['role'] == 'compact2' and report['output_arity'] == 2
               and report['domain_hex32'] == profile.domain.hex()
               and report['proof_sha256'] == p.h(proof).hex()
               and report['authorization_sha256'] == p.h(candidate.auth).hex()
               and report['parameter_manifest_sha256'] == profile.data['child_parameter_manifest_sha256']
               and report['compiled_build_identity_sha256'] == manifest['compiled_build_identity_sha256']
               and report['vk_sha256'] == profile.data['child_vk_sha256']
               and report['pk_sha256'] == manifest['pk_sha256']
               and report['pk_bytes'] == manifest['pk_bytes'], 'exact-public-proof-artifacts-and-profile')
        frame = bytearray.fromhex(case['transaction']['inputs'][0]['signatureScript'])
        p.need(frame[68:196] == bytes(128), 'only-proof-substitution')
        frame[68:196] = proof
        case['transaction']['inputs'][0]['signatureScript'] = frame.hex()
        component = public_component(prepared, proof, case)
        c.native_runtime.save(output / 'COMPONENT.json', component)
        successor = {'schema': SUCCESSOR_SCHEMA, 'classification': CLASSIFICATION,
            'child_profile_sha256': profile.sha256, 'domain_hex32': profile.domain.hex(),
            'wrapper_domain_hex32': profile.wrapper_domain.hex(),
            'previous_point': {'transactionId': case['transaction']['id'], 'index': 0},
            'previous_point_kind': 'CANONICAL_PREVIOUS_VIRTUAL_BODY',
            'reserve_sompi': candidate.reserve_after, 'state_hex112': candidate.after.state(profile.domain).hex(),
            'snapshot': snapshot_record(candidate.after), 'genuine_child_proof_verified': True,
            'actual_wrapper_or_chain_accepted': False}
        c.native_runtime.save(output / 'SUCCESSOR.json', successor)
        result = {'schema': 'kpx5-public-owner-component-result/v1',
            'classification': CLASSIFICATION, 'child_profile_sha256': profile.sha256,
            'wallet_policy': 'ONE_INVOICE_POSITIVE_SENDER_CHANGE',
            'genuine_compact_P0_child_proof_verified': True,
            'whole_PK_READY_before_own_actor_seed': True, 'one_actor_witness_FD_only': True,
            'fee_sompi': candidate.fee, 'reserve_after_sompi': candidate.reserve_after,
            'official_virtual_body_ID_normalized_before_owner_witness': True,
            'official_virtual_body_metrics': metrics,
            'native_Full_actual_wrapper_or_chain_acceptance_claimed': False,
            'requested_own_public_context_only': True, 'public_oracle_received_private_witness': False,
            'discarded_preparations_private_witness_seed_or_other_owner_map_exported': False,
            'quote_reference_requires_final_confirmation': True}
        c.native_runtime.save(output / 'RESULTS.json', result)
        return result
    finally:
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate()


def main(args):
    profile = load_profile(args.profile, args.profile_sha256)
    if args.operation == 'make-context':
        return make_context(profile, args)
    load().primitives.need(type(args.workers) is int and args.workers > 0, 'positive-prover-workers')
    return prove_child(profile, args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    prepare = sub.add_parser('make-context')
    for name in ('head', 'recipient-note', 'output'):
        prepare.add_argument('--' + name, type=Path, required=True)
    prepare.add_argument('--actor', type=int, choices=(0, 1), required=True)
    prepare.add_argument('--allocated-fees-sompi', type=int, nargs=2, required=True)
    prepare.add_argument('--outer-fee-sompi', type=int, required=True)
    prepare.add_argument('--exit-credit-sompi', type=int, required=True)
    prepare.add_argument('--quote-reference-sha256', required=True)
    prove = sub.add_parser('prove-child')
    for name in ('context', 'manifest', 'prover', 'pk', 'output'):
        prove.add_argument('--' + name, type=Path, required=True)
    prove.add_argument('--context-sha256', required=True)
    prove.add_argument('--prover-sha256', required=True)
    prove.add_argument('--workers', type=int, default=2)
    prove.add_argument('--execute', action='store_true')
    prove.add_argument('--must-be-absent', type=Path, action='append', default=[])
    try:
        print(json.dumps(main(parser.parse_args()), sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit('public-owner component refused') from None


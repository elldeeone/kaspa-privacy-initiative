#!/usr/bin/env python3
"""Known PUBLIC unsafe actor setup only; no PK/prover/native/network operation.

One process may derive only one nominal actor's seed. The assembler reads only
the two public records and never derives either actor seed. This is deliberately
constructed state, not a GN, deposit, accepted backing or privacy experiment.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from reuse import load, ROOT

LABEL = b'ADR59/PUBLIC_SYNTHETIC_DO_NOT_FUND/TWO_SCHEDULED_PAYMENTS/v1'
VALUE = 2_000_000_000
CLASSIFICATION = 'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATE'
_derived_actor = None


@dataclass(frozen=True)
class Profile:
    data: dict
    sha256: str
    domain: bytes
    wrapper_domain: bytes
    tail: bytes
    vk: bytes


def load_profile(path, expected_sha256):
    c = load()
    p = c.primitives
    c.history.hexbytes(expected_sha256, 32)
    raw = c.receiver.no_symlinks(path).read_bytes()
    p.need(hashlib.sha256(raw).hexdigest() == expected_sha256, 'installed-child-profile-pin')
    data = p.parse(raw)
    p.need(type(data) is dict and set(data) == {
        'schema', 'classification', 'selected', 'trial_id', 'child_count',
        'child_domain_hex32', 'child_mode', 'child_parameter_manifest_sha256',
        'child_role', 'child_template_tail_hex', 'child_vk_hex328', 'child_vk_sha256',
        'wrapper_domain_hex32', 'journal_bytes', 'payload_bytes', 'owner_witness_or_funding_authority'
    } and data['schema'] == 'kpx5-public-virtual-settlement-child-profile/v1'
        and data['classification'] == 'PUBLIC_SYNTHETIC_DO_NOT_FUND_UNFUNDED_BENCHMARK_ONLY'
        and data['selected'] is True and data['owner_witness_or_funding_authority'] is False
        and type(data['child_count']) is int and data['child_count'] == 2
        and type(data['child_mode']) is int and data['child_mode'] == 2
        and data['child_role'] == 'compact2', 'selected-public-child-profile')
    domain = c.history.hexbytes(data['child_domain_hex32'], 32)
    wrapper = c.history.hexbytes(data['wrapper_domain_hex32'], 32)
    p.need(domain != wrapper and domain != p.ZERO and wrapper != p.ZERO, 'distinct-child-wrapper-domains')
    tail = c.history.hexbytes(data['child_template_tail_hex'])
    vk = c.history.hexbytes(data['child_vk_hex328'], 328)
    p.need(len(tail) > 0 and p.h(vk).hex() == data['child_vk_sha256'], 'profile-child-template-and-VK')
    c.history.hexbytes(data['child_parameter_manifest_sha256'], 32)
    return Profile(data, expected_sha256, domain, wrapper, tail, vk)


def actor_wallet(profile, actor):
    global _derived_actor
    c = load()
    p = c.primitives
    p.need(type(actor) is int and actor in (0, 1), 'one-public-actor')
    p.need(_derived_actor is None or _derived_actor == actor, 'one-actor-seed-per-process')
    _derived_actor = actor
    seed = p.h(LABEL, b'/owner-seed\0', profile.domain, p.u32(actor))
    return c.receiver.module().Receiver(seed, profile.domain, c.receiver.Crypto())


def public_note(profile, actor):
    c = load()
    p = c.primitives
    wallet = actor_wallet(profile, actor)
    initial = wallet.invoice(0)
    invoice = wallet.invoice(1)
    rho = p.h(LABEL, b'/initial-rho\0', profile.domain, p.u32(actor))
    receipt = c.receiver.module().Receipt.for_invoice(initial, VALUE, rho)
    cipher = wallet.crypto.seal(initial.delivery_pk, receipt.encode())
    return {'schema': 'kpx5-public-unsafe-initial-actor-note/v1',
        'classification': CLASSIFICATION, 'fixture_label': LABEL.decode(),
        'domain_hex32': profile.domain.hex(), 'actor_position': actor,
        'note_hex168': receipt.note_bytes().hex(), 'cm_hex32': receipt.commitment().hex(),
        'cipher_hex264': p.fixed(cipher, 264).hex(),
        'initial_invoice_hex208': initial.encode().hex(),
        'payment_invoice_hex208': invoice.encode().hex(),
        'proving_parameters_private_main_inputs_or_native_read': False}


def read_note(raw, profile):
    c = load()
    p = c.primitives
    row = p.parse(raw)
    p.need(type(row) is dict and set(row) == {
        'schema', 'classification', 'fixture_label', 'domain_hex32', 'actor_position',
        'note_hex168', 'cm_hex32', 'cipher_hex264', 'initial_invoice_hex208',
        'payment_invoice_hex208', 'proving_parameters_private_main_inputs_or_native_read'
    } and row['schema'] == 'kpx5-public-unsafe-initial-actor-note/v1'
        and row['classification'] == CLASSIFICATION and row['fixture_label'] == LABEL.decode()
        and row['domain_hex32'] == profile.domain.hex()
        and type(row['actor_position']) is int and row['actor_position'] in (0, 1)
        and row['proving_parameters_private_main_inputs_or_native_read'] is False,
        'strict-public-initial-note')
    note = c.history.hexbytes(row['note_hex168'], 168)
    initial = c.actions.invoice(c.history.hexbytes(row['initial_invoice_hex208'], 208), profile.domain)
    payee = c.actions.invoice(c.history.hexbytes(row['payment_invoice_hex208'], 208), profile.domain)
    expected = c.receiver.module().Receipt.for_invoice(initial, VALUE, note[72:104])
    p.need(initial.index == 0 and payee.index == 1 and expected.note_bytes() == note
           and initial.encode() != payee.encode()
           and p.note_cm(profile.domain, note).hex() == row['cm_hex32'], 'initial-note-public-binding')
    cipher = c.history.hexbytes(row['cipher_hex264'], 264)
    return row, p.Delivery(row['actor_position'], p.note_cm(profile.domain, note), cipher)


def snapshot_record(snapshot):
    return {'cm_cursor': snapshot.cm_cursor,
        'deliveries': [{'position': row.position, 'cm_hex32': row.cm.hex(),
                        'cipher_hex264': row.ciphertext.hex()} for row in snapshot.deliveries],
        'nullifiers': [{'value_hex32': row.value.hex(), 'next_value_hex32': row.next_value.hex(),
                        'next_index': row.next_index} for row in snapshot.nullifiers]}


def parse_snapshot(value, domain, expected_state):
    c = load()
    p = c.primitives
    p.need(type(value) is dict and set(value) == {'cm_cursor', 'deliveries', 'nullifiers'}
           and type(value['deliveries']) is list and type(value['nullifiers']) is list,
           'strict-public-snapshot')
    deliveries = []
    for row in value['deliveries']:
        p.need(type(row) is dict and set(row) == {'position', 'cm_hex32', 'cipher_hex264'},
               'strict-public-delivery')
        deliveries.append(p.Delivery(row['position'], c.history.hexbytes(row['cm_hex32'], 32),
                                     c.history.hexbytes(row['cipher_hex264'], 264)))
    nfs = []
    for row in value['nullifiers']:
        p.need(type(row) is dict and set(row) == {'value_hex32', 'next_value_hex32', 'next_index'},
               'strict-public-NF-row')
        nfs.append(p.NFEntry(c.history.hexbytes(row['value_hex32'], 32),
                            c.history.hexbytes(row['next_value_hex32'], 32), row['next_index']))
    snapshot = p.Snapshot(value['cm_cursor'], tuple(deliveries), tuple(nfs)).verify()
    p.need(snapshot.state(domain) == p.fixed(expected_state, 112), 'snapshot-selected-state')
    return snapshot


def assemble(profile, records):
    c = load()
    p = c.primitives
    p.need(type(records) is list and len(records) == 2, 'two-public-actor-records')
    parsed = [read_note(raw, profile) for raw in records]
    p.need([row[0]['actor_position'] for row in parsed] == [0, 1]
           and parsed[0][1].cm != parsed[1][1].cm, 'two-distinct-ordered-public-notes')
    snapshot = p.Snapshot(2, tuple(row[1] for row in parsed), (p.NFEntry(p.ZERO, p.ZERO, 0),)).verify()
    state = snapshot.state(profile.domain)
    point = {'transactionId': p.h(LABEL, b'/constructed-wrapper-Q0\0',
                                 profile.wrapper_domain, state).hex(), 'index': 0}
    return {'schema': 'kpx5-public-constructed-two-owner-prestate/v1',
        'classification': CLASSIFICATION, 'child_profile_sha256': profile.sha256,
        'domain_hex32': profile.domain.hex(), 'wrapper_domain_hex32': profile.wrapper_domain.hex(),
        'previous_point': point, 'previous_point_kind': 'CONSTRUCTED_WRAPPER_HEAD_NOT_ACCEPTED',
        'reserve_sompi': 2 * VALUE, 'state_hex112': state.hex(),
        'snapshot': snapshot_record(snapshot),
        'accepted_chain_backing_currentness_or_GN_claimed': False,
        'proof_native_PK_or_main_inputs_read': False}


def save_new(path, value):
    c = load()
    target = c.receiver.no_symlinks(path)
    p = c.primitives
    p.need(not target.is_relative_to(ROOT) and not target.exists(), 'fresh-public-fixture-outside-Git')
    c.native_runtime.save(target, value)


def main(args):
    profile = load_profile(args.profile, args.profile_sha256)
    if args.operation == 'public-note':
        value = public_note(profile, args.actor)
    else:
        value = assemble(profile, [load().receiver.no_symlinks(path).read_bytes() for path in args.note])
    save_new(args.output, value)
    return {'operation': args.operation, 'classification': CLASSIFICATION,
            'public_fixture_written': True, 'proof_native_PK_main_or_network': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    note = sub.add_parser('public-note')
    note.add_argument('--actor', type=int, choices=(0, 1), required=True)
    note.add_argument('--output', type=Path, required=True)
    both = sub.add_parser('assemble')
    both.add_argument('--note', type=Path, action='append', required=True)
    both.add_argument('--output', type=Path, required=True)
    try:
        print(json.dumps(main(parser.parse_args()), sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit('public-actor fixture refused') from None


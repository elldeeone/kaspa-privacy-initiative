#!/usr/bin/env python3
"""Finite-stage isolated owner worker; never performs network requests.

Only this process reads its new original seed. Its controller must not read or
hash private backups/requests/invoices/witnesses. It may consume PUBLIC.json,
the completed projection and a direct public Exit proof.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import secrets
import stat
import sys

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'recovery'))
import history
import payment
from support import Assets, DOMAIN, amount, checked, digest, encoded, fee_amount, fields, hx, need, parse, read, uint, write_new


@contextmanager
def owner_lock(owner):
    fd = os.open(checked(owner / 'OWNER-LOCK'), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
             'private-owner-lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def own_file(owner, path):
    path = checked(path)
    need(path.is_relative_to(owner), 'own-private-file-required')
    return path


def backup(raw):
    value = parse(raw)
    fields(value, ('schema', 'domain_hex32', 'seed_hex32'), 'seed-only-backup-fields')
    need(value['schema'] == 'kpxa-original-seed-backup/v1' and value['domain_hex32'] == DOMAIN.hex(),
         'seed-only-backup-domain')
    hx(value['seed_hex32'], 32)
    return value


def public(a, value):
    write_new(a.public_output / 'PUBLIC.json', encoded(value) + b'\n')


def selected_assets(a, roles):
    return Assets(read(a.assets, a.assets_sha256), a.assets_sha256, prove_roles=roles)


def own_receiver(a, assets):
    value = backup(read(a.owner / 'BACKUP.json', private=True))
    return assets.receiver(hx(value['seed_hex32'], 32))


def accepted_history(a, assets):
    context = parse(read(a.context, a.context_sha256))
    fields(context, ('schema', 'domain_hex32', 'genesis_sha256', 'checkpoint'), 'history-context-fields')
    need(context['schema'] == 'kpxa-selected-history-context/v1'
         and context['domain_hex32'] == DOMAIN.hex(), 'selected-history-context')
    return history.load(read(a.history, a.history_sha256), context['checkpoint'],
                        context['genesis_sha256'], assets)


def selected_fees(a, assets):
    need(a.native_fee_policy is not None and a.native_fee_policy_sha256 is not None,
         'independent-native-fee-policy-required-before-authorization')
    sys.path.insert(0, str(BASE / 'integration'))
    from native_fees import NativeFees
    return NativeFees(assets, read(a.native_fee_policy, a.native_fee_policy_sha256),
                      a.native_fee_policy_sha256)


def request(a):
    need(a.request is not None, 'own-private-request-required')
    return parse(read(own_file(a.owner, a.request), private=True))


def initialize(a):
    need(not (a.owner / 'BACKUP.json').exists(), 'fresh-unfunded-owner-required')
    assets = selected_assets(a, ('output',))
    amount(a.admission_sompi)
    seed = secrets.token_bytes(32)
    receiver = assets.receiver(seed)
    # Public initial deposit amount is bound by the Output relation through an
    # independently recomputable CV(value,0); Note168 stays encrypted/local.
    created = payment.output(assets, receiver.invoice(0), a.admission_sompi, blind=bytes(32))
    need(receiver.open(created.row[96:360]).encode() == created.receipt.encode(),
         'original-seed-initial-receipt-roundtrip')
    # Complete public output contains no owner descriptor/index/invoice PK.
    funding = b'\0\0\x20' + receiver.keys(0xffffffff).invoice.native_pk + b'\xac'
    write_new(a.owner / 'BACKUP.json', encoded({'schema': 'kpxa-original-seed-backup/v1',
        'domain_hex32': DOMAIN.hex(), 'seed_hex32': seed.hex()}) + b'\n', 0o600)
    record = {'schema': 'kpxa-initial-public/v1', 'domain_hex32': DOMAIN.hex(),
        'output_hex520': created.row.hex(), 'admission_sompi': a.admission_sompi,
        'funding_spk_hex36': funding.hex()}
    write_new(a.owner / 'INITIAL-PUBLIC.json', encoded(record) + b'\n')
    public(a, record)


def restore(a):
    need(not (a.owner / 'BACKUP.json').exists(), 'fresh-restoration-runtime')
    # A single selected original backup may be mounted read-only at --backup;
    # the parent never inspects its bytes or hashes its witness/seed contents.
    raw = read(a.backup, private=True)
    value = backup(raw)
    write_new(a.owner / 'BACKUP.json', encoded(value) + b'\n', 0o600)
    public(a, {'schema': 'kpxa-seed-restored/v1', 'seed_only': True,
               'private_maps_imported': False, 'recovery_verified': False})


def invoice(a):
    assets = selected_assets(a, ())
    receiver = own_receiver(a, assets)
    # Deliver this file through the authenticated confidential counterparty
    # channel. It is not a public readiness export or scan-index directory.
    raw = receiver.invoice(payment.fresh_index(receiver)).encode()
    write_new(a.owner / 'INVOICE208.bin', raw)
    public(a, {'schema': 'kpxa-private-invoice-ready/v1', 'invoice_exported_publicly': False})


def scan(a):
    assets = selected_assets(a, ())
    accepted = accepted_history(a, assets)
    receiver = own_receiver(a, assets)
    history.claims(accepted, receiver, assets)  # mandatory nonempty historical cohort
    payment.reconcile_payouts(accepted, receiver, assets)
    public(a, {'schema': 'kpxa-seed-scan-complete/v1', 'history_sha256': a.history_sha256,
        'seed_only': True, 'scan_completed': True, 'history_cohort_verified': True,
        'terminal_reconciled': accepted.reserve == 0, 'private_claims_exported': False})


def pay(a):
    assets = selected_assets(a, ('output', 'spend'))
    accepted = accepted_history(a, assets)
    receiver = own_receiver(a, assets)
    value = request(a)
    fields(value, ('schema', 'payment_sompi', 'fee_sompi', 'invoice_path', 'invoice_sha256', 'position'),
           'private-payment-request-fields')
    need(value['schema'] == 'kpxa-private-payment-request/v1', 'private-payment-request-schema')
    native_fees = selected_fees(a, assets)
    need(type(value['fee_sompi']) is int and value['fee_sompi'] == native_fees.payment_fee(accepted),
         'owner-request-must-approve-exact-current-native-fee')
    # A peer invoice is the only extra private input mount. It must be a single
    # file at /invoice/INVOICE208.bin or inside this owner's private directory.
    path = checked(value['invoice_path'])
    need(path.is_relative_to(a.owner) or path == Path('/invoice/INVOICE208.bin'), 'single-private-invoice-mount')
    invoice_raw = read(path, private=True)
    draft = payment.prepare(assets, accepted, receiver, invoice_raw=invoice_raw,
        invoice_sha256=value['invoice_sha256'], payment_sompi=value['payment_sompi'],
        fee_sompi=value['fee_sompi'], position=value['position'])
    raw = payment.authorize(assets, accepted, receiver, draft,
                            before_proof=lambda raw: native_fees.require(raw, 'payment'))
    write_new(a.public_output / 'PROJECTION.bin', raw)
    public(a, {'schema': 'kpxa-complete-payment/v1', 'history_sha256': a.history_sha256,
        'component_authorization_complete': True, 'output_count': 2,
        'requires_other_owner': False, 'native_confirmed': False})


def campaign_pay(a):
    """Authenticated local invoice IPC; controller never reads invoice bytes.

    The caller binds exactly one recipient-worker-produced invoice read-only at
    /invoice/INVOICE208.bin. This private namespace binding is the authenticated
    channel; sealed encryption is not the authentication mechanism.
    """
    assets = selected_assets(a, ('output', 'spend'))
    accepted = accepted_history(a, assets)
    receiver = own_receiver(a, assets)
    value = request(a)
    fields(value, ('schema', 'payment_sompi', 'fee_cap_sompi', 'selection_kind'),
           'private-campaign-payment-request-fields')
    need(value['schema'] == 'kpxa-private-campaign-payment-request/v1', 'private-campaign-payment-schema')
    native_fees = selected_fees(a, assets)
    fee = native_fees.payment_fee(accepted)
    need(fee <= fee_amount(value['fee_cap_sompi']), 'owner-approved-payment-fee-cap')
    invoice_raw = read('/invoice/INVOICE208.bin', private=True)
    draft = payment.prepare(assets, accepted, receiver, invoice_raw=invoice_raw,
        invoice_sha256=digest(invoice_raw), payment_sompi=value['payment_sompi'],
        fee_sompi=fee, selection_kind=value['selection_kind'])
    raw = payment.authorize(assets, accepted, receiver, draft,
                            before_proof=lambda raw: native_fees.require(raw, 'payment'))
    write_new(a.public_output / 'PROJECTION.bin', raw)
    public(a, {'schema': 'kpxa-complete-payment/v1', 'history_sha256': a.history_sha256,
        'component_authorization_complete': True, 'output_count': 2,
        'requires_other_owner': False, 'native_confirmed': False})


def exit_note(a):
    assets = selected_assets(a, ('exit',))
    accepted = accepted_history(a, assets)
    receiver = own_receiver(a, assets)
    value = request(a)
    fields(value, ('schema', 'fee_sompi', 'position'), 'private-exit-request-fields')
    need(value['schema'] == 'kpxa-private-exit-request/v1', 'private-exit-request-schema')
    native_fees = selected_fees(a, assets)
    owned = history.claims(accepted, receiver, assets)
    claim = history.select(accepted, receiver, assets, position=value['position'])
    quoted_fee = native_fees.exit_fee(accepted, claim, payment.payout_spk(accepted, receiver, owned, claim))
    need(type(value['fee_sompi']) is int and value['fee_sompi'] == quoted_fee,
         'owner-request-must-approve-exact-current-native-exit-fee')
    raw, proof = payment.independent_exit(assets, accepted, receiver,
        fee_sompi=value['fee_sompi'], position=value['position'],
        before_proof=lambda raw: native_fees.require(raw, 'exit'))
    write_new(a.public_output / 'PROJECTION.bin', raw)
    write_new(a.public_output / 'EXIT-PROOF.bin', proof)
    public(a, {'schema': 'kpxa-complete-independent-exit/v1', 'history_sha256': a.history_sha256,
        'component_authorization_complete': True, 'requires_outer_prover': False,
        'requires_other_owner': False, 'native_confirmed': False})


def recovery_exit(a):
    """Original-seed-only exit with a privately enforced explicit fee cap."""
    assets = selected_assets(a, ('exit',))
    accepted = accepted_history(a, assets)
    receiver = own_receiver(a, assets)
    value = request(a)
    fields(value, ('schema', 'fee_cap_sompi'), 'private-recovery-exit-request-fields')
    need(value['schema'] == 'kpxa-private-recovery-exit-request/v1', 'private-recovery-exit-schema')
    cap = fee_amount(value['fee_cap_sompi'])
    native_fees = selected_fees(a, assets)
    owned = history.claims(accepted, receiver, assets)
    claim = history.select(accepted, receiver, assets)
    fee = native_fees.exit_fee(accepted, claim, payment.payout_spk(accepted, receiver, owned, claim))
    need(fee <= cap, 'owner-approved-recovery-exit-fee-cap')
    raw, proof = payment.independent_exit(assets, accepted, receiver, fee_sompi=fee,
        position=claim.position, before_proof=lambda raw: native_fees.require(raw, 'exit'))
    write_new(a.public_output / 'PROJECTION.bin', raw)
    write_new(a.public_output / 'EXIT-PROOF.bin', proof)
    public(a, {'schema': 'kpxa-complete-independent-exit/v1', 'history_sha256': a.history_sha256,
        'component_authorization_complete': True, 'requires_outer_prover': False,
        'requires_other_owner': False, 'native_confirmed': False})


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'restore', 'invoice', 'scan', 'pay', 'exit', 'campaign-pay', 'recovery-exit'))
    for name in ('owner', 'public-output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('assets', 'history', 'context', 'request', 'backup', 'native-fee-policy'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'history-sha256', 'context-sha256', 'native-fee-policy-sha256'):
        p.add_argument('--' + name)
    p.add_argument('--admission-sompi', type=int)
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        a = p.parse_args()
        a.owner, a.public_output = checked(a.owner), checked(a.public_output)
        need(a.owner.is_dir() and stat.S_IMODE(a.owner.stat().st_mode) == 0o700,
             'owner-private-directory-mode')
        need(a.public_output.is_dir() and not a.public_output.is_relative_to(a.owner)
             and not a.owner.is_relative_to(a.public_output),
             'separate-public-output-directory')
        with owner_lock(a.owner):
            {'init': initialize, 'restore': restore, 'invoice': invoice, 'scan': scan,
             'pay': pay, 'exit': exit_note, 'campaign-pay': campaign_pay,
             'recovery-exit': recovery_exit}[a.operation](a)
        print(encoded({'operation': a.operation, 'completed': True}).decode())
    except Exception:
        p.exit(2, 'owner operation refused; private material not disclosed\n')

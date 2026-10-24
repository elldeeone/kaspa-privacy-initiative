#!/usr/bin/env python3
"""One owner only: private Output creation, private MPC upload, effects auth."""
import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import secrets
import stat

from paths import checked, digest, encoded, fields, hx, need, parse, stable_read, uint, write_new
from support import (DOMAIN, Q, MIN_NOTE, MAX_VALUE, CRYPTO_SHA, ROOT, Relations, amount, crypto,
                     module, recipient, scalar)

PROGRAM_SHA = 'fbf7b425cfd996db032edf33151440c3bf14dba2b8a89eaa3df9be7888bcf44d'
CODEC_SHA = 'f4d30ed15fc2bb39b2790a6a178f3911b3e3debd6946f073e36e4581d3ed8951'
ASSET_FIELDS = ('schema', 'domain_hex32', 'component_profile', 'component_profile_sha256', 'relation', 'crypto', 'spend', 'output',
                'codec_sha256', 'wire_sha256')
CONTEXT_FIELDS = ('schema', 'domain_hex32', 'component_profile_sha256', 'prior_state_hex112',
    'previous_outpoint_hex36', 'reserve_sompi', 'fee_sompi', 'fee_shares_sompi',
    'initial_cms_hex32', 'native_tail_hex')


def private_json(path):
    return parse(stable_read(path, private=True))


def private_save(path, value):
    write_new(path, encoded(value) + b'\n')


def public_save(a, value):
    write_new(a.output / 'PUBLIC.json', encoded(value) + b'\n', 0o400)


def owner_state(a):
    value = private_json(a.owner / 'OWNER.json')
    fields(value, ('schema', 'domain_hex32', 'participant_id_hex32', 'seed_hex32',
                   'initial_position', 'input_receipt_hex216'), 'owner-state-fields')
    need(value['schema'] == 'kpx7-unfunded-owner-state/v1'
         and value['domain_hex32'] == DOMAIN.hex(), 'new-unfunded-owner-domain')
    hx(value['participant_id_hex32'], 32); hx(value['seed_hex32'], 32)
    need(uint(value['initial_position'], 32) < 3, 'initial-three-note-position')
    v2 = recipient(); opened = v2.Receipt.parse(hx(value['input_receipt_hex216'], 216))
    need(opened.domain == DOMAIN and opened.index == 0, 'original-input-receipt-context')
    return value, opened


def attempt_directories(a):
    directory = a.owner / 'attempts'
    if not directory.exists():
        return []
    need(directory.is_dir(), 'attempt-directory')
    result = sorted(directory.iterdir())
    need(all(p.is_dir() and len(p.name) == 6 and p.name.isascii() and p.name.isdigit()
             and int(p.name) > 0 for p in result), 'generic-private-attempt-names')
    return result


def no_authorized_attempt(a):
    # Metadata FIRST. Never reopen an old output map for a post-auth blame,
    # reconnect, repeat authorization or retry request.
    directories = attempt_directories(a)
    need(not any((p / 'DISCLOSURE-CLOSED').exists() for p in directories),
         'authorization-may-settle-reconciliation-required')
    return directories


@contextmanager
def owner_lock(a):
    path = checked(a.owner / 'OWNER-LOCK')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, 'own-private-operation-lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def archive_pre_authorization_input(a, previous, input_file):
    """Owner-local move only; never reveal, hash or reuse an old tuple map."""
    no_authorized_attempt(a)
    if not input_file.exists():
        return
    need(previous, 'original-MPC-input-has-no-attempt')
    state = private_json(previous[-1] / 'STATE.json')
    info = checked(input_file).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == 2695
         and info.st_dev.to_bytes(8, 'little').hex() == state['input_device_hex8']
         and info.st_ino.to_bytes(8, 'little').hex() == state['input_inode_hex8'],
         'old-own-MPC-input-identity-before-private-archive')
    target = checked(previous[-1] / 'MPC-INPUT.bin')
    need(not target.exists(), 'fresh-own-MPC-input-archive')
    os.rename(input_file, target)
    for folder in (input_file.parent, target.parent):
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def load_assets(a, mode):
    raw = stable_read(a.assets)
    need(digest(raw) == a.assets_sha256, 'external-wallet-assets-pin')
    assets = parse(raw); fields(assets, ASSET_FIELDS, 'wallet-assets-fields')
    need(assets['schema'] == 'kpx7-wallet-assets/v1' and assets['domain_hex32'] == DOMAIN.hex()
         and assets['codec_sha256'] == CODEC_SHA
         and assets['crypto']['sha256'] == CRYPTO_SHA, 'new-selected-wallet-assets')
    hx(assets['component_profile_sha256'], 32)
    for name in ('relation', 'crypto'):
        fields(assets[name], ('path', 'sha256'), 'selected-program-fields')
        hx(assets[name]['sha256'], 32)
    for name in ('spend', 'output'):
        fields(assets[name], ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'selected-parameter-fields')
        hx(assets[name]['manifest_sha256'], 32); hx(assets[name]['pk_sha256'], 32)
    # Whole selected proving key is ready before any owner-state read. The
    # recipient-only Output verifier does not require its old proving key.
    relation = Relations(assets, mode)
    c = crypto(assets['crypto']['path'])
    codec = module(ROOT / 'poc/owner-private-payments/construction/codec.py',
                   assets['codec_sha256'], '_kpx7_wallet_construction')
    wire = module(ROOT / 'poc/owner-private-payments/verification/wire.py',
                  assets['wire_sha256'], '_kpx7_wallet_public_wire')
    return assets, relation, c, codec, wire


def session_context(a, codec):
    raw = stable_read(a.session)
    need(digest(raw) == a.session_sha256, 'external-public-session-pin')
    session, session_sha = codec.session(raw, PROGRAM_SHA)
    need(session_sha == digest(codec.canonical_json(session)) and session['domain_hex'] == DOMAIN.hex(),
         'canonical-common-session')
    return session, session_sha


def validate_context(raw, expected, session, wire):
    need(digest(raw) == expected == session['public_effects_context_sha256'], 'common-premix-context-pin')
    context = parse(raw); fields(context, CONTEXT_FIELDS, 'premix-context-fields')
    need(context['schema'] == 'kpx7-wallet-premix-context/v1'
         and context['domain_hex32'] == DOMAIN.hex()
         and context['component_profile_sha256'] == session['circuit_profile_sha256'], 'premix-context-domain')
    state = wire.parse_state(hx(context['prior_state_hex112'], 112))
    need(digest(state.raw) == session['prior_state_digest'] and state.cm_count == 3
         and state.nf_count == 1, 'selected-unfunded-prior-state')
    point = hx(context['previous_outpoint_hex36'], 36)
    need(point[:32] != bytes(32) and type(context['reserve_sompi']) is int
         and MIN_NOTE <= context['reserve_sompi'] <= MAX_VALUE, 'premix-native-point-and-reserve')
    fee = context['fee_sompi']; shares = context['fee_shares_sompi']
    need(type(fee) is int and 0 < fee < context['reserve_sompi']
         and type(shares) is list and len(shares) == 3
         and all(type(v) is int and 0 <= v <= fee for v in shares)
         and sum(shares) == fee, 'approved-integer-fee-policy')
    need(type(context['initial_cms_hex32']) is list and len(context['initial_cms_hex32']) == 3,
         'initial-public-CM-prefix')
    cms = [hx(value, 32) for value in context['initial_cms_hex32']]
    need(len(set(cms)) == 3, 'distinct-initial-CMs')
    tree = recipient().Tree(16, cms, b'KPX1CMN\0', wire.CM_EMPTY)
    need(tree.root == state.cm_root, 'authenticated-original-CM-prefix')
    tail = context['native_tail_hex']
    need(type(tail) is str and len(tail) % 2 == 0 and tail
         and all(c in '0123456789abcdef' for c in tail), 'approved-native-template-tail')
    return context, tree


def initialize(a):
    need(not (a.owner / 'OWNER.json').exists(), 'fresh-owner-required')
    amount(a.admission_sompi); need(uint(a.position, 32) < 3, 'initial-position')
    participant = hx(a.participant_id, 32); need(participant != bytes(32), 'participant-identity')
    c = crypto(a.crypto); v2 = recipient()
    seed = secrets.token_bytes(32); wallet = v2.Receiver(seed, DOMAIN, c)
    receipt = v2.Receipt.for_invoice(wallet.invoice(0), a.admission_sompi, secrets.token_bytes(32))
    # The whole authority is born here. No trusted supervisor creates a seed
    # dictionary or opens this file afterwards.
    private_save(a.owner / 'OWNER.json', {'schema': 'kpx7-unfunded-owner-state/v1',
        'domain_hex32': DOMAIN.hex(), 'participant_id_hex32': participant.hex(),
        'seed_hex32': seed.hex(), 'initial_position': a.position,
        'input_receipt_hex216': receipt.encode().hex()})
    for party in range(3):
        write_new(a.owner / ('RECEIVE-INVOICE-' + str(party) + '.bin'),
                  participant + wallet.invoice(1 + party).encode(), 0o400)
    public_save(a, {'schema': 'kpx7-unfunded-owner-public/v1', 'domain_hex32': DOMAIN.hex(),
        'participant_id_hex32': participant.hex(), 'initial_cm_hex32': receipt.commitment().hex(),
        'initial_position': a.position, 'admission_sompi': a.admission_sompi})


def private_peer_invoice(raw, session, destination, sender):
    need(len(raw) == 240 and raw[:32] == hx(session['roster'][destination], 32),
         'private-peer-participant-and-invoice-binding')
    invoice = recipient().Invoice.parse(raw[32:])
    need(invoice.domain == DOMAIN and invoice.index == 1 + sender, 'private-peer-invoice-context')
    return invoice


def prepare(a):
    previous = no_authorized_attempt(a)
    assets, relation, c, codec, wire = load_assets(a, 'prepare')
    session, session_sha = session_context(a, codec)
    need(session['circuit_profile_sha256'] == assets['component_profile_sha256'], 'selected-component-profile')
    context_raw = stable_read(a.context)
    context, tree = validate_context(context_raw, a.context_sha256, session, wire)
    need(type(a.party) is int and 0 <= a.party < 3, 'three-party-index')
    for old in previous:
        old_session = private_json(old / 'SESSION.json')
        need(old_session['session_sha256'] != session_sha, 'fresh-attempt-session-required')
    owner, input_receipt = owner_state(a)
    need(session['roster'][a.party] == owner['participant_id_hex32']
         and owner['initial_position'] == a.party
         and context['initial_cms_hex32'][a.party] == input_receipt.commitment().hex(),
         'own-original-input-admission')
    wallet = recipient().Receiver(hx(owner['seed_hex32'], 32), DOMAIN, c)
    expected_invoice = wallet.invoice(input_receipt.index)
    need(input_receipt.invoice(expected_invoice.delivery_pk) == expected_invoice, 'own-original-note-rederived')
    available = input_receipt.value_sompi - context['fee_shares_sompi'][a.party]
    need(2 * MIN_NOTE <= available <= MAX_VALUE, 'own-approved-fee-and-two-positive-outputs')
    rin = secrets.randbelow(Q).to_bytes(32, 'little')
    cv = relation.commit(input_receipt.value_sompi, rin)
    nf = wallet.nullifier(input_receipt, owner['initial_position'])
    need(nf != bytes(32), 'original-nonzero-NF')
    candidates = [i for i in range(3) if i != a.party]
    destination = candidates[secrets.randbelow(len(candidates))]
    # The recipient and amount are chosen privately, not in host argv or a
    # central fixture plan. All output metadata has fixed-width encodings.
    payment = MIN_NOTE + secrets.randbelow(available - 2 * MIN_NOTE + 1)
    peer_raw = stable_read(Path('/peers') / (str(destination) + '.bin'), private=True)
    peer = private_peer_invoice(peer_raw, session, destination, a.party)
    invoices = [peer, wallet.invoice(4)]
    values = [payment, available - payment]
    rows, private_outputs, output_blinds, truth = [], [], [], []
    for index, (invoice, value) in enumerate(zip(invoices, values)):
        receipt = recipient().Receipt.for_invoice(invoice, amount(value), secrets.token_bytes(32))
        cf = c.seal(invoice.delivery_pk, receipt.encode()); need(len(cf) == 264, 'CF264-width')
        blind = secrets.randbelow(Q).to_bytes(32, 'little'); output_blinds.append(int.from_bytes(blind, 'little'))
        out_cv = relation.commit(value, blind); cm = receipt.commitment(); cfh = bytes.fromhex(digest(cf))
        statement = b'KPX7OU01' + DOMAIN + cm + out_cv + cfh
        proof = relation.prove('output', statement, {'schema': 'kpx7-owner-private-output-witness/v1',
            'note_hex168': receipt.note_bytes().hex(), 'blind_hex32': blind.hex()})
        row = cm + out_cv + cf + cfh + proof; need(len(row) == 520, 'complete-output-tuple')
        relation.output(row); rows.append(row)
        private_outputs.append({'tuple_hex520': row.hex(), 'receipt_hex216': receipt.encode().hex(),
            'blind_hex32': blind.hex(), 'recipient_id_hex32': session['roster'][destination if index == 0 else a.party]})
        truth.append({'tuple_sha256': digest(row), 'cm_hex32': cm.hex(),
            'recipient_id_hex32': session['roster'][destination if index == 0 else a.party],
            'value_hex8': value.to_bytes(8, 'little').hex(), 'kind': 'payment' if index == 0 else 'change'})
    beta = (int.from_bytes(rin, 'little') - sum(output_blinds)) % Q
    packed = codec.owner_input(rows, beta)
    need(len(packed) == 2695 and len(packed.splitlines()) == 35, 'fixed-private-MPC-input-metadata')
    input_file = a.mpc / ('Input-P' + str(a.party) + '-0')
    archive_pre_authorization_input(a, previous, input_file)
    directory = a.owner / 'attempts'; directory.mkdir(mode=0o700, exist_ok=True)
    attempt = directory / str(len(previous) + 1).zfill(6); attempt.mkdir(mode=0o700)
    private_save(attempt / 'SESSION.json', {'session': session, 'session_sha256': session_sha})
    write_new(attempt / 'CONTEXT.json', context_raw)
    write_new(input_file, packed, 0o400); info = input_file.stat()
    private_save(attempt / 'STATE.json', {'schema': 'kpx7-private-owner-attempt/v1',
        'session_sha256': session_sha, 'party': a.party, 'rin_hex32': rin.hex(),
        'nf_hex32': nf.hex(), 'cv_hex64': cv.hex(), 'outputs': private_outputs,
        'input_device_hex8': info.st_dev.to_bytes(8, 'little').hex(),
        'input_inode_hex8': info.st_ino.to_bytes(8, 'little').hex()})
    private_save(attempt / 'TRUTH.json', {'schema': 'kpx7-private-owner-output-truth/v1',
        'session_sha256': session_sha, 'creator_participant_id_hex32': owner['participant_id_hex32'],
        'outputs': truth})
    public_save(a, {'schema': 'kpx7-owner-input-ready/v1',
        'participant_id_hex32': owner['participant_id_hex32'], 'session_sha256': session_sha,
        'input_cm_hex32': input_receipt.commitment().hex(), 'nf_hex32': nf.hex(), 'cv_hex64': cv.hex(),
        'own_output_count': 2, 'mpc_input_written': True, 'financial_authorization': False})


def authorize(a):
    attempts = no_authorized_attempt(a)
    need(attempts, 'private-attempt-required'); attempt = attempts[-1]
    assets, relation, c, codec, wire = load_assets(a, 'authorize')
    session, session_sha = session_context(a, codec)
    need(session['circuit_profile_sha256'] == assets['component_profile_sha256'], 'selected-component-profile')
    selected_session = private_json(attempt / 'SESSION.json')
    need(selected_session == {'session': session, 'session_sha256': session_sha}, 'same-owner-attempt-session')
    context_raw = stable_read(attempt / 'CONTEXT.json', private=True)
    context, tree = validate_context(context_raw, session['public_effects_context_sha256'], session, wire)
    state = private_json(attempt / 'STATE.json'); owner, input_receipt = owner_state(a)
    need(state['session_sha256'] == session_sha and session['roster'][state['party']] == owner['participant_id_hex32'],
         'same-private-owner-attempt')
    input_file = a.mpc / ('Input-P' + str(state['party']) + '-0'); info = input_file.stat()
    need(info.st_dev.to_bytes(8, 'little').hex() == state['input_device_hex8']
         and info.st_ino.to_bytes(8, 'little').hex() == state['input_inode_hex8']
         and info.st_size == 2695, 'own-private-MPC-input-identity')
    result_path = checked(a.mpc / a.own_mpc_result)
    need(result_path.is_relative_to(a.mpc) and result_path.name == 'OWN-MPC-PROJECTION.json',
         'own-engine-result-only')
    mixed = private_json(result_path)
    fields(mixed, ('schema', 'session_sha256', 'rows_hex', 'delta_decimal',
                   'tuple_bytes', 'row_count', 'scope'), 'own-MPC-result-fields')
    need(mixed['schema'] == 'kpx7-mixed-complete-outputs/v1' and mixed['session_sha256'] == session_sha
         and mixed['tuple_bytes'] == 520 and mixed['row_count'] == 6
         and mixed['scope'] == 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION', 'own-completed-MPC-session')
    need(type(mixed['rows_hex']) is list and len(mixed['rows_hex']) == 6
         and type(mixed['tuple_bytes']) is int and type(mixed['row_count']) is int,
         'typed-own-MPC-result-shape')
    rows = [hx(v, 520) for v in mixed['rows_hex']]
    need(len(rows) == len(set(rows)) == 6, 'six-unique-complete-MPC-rows')
    text = mixed['delta_decimal']
    need(type(text) is str and text.isascii() and text.isdigit() and str(int(text)) == text
         and 0 <= int(text) < Q, 'canonical-MPC-aggregate')
    delta = int(text).to_bytes(32, 'little')
    raw = stable_read(a.projection)
    need(digest(raw) == a.projection_sha256, 'selected-projection-pin')
    wire.validate_public(raw); projection = wire.parse_projection(raw); body = projection.body
    need(body.session == bytes.fromhex(session_sha)
         and body.roster == wire.sha(b'KPX7RO01', *(bytes.fromhex(p) for p in session['roster']))
         and body.point == hx(context['previous_outpoint_hex36'], 36)
         and body.old_state.raw == hx(context['prior_state_hex112'], 112)
         and body.old_reserve == context['reserve_sompi'] and body.fee == context['fee_sompi']
         and body.payout == 0 and body.new_reserve + body.fee == body.old_reserve,
         'exact-approved-native-effects-and-prior-state')
    tail = bytes.fromhex(context['native_tail_hex'])
    need(projection.input_spk == wire.state_spk(body.old_state.raw, tail)
         and projection.output_spk == wire.state_spk(body.new_state.raw, tail), 'selected-native-template-effects')
    need([out.tuple_bytes for out in body.outputs] == rows and body.delta == delta,
         'same-own-engine-pool-and-aggregate')
    for row in rows:
        relation.output(row)
    need(type(state['outputs']) is list and len(state['outputs']) == 2, 'two-private-created-outputs')
    total_created = 0
    for expected in state['outputs']:
        row = hx(expected['tuple_hex520'], 520)
        need(rows.count(row) == 1, 'own-complete-output-inclusion')
        receipt = recipient().Receipt.parse(hx(expected['receipt_hex216'], 216))
        total_created += receipt.value_sompi
        need(receipt.commitment() == row[:32]
             and relation.commit(receipt.value_sompi, hx(expected['blind_hex32'], 32)) == row[32:96],
             'own-output-CM-value-opening')
    need(total_created == input_receipt.value_sompi - context['fee_shares_sompi'][state['party']],
         'own-private-output-and-approved-fee-conservation')
    wallet = recipient().Receiver(hx(owner['seed_hex32'], 32), DOMAIN, c)
    own_change = state['outputs'][1]
    change_row = hx(own_change['tuple_hex520'], 520)
    change_receipt = wallet.open(change_row[96:360])
    need(change_receipt.encode().hex() == own_change['receipt_hex216'] and change_receipt.index == 4,
         'own-change-delivery-rederivation')
    # Recognize only inside this owner. No owned output position/hash/count map
    # is returned to the coordinator. Output proof verification preceded this.
    for row in rows:
        try:
            received = wallet.open(row[96:360])
        except recipient().Invalid:
            continue
        need(received.commitment() == row[:32], 'owned-delivery-CM')
    own_nf = wallet.nullifier(input_receipt, owner['initial_position'])
    own_cv = relation.commit(input_receipt.value_sompi, hx(state['rin_hex32'], 32))
    need(own_nf.hex() == state['nf_hex32'] and own_cv.hex() == state['cv_hex64']
         and sum(spend.nf == own_nf and spend.cv == own_cv for spend in body.spends) == 1,
         'own-stable-original-NF-and-fresh-CV')
    relation.balance([s.cv for s in body.spends], [o.cv for o in body.outputs], body.fee, body.delta)
    effects = wire.effects_digest(raw)
    # Irreversible local barrier is durable BEFORE a usable authorization is
    # generated. There is no reveal/blame/revalidate route past this barrier.
    write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
    statement = b'KPX7SP01' + DOMAIN + body.old_state.cm_root + own_nf + own_cv + effects
    keys = wallet.keys(input_receipt.index)
    proof = relation.prove('spend', statement, {'schema': 'kpx7-owner-private-spend-witness/v1',
        'note_hex168': input_receipt.note_bytes().hex(), 's_hex32': keys.owner_secret.hex(),
        'k_hex32': keys.nf_secret.hex(), 'position': owner['initial_position'],
        'cm_path_hex': [p.hex() for p in tree.path(owner['initial_position'])],
        'blind_hex32': state['rin_hex32']})
    exported = {'schema': 'kpx7-owner-spend-authorization/v1', 'session_sha256': session_sha,
        'effects_digest_hex32': effects.hex(), 'nf_hex32': own_nf.hex(), 'cv_hex64': own_cv.hex(),
        'statement_hex200': statement.hex(), 'proof_hex128': proof.hex()}
    private_save(attempt / 'AUTHORIZATION.json', exported)
    public_save(a, exported)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'prepare', 'authorize'))
    for name in ('owner', 'mpc', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('crypto', 'assets', 'session', 'context', 'projection'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'session-sha256', 'context-sha256', 'projection-sha256', 'participant-id'):
        p.add_argument('--' + name)
    for name in ('position', 'admission-sompi', 'party'):
        p.add_argument('--' + name, type=int)
    p.add_argument('--own-mpc-result', type=Path)
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        a = p.parse_args(); a.owner = checked(a.owner); a.mpc = checked(a.mpc); a.output = checked(a.output)
        need(a.owner.is_dir() and a.mpc.is_dir() and a.output.is_dir(), 'selected-owner-namespace')
        with owner_lock(a):
            {'init': initialize, 'prepare': prepare, 'authorize': authorize}[a.operation](a)
        print(encoded({'operation': a.operation, 'completed': True}).decode())
    except Exception:
        p.exit(2, 'owner operation refused; private material not disclosed\n')

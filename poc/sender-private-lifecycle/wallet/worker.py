#!/usr/bin/env python3
"""Owner-local sender-private operations using unchanged financial proofs.

NF/CV and Spend proofs enter authenticated MPC only as private owner streams.
Public per-owner readiness exports contain no such row or proof identifier.
"""
import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import secrets
import stat

import history
from paths import attributes, checked, digest, encoded, fields, hx, need, parse, stable_read, uint, write_new
from support import DOMAIN, Q, MIN_NOTE, MAX_VALUE, CRYPTO_SHA, ROOT, Relations, amount, crypto, module, recipient

BACKUP_FIELDS = ('schema', 'domain_hex32', 'participant_id_hex32', 'seed_hex32')
ASSET_FIELDS = ('schema', 'domain_hex32', 'component_profile', 'component_profile_sha256',
    'relation', 'crypto', 'spend', 'output', 'exit', 'codec_sha256', 'wire_sha256', 'program_source_sha256')
CONTEXT_FIELDS = ('schema', 'domain_hex32', 'component_profile_sha256', 'prior_state_hex112',
    'previous_outpoint_hex36', 'reserve_sompi', 'fee_sompi', 'fee_shares_sompi', 'native_tail_hex')


def private_json(path):
    return parse(stable_read(path, private=True))


def private_save(path, value):
    write_new(path, encoded(value) + b'\n')


def public_save(a, value):
    write_new(a.output / 'PUBLIC.json', encoded(value) + b'\n', 0o400)


def decode_backup(raw):
    value = parse(raw); fields(value, BACKUP_FIELDS, 'seed-only-backup-fields')
    need(value['schema'] == 'kpx8-owner-seed-backup/v1' and value['domain_hex32'] == DOMAIN.hex(),
         'selected-seed-backup-domain')
    need(hx(value['participant_id_hex32'], 32) != bytes(32), 'participant-identity')
    hx(value['seed_hex32'], 32)
    return value


def own_wallet(a, c):
    owner = decode_backup(stable_read(a.owner / 'BACKUP.json', private=True))
    return owner, recipient().Receiver(hx(owner['seed_hex32'], 32), DOMAIN, c)


def round_alias(owner, round_id):
    """Reuse the pinned recipient HMAC derivation under a separate purpose.

    The 32-byte public round ID is selected before constructing SESSION, so
    neither the alias nor its derivation requires the resulting session hash.
    Native keys, note/nullifier keys and receipt indices are unchanged.
    """
    alias_domain = hx(digest(b'KPX9AL01' + DOMAIN + hx(round_id, 32)), 32)
    result = recipient().derive(hx(owner['seed_hex32'], 32), alias_domain,
                                b'ROUNDAL\0', 0)
    need(result != bytes(32), 'nonzero-round-alias')
    return result.hex()


def alias(a):
    # Authenticate the fixed derivation source before opening the own backup.
    recipient()
    owner = decode_backup(stable_read(a.owner / 'BACKUP.json', private=True))
    public_save(a, {'schema': 'kpx9-owner-round-alias/v1',
        'session_id_hex32': hx(a.round_id, 32).hex(),
        'round_alias_hex32': round_alias(owner, a.round_id)})


@contextmanager
def owner_lock(a):
    fd = os.open(checked(a.owner / 'OWNER-LOCK'),
        os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, 'own-private-operation-lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def attempts(a):
    directory = a.owner / 'attempts'
    if not directory.exists():
        return []
    result = sorted(directory.iterdir())
    need(all(p.is_dir() and len(p.name) == 6 and p.name.isascii() and p.name.isdigit()
             and int(p.name) > 0 for p in result), 'generic-private-attempt-names')
    return result


def reconcile(a, accepted, *, require_settled=True):
    # Read only minimal guards after authorization, never an old output map.
    result = attempts(a); spent = {entry[0].hex() for entry in accepted.state.entries}
    for attempt in result:
        if (attempt / 'DISCLOSURE-CLOSED').exists() and not (attempt / 'RECONCILED').exists():
            guard = private_json(attempt / 'GUARD.json')
            if guard['nf_hex32'] in spent:
                write_new(attempt / 'RECONCILED', b'', 0o400)
            else:
                need(not require_settled, 'authorization-may-settle-reconciliation-required')
    return result


def new_attempt(a, guard):
    parent = a.owner / 'attempts'
    if not parent.exists():
        parent.mkdir(mode=0o700)
        sync_directory(a.owner)
    attempt = parent / str(len(attempts(a)) + 1).zfill(6); attempt.mkdir(mode=0o700)
    sync_directory(parent)
    private_save(attempt / 'GUARD.json', guard)
    return attempt


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_assets(a, mode):
    raw = stable_read(a.assets); need(digest(raw) == a.assets_sha256, 'external-wallet-assets-pin')
    assets = parse(raw); fields(assets, ASSET_FIELDS, 'wallet-assets-fields')
    need(assets['schema'] == 'kpx8-wallet-assets/v1' and assets['domain_hex32'] == DOMAIN.hex()
         and assets['crypto']['sha256'] == CRYPTO_SHA, 'selected-lifecycle-assets')
    for name in ('component_profile_sha256', 'codec_sha256', 'wire_sha256', 'program_source_sha256'):
        hx(assets[name], 32)
    for name in ('relation', 'crypto'):
        fields(assets[name], ('path', 'sha256'), 'selected-program-fields'); hx(assets[name]['sha256'], 32)
    for name in ('spend', 'output', 'exit'):
        fields(assets[name], ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'selected-parameter-fields')
        hx(assets[name]['manifest_sha256'], 32); hx(assets[name]['pk_sha256'], 32)
    relation = Relations(assets, mode)  # authenticate whole needed PK before seed
    c = crypto(assets['crypto']['path'])
    codec = module(ROOT / 'poc/sender-private-lifecycle/admission/codec.py',
                   assets['codec_sha256'], '_kpx9_wallet_construction')
    wire = module(ROOT / 'poc/owner-private-lifecycle/verification/wire.py',
                   assets['wire_sha256'], '_kpx9_wallet_public_wire')
    return assets, relation, c, codec, wire


def session_context(a, assets, codec):
    raw = stable_read(a.session); need(digest(raw) == a.session_sha256, 'external-public-session-pin')
    session, selected = codec.session(raw, assets['program_source_sha256'])
    need(selected == digest(codec.canonical_json(session)) and session['domain_hex'] == DOMAIN.hex()
         and session['circuit_profile_sha256'] == assets['component_profile_sha256'], 'selected-session')
    return session, selected


def context_and_history(a, assets, relation, codec, wire, session=None, private_context=None):
    raw = stable_read(a.context) if private_context is None else private_context
    expected = a.context_sha256 if session is None else session['public_effects_context_sha256']
    need(digest(raw) == expected, 'external-context-pin')
    context = parse(raw); fields(context, CONTEXT_FIELDS, 'lifecycle-context-fields')
    need(context['schema'] == 'kpx8-wallet-premix-context/v1' and context['domain_hex32'] == DOMAIN.hex()
         and context['component_profile_sha256'] == assets['component_profile_sha256'], 'context-domain-profile')
    state = wire.parse_state(hx(context['prior_state_hex112'], 112))
    if session is not None:
        need(digest(state.raw) == session['prior_state_digest'], 'session-prior-state')
    fee = uint(context['fee_sompi']); reserve = uint(context['reserve_sompi'])
    shares = context['fee_shares_sompi']
    need(0 < fee <= MAX_VALUE and 0 <= reserve <= MAX_VALUE
         and type(shares) is list and len(shares) == 3
         and all(type(v) is int and 0 <= v <= fee for v in shares) and sum(shares) == fee,
         'approved-integer-fee-policy')
    tail = context['native_tail_hex']
    need(type(tail) is str and tail and len(tail) % 2 == 0
         and all(c in '0123456789abcdef' for c in tail), 'selected-native-tail')
    raw_history = stable_read(a.history); need(digest(raw_history) == a.history_sha256, 'complete-history-pin')
    accepted = history.load(raw_history, {'state_hex112': context['prior_state_hex112'],
        'reserve_sompi': reserve, 'outpoint_hex36': context['previous_outpoint_hex36']},
        relation, wire, codec, assets['program_source_sha256'])
    return context, accepted


def select_claim(accepted, wallet, participant, kind, minimum=MIN_NOTE):
    available = [row for row in history.claims(accepted, wallet, participant)
                 if not row['spent'] and row['receipt'].value_sompi >= minimum]
    need(kind in ('initial', 'received', 'change', 'any', 'received-or-change'), 'note-selection-policy')
    if kind == 'received-or-change':
        matching = [row for row in available if row['kind'] == 'received']
        if not matching:
            matching = [row for row in available if row['kind'] == 'change']
    else:
        matching = [row for row in available if kind == 'any' or row['kind'] == kind]
    need(matching, 'no-available-claim-for-private-selection')
    return max(matching, key=lambda row: (row['receipt'].value_sompi, -row['position']))


def initialize(a):
    need(not (a.owner / 'BACKUP.json').exists(), 'fresh-owner-required')
    amount(a.admission_sompi); need(uint(a.position, 32) < 3, 'initial-position')
    participant = hx(a.participant_id, 32); need(participant != bytes(32), 'participant-identity')
    c = crypto(a.crypto); seed = secrets.token_bytes(32); wallet = recipient().Receiver(seed, DOMAIN, c)
    owner = {'schema': 'kpx8-owner-seed-backup/v1', 'domain_hex32': DOMAIN.hex(),
             'participant_id_hex32': participant.hex(), 'seed_hex32': seed.hex()}
    receipt = recipient().Receipt.for_invoice(wallet.invoice(0), a.admission_sompi, secrets.token_bytes(32))
    cf = c.seal(wallet.invoice(0).delivery_pk, receipt.encode())
    need(len(cf) == 264 and wallet.open(cf) == receipt, 'own-initial-delivery-roundtrip')
    record = receipt.note_bytes() + receipt.commitment() + cf + hx(digest(cf), 32)
    funding = wallet.keys(0xffffffff).invoice.native_pk
    private_save(a.owner / 'BACKUP.json', owner)
    public = {'schema': 'kpx8-owner-initial-public/v1', 'domain_hex32': DOMAIN.hex(),
        'participant_id_hex32': participant.hex(), 'initial_position': a.position,
        'admission_sompi': a.admission_sompi, 'initial_record_hex496': record.hex(),
        'funding': {'xonly_hex32': funding.hex(), 'script_public_key': (b'\0\0\x20' + funding + b'\xac').hex()}}
    private_save(a.owner / 'INITIAL-PUBLIC.json', public); public_save(a, public)


def restore(a):
    need(not (a.owner / 'BACKUP.json').exists() and not attempts(a), 'fresh-restoration-runtime')
    owner = decode_backup(stable_read(a.backup, private=True))
    private_save(a.owner / 'BACKUP.json', owner)
    public_save(a, {'schema': 'kpx9-owner-restored/v1', 'domain_hex32': DOMAIN.hex(),
        'seed_only': True, 'private_maps_imported': False})


def invoice(a):
    assets, relation, c, codec, wire = load_assets(a, 'scan')
    session, session_sha = session_context(a, assets, codec)
    _, accepted = context_and_history(a, assets, relation, codec, wire, session)
    owner, wallet = own_wallet(a, c); reconcile(a, accepted)
    own_alias = round_alias(owner, session['session_id'])
    need(own_alias in session['roster'], 'own-session-round-alias')
    for sender in range(3):
        index = history.invoice_index(session_sha, sender, b'PAYMENT\0')
        target = a.owner / ('RECEIVE-INVOICE-' + str(sender) + '.bin')
        if target.exists():
            archive = a.owner / 'invoices'; archive.mkdir(mode=0o700, exist_ok=True)
            os.rename(target, archive / (str(len(list(archive.iterdir())) + 1).zfill(6) + '.bin'))
        write_new(target, hx(own_alias, 32) + wallet.invoice(index).encode(), 0o400)
    public_save(a, {'schema': 'kpx9-owner-invoices-ready/v1', 'session_sha256': session_sha,
        'private_invoice_count': 3})


def prepare(a):
    assets, relation, c, codec, wire = load_assets(a, 'prepare')
    session, session_sha = session_context(a, assets, codec); context_raw = stable_read(a.context)
    context, accepted = context_and_history(a, assets, relation, codec, wire, session)
    owner, wallet = own_wallet(a, c); previous = reconcile(a, accepted)
    need(type(a.party) is int and 0 <= a.party < 3
         and session['roster'][a.party] == round_alias(owner, session['session_id']), 'own-session-party')
    need(all(private_json(p / 'GUARD.json')['session_sha256'] != session_sha for p in previous), 'fresh-session-required')
    share = context['fee_shares_sompi'][a.party]
    selected = select_claim(accepted, wallet, owner['participant_id_hex32'], a.note_kind, 2 * MIN_NOTE + share)
    receipt, position, nf = selected['receipt'], selected['position'], selected['nf']
    available = receipt.value_sompi - share; rin = secrets.randbelow(Q).to_bytes(32, 'little')
    cv = relation.commit(receipt.value_sompi, rin)
    destinations = [i for i in range(3) if i != a.party]; destination = destinations[secrets.randbelow(2)]
    raw_peer = stable_read(Path('/peers') / (str(destination) + '.bin'), private=True)
    need(len(raw_peer) == 240 and raw_peer[:32] == hx(session['roster'][destination], 32), 'private-peer-participant')
    peer = recipient().Invoice.parse(raw_peer[32:])
    need(peer.domain == DOMAIN and peer.index == history.invoice_index(session_sha, a.party, b'PAYMENT\0'),
         'fresh-private-peer-invoice')
    change_index = history.invoice_index(session_sha, a.party, b'CHANGE\0\0')
    need(change_index != peer.index, 'distinct-payment-change-indices')
    requested = getattr(a, 'payment_sompi', None)
    if requested is None:
        low = max(MIN_NOTE, available // 3); high = min(available - MIN_NOTE, available - low)
        need(low <= high, 'two-positive-output-policy'); payment = low + secrets.randbelow(high - low + 1)
    else:
        payment = amount(requested)
        need(available - payment >= MIN_NOTE, 'exact-requested-payment-and-positive-change')
    rows, outputs, blinds = [], [], []
    for iv, value, target in ((peer, payment, destination), (wallet.invoice(change_index), available - payment, a.party)):
        received = recipient().Receipt.for_invoice(iv, amount(value), secrets.token_bytes(32))
        cf = c.seal(iv.delivery_pk, received.encode()); need(len(cf) == 264, 'CF264-width')
        blind = secrets.randbelow(Q).to_bytes(32, 'little'); blinds.append(int.from_bytes(blind, 'little'))
        cm = received.commitment(); output_cv = relation.commit(value, blind); cfh = hx(digest(cf), 32)
        proof = relation.prove('output', b'KPX8OU01' + DOMAIN + cm + output_cv + cfh,
            {'schema': 'kpx8-owner-private-output-witness/v1', 'note_hex168': received.note_bytes().hex(), 'blind_hex32': blind.hex()})
        row = cm + output_cv + cf + cfh + proof; relation.output(row); rows.append(row)
        outputs.append({'tuple_hex520': row.hex(), 'receipt_hex216': received.encode().hex(),
            'blind_hex32': blind.hex(), 'recipient_id_hex32': session['roster'][target]})
    packed = codec.owner_input(nf + cv, rows, (int.from_bytes(rin, 'little') - sum(blinds)) % Q)
    need(len(packed) == 3003, 'fixed-private-MPC-input-width')
    input_file = a.mpc / ('Input-P' + str(a.party) + '-0')
    if input_file.exists():
        need(previous, 'prior-MPC-input-attempt-required')
        os.rename(input_file, previous[-1] / 'MPC-INPUT.bin')
    write_new(input_file, packed, 0o400); info = input_file.stat()
    attempt = new_attempt(a, {'session_sha256': session_sha, 'nf_hex32': nf.hex(),
        'input_device': info.st_dev, 'input_inode': info.st_ino})
    private_save(attempt / 'SESSION.json', session); write_new(attempt / 'CONTEXT.json', context_raw)
    private_save(attempt / 'STATE.json', {'party': a.party, 'position': position,
        'receipt_hex216': receipt.encode().hex(), 'rin_hex32': rin.hex(), 'nf_hex32': nf.hex(),
        'cv_hex64': cv.hex(), 'outputs': outputs, 'change_index': change_index, 'selected_kind': selected['kind']})
    public_save(a, {'schema': 'kpx9-owner-input-ready/v1', 'session_sha256': session_sha,
        'own_output_count': 2, 'mpc_input_written': True, 'financial_authorization': False})


def authorization_target(a, directory, party, accepted, current_attempt, codec):
    """Archive only an exact, settled own phase-two stream before reuse.

    A phase-two directory can survive a successful round. Its previous private
    stream is no longer useful authority only after its stable NF is spent in
    the authenticated current history. Match the complete bytes to one settled
    own attempt; neither a filename nor a local completion flag is sufficient.
    """
    need(type(party) is int and 0 <= party < 3, 'private-authorization-party')
    target = checked(directory / ('Input-P' + str(party) + '-0'))
    need(target.parent == directory, 'private-authorization-input-parent')
    if not target.exists():
        return target
    before = target.lstat()
    raw = stable_read(target, before, private=True)
    try:
        row = codec.unpack(codec.decode_stream(raw, 'authorize'), 224)
    except (ValueError, TypeError, UnicodeError):
        need(False, 'fresh-private-authorization-input-malformed')
    need(codec.authorization_input(row) == raw, 'fresh-private-authorization-input-malformed')
    old_nf = row[:32]
    need(old_nf != bytes(32) and old_nf in {entry[0] for entry in accepted.state.entries},
         'fresh-private-authorization-input-unsettled-NF')
    matches = []
    for previous in attempts(a):
        if previous >= current_attempt:
            continue
        guard = private_json(previous / 'GUARD.json')
        if guard['nf_hex32'] != old_nf.hex():
            continue
        # Never reopen an unsettled attempt's private authorization/state.
        if not ((previous / 'DISCLOSURE-CLOSED').exists()
                and (previous / 'RECONCILED').exists()
                and (previous / 'AUTHORIZATION.json').exists()):
            continue
        authorization = private_json(previous / 'AUTHORIZATION.json')
        if authorization.get('schema') != 'kpx8-owner-spend-authorization/v1':
            continue
        fields(authorization, ('schema', 'session_sha256', 'effects_digest_hex32',
            'nf_hex32', 'cv_hex64', 'statement_hex200', 'proof_hex128'),
            'prior-private-spend-authorization-fields')
        expected = (hx(authorization['nf_hex32'], 32) + hx(authorization['cv_hex64'], 64)
                    + hx(authorization['proof_hex128'], 128))
        if expected != row:
            continue
        state = private_json(previous / 'STATE.json')
        statement = hx(authorization['statement_hex200'], 200)
        hx(guard['session_sha256'], 32)
        need(type(state['party']) is int and state['party'] == party
             and state['nf_hex32'] == guard['nf_hex32'] == authorization['nf_hex32']
             and state['cv_hex64'] == authorization['cv_hex64']
             and authorization['session_sha256'] == guard['session_sha256']
             and statement[:40] == b'KPX8SP01' + DOMAIN
             and statement[72:168] == row[:96]
             and statement[168:] == hx(authorization['effects_digest_hex32'], 32),
             'prior-private-spend-party-session-row-binding')
        matches.append(previous)
    need(len(matches) == 1, 'fresh-private-authorization-input-unregistered-or-unsettled')
    archive = checked(matches[0] / 'MPC-AUTHORIZATION-INPUT.bin')
    if archive.exists():
        # Complete an interrupted archive without overwriting any prior file.
        need(stable_read(archive, private=True) == raw,
             'prior-private-authorization-archive-conflict')
    else:
        write_new(archive, raw, 0o400)  # O_EXCL; file and containing directory fsynced.
    need(attributes(target.lstat()) == attributes(before),
         'prior-private-authorization-input-changed')
    target.unlink()
    sync_directory(directory)
    sync_directory(matches[0])
    return target


def authorize(a):
    previous = attempts(a); need(previous, 'private-attempt-required'); attempt = previous[-1]
    need(not (attempt / 'DISCLOSURE-CLOSED').exists(), 'authorization-may-settle-reconciliation-required')
    need(a.authorization_mpc is not None, 'own-authorization-directory-required')
    authorization_mpc = checked(a.authorization_mpc)
    need(authorization_mpc.is_dir()
         and all(authorization_mpc != p and not authorization_mpc.is_relative_to(p)
                 and not p.is_relative_to(authorization_mpc) for p in (a.owner, a.mpc))
         and stat.S_IMODE(authorization_mpc.stat().st_mode) == 0o700,
         'separate-private-authorization-directory')
    assets, relation, c, codec, wire = load_assets(a, 'authorize')
    session, session_sha = session_context(a, assets, codec)
    need(private_json(attempt / 'SESSION.json') == session, 'same-owner-attempt-session')
    context, accepted = context_and_history(a, assets, relation, codec, wire, session,
        stable_read(attempt / 'CONTEXT.json', private=True))
    state = private_json(attempt / 'STATE.json'); owner, wallet = own_wallet(a, c)
    receipt = recipient().Receipt.parse(hx(state['receipt_hex216'], 216)); guard = private_json(attempt / 'GUARD.json')
    need(guard['session_sha256'] == session_sha
         and session['roster'][state['party']] == round_alias(owner, session['session_id']),
         'same-private-owner-attempt')
    info = (a.mpc / ('Input-P' + str(state['party']) + '-0')).stat()
    need((info.st_dev, info.st_ino, info.st_size) == (guard['input_device'], guard['input_inode'], 3003), 'own-MPC-input-identity')
    result_path = checked(a.mpc / a.own_mpc_result)
    need(result_path.is_relative_to(a.mpc) and result_path.name == 'OWN-MPC-PROJECTION.json', 'own-engine-result-only')
    mixed = private_json(result_path)
    fields(mixed, ('schema', 'session_sha256', 'input_rows_hex96', 'rows_hex', 'delta_decimal', 'scope'),
        'own-MPC-result-fields')
    need(mixed['schema'] == 'kpx9-mixed-inputs-outputs/v1' and mixed['session_sha256'] == session_sha
         and mixed['scope'] == 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION', 'own-MPC-session')
    rows = [hx(row, 520) for row in mixed['rows_hex']]; need(len(rows) == len(set(rows)) == 6, 'six-unique-MPC-rows')
    inputs = [hx(row, 96) for row in mixed['input_rows_hex96']]
    need(len(inputs) == len(set(inputs)) == 3
         and len({row[:32] for row in inputs}) == 3, 'three-unique-MPC-inputs')
    text = mixed['delta_decimal']
    need(type(text) is str and text.isascii() and text.isdigit() and str(int(text)) == text and 0 <= int(text) < Q,
         'canonical-MPC-aggregate')
    raw = stable_read(a.projection); need(digest(raw) == a.projection_sha256, 'projection-pin')
    wire.validate_public(raw); projection = wire.parse_projection(raw); body = projection.body
    need(body.session == hx(session_sha, 32)
         and body.roster == wire.sha(b'KPX8RO01', *(hx(p, 32) for p in session['roster']))
         and body.point == accepted.point and body.old_state.raw == accepted.state.state(DOMAIN)
         and body.old_reserve == accepted.reserve and body.fee == context['fee_sompi']
         and body.payout == 0 and body.new_reserve + body.fee == body.old_reserve, 'exact-approved-financial-effects')
    tail = bytes.fromhex(context['native_tail_hex'])
    need(projection.input_spk == wire.state_spk(body.old_state.raw, tail)
         and projection.output_spk == wire.state_spk(body.new_state.raw, tail), 'selected-native-policy')
    need([out.tuple_bytes for out in body.outputs] == rows and body.delta == int(text).to_bytes(32, 'little'),
         'same-own-engine-pool-and-aggregate')
    need([spend.nf + spend.cv for spend in body.spends] == inputs,
         'same-own-engine-shuffled-inputs')
    for row in rows:
        relation.output(row)
    need(type(state['outputs']) is list and len(state['outputs']) == 2, 'two-created-outputs')
    total = 0
    for expected in state['outputs']:
        row = hx(expected['tuple_hex520'], 520); created = recipient().Receipt.parse(hx(expected['receipt_hex216'], 216))
        need(rows.count(row) == 1 and created.commitment() == row[:32]
             and relation.commit(created.value_sompi, hx(expected['blind_hex32'], 32)) == row[32:96], 'own-output-inclusion')
        total += created.value_sompi
    need(total == receipt.value_sompi - context['fee_shares_sompi'][state['party']], 'own-integer-conservation')
    change = state['outputs'][1]; change_row = hx(change['tuple_hex520'], 520)
    opened = wallet.open(change_row[96:360])
    need(opened.encode().hex() == change['receipt_hex216'] and opened.index == state['change_index'], 'own-change-delivery')
    history.claims(history.History(accepted.state, accepted.reserve, accepted.point,
        [(row[:32], row[96:360]) for row in rows], [(session_sha, session['roster'])]),
        wallet, owner['participant_id_hex32'])
    nf = wallet.nullifier(receipt, state['position']); cv = relation.commit(receipt.value_sompi, hx(state['rin_hex32'], 32))
    need(nf.hex() == state['nf_hex32'] == guard['nf_hex32'] and cv.hex() == state['cv_hex64']
         and nf not in {entry[0] for entry in accepted.state.entries}
         and accepted.state.cms[state['position']] == receipt.commitment()
         and sum(s.nf == nf and s.cv == cv for s in body.spends) == 1, 'own-current-note-NF-CV')
    relation.balance([s.cv for s in body.spends], [o.cv for o in body.outputs], body.fee, body.delta)
    effects = wire.effects_digest(raw); keys = wallet.keys(receipt.index); path = accepted.state.cm.path(state['position'])
    target = authorization_target(a, authorization_mpc, state['party'], accepted, attempt, codec)
    write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
    statement = b'KPX8SP01' + DOMAIN + body.old_state.cm_root + nf + cv + effects
    proof = relation.prove('spend', statement, {'schema': 'kpx8-owner-private-spend-witness/v1',
        'note_hex168': receipt.note_bytes().hex(), 's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
        'position': state['position'], 'cm_path_hex': [path[i:i + 32].hex() for i in range(0, 512, 32)],
        'blind_hex32': state['rin_hex32']})
    export = {'schema': 'kpx8-owner-spend-authorization/v1', 'session_sha256': session_sha,
        'effects_digest_hex32': effects.hex(), 'nf_hex32': nf.hex(), 'cv_hex64': cv.hex(),
        'statement_hex200': statement.hex(), 'proof_hex128': proof.hex()}
    private_save(attempt / 'AUTHORIZATION.json', export)
    packed = codec.authorization_input(nf + cv + proof)
    need(len(packed) == 616, 'fixed-private-authorization-input-width')
    write_new(target, packed, 0o400)
    public_save(a, {'schema': 'kpx9-owner-authorization-ready/v1',
        'session_sha256': session_sha, 'effects_digest_hex32': effects.hex(),
        'authorization_input_written': True, 'proof_publicly_exported': False})


def scan(a):
    assets, relation, c, codec, wire = load_assets(a, 'scan')
    _, accepted = context_and_history(a, assets, relation, codec, wire)
    owner, wallet = own_wallet(a, c); owned = history.claims(accepted, wallet, owner['participant_id_hex32'])
    reconcile(a, accepted)
    parent = a.owner / 'scans'; parent.mkdir(mode=0o700, exist_ok=True)
    private_save(parent / (str(len(list(parent.iterdir())) + 1).zfill(6) + '.json'),
        {'checkpoint': accepted.checkpoint(), 'claims': [{'position': row['position'],
         'receipt_hex216': row['receipt'].encode().hex(), 'nf_hex32': row['nf'].hex(),
         'spent': row['spent'], 'kind': row['kind']} for row in owned]})
    terminal = accepted.reserve == 0
    recovered_payouts = final_payout_reconciliation(accepted, wallet, owner['participant_id_hex32'], owned)
    if terminal:
        need(all(row['spent'] for row in owned), 'terminal-scan-has-unspent-owned-claim')
    public_save(a, {'schema': 'kpx9-owner-scan-complete/v1', 'domain_hex32': DOMAIN.hex(),
        'history_sha256': a.history_sha256,
        'seed_only': True, 'scan_completed': True, 'private_claims_exported': False,
        'terminal_reconciled': terminal, 'native_payout_keys_rederived': recovered_payouts})


def payout_spk(accepted, wallet, owned, claim):
    """Existing native-key derivation at a fresh reproducible public index."""
    used = {row['receipt'].index for row in owned} | {0, 0xffffffff}
    need(accepted.point is not None, 'live-exit-point')
    for counter in range(1 << 32):
        raw = hx(digest(b'KPX8EP01' + DOMAIN + accepted.point + claim['nf']
                        + counter.to_bytes(4, 'little')), 32)
        index = int.from_bytes(raw[:8], 'little')
        if index not in used:
            return b'\0\0\x20' + wallet.keys(index).invoice.native_pk + b'\xac'
    need(False, 'fresh-native-payout-index-exhausted')


def final_payout_reconciliation(accepted, wallet, participant, owned):
    by_nf = {row['nf']: row for row in owned}
    for item in accepted.exits:
        if item['nf'] not in by_nf:
            continue
        prefix = history.History(accepted.state, accepted.reserve, item['point'],
            accepted.deliveries[:item['delivery_count']], accepted.sessions[:item['session_count']])
        known = history.claims(prefix, wallet, participant)
        need(payout_spk(prefix, wallet, known, by_nf[item['nf']]) == item['payout_spk'],
             'original-seed-must-rederive-historical-payout-key')
    return True


def exit_ready(a):
    assets, relation, c, codec, wire = load_assets(a, 'scan')
    _, accepted = context_and_history(a, assets, relation, codec, wire)
    owner, wallet = own_wallet(a, c); reconcile(a, accepted, require_settled=False)
    owned = history.claims(accepted, wallet, owner['participant_id_hex32'])
    if not any(not row['spent'] for row in owned):
        public_save(a, {'schema': 'kpx9-owner-no-unspent-claim/v1',
            'history_sha256': a.history_sha256, 'empty': True})
        return
    claim = select_claim(accepted, wallet, owner['participant_id_hex32'], a.note_kind)
    receipt = claim['receipt']
    spk = payout_spk(accepted, wallet, owned, claim)
    public_save(a, {'schema': 'kpx9-owner-exit-ready/v1', 'domain_hex32': DOMAIN.hex(),
        'history_sha256': a.history_sha256,
        'nf_hex32': claim['nf'].hex(), 'gross_claim_sompi': receipt.value_sompi,
        'payout_spk_hex36': spk.hex(), 'financial_authorization': False})


def exit_note(a):
    assets, relation, c, codec, wire = load_assets(a, 'exit')
    context, accepted = context_and_history(a, assets, relation, codec, wire)
    owner, wallet = own_wallet(a, c); reconcile(a, accepted, require_settled=False)
    raw = stable_read(a.projection); need(digest(raw) == a.projection_sha256, 'exit-projection-pin')
    wire.validate_exit_public(raw); projection = wire.parse_exit_projection(raw); body = projection.body
    need(body.point == accepted.point and body.old_state.raw == accepted.state.state(DOMAIN)
         and body.old_reserve == accepted.reserve and body.fee == context['fee_sompi'], 'exact-approved-exit-state-fee')
    tail = bytes.fromhex(context['native_tail_hex'])
    need(projection.input_spk == wire.state_spk(body.old_state.raw, tail), 'selected-exit-input-policy')
    if body.new_reserve:
        need(projection.outputs[0][1] == wire.state_spk(body.new_state.raw, tail), 'same-policy-exit-successor')
    owned = history.claims(accepted, wallet, owner['participant_id_hex32'])
    matching = [row for row in owned if not row['spent'] and row['nf'] == body.nf]
    need(len(matching) == 1, 'own-current-unspent-exit-note')
    claim = matching[0]; receipt = claim['receipt']
    need(body.payout + body.fee == receipt.value_sompi
         and body.payout_spk == payout_spk(accepted, wallet, owned, claim), 'own-exit-value-destination')
    keys = wallet.keys(receipt.index)
    attempt = new_attempt(a, {'session_sha256': body.session.hex(), 'nf_hex32': body.nf.hex()})
    write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
    effects = wire.exit_effects_digest(raw); path = accepted.state.cm.path(claim['position'])
    statement = b'KPX8EX01' + DOMAIN + body.old_state.cm_root + body.nf + effects + body.payout.to_bytes(8, 'little') + body.fee.to_bytes(8, 'little')
    proof = relation.prove('exit', statement, {'schema': 'kpx8-owner-private-exit-witness/v1',
        'note_hex168': receipt.note_bytes().hex(), 's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
        'position': claim['position'], 'cm_path_hex': [path[i:i + 32].hex() for i in range(0, 512, 32)]})
    export = {'schema': 'kpx8-owner-exit-authorization/v1', 'history_sha256': a.history_sha256,
        'projection_sha256': a.projection_sha256, 'effects_digest_hex32': effects.hex(),
        'nf_hex32': body.nf.hex(), 'statement_hex152': statement.hex(), 'proof_hex128': proof.hex()}
    private_save(attempt / 'AUTHORIZATION.json', export); public_save(a, export)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'restore', 'alias', 'invoice', 'scan', 'prepare', 'authorize', 'exit-ready', 'exit'))
    for name in ('owner', 'mpc', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('crypto', 'assets', 'session', 'context', 'projection', 'history', 'backup'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'session-sha256', 'context-sha256', 'projection-sha256', 'history-sha256', 'participant-id'):
        p.add_argument('--' + name)
    for name in ('position', 'admission-sompi', 'party'):
        p.add_argument('--' + name, type=int)
    p.add_argument('--payment-sompi', type=int)
    p.add_argument('--note-kind', choices=('initial', 'received', 'change', 'any', 'received-or-change'), default='any')
    p.add_argument('--own-mpc-result', type=Path)
    p.add_argument('--authorization-mpc', type=Path)
    p.add_argument('--round-id')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        a = p.parse_args(); a.owner = checked(a.owner); a.mpc = checked(a.mpc); a.output = checked(a.output)
        need(a.owner.is_dir() and a.mpc.is_dir() and a.output.is_dir(), 'selected-owner-namespace')
        with owner_lock(a):
            {'init': initialize, 'restore': restore, 'invoice': invoice, 'scan': scan,
             'alias': alias, 'prepare': prepare, 'authorize': authorize, 'exit-ready': exit_ready, 'exit': exit_note}[a.operation](a)
        print(encoded({'operation': a.operation, 'completed': True}).decode())
    except Exception:
        p.exit(2, 'owner operation refused; private material not disclosed\n')


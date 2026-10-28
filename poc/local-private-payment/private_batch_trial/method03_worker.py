"""UNSELECTED METHOD03 owner roles; source only until Root freezes the complete vector.

Reuses existing CF/AuthExit/profile/KDF. Both arms require fresh self-payouts.
No publication-order role or controller read of honest candidate/truth exists.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

import exit_wire
import fresh_self_payout
import genesis
import lifecycle_worker as lifecycle
import private_worker as boundary
import wallet_history
import wallet_profile as wallet

read, write, parse, need = boundary.read, boundary.write, boundary.parse, boundary.need
ARMS = (('A', 11), ('B', 13))
VALUE, FEE, RESERVE = 200_000_000, 1, 6_000_000_000


def receiver(config):
    # Runtime/code admission precedes the one Original read.
    profile = wallet.Profile(bytes.fromhex(config['domain_hex32']), bytes.fromhex(config['profile_hex32']))
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['js_leaf_map_sha256'], '/runtime/js')
    authority = boundary.NamespaceAuthority('/runtime/node', modules)
    crypto = wallet.Crypto('/runtime/crypto')
    record = parse(read('/budget/ORIGINAL.json', config['owner_budget_sha256'], private=True))
    need(type(record) is dict and set(record) == {'schema', 'identity_key', 'owner_component',
         'funding_spk_hex36', 'profile_id_hex32', 'domain_hex32', 'binding', 'source_sha256',
         'slot_grammar_sha256', 'bootstrap', 'initial_public_sha256', 'spec_sha256'}
         and record['schema'] == 'kpb-method03-consumed-vector-budget/v1'
         and record['owner_component'] == config['owner_component']
         and type(config['owner_component']) is int
         and type(record['owner_component']) is int
         and record['identity_key'] == config['budget_identity_key']
         and record['profile_id_hex32'] == config['profile_hex32']
         and record['domain_hex32'] == config['domain_hex32']
         and record['binding'] == config['binding']
         and all(record[key] == config[key] for key in
                 ('source_sha256', 'slot_grammar_sha256', 'spec_sha256')),
         'method03-source-bound-consumed-Original-budget')
    seed = boundary.load_backup('/original/BACKUP.json', profile)
    own = wallet.Receiver(seed, profile, crypto, authority)
    funding = b'\0\0\x20' + own.invoice(0xffffffff).native_pk + b'\xac'
    need(funding.hex() == record['funding_spk_hex36'], 'method03-actual-Original-budget-identity')
    return own, authority, wallet
def invoice(config):
    own, authority, _ = receiver(config)
    try:
        for arm, index in ARMS:
            write('/owner/INVOICE-' + arm + '.bin', own.invoice(index).encode())
    finally:
        authority.close()


def plans(config):
    # Test user choices are generated in this separate private role, never as
    # a public cyclic schedule or a controller's --recipient argument.
    recipients = [0, 1, 2]
    secrets.SystemRandom().shuffle(recipients)
    for sender, target in enumerate(recipients):
        destination = Path('/owner/owner-' + str(sender)); destination.mkdir(mode=0o700)
        value = {'schema': 'kpb-method03-private-user-plan/v1', 'binding': config['binding'],
                 'sender': sender, 'recipient': target, 'value_sompi': VALUE, 'fee_sompi': FEE}
        write(destination / 'PLAN.json', value)
        for arm, _ in ARMS:
            write(destination / ('INVOICE-' + arm + '.bin'),
                  read('/invoices/owner-' + str(target) + '/INVOICE-' + arm + '.bin', private=True))


def construct(config):
    own, authority, _ = receiver(config)
    try:
        plan = parse(read('/plan/PLAN.json', private=True))
        need(type(plan) is dict and set(plan) == {'schema', 'binding', 'sender', 'recipient', 'value_sompi', 'fee_sompi'}
             and plan['schema'] == 'kpb-method03-private-user-plan/v1'
             and plan['binding'] == config['binding'] and plan['sender'] == config['owner_component']
             and type(plan['sender']) is int and type(plan['recipient']) is int
             and plan['recipient'] in (0, 1, 2) and type(plan['value_sompi']) is int
             and type(plan['fee_sompi']) is int and plan['value_sompi'] == VALUE and plan['fee_sompi'] == FEE,
             'method03-actual-private-user-plan')
        prover = boundary.NamespaceProver(own.profile, '/runtime/prover', config['binary_sha256'],
            '/output-parameters/MANIFEST.json', config['output_manifest_sha256'],
            '/output-parameters/parameters.pk', read_public=read)
        records = []
        for arm, index in ARMS:
            item = wallet.Invoice.parse(read('/plan/INVOICE-' + arm + '.bin', private=True))
            need(item.domain == own.profile.domain and item.index == index, 'method03-authorized-invoice')
            created = prover.create(own.crypto, item, plan['value_sompi'])
            write('/owner/ROW-' + arm + '.bin', created.row)
            records.append({'arm': arm, 'owner': plan['recipient'], 'invoice_hex208': item.encode().hex(),
                'receipt_hex216': created.receipt.encode().hex(), 'rho_hex32': created.receipt.rho.hex(),
                'cm_hex32': created.receipt.commitment().hex(), 'value_sompi': VALUE,
                'blind_hex32': created.blind.hex(), 'tuple_hex520': created.row.hex()})
        write('/owner/OWN-SENDER-RECORD.json', {'schema': 'kpb-method03-actual-sender-record/v1',
              'binding': config['binding'], 'sender': config['owner_component'], 'created': records})
    finally:
        authority.close()


def feed(config):
    # No Original or note opening enters this collector. Its private inputs
    # are the exact public rows, not yet linked to provider labels in public.
    sender_order = [0, 1, 2]
    # Keep actual creator order; no publication order or favorable shuffle is manufactured.
    result = {'schema': 'kpb-method03-unlabelled-notes/v1', 'binding': config['binding'], 'arms': {}}
    all_cms = []
    for arm, _ in ARMS:
        rows = [read('/rows/owner-' + str(sender) + '/ROW-' + arm + '.bin', private=True) for sender in sender_order]
        need(all(type(row) is bytes and len(row) == 520 for row in rows), 'method03-three-actual-rows')
        need(len({row[:32] for row in rows}) == 3, 'method03-three-distinct-independent-CMs')
        all_cms.extend(row[:32] for row in rows)
        state = wallet_history.trees.PublicState([row[:32] for row in rows])
        point = secrets.token_bytes(32) + bytes(4)
        head = wallet_history.context(genesis.EXPECTED_IDENTITY, point, state, RESERVE)
        result['arms'][arm] = {'context_hex276': head.encode().hex(), 'rows_hex520': [row.hex() for row in rows]}
    need(len(set(all_cms)) == 6, 'method03-independent-CMs-across-main-arms')
    write('/out/NOTES.json', result, 0o400)


def prove(config):
    arm = config['arm']
    own, authority, module = receiver(config)
    try:
        notes = parse(read('/public/NOTES.json', config['notes_sha256']))
        need(notes['binding'] == config['binding'], 'method03-common-note-binding')
        selected = notes['arms'][arm]
        context = exit_wire.HeadContext.parse(bytes.fromhex(selected['context_hex276']))
        need((context.chain, context.pool, context.profile, context.domain, context.service) == genesis.EXPECTED_IDENTITY,
             'method03-exact-selected-public-identity')
        rows = [bytes.fromhex(row) for row in selected['rows_hex520']]
        state = wallet_history.trees.PublicState([row[:32] for row in rows])
        need(context.cm_count == 3 and context.nf_count == 1 and context.reserve == RESERVE
             and context.cm_root == state.cm.root() and context.nf_root == state.nf.root(), 'method03-frozen-head-shape')
        found = []
        for position, row in enumerate(rows):
            try:
                receipt = own.open(row[96:360])
            except wallet.Invalid:
                continue
            need(receipt.index == dict(ARMS)[arm] and receipt.value_sompi == VALUE
                 and receipt.commitment() == row[:32], 'method03-real-owned-note')
            path = state.cm.path(position)
            found.append(wallet.RecoveredOpening(position, receipt, own.nullifier(receipt, position),
                tuple(path[at:at + 32] for at in range(0, 512, 32)), False))
        need(len(found) == 1, 'method03-exactly-one-owned-independent-note')
        claim = found[0]
        following = state.copy(); witness = following.insert(claim.nf)
        action = secrets.token_bytes(32)
        destination = own.fresh_payout(context, claim.nf, action).script_public_key
        body = exit_wire.body(context, action, following.nf.root(), len(following.entries),
            RESERVE - VALUE, FEE, VALUE - FEE, destination, claim.nf, witness)
        tail = read('/policy/IMMUTABLE-TAIL.bin', config['tail_sha256'])
        projection = exit_wire.projection(body, tail)
        approved = module.authorize_exit(own, claim, projection, context, tail, approved_fee_sompi=FEE)
        normalized = lifecycle.normalize(authority.signature_inputs(approved.statement, approved.authorization))
        request = {**approved.private_request, 'signature': normalized}
        checked = parse(lifecycle.private_call(['/runtime/prover'], {**request, 'operation': 'check-joined'}))
        need(all(checked['counts'][name] == 0 for name in
                 ('native_residual_failures', 'signature_residual_failures', 'link_residual_failures')),
             'method03-actual-joined-AuthExit-matrix')
        manifest = parse(read('/exit-parameters/MANIFEST.json', config['exit_manifest_sha256']))
        parameters = {'manifest': '/exit-parameters/MANIFEST.json', 'manifest_sha256': config['exit_manifest_sha256']}
        proof = parse(lifecycle.private_call(['/runtime/prover'], {**request, 'operation': 'prove',
            'parameters': {**parameters, 'pk': '/exit-parameters/parameters.pk', 'pk_sha256': manifest['pk_sha256']}}))
        verified = parse(lifecycle.private_call(['/runtime/prover'], {'operation': 'verify', 'role': 'new-auth-exit',
            'profile': request['profile'], 'statement_hex': approved.statement.hex(),
            'proof_hex128': proof['proof_hex128'], 'parameters': parameters}))
        need(verified['accepted'] is True, 'method03-genuine-existing-key-AuthExit')
        restored, restored_authority, _ = receiver(config)
        try:
            owned = fresh_self_payout.recover_public(restored, projection, tail)
            need(owned is not None and owned.script_public_key == destination,
                 'method03-Original-plus-public-exit-restoration')
            need(restored.crypto.xonly(owned.secret) == owned.public_key, 'method03-restored-native-key-control')
        finally:
            restored_authority.close()
        # Honest truth remains in this owner's private leaf, never in the controller.
        write('/owner/TRUTH.json', {'schema': 'kpb-method03-one-owner-exit-truth/v1',
            'binding': config['binding'], 'source_sha256': config['source_sha256'],
            'slot_grammar_sha256': config['slot_grammar_sha256'], 'spec_sha256': config['spec_sha256'],
            'owner_component': config['owner_component'], 'arm': arm,
            'profile_id_hex32': config['profile_hex32'], 'domain_hex32': config['domain_hex32'],
            'nf_hex32': claim.nf.hex(), 'destination_spk_hex36': destination.hex()})
        write('/owner/EXIT-CANDIDATE.json', {'schema': 'kpb-owner-prepared-independent-exit/v1',
            'scope': wallet_history.SCOPE, 'projection_hex': projection.hex(), 'proof_hex128': proof['proof_hex128'],
            'statement_hex152': approved.statement.hex(), 'native_or_chain_acceptance': False})
        write('/out/PUBLIC.json', {'schema': 'kpb-original-lifecycle-operation/v1', 'operation': 'exit',
            'scope': wallet_history.SCOPE, 'private_original_or_witness_exported': False,
            'accepted_backing_or_native_settlement': False, 'actual_AuthExit_proof': True,
            'original_only_recovered_claim': True, 'service_or_other_owner_dependency': False,
            'candidate_exported': False}, 0o400)
    finally:
        authority.close()


def contact(config):
    own, authority, _ = receiver(config)
    try:
        record = parse(read('/sender/OWN-SENDER-RECORD.json', private=True))
        need(record['binding'] == config['binding'] and record['sender'] == 1, 'method03-actual-colluder-sender')
        # These are actual privately acquired contact invoices, not a global
        # public catalog. No other Original is mounted in this role.
        contacts = {arm: [] for arm, _ in ARMS}
        for owner in range(3):
            for arm, index in ARMS:
                item = wallet.Invoice.parse(read('/contacts/owner-' + str(owner) + '/INVOICE-' + arm + '.bin', private=True))
                need(item.domain == own.profile.domain and item.index == index, 'method03-actual-contact-index')
                contacts[arm].append({'owner': owner, 'native_pk_hex32': item.native_pk.hex(),
                    'delivery_pk_hex32': item.delivery_pk.hex(), 'invoice_index': index,
                    'domain_hex32': item.domain.hex(), 'profile_hex32': own.profile.profile_id.hex()})
        notes = parse(read('/public/NOTES.json', config['notes_sha256']))
        public = parse(read('/public/EXITS.json', config['exits_sha256']))
        need(type(public) is dict and set(public) == {'schema', 'binding', 'records'}
             and public['schema'] == 'kpb-method03-unlabelled-exits/v1'
             and public['binding'] == config['binding'] and len(public['records']) == 6,
             'method03-actual-unlabelled-received-exits')
        effects = []
        ordinals = []
        for entry in public['records']:
            need(set(entry) == {'ordinal', 'projection_hex', 'proof_hex128', 'statement_hex152', 'exit_id'}
                 and type(entry['ordinal']) is int, 'method03-unlabelled-global-record')
            raw = bytes.fromhex(entry['projection_hex'])
            need(len(raw) == 1844 and hashlib.sha256(raw).hexdigest() == entry['exit_id'],
                 'method03-received-continuing-projection')
            effect = exit_wire.validate_public(raw)
            need(effect.new_reserve > 0, 'method03-continuing-arm-only')
            effects.append((raw, effect)); ordinals.append(entry['ordinal'])
        need(set(ordinals) == set(range(1, 7)), 'method03-actual-six-global-ordinals')
        facts = {'schema': 'kpb-method03-private-contact-view/v1', 'binding': config['binding'], 'arms': {}}
        all_contacts = [entry for arm, _ in ARMS for entry in contacts[arm]]
        for arm, index in ARMS:
            selected = notes['arms'][arm]
            rows = [bytes.fromhex(row) for row in selected['rows_hex520']]
            known = []
            for position, row in enumerate(rows):
                try:
                    receipt = own.open(row[96:360])
                except wallet.Invalid:
                    continue
                need(receipt.index == index, 'method03-own-receipt-index')
                nf = own.nullifier(receipt, position)
                known.append(nf)
            need(len(known) == 1, 'method03-one-actual-own-NF')
            context = bytes.fromhex(selected['context_hex276'])
            arm_effects = [(raw, effect) for raw, effect in effects if effect.context.encode() == context]
            need(len(arm_effects) == 3, 'method03-arm-by-actual-public-context-only')
            matching = [raw for raw, effect in arm_effects if effect.nf == known[0]]
            need(len(matching) == 1, 'method03-own-public-payout')
            effect = exit_wire.validate_public(matching[0])
            receipts = [entry for entry in record['created'] if entry['arm'] == arm]
            need(len(receipts) == 1, 'method03-real-constructed-receipt')
            entry = receipts[0]
            facts['arms'][arm] = {'contacts': all_contacts,
                'own_payouts': [{'owner': 1, 'spk_hex36': effect.payout_spk.hex(), 'nf_hex32': known[0].hex()}],
                'known_receipts': [{'owner': entry['owner'], 'rho_hex32': entry['rho_hex32'],
                    'cm_hex32': entry['cm_hex32'], 'value': entry['value_sompi'], 'known_consumed': True,
                    'invoice_hex208': entry['invoice_hex208'], 'receipt_hex216': entry['receipt_hex216'],
                    'blind_hex32': entry['blind_hex32'], 'tuple_hex520': entry['tuple_hex520']}],
                'unmodeled': [{'scope': 'CONTROLLER+TERMINAL',
                    'category': 'opaque-receipt-invoice-blind-tuple-semantics',
                    'evidence_refs': ['actual-corrupt-owner-sender-record-and-contact-role']},
                    {'scope': 'GLOBAL-HOST/UNION', 'category': 'full-corrupt-server-view',
                     'evidence_refs': ['unfunded-component-scope-no-financial-MPC-server-view']} ]}
        write('/owner/CONTACT.json', facts)
    finally:
        authority.close()


def main():
    os.umask(0o077)
    operation = sys.argv[1]
    config = parse(read('/CONFIG.json'))
    need(operation in ('invoice', 'plans', 'construct', 'feed', 'prove', 'contact'), 'method03-finite-operation')
    marker = parse(read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-method03-namespace/v1', 'network': 'disabled', 'operation': operation,
                    'Original_slots': 1 if operation in ('invoice', 'construct', 'prove', 'contact') else 0},
         'method03-closed-role')
    need([line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]] == ['lo'],
         'method03-network-off')
    need(not Path('/home/luke/.codex').exists() and not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists(),
         'method03-host-private-absent')
    for member in config['source_members'] + config['runtime_members']:
        read(member['path'], member['sha256'])
    globals()[operation](config)
    if operation != 'prove':
        write('/out/PUBLIC.json', {'schema': 'kpb-method03-role-result/v1', 'operation': operation,
            'binding': config['binding'], 'private_body_or_key_exported': False, 'accepted_backing_or_chain': False}, 0o400)


if __name__ == '__main__':
    main()

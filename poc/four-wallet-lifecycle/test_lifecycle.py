"""Public unsafe receipt/state controls; no PK, proving or native-VM claims."""
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from compat import core, payment
import no_append
from paths import guard, checked
from replay import advance, snapshot_input, snapshot_record
from runtime import Runtime
from preparation import public_body
from worker import Worker, ready_expected, validate_quote

DOMAIN = bytes.fromhex('2630ed4a338afa60d3e1747a0d8875ba05f4b6694eefc345a977def800c4b89e')
TAG = b'PUBLIC_UNSAFE_DO_NOT_FUND/FOUR_WALLET_LIGHT_CONTROLS/v1\0'


def fixture():
    c = core(); p = c.primitives
    seeds = tuple(p.h(TAG, bytes([index])) for index in range(4))
    wallets = tuple(c.receiver.module().Receiver(seed, DOMAIN, c.receiver.Crypto()) for seed in seeds)
    deliveries = []
    for position, owner in enumerate((0, 2)):
        invoice = wallets[owner].invoice(0)
        receipt = c.receiver.module().Receipt.for_invoice(invoice, 2_000_000_000,
                                                          p.h(TAG, b'rho', bytes([owner])))
        cipher = wallets[owner].crypto.seal(invoice.delivery_pk, receipt.encode())
        deliveries.append(p.Delivery(position, receipt.commitment(), cipher))
    snapshot = p.Snapshot(2, tuple(deliveries), (p.NFEntry(p.ZERO, p.ZERO, 0),)).verify()
    point = {'transactionId': p.h(TAG, b'NONEXISTENT-SOURCE').hex(), 'index': 0}
    return seeds, wallets, snapshot, point


def recovered(wallet, snapshot):
    return core().receiver.recover(wallet, snapshot, snapshot.state(DOMAIN))


def payment_candidate(wallet, recipient, snapshot, point, reserve):
    m = payment(); c = core()
    claims = no_append.available(recovered(wallet, snapshot))
    assert len(claims) == 1
    request = m.Request.parse(c.native_runtime.encoded({
        'schema': m.REQUEST_SCHEMA, 'domain_hex32': DOMAIN.hex(),
        'recipient_invoice_hex208': recipient.invoice(1).encode().hex(),
        'net_principal_sompi': 1_000_000_000, 'recipient_exit_credit_sompi': 20_000_000}), DOMAIN)
    prepared = m.prepare_payment(wallet, snapshot, claims[0], point, reserve, 10_000_000,
        request, recovered(wallet, snapshot).owned, expected_exit_credit_sompi=20_000_000,
        fee_context=m.VIRTUAL, excluded_change_indices=(0, 1))
    return prepared.candidate


class FourWalletControls(unittest.TestCase):
    def test_four_distinct_wallets_two_payments_four_exits_and_backup_key_recovery(self):
        c = core(); p = c.primitives
        seeds, wallets, snapshot, anchor = fixture()
        self.assertEqual(len({wallet.invoice(1).encode() for wallet in wallets}), 4)
        point, reserve = anchor, 4_000_000_000
        payment_fees, exit_fees, payouts = 0, 0, []
        for ordinal, (sender, recipient) in enumerate(((0, 1), (2, 3))):
            candidate = payment_candidate(wallets[sender], wallets[recipient], snapshot, point, reserve)
            following, f = advance(snapshot, reserve, point, candidate.payload(), DOMAIN)
            self.assertEqual(following.state(DOMAIN), candidate.after.state(DOMAIN))
            self.assertEqual(candidate.payout, 0)
            self.assertEqual(candidate.fee, 10_000_000)
            snapshot, reserve = following, candidate.reserve_after
            payment_fees += candidate.fee
            point = {'transactionId': p.h(TAG, b'FAKE-VIRTUAL', bytes([ordinal])).hex(), 'index': 0}
        self.assertEqual((snapshot.cm_cursor, len(snapshot.nullifiers)), (6, 5))
        # A/C own only positive change; B/D own only incoming payment. No
        # two-real-input consolidation from the former cross-payment model.
        self.assertEqual([len(no_append.available(recovered(w, snapshot))) for w in wallets], [1] * 4)
        for owner, wallet in enumerate(wallets):
            own = recovered(wallet, snapshot)
            claim = no_append.available(own)[0]
            material = no_append.prepare(seeds[owner], wallet, snapshot, own, (claim,),
                point, anchor, reserve, expected_domain=DOMAIN)
            candidate = material.candidate(20_000_000)
            self.assertEqual(sum(row['real'] for row in candidate.inputs), 1)
            self.assertNotEqual(candidate.auth[495:527], claim.receipt.native_pk)
            following, _ = advance(snapshot, reserve, point, candidate.payload(), DOMAIN)
            txid = p.h(TAG, b'FAKE-EXIT', bytes([owner])).hex()
            payouts.append({'transaction_id': txid, 'auth_hex528': candidate.auth.hex(),
                'amount_sompi': candidate.payout, 'script_public_key': candidate.auth[492:528].hex()})
            snapshot, reserve = following, candidate.reserve_after
            point = {'transactionId': txid, 'index': 0} if reserve else None
            exit_fees += candidate.fee
        self.assertEqual((snapshot.cm_cursor, len(snapshot.nullifiers), reserve), (6, 13, 0))
        self.assertEqual(sum(row['amount_sompi'] for row in payouts) + payment_fees + exit_fees,
                         4_000_000_000)
        for owner, wallet in enumerate(wallets):
            own = recovered(wallet, snapshot)
            self.assertEqual(len(own.owned), 2 if owner in (0, 2) else 1)
            self.assertTrue(all(claim.spent for claim in own.owned))
            self.assertEqual(no_append.available(own), [])
            controls = no_append.controlled_payouts(seeds[owner], wallet, own, anchor, payouts)
            self.assertEqual(controls['historical_native_payout_key_control_match_count'], 1)
            self.assertEqual(controls['one_known_NF_exact_key_matches_without_arity_claim'], 1)
            self.assertEqual(controls['bounded_two_real_group_reconstruction_count'], 0)
            self.assertEqual(controls['unresolved_owned_NF_payout_records'], 0)
            self.assertFalse(controls['native_current_UTXO_or_spendability_verified'])

    def test_wrong_domain_old_current_state_and_duplicate_spend_reject(self):
        c = core(); seeds, wallets, snapshot, point = fixture()
        own = recovered(wallets[0], snapshot); claim = no_append.available(own)[0]
        with self.assertRaises(ValueError):
            no_append.prepare(seeds[0], wallets[0], snapshot, own, (claim,), point, point,
                              4_000_000_000, expected_domain=bytes(32))
        candidate = payment_candidate(wallets[0], wallets[1], snapshot, point, 4_000_000_000)
        after, _ = advance(snapshot, 4_000_000_000, point, candidate.payload(), DOMAIN)
        with self.assertRaises(ValueError):
            advance(after, candidate.reserve_after, point, candidate.payload(), DOMAIN)
        spent = recovered(wallets[0], after)
        self.assertTrue(spent.owned[0].spent)
        with self.assertRaises(ValueError):
            c.primitives.insert_nf(after, claim.nf)
        with self.assertRaises(ValueError):
            no_append.prepare(seeds[0], wallets[0], after, spent, (claim,), point, point,
                              candidate.reserve_after, expected_domain=DOMAIN)

    def test_snapshot_duplicate_position_wrong_NF_table_and_cipher_width_reject(self):
        _, _, snapshot, _ = fixture()
        value = snapshot_record(snapshot)
        self.assertEqual(snapshot_input(value).state(DOMAIN), snapshot.state(DOMAIN))
        for mutate in (lambda x: x['deliveries'].append(copy.deepcopy(x['deliveries'][0])),
                       lambda x: x['nullifiers'][0].update(next_index=1),
                       lambda x: x['deliveries'][0].update(cipher_hex264='00')):
            bad = copy.deepcopy(value); mutate(bad)
            with self.assertRaises(ValueError):
                snapshot_input(bad)

    def test_actual_runtime_requires_explicit_DAA_before_any_other_action(self):
        runtime = object.__new__(Runtime)
        with self.assertRaises(ValueError):
            runtime.body(None, None, None, None, None)
        with self.assertRaises(TypeError):
            runtime.finalize(None, None, None, None, None, None, None, None)

    def test_backup_alias_and_parent_components_fail_before_output_creation(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-public-path-control-') as temporary:
            root = Path(temporary)
            backup = root / 'unsafe-public-backup'
            backup.write_bytes(b'KNOWN_PUBLIC_CONTROL_ONLY'); backup.chmod(0o600)
            alias = root / 'public-alias'; alias.hardlink_to(backup)
            output = root / 'never-created'
            with self.assertRaises(ValueError):
                guard(backup, (path for path in (alias,)), output)
            self.assertFalse(output.exists())
            with self.assertRaises(ValueError):
                checked(root / '..' / 'unsafe-path')

    def test_quote_binds_candidate_and_coherently_changed_context_before_witness(self):
        c = core(); p = c.primitives
        _, wallets, snapshot, point = fixture()
        candidate = payment_candidate(wallets[0], wallets[1], snapshot, point, 4_000_000_000)
        runtime = SimpleNamespace(profile=SimpleNamespace(child_template_tail=b'PUBLIC_CONTROL_TAIL'*20,
                                                          aggregate_budget=1600))
        case = public_body(candidate, runtime)
        contexts = [{'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
            'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': row['isCoinbase'],
            'covenant_id': row['covenantId']} for row in case['entries']]
        quote = {'witness_context': 'EXACT_VIRTUAL_OWNER_ALLOCATION', 'transaction': case['transaction'],
            'contexts': contexts, 'rate': 100, 'authorization_sha256': p.h(candidate.auth).hex()}
        quote['quote_id'] = c.native_runtime.quote_id(quote['transaction'], contexts, 100)
        validate_quote(candidate, quote, runtime)
        for mutate, rehash in ((lambda x: x.update(authorization_sha256='00'*32), False),
                (lambda x: x['contexts'][0].update(amount_sompi='4000000001'), True),
                (lambda x: x['transaction']['inputs'][0].update(computeBudget=1700), True)):
            bad = copy.deepcopy(quote); mutate(bad)
            if rehash:
                bad['quote_id'] = c.native_runtime.quote_id(bad['transaction'], bad['contexts'], bad['rate'])
            with self.assertRaises(ValueError):
                validate_quote(candidate, bad, runtime)
        worker = object.__new__(Worker); worker._ready = False
        with patch('worker.os.fdopen', side_effect=AssertionError('witness-pipe-touched')) as opened:
            with self.assertRaises(ValueError):
                worker.prove(candidate, quoted=quote)
            opened.assert_not_called()

    def test_inventory_checks_every_metadata_entry_before_first_member_read(self):
        import installation as install
        with tempfile.TemporaryDirectory(prefix='kpx6-public-inventory-control-') as temporary:
            root = Path(temporary); tree = root / 'public-tree'; tree.mkdir()
            backup = root / 'private' / 'backup'; backup.parent.mkdir()
            literal = b'PUBLIC_UNSAFE_CONTROL_BACKUP'; backup.write_bytes(literal); backup.chmod(0o600)
            names = sorted(install.mapping('local'))
            rows = []
            for index, name in enumerate(names):
                target = tree / name; target.parent.mkdir(parents=True, exist_ok=True)
                raw = b'PUBLIC_CONTROL_MEMBER_' + str(index).encode()
                if name == names[-1]:
                    target.hardlink_to(backup); raw = literal
                else:
                    target.write_bytes(raw)
                rows.append({'path': name, 'kind': 'runtime-source', 'bytes': len(raw),
                             'sha256': install.digest(raw)})
            inventory = root / 'inventory.json'
            raw = json.dumps({'schema': 'kpx4-public-software-bundle/v1',
                'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
                'files': rows}).encode(); inventory.write_bytes(raw)
            args = SimpleNamespace(inventory=inventory, inventory_sha256=install.digest(raw),
                                   software_root=tree, source_kind='local')
            info = backup.stat(); opened = []
            original = install.read_public
            def read(path, *a, **kw):
                opened.append(Path(path)); return original(path, *a, **kw)
            with patch('installation.read_public', side_effect=read):
                with self.assertRaises(ValueError):
                    install.entries(args, frozenset({(info.st_dev, info.st_ino)}), (backup.parent,))
            self.assertEqual(opened, [inventory])

    def test_owner_first_backup_read_is_after_exact_READY(self):
        import owner
        profile = SimpleNamespace(domain=DOMAIN, parameter_manifest_sha256='11'*32,
            vk=b'\x21'*328, build_identity_sha256='22'*32, profile_sha256='33'*32)
        closed = []
        with tempfile.TemporaryDirectory(prefix='kpx6-public-READY-control-') as temporary:
            root = Path(temporary)
            backup = root / 'backup'; backup.write_bytes(b'PUBLIC_CONTROL_TRAP_NOT_VALID_JSON'); backup.chmod(0o600)
            public_file = root / 'public.json'; public_file.write_bytes(b'{}')
            pk = root / 'public.pk'; pk.write_bytes(b'PUBLIC_CONTROL_NOT_A_REAL_PK'); pk.chmod(0o400)
            original = Path.read_bytes
            for good in (False, True):
                reads = []
                args = SimpleNamespace(op='prepare-full-cashout', source_kind='local', pk=pk,
                    manifest=public_file, execute=True, workers=1, fee_rate=100, request=None,
                    virtual_prefix=None, minimum_payout_sompi=10_000_000,
                    history=public_file, history_sha256='44'*32, financial_profile=public_file,
                    financial_sha256='33'*32, backup=backup, output=root/('run-'+str(good)),
                    runtime_root=root, must_be_absent=[])
                class FakeWorker:
                    ready = Worker.ready
                    def __init__(self, *a, **kw):
                        self.profile=profile; self._ready=False
                        line=json.dumps(ready_expected(profile) if good else {})+'\n'
                        self.process=SimpleNamespace(stdout=io.StringIO(line))
                    def close(self): closed.append(True)
                def read(path):
                    if path == backup: reads.append(True)
                    return original(path)
                with patch.object(owner,'public_paths',return_value=[public_file,pk]), \
                     patch.object(owner,'financial',return_value=profile), \
                     patch.object(owner,'Runtime',return_value=SimpleNamespace(profile=profile)), \
                     patch.object(owner,'parameter_manifest',return_value={}), \
                     patch.object(owner,'replay_source',return_value={
                         'trial_id':'11111111-1111-4111-8111-111111111111'}), \
                     patch.object(owner,'Worker',FakeWorker), \
                     patch.object(Path,'read_bytes',read):
                    with self.assertRaises((ValueError, KeyError)):
                        owner.run(args)
                self.assertEqual(len(reads), 1 if good else 0)
            self.assertEqual(len(closed),2)


if __name__ == '__main__':
    unittest.main()

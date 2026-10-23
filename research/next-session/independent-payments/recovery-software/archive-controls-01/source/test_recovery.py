import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from software_bundle import Invalid, digest, encoded, inventory, restore, verify
from reconcile import reconcile


def fixture(terminal=False):
    session = {'request_nonce_hex32': '01' * 32, 'provider_id': 'PUBLIC_FIXTURE_NODE',
               'network_id': 'testnet-10', 'genesis_hash_hex': '02' * 32,
               'domain_hex32': '03' * 32, 'descriptor_sha256': '04' * 32,
               'birth_start_hash': '07' * 32,
               'founding_outpoint': {'transactionId': '05' * 32, 'index': 0}}
    ids = ['05' * 32, '06' * 32]
    points = [{'transactionId': value, 'index': 0} for value in ids]
    entry = {'amount_sompi': 60_000_000, 'script_public_key': '0000aa',
             'block_daa_score': 42, 'is_coinbase': False, 'covenant_id': None}
    replay = {'descriptor_sha256': session['descriptor_sha256'],
              'classification': 'PUBLIC_CONTRACT_FIXTURE_NOT_ACCEPTED',
              'ordered_transaction_ids': ids, 'head_outpoint': None if terminal else points[-1],
              'head_utxo': None if terminal else entry, 'terminal': terminal,
              'reserve_outpoints': points[:-1] if terminal else points,
              'public_replay_complete': True, 'native_Full_all_engines': True}
    observation = {'schema': 'kpx4-selected-node-reconciliation/v1',
        'source_kind': 'PUBLIC_CONTRACT_FIXTURE_NOT_A_NODE', **session,
        'frontier': {'start_hash': '07' * 32, 'end_hash': '08' * 32,
                     'reached_end': True, 'missing': [], 'pruned': False, 'removed_block_hashes': []},
        'acceptance': [{'transaction_id': value, 'accepting_block_hash': '09' * 32,
                        'block_daa_score': i} for i, value in enumerate(ids)],
        'queries': [{'outpoint': value, 'queried': True,
                     'utxo': entry if value == points[-1] and not terminal else None}
                    for value in replay['reserve_outpoints']],
        'postquery': {'start_hash': '08' * 32, 'end_hash': '0a' * 32, 'reached_end': True,
                      'missing': [], 'pruned': False, 'removed_block_hashes': [],
                      'related_transaction_ids': [], 'watched_outpoints': [] if terminal else [points[-1]]}}
    return replay, observation, session


class SoftwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'bundle'
        (self.root / 'prover/src').mkdir(parents=True)
        (self.root / 'prover/Cargo.toml').write_text('PUBLIC INERT CARGO TOML')
        (self.root / 'prover/src/main.rs').write_text('// PUBLIC INERT SOURCE')
        self.data = inventory(self.root, [('source', 'prover/Cargo.toml'),
                                         ('source', 'prover/src/main.rs')])
        self.raw = encoded(self.data)
        self.expected = digest(self.raw)

    def tearDown(self):
        self.temp.cleanup()

    def test_verified_bytes_never_select_execute_or_authorize(self):
        result = verify(self.root, self.raw, self.expected)
        self.assertEqual(result['files_verified'], 2)
        self.assertFalse(result['executable_selected_or_launched'])
        self.assertFalse(result['currentness_verified'])
        self.assertFalse(result['spend_authorized'])

    def test_missing_source(self):
        (self.root / 'prover/src/main.rs').unlink()
        with self.assertRaises(Invalid): verify(self.root, self.raw, self.expected)

    def test_corrupt_same_length_source(self):
        target = self.root / 'prover/src/main.rs'
        target.write_bytes(b'x' * target.stat().st_size)
        with self.assertRaisesRegex(Invalid, '^public-file-digest$'):
            verify(self.root, self.raw, self.expected)

    def test_wrong_external_root(self):
        with self.assertRaisesRegex(Invalid, '^external-inventory-pin$'):
            verify(self.root, self.raw, '00' * 32)

    def test_source_truncation(self):
        (self.root / 'prover/src/main.rs').write_bytes(b'')
        with self.assertRaisesRegex(Invalid, '^public-file-length$'):
            verify(self.root, self.raw, self.expected)

    def test_traversal_absolute_and_normalization_aliases(self):
        for value in ('../outside', '/absolute', 'prover/../outside', './prover/Cargo.toml',
                      'prover//Cargo.toml', 'prover\\Cargo.toml'):
            with self.subTest(value=value):
                data = copy.deepcopy(self.data); data['files'][0]['path'] = value
                raw = encoded(data)
                with self.assertRaisesRegex(Invalid, '^unsafe-relative-path$'):
                    verify(self.root, raw, digest(raw))

    def test_duplicate_inventory_path(self):
        data = copy.deepcopy(self.data); data['files'].append(data['files'][0])
        raw = encoded(data)
        with self.assertRaisesRegex(Invalid, '^duplicate-software-path$'):
            verify(self.root, raw, digest(raw))

    def test_symlink_parent_and_leaf(self):
        target = self.root / 'prover/src/main.rs'
        target.unlink(); target.symlink_to(self.root / 'prover/Cargo.toml')
        with self.assertRaisesRegex(Invalid, '^public-symlink$'):
            verify(self.root, self.raw, self.expected)

    def test_backup_hardlink_guard_before_public_open(self):
        backup = self.base / 'PUBLIC-NONSEED-SENTINEL'
        target = self.root / 'prover/src/main.rs'
        os.link(target, backup)
        actual_open = os.open
        opened = []
        def spy(path, *args, **kwargs):
            opened.append(Path(path))
            return actual_open(path, *args, **kwargs)
        with patch('software_bundle.os.open', side_effect=spy):
            with self.assertRaisesRegex(Invalid, '^public-private-inode-alias$'):
                verify(self.root, self.raw, self.expected, forbidden_inputs=[backup])
        self.assertNotIn(target, opened)

    def test_unlisted_build_config_and_build_script_never_restored(self):
        (self.root / 'prover/build.rs').write_text('PUBLIC INERT UNLISTED BUILD SCRIPT')
        (self.root / 'prover/.cargo').mkdir()
        (self.root / 'prover/.cargo/config.toml').write_text('PUBLIC INERT UNLISTED CONFIG')
        output = self.base / 'restored'
        result = restore(self.root, self.raw, self.expected, output)
        self.assertTrue(result['only_inventory_entries_restored'])
        self.assertFalse((output / 'prover/build.rs').exists())
        self.assertFalse((output / 'prover/.cargo').exists())
        self.assertEqual(sorted(str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()),
                         ['prover/Cargo.toml', 'prover/src/main.rs'])

    def test_restore_refuses_existing_destination(self):
        with self.assertRaisesRegex(Invalid, '^fresh-software-output-required$'):
            restore(self.root, self.raw, self.expected, self.root)

    def test_generator_guard_survives_verify_then_hardlink_swap(self):
        backup = self.base / 'PUBLIC-NONSEED-SWAP-SENTINEL'
        backup.write_text('PUBLIC INERT SENTINEL DO NOT READ')
        target = self.root / 'prover/src/main.rs'
        real_verify = verify
        swapped = False
        def swapping_verify(*args, **kwargs):
            nonlocal swapped
            result = real_verify(*args, **kwargs)
            target.unlink(); os.link(backup, target)
            swapped = True
            return result
        actual_open = os.open
        sentinel_opened = []
        def spy(path, *args, **kwargs):
            if swapped and Path(path) == target:
                sentinel_opened.append(True)
            return actual_open(path, *args, **kwargs)
        with patch('software_bundle.verify', side_effect=swapping_verify), \
             patch('software_bundle.os.open', side_effect=spy):
            with self.assertRaisesRegex(Invalid, '^public-private-inode-alias$'):
                restore(self.root, self.raw, self.expected, self.base / 'restore-swap',
                        forbidden_inputs=(value for value in [backup]))
        self.assertEqual(sentinel_opened, [])

    def test_duplicate_json_key(self):
        raw = b'{"schema":1,"schema":2}'
        with self.assertRaisesRegex(Invalid, '^duplicate-json-field$'):
            verify(self.root, raw, digest(raw))


class ReconciliationTests(unittest.TestCase):
    def check(self, replay, observation, session):
        return reconcile(replay, observation, session, fixture_contract_only=True)

    def test_live_head_fixture_join_never_authorizes(self):
        result = self.check(*fixture())
        self.assertTrue(result['join_contract_satisfied'])
        self.assertFalse(result['currentness_verified'])
        self.assertFalse(result['accepted_chain_backing_verified'])
        self.assertFalse(result['spend_authorized'])

    def test_terminal_requires_all_reserve_spent(self):
        self.assertTrue(self.check(*fixture(True))['terminal'])
        replay, obs, session = fixture(True)
        obs['queries'][0]['utxo'] = fixture()[0]['head_utxo']
        with self.assertRaisesRegex(Invalid, '^current-head-spent-replaced-or-context-mismatch$'):
            self.check(replay, obs, session)

    def test_archived_synthetic_cannot_enter_live_contract(self):
        replay, obs, session = fixture()
        replay['classification'] = 'SUPPLIED_SYNTHETIC_CONTEXTS_ONLY'
        obs['source_kind'] = 'SELECTED_VALIDATING_NODE_RPC'
        with self.assertRaisesRegex(Invalid, '^synthetic-history-cannot-authorize-spend$'):
            reconcile(replay, obs, session)

    def test_stale_request_nonce(self):
        replay, obs, session = fixture(); obs['request_nonce_hex32'] = '0b' * 32
        with self.assertRaisesRegex(Invalid, '^observation-session-or-instance-mismatch$'):
            self.check(replay, obs, session)

    def test_cross_domain_network_provider_or_descriptor(self):
        for key in ('domain_hex32', 'genesis_hash_hex', 'descriptor_sha256', 'provider_id', 'network_id'):
            replay, obs, session = fixture(); obs[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_missing_suffix_reordered_or_conflicting_successor(self):
        for mutate in (lambda obs: obs['acceptance'].pop(),
                       lambda obs: obs['acceptance'].reverse(),
                       lambda obs: obs['acceptance'][-1].update(transaction_id='0c' * 32)):
            replay, obs, session = fixture(); mutate(obs)
            with self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_reorg_removed_or_pruned_frontier(self):
        for key, value in (('removed_block_hashes', ['0d' * 32]), ('pruned', True),
                           ('missing', ['0e' * 32]), ('reached_end', False)):
            replay, obs, session = fixture(); obs['frontier'][key] = value
            with self.subTest(key=key), self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_head_spent_or_wrong_amount_script_daa(self):
        for key in ('amount_sompi', 'script_public_key', 'block_daa_score'):
            replay, obs, session = copy.deepcopy(fixture())
            obs['queries'][-1]['utxo'] = copy.deepcopy(obs['queries'][-1]['utxo'])
            obs['queries'][-1]['utxo'][key] = '0000ab' if key == 'script_public_key' else 1
            with self.subTest(key=key), self.assertRaises(Invalid): self.check(replay, obs, session)
        replay, obs, session = fixture(); obs['queries'][-1]['utxo'] = None
        with self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_explicit_exact_all_reserve_queries_required(self):
        for mutate in (lambda obs: obs['queries'].pop(0),
                       lambda obs: obs['queries'].append(obs['queries'][0]),
                       lambda obs: obs['queries'][0].update(queried=False)):
            replay, obs, session = fixture(); mutate(obs)
            with self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_postquery_spend_removal_gap_and_missing_watch(self):
        for key, value in (('related_transaction_ids', ['0f' * 32]),
                           ('removed_block_hashes', ['10' * 32]), ('reached_end', False),
                           ('start_hash', '11' * 32), ('watched_outpoints', [])):
            replay, obs, session = fixture(); obs['postquery'][key] = value
            with self.subTest(key=key), self.assertRaises(Invalid): self.check(replay, obs, session)

    def test_byte_verified_history_without_observation_is_not_current(self):
        replay, obs, session = fixture()
        with self.assertRaises(Invalid): self.check(replay, {}, session)

    def test_self_asserted_fresh_flag_rejected(self):
        replay, obs, session = fixture(); obs['fresh'] = True
        with self.assertRaisesRegex(Invalid, '^observation-fields$'):
            self.check(replay, obs, session)

    def test_birth_anchor_and_founding_point_are_pinned_not_only_hex(self):
        replay, obs, session = fixture(); obs['frontier']['start_hash'] = '12' * 32
        with self.assertRaisesRegex(Invalid, '^pinned-birth-frontier-start-required$'):
            self.check(replay, obs, session)
        replay, obs, session = fixture()
        session['founding_outpoint'] = {'transactionId': '13' * 32, 'index': 0}
        obs['founding_outpoint'] = session['founding_outpoint']
        with self.assertRaisesRegex(Invalid, '^pinned-founding-outpoint-and-history-required$'):
            self.check(replay, obs, session)


if __name__ == '__main__':
    unittest.main(verbosity=2)

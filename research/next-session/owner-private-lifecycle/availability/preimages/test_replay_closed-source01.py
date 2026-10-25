"""Public synthetic guard/packet controls. No real backup or proof access."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('replay_closed', Path(__file__).with_name('replay_closed.py'))
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kpx8-replay-public-controls-')
        self.base = Path(self.temporary.name)
        self.private = self.base / 'synthetic-private'
        self.private.mkdir()
        self.public = self.base / 'public'
        self.public.mkdir()
        self.coverage = patch.object(replay, 'retained_roots', return_value=(self.private,))
        self.coverage.start()

    def tearDown(self):
        self.coverage.stop()
        self.temporary.cleanup()

    def policy(self):
        return replay.PublicPolicy([self.private])

    def source(self, name='selected', raw=b'selected public content'):
        path = self.public / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def selection(self):
        item = lambda name: {'path': name + '.json', 'bytes': 1, 'sha256': '11' * 32}
        return {'schema': 'kpx8-closed-replay-public-inputs/v1',
                'financial_profile_sha256': replay.PROFILE_SHA,
                'inputs': {name: item(name) for name in replay.INPUTS},
                'pages': [item('attempt-001/page-001.json.gz')],
                'expected': {'history_sha256': '22' * 32, 'checkpoint_sha256': '33' * 32}}

    def test_omitted_whole_private_root_refuses_before_content_open(self):
        nested = self.private / 'small-own-parent'
        nested.mkdir()
        with patch.object(replay.os, 'open') as opened:
            with self.assertRaisesRegex(replay.Refused, 'whole-retained-private-coverage'):
                replay.PublicPolicy([nested])
            opened.assert_not_called()

    def test_private_path_and_hardlink_refuse_before_content_open(self):
        secret = self.private / 'synthetic-secret'
        secret.write_bytes(b'public synthetic fixture, never an original backup')
        alias = self.public / 'alias'
        os.link(secret, alias)
        policy = self.policy()
        with patch.object(replay.os, 'open') as opened:
            for path in (secret, alias):
                with self.assertRaises(replay.Refused):
                    policy.read(path, '00' * 32)
            opened.assert_not_called()

    def test_moved_private_inode_is_remembered(self):
        secret = self.private / 'synthetic-secret'
        secret.write_bytes(b'synthetic private fixture')
        policy = self.policy()
        outside = self.public / 'moved'
        secret.rename(outside)
        with patch.object(replay.os, 'open') as opened:
            with self.assertRaisesRegex(replay.Refused, 'public-private-inode-or-type'):
                policy.read(outside, '00' * 32)
            opened.assert_not_called()

    def test_swap_to_private_inode_refuses_before_first_byte(self):
        secret = self.private / 'synthetic-secret'
        secret.write_bytes(b'synthetic private fixture')
        selected, pin = self.source()
        policy = self.policy()
        original_open = os.open

        def swapped(path, flags):
            selected.unlink()
            os.link(secret, selected)
            return original_open(path, flags)

        with patch.object(replay.os, 'open', side_effect=swapped), patch.object(replay.os, 'fdopen') as read:
            with self.assertRaisesRegex(replay.Refused, 'public-before-first-byte'):
                policy.read(selected, pin)
            read.assert_not_called()

    def test_symlink_rejected_and_complete_public_bytes_selected(self):
        selected, pin = self.source()
        link = self.public / 'symlink'
        link.symlink_to(selected)
        policy = self.policy()
        with self.assertRaisesRegex(replay.Refused, 'public-path-symlink'):
            policy.read(link, pin)
        self.assertEqual(policy.read(selected, pin), b'selected public content')
        with self.assertRaisesRegex(replay.Refused, 'whole-selected-public-bytes'):
            policy.read(selected, '00' * 32)

    def test_packet_canonical_paths_exact_roles_and_output_pins(self):
        selected = self.selection()
        self.assertEqual(replay.packet(replay.encoded(selected)), selected)
        for mutation in ('duplicate', 'missing-input', 'wrong-profile', 'bool-size', 'traversal', 'dot'):
            value = copy.deepcopy(selected)
            if mutation == 'duplicate':
                value['pages'].append(copy.deepcopy(value['pages'][0]))
            elif mutation == 'missing-input':
                value['inputs'].pop('sessions')
            elif mutation == 'wrong-profile':
                value['financial_profile_sha256'] = '00' * 32
            elif mutation == 'bool-size':
                value['pages'][0]['bytes'] = True
            elif mutation == 'traversal':
                value['pages'][0]['path'] = '../omitted-page'
            else:
                value['pages'][0]['path'] = '.'
            with self.assertRaises(replay.Refused, msg=mutation):
                replay.packet(replay.encoded(value))

    def test_all_main_and_post_query_page_paths_required(self):
        fetch = {'pages': [{'path': 'main/page-01.gz'}],
                 'current_view': {'post_query_delta': {'pages': [{'path': 'delta/page-01.gz'}]}}}
        self.assertEqual(replay.page_paths(fetch), {'main/page-01.gz', 'delta/page-01.gz'})
        fetch['current_view']['post_query_delta']['pages'][0]['path'] = 'main/page-01.gz'
        with self.assertRaisesRegex(replay.Refused, 'distinct-full-and-post-query-page-paths'):
            replay.page_paths(fetch)

    def test_fresh_selected_executable_mode_and_existing_file_preserved(self):
        target = self.public / 'runtime' / 'selected-executable'
        replay.write(target, b'public executable fixture', 0o500)
        self.assertEqual(target.stat().st_mode & 0o777, 0o500)
        with self.assertRaises(FileExistsError):
            replay.write(target, b'replacement', 0o500)
        self.assertEqual(target.read_bytes(), b'public executable fixture')


if __name__ == '__main__':
    unittest.main()

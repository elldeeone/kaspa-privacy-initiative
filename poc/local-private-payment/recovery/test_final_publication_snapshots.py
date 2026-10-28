"""Historical public origins must preserve the frozen candidate bytes."""
import hashlib
from pathlib import Path
import runpy
import unittest

import final_publication_launch_prepared_snapshots as prepared


class FrozenDocumentOrigins(unittest.TestCase):
    def test_all_five_exact_public_snapshots_are_guard_admitted(self):
        self.assertEqual(len(prepared.PUBLIC_DOCUMENT_SNAPSHOTS), 5)
        guard = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
        for source, route in prepared.PUBLIC_DOCUMENT_SNAPSHOTS.items():
            with self.subTest(source=source):
                logical = {'source': source, 'path': route['path'],
                           'bytes': route['bytes'], 'sha256': route['sha256']}
                resolved = prepared.candidate_origin(logical)
                self.assertEqual(resolved, {**logical, 'source': route['snapshot']})
                self.assertEqual(logical['source'], source)
                self.assertNotEqual(resolved['source'], source)
                raw = guard['read'](resolved['source'], resolved['sha256'])
                self.assertEqual(len(raw), logical['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), logical['sha256'])

    def test_wrong_logical_identity_refuses_before_any_origin_read(self):
        for source, route in prepared.PUBLIC_DOCUMENT_SNAPSHOTS.items():
            original = {'source': source, 'path': route['path'],
                        'bytes': route['bytes'], 'sha256': route['sha256']}
            for key, value in [('path', route['path']+'-other'),
                               ('bytes', route['bytes']+1),
                               ('sha256', '0'*64)]:
                with self.subTest(source=source, changed=key):
                    with self.assertRaises(ValueError):
                        prepared.candidate_origin({**original, key: value})

    def test_other_sources_have_no_alias_or_new_read_authority(self):
        row = {'source': '/unselected/ordinary-public-file', 'path': 'ordinary',
               'bytes': 123, 'sha256': '1'*64}
        self.assertIs(prepared.candidate_origin(row), row)

    def test_frozen_snapshots_are_not_current_worktree_documents(self):
        for source, route in prepared.PUBLIC_DOCUMENT_SNAPSHOTS.items():
            self.assertIn('/.local/wrapup-2026-10-27/previous-selected-documents/', route['snapshot'])
            self.assertEqual(Path(route['snapshot']).name, Path(source).name)


if __name__ == '__main__':
    unittest.main()

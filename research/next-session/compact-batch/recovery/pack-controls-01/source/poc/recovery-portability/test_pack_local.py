"""Fixed public-only pack inputs; no actual PK, private backup, upload or proof."""
import dataclasses
import os
from pathlib import Path
import tempfile
import unittest

import capsule as c
from pack_local import pack_local
from test_capsule import PublicFixture


class LocalPackControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.f = PublicFixture(self.temporary.name)
        self.paths = {kind: self.f.objects / c.sha(raw) for kind, raw in self.f.raw.items()}

    def test_full_pack_consumed_by_production_stager(self):
        f = self.f
        result = pack_local(f.selection, self.paths, f.parent / 'packed')
        staged = c.stage_capsule(f.parent / 'packed/capsule.json', result['capsule_sha256'],
            f.selection, [f.parent / 'packed'], f.parent / 'restored')
        self.assertEqual(staged.owned_json['history'], f.raw['history'])
        self.assertEqual(staged.staged_paths['public_parameters'].read_bytes(), f.pk)
        self.assertFalse(result['publication_authorized'])
        self.assertFalse(result['spend_authorized'])

    def test_recognition_pack_omits_PK_and_can_restore_without_it(self):
        f = self.f
        self.paths.pop('public_parameters')
        result = pack_local(f.selection, self.paths, f.parent / 'packed', mode='recognition')
        self.assertFalse((f.parent / 'packed/objects/sha256' / c.sha(f.pk)).exists())
        staged = c.stage_capsule(f.parent / 'packed/capsule.json', result['capsule_sha256'],
            f.selection, [f.parent / 'packed'], f.parent / 'restored', mode='recognition')
        self.assertFalse(staged.public_receipt()['public_PK_staged'])

    def test_wrong_role_fails_before_unavailable_PK_source(self):
        f = self.f
        f.parameter['role'] = 'wide32'
        f.rebuild()
        self.paths = {kind: f.objects / c.sha(raw) for kind, raw in f.raw.items()}
        self.paths['public_parameters'] = f.parent / 'NOT_PRESENT_PUBLIC_PK'
        with self.assertRaisesRegex(c.Invalid, '^parameter-manifest-role$'):
            pack_local(f.selection, self.paths, f.parent / 'packed')

    def test_wrong_full_PK_never_emits_an_actual_unexpected_digest(self):
        f = self.f
        bad = f.parent / 'public-corruption'
        bad.write_bytes(b'X' * len(f.pk))
        self.paths['public_parameters'] = bad
        with self.assertRaisesRegex(c.Invalid, '^selected-PK-digest$'):
            pack_local(f.selection, self.paths, f.parent / 'packed')
        self.assertFalse((f.parent / 'packed/capsule.json').exists())

    def test_noninventory_command_is_rejected(self):
        f = self.f
        f.software['command'] = 'NEVER_EXECUTE'
        f.rebuild()
        self.paths = {kind: f.objects / c.sha(raw) for kind, raw in f.raw.items()}
        with self.assertRaisesRegex(c.Invalid, '^software-inventory-fields$'):
            pack_local(f.selection, self.paths, f.parent / 'packed')

    def test_source_hardlink_backup_alias_is_rejected(self):
        f = self.f
        sentinel = f.parent / 'PUBLIC_NON_SEED_SENTINEL'
        os.link(self.paths['history'], sentinel)
        with self.assertRaisesRegex(c.Invalid, '^public-private-inode-alias$'):
            pack_local(f.selection, self.paths, f.parent / 'packed', [sentinel])


if __name__ == '__main__':
    unittest.main()

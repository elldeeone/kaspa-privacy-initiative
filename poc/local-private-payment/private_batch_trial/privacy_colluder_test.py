"""Public known-seed crypto/one-colluder namespace controls, no actual trial."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_codec as codec
import owner_record
import privacy_colluder as producer
import privacy_launch as launch
import privacy_launch_test as launcher_test


class MetadataMove(unittest.TestCase):
    def test_atomic_no_clobber_symlink_alias_and_original_inode(self):
        with tempfile.TemporaryDirectory(prefix='kpb-PUBLIC-leaf-move-control-') as name:
            base = Path(name); source, destination = base / 'source', base / 'destination'
            source.write_bytes(b'PUBLIC SOURCE'); source.chmod(0o600)
            destination.write_bytes(b'PUBLIC EXISTING'); destination.chmod(0o600)
            with self.assertRaises(OSError): producer.move_original_no_replace(source, destination)
            self.assertEqual(destination.read_bytes(), b'PUBLIC EXISTING')
            destination.unlink(); destination.symlink_to(source)
            with self.assertRaises(ValueError): producer.move_original_no_replace(source, destination)
            destination.unlink(); alias = base / 'alias'; os.link(source, alias)
            with self.assertRaises(ValueError): producer.move_original_no_replace(source, destination)
            alias.unlink(); before = source.stat()
            producer.move_original_no_replace(source, destination)
            self.assertFalse(source.exists()); self.assertEqual(destination.stat().st_ino, before.st_ino)
            self.assertEqual(destination.stat().st_nlink, 1)


class ActualColluderNamespace(unittest.TestCase):
    @classmethod
    def setUpClass(cls): launcher_test.LauncherControls.setUpClass()

    def test_actual_known_seed_CF_derivation_and_original_leaf_routing(self):
        control = launcher_test.LauncherControls(methodName='test_actual_launcher_full_public_fixture_and_fixed_repeat_refusal')
        control.setUp(); self.addCleanup(control.doCleanups)
        selected, _ = control.fixture(with_server=False)
        sources = producer.sources(); mounts = []
        source_rows = []
        for name, path in sources.items():
            raw = control.public_read(path); source_rows.append({'name': name, 'sha256': launcher_test.digest(raw)})
            mounts += ['--ro-bind', str(path), str(path)]
        fixture = producer.HERE / 'privacy_colluder_fixture.py'; control.public_read(fixture)
        mounts += ['--ro-bind', str(fixture), str(fixture)]
        for path, pin in ((producer.NODE, producer.NODE_PIN), (producer.CRYPTO, producer.CRYPTO_PIN),
                          (producer.LEAF_MAP, producer.LEAF_MAP_PIN)): control.public_read(path, pin)
        generated = control.base / 'PUBLIC-generated-crypto'; generated.mkdir()
        marker = control.base / 'PUBLIC-crypto-fixture-NAMESPACE.json'
        control.save(marker, {'schema': 'kpb-PUBLIC-known-seed-colluder-fixture/v1', 'financial_proofs': False})
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
            '--ro-bind', str(producer.NODE), '/runtime/node', '--ro-bind', str(producer.CRYPTO), '/runtime/crypto',
            '--ro-bind', str(producer.JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
            '--ro-bind', str(producer.LEAF_MAP), '/runtime/JS-INSTALLED-LEAF-MAP.json',
            '--ro-bind', str(marker), '/NAMESPACE.json', '--bind', str(generated), '/out',
            '/usr/bin/python3', '-B', '-S', str(fixture)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(result.returncode, 0, 'PUBLIC-known-seed fixture: ' + result.stderr.decode(errors='replace')[:2000])
        # Every byte below is an explicitly generated PUBLIC known-seed fixture,
        # not an actual private Original/local record. Production controller
        # reads are still prohibited from the fixture's routed private tree.
        control.save(control.private / 'owner-1/BACKUP.json', {'schema': 'kpb-ak-bound-original-seed-backup/v1',
            'domain_hex32': launch.DOMAIN, 'profile_id_hex32': launch.PROFILE, 'kdf_tag_ascii8': 'KPBKDF01',
            'seed_hex32': (bytes([2]) * 32).hex()}, 0o600)
        for r in (1, 2):
            selected['rounds'][r - 1]['projection'] = control.save(control.base / ('PUBLIC-ACTUAL-CF-PROJECTION-' + str(r) + '.bin'),
                (generated / ('PROJECTION-' + str(r) + '.bin')).read_bytes())
            own = control.private / 'operations' / ('public-pay-r' + str(r)) / 'owner-1'
            control.save(own / owner_record.LEAF, (generated / ('RECORD-' + str(r) + '-V2.bin')).read_bytes(), 0o600)
            (own / 'COLLUDER-CONSTRAINTS.json').unlink()  # discard only the unexecuted PUBLIC setup model
        diagnostic = control.save(control.base / 'PUBLIC-ACTUAL-CF-DIAGNOSTIC.json', selected)
        producer_selection = control.save(control.base / 'PUBLIC-PRODUCER-SELECTION.json', {
            'schema': 'kpb-colluder-view-producer-selection/v1', 'diagnostic_selection': diagnostic,
            'source_members': source_rows})
        plan = producer.run(producer_selection['path'], producer_selection['sha256'], 1)
        self.assertFalse(plan['executed'])
        for r in (1, 2):
            receipt = producer.run(producer_selection['path'], producer_selection['sha256'], r, True)
            self.assertFalse(receipt['private_bodies_read_or_hashed'])
            target = control.private / 'operations' / ('public-pay-r' + str(r)) / 'owner-1/COLLUDER-CONSTRAINTS.json'
            launch.leaf_metadata(target, 0o600)
            with self.assertRaises(ValueError): producer.run(producer_selection['path'], producer_selection['sha256'], r, True)
        launch.run('observe', diagnostic['path'], diagnostic['sha256'], execute=True)
        observation = codec.parse(control.public_read(control.bootstrap / control.label / 'privacy-diagnostics/observe/PUBLIC.json'))
        union = observation['views'][-1]
        self.assertEqual([part['joint_candidates'] for part in union['rounds']], [6, 6])
        self.assertEqual([part['output_creator_assignments'] for part in union['rounds']], [3, 3])
        self.assertGreater(union['coverage']['missing_artifacts'], 0)  # no invented complete corrupt-server capture
        self.assertFalse(any(path.is_relative_to(control.private_base) for path in control.read_paths))


if __name__ == '__main__': unittest.main()

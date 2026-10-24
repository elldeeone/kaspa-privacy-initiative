"""Known-public calibration of the stdlib finite runtime packer only."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_runtime as stage


def fixture(root, *, alias_last=False, alias_profile=False):
    private_files = []
    for role in 'ABCD':
        path = root / 'private' / role / 'backup'
        path.parent.mkdir(parents=True); path.write_bytes(('PUBLIC_CONTROL_BACKUP_'+role).encode())
        path.chmod(0o600); private_files.append(path)
    public = root / 'public'; public.mkdir()
    profile = public / 'profile.json'; profile.write_bytes(b'PUBLIC_CONTROL_NOT_FINANCIAL_AUTHORITY')
    if alias_profile:
        profile.unlink(); profile.hardlink_to(private_files[-1])
    node = public / 'node'; node.write_bytes(b'PUBLIC_CONTROL_NODE_NOT_EXECUTABLE')
    prover = public / 'prover'; prover.write_bytes(b'PUBLIC_CONTROL_PROVER_NOT_EXECUTABLE')
    if alias_last:
        prover.unlink(); prover.hardlink_to(private_files[-1])
    manifest = public / 'manifest.json'; manifest.write_bytes(b'PUBLIC_CONTROL_PARAMETER_METADATA')
    freeze = public / 'freeze.json'
    freeze.write_text(json.dumps({'schema':'kpx6-four-wallet-lifecycle-source-freeze/v1','files':[]}))
    values = {role: {'basename':role,'bytes':path.stat().st_size,
                    'sha256':stage.digest(path.read_bytes())}
              for role,path in (('node',node),('prover',prover))}
    fp = SimpleNamespace(profile_sha256=stage.digest(profile.read_bytes()),
        parameter_manifest_sha256=stage.digest(manifest.read_bytes()), executables=values)
    artifacts = public / 'artifacts.json'
    artifacts.write_text(json.dumps({'schema':'kpx6-four-wallet-public-runtime-artifact-inventory/v1',
        'financial_profile_sha256':fp.profile_sha256,
        'files':[{**values[role],'path':str(path)} for role,path in (('node',node),('prover',prover))]}))
    args = SimpleNamespace(output=root/'result', financial_profile=profile,
        financial_sha256=fp.profile_sha256, artifacts=artifacts,
        artifacts_sha256=stage.digest(artifacts.read_bytes()), source_freeze=freeze,
        source_freeze_sha256=stage.digest(freeze.read_bytes()), manifest=manifest,
        exclude_private_file=private_files, exclude_private_dir=[p.parent for p in private_files],
        source_kind='local')
    return args, fp, public, private_files


class RuntimeStagingControls(unittest.TestCase):
    def test_selected_public_positive_and_late_fourth_backup_alias(self):
        for alias in (False,True):
            with tempfile.TemporaryDirectory(prefix='kpx6-public-stage-control-') as temporary:
                args, fp, public, backups = fixture(Path(temporary),alias_last=alias)
                opened=[];original=stage.read_public
                def read(path,*a,**kw):
                    opened.append(Path(path));return original(path,*a,**kw)
                with patch.object(stage,'financial',return_value=fp), \
                     patch.object(stage,'mapping',return_value={'runtime/node':'/runtime/node',
                                                               'runtime/prover':'/runtime/prover'}), \
                     patch.object(stage,'read_public',side_effect=read):
                    if alias:
                        with self.assertRaises(ValueError):stage.stage(args)
                        self.assertFalse(args.output.exists())
                        self.assertNotIn(public/'node',opened)
                        self.assertNotIn(public/'prover',opened)
                    else:
                        result=stage.stage(args)
                        self.assertEqual(result['public_software_files'],4)
                        self.assertFalse(result['original_backup_or_PK_bytes_read'])
                        self.assertEqual((args.output/'runtime/node').stat().st_mode&0o777,0o500)
                self.assertTrue(all(path not in opened for path in backups))

    def test_profile_alias_refuses_before_any_public_byte(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-public-stage-control-') as temporary:
            args,_,_,_=fixture(Path(temporary),alias_profile=True)
            with patch.object(stage,'read_public',side_effect=AssertionError('public-read-before-alias-guard')) as read:
                with self.assertRaises(ValueError):stage.stage(args)
                read.assert_not_called()
            self.assertFalse(args.output.exists())


if __name__=='__main__':unittest.main()

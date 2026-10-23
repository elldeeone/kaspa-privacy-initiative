"""A separate real CLI process restores public fixtures after source/cache loss."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import capsule as c
from test_capsule import PublicFixture
from test_https_mirror import server


class SourceLossCLI(unittest.TestCase):
    def test_source_and_cache_absent_in_actual_retrieval_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = PublicFixture(tmp)
            (f.objects / f.root_sha).write_bytes(f.index_path.read_bytes())
            fallback = f.parent / 'fallback-cas'
            shutil.copytree(f.root, fallback)
            old_cache = f.parent / 'OLD_PUBLIC_CACHE'
            old_cache.mkdir()
            (old_cache / 'public-parameters').write_bytes(f.pk)
            selection = f.parent / 'trusted-selection.json'
            selection.write_bytes(c.encoded(f.selection_dict))
            output = f.parent / 'empty-client-output'
            output.mkdir(mode=0o700)
            with server(fallback) as (live, _):
                with server(f.root) as (gone, _):
                    pass
                # Only owned public fake fixture directories are removed.
                shutil.rmtree(f.root)
                shutil.rmtree(old_cache)
                code = Path(__file__).resolve().parent
                probe = (
                    'import json,pathlib,runpy,sys; '
                    'a,b=sys.argv[1:3]; '
                    'assert not pathlib.Path(a).exists() and not pathlib.Path(b).exists(); '
                    'pathlib.Path("/out/SOURCE-ABSENCE.json").write_text(json.dumps('
                    '{"original_source_absent":True,"original_cache_absent":True,'
                    '"only_explicit_public_selection_and_code_mounted":True})); '
                    'sys.argv=["/work/https_mirror.py"]+sys.argv[3:]; '
                    'runpy.run_path("/work/https_mirror.py",run_name="__main__")')
                command = ['/usr/bin/bwrap', '--unshare-all', '--share-net', '--clearenv',
                    '--die-with-parent', '--new-session', '--ro-bind', '/usr', '/usr',
                    '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                    '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
                    '--tmpfs', '/tmp', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
                    '--ro-bind', str(code / 'capsule.py'), '/work/capsule.py',
                    '--ro-bind', str(code / 'https_mirror.py'), '/work/https_mirror.py',
                    '--ro-bind', str(selection), '/trusted-selection.json',
                    '--bind', str(output), '/out', '--chdir', '/work',
                    '--setenv', 'PATH', '/usr/bin:/bin', '/usr/bin/python3', '-B', '-c', probe,
                    str(f.root), str(old_cache), f.root_sha, '/trusted-selection.json', '/out/restored',
                    '--mirror-base', gone, '--mirror-base', live, '--allow-loopback-http']
                process = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(process.stdout)
            absence = json.loads((output / 'SOURCE-ABSENCE.json').read_bytes())
            self.assertTrue(absence['original_source_absent'])
            self.assertTrue(absence['original_cache_absent'])
            self.assertTrue(all(row['mirror_ordinal'] == 1
                                for row in report['transport']['objects_downloaded']))
            self.assertEqual((output / 'restored/spend-material/public_parameters').read_bytes(), f.pk)
            self.assertFalse(report['capsule']['current_state_verified'])
            self.assertFalse(report['capsule']['spend_authorized'])
            self.assertFalse(report['transport']['independent_provider_or_retention_qualification'])


if __name__ == '__main__':
    unittest.main()

"""Actual network-off import/boundary probes; no RPC, mining or keys."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

import funding_network as network


class PublicNamespaceImports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='kpb-public-network-import-control-')
        root = Path(cls.temporary.name)
        read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        cls.mounts = []
        for index, source in enumerate(network.sources()):
            target = root / ('public-source-' + str(index))
            target.write_bytes(read(source)); target.chmod(0o400)
            cls.mounts += ['--ro-bind', str(target), str(source)]
        manifest, wheels = network.admitted_wheels(read)
        cls.pythonpath = manifest['runtime_pythonpath']
        for wheel in wheels:
            cls.mounts += ['--ro-bind', wheel['path'], wheel['mount']]
        read(network.bootstrap.NODE, network.bootstrap.wallet.NODE_SHA256)
        cls.mounts += ['--ro-bind', str(network.bootstrap.NODE), '/node']
        for name, pin in network.SDK_PINS.items():
            read(network.SDK / name, pin)
            cls.mounts += ['--ro-bind', str(network.SDK / name), '/sdk/' + name]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def command(self):
        return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *self.mounts, '--chdir', '/tmp']

    def test_actual_new_network_sources_and_shared_SDK_import_without_network_or_secrets(self):
        common = (network.HERE / 'funding_network_common.mjs').as_uri()
        main = (network.HERE / 'funding_network.mjs').as_uri()
        script = ('import fs from "node:fs"; await import(' + json.dumps(main) + '); '
            'const c=await import(' + json.dumps(common) + '); const k=c.loadSdk("/sdk"); '
            'if(typeof k.Transaction!=="function"||typeof k.PoW!=="function")throw Error("SDK"); '
            'if(fs.existsSync("/etc/ssl/private")||fs.existsSync("/original")||fs.existsSync("/home/luke/.codex"))throw Error("private mount"); '
            'const lines=fs.readFileSync("/proc/net/dev","utf8").trim().split("\\n").slice(2); '
            'if(lines.length!==1||!lines[0].trim().startsWith("lo:"))throw Error("network"); '
            'console.log(JSON.stringify({new_sources_imported:true,shared_SDK_imported:true,network_off:true,private_roots_absent:true}));')
        result = subprocess.run(self.command() + ['/node', '--input-type=module', '-e', script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(result.returncode, 0, 'public-fixture namespace diagnostic: ' + result.stderr.decode(errors='replace')[:3000])
        self.assertTrue(json.loads(result.stdout)['network_off'])

    def test_actual_wheel_only_python_imports_with_no_site_packages_or_pycache(self):
        script = ('import json,os,sys,websockets,python_socks; '
            'assert all(".whl/" in m.__file__ for m in (websockets,python_socks)); '
            'assert sys.flags.no_site and sys.dont_write_bytecode; '
            'assert not os.path.exists("/etc/ssl/private") and not os.path.exists("/original"); '
            'print(json.dumps({"websockets":websockets.__version__,"python_socks":python_socks.__version__,"wheel_only":True}))')
        result = subprocess.run(self.command() + ['--setenv', 'PYTHONPATH', self.pythonpath,
            '/usr/bin/python3', '-B', '-S', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(result.returncode, 0, 'finite wheel-only import failed')
        self.assertEqual(json.loads(result.stdout), {'websockets': '17.3', 'python_socks': '3.1.1', 'wheel_only': True})

    def test_actual_public_native_gate_imports_without_private_roots(self):
        script = ('import json,os,sys; sys.path.insert(0,' + repr(str(network.HERE)) + '); '
            'import funding_network_gate; '
            'assert sys.flags.no_site and sys.dont_write_bytecode; '
            'assert not os.path.exists("/original") and not os.path.exists("/etc/ssl/private"); '
            'print(json.dumps({"public_gate_imported":True,"private_roots_absent":True}))')
        result = subprocess.run(self.command() + ['/usr/bin/python3', '-B', '-S', '-c', script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(result.returncode, 0, 'public-fixture gate import: ' + result.stderr.decode(errors='replace')[:3000])
        self.assertTrue(json.loads(result.stdout)['public_gate_imported'])


if __name__ == '__main__': unittest.main()

#!/usr/bin/env python3
"""Launch only the selected public acquire/build/run phase in a minimal namespace."""
import json
from pathlib import Path
import subprocess
import sys

phase = sys.argv[1]
assert phase in {'acquire', 'build', 'run'}
attempt = sys.argv[2] if len(sys.argv) == 3 else '01'
assert attempt.isdigit() and 1 <= int(attempt) <= 999
base = Path('/home/luke/projects/kpi-intensive-2026-10-22/private-construction-build-01')
assert base.is_dir() and not base.is_symlink()
output = base/('out' if attempt == '01' else 'out-'+attempt)
output.mkdir(mode=0o700, exist_ok=True)
assert not output.is_symlink()
assert not (output/phase).exists(), 'fresh retained phase output required'
toolchain = Path('/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu')
argv = ['systemd-run', '--user', '--quiet', '--wait', '--collect', '--pipe',
    '--unit=kpi-private-construction-'+phase+'-'+attempt,
    '--property=CPUQuota=200%', '--property=MemoryMax=4G',
    '--property=MemorySwapMax=0', '--property=TasksMax=512',
    '/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
    '--unshare-uts', '--new-session', '--die-with-parent', '--clearenv']
if phase != 'acquire':
    argv += ['--unshare-net']
for name in ('/usr', '/bin', '/lib', '/lib64'):
    if Path(name).exists():
        argv += ['--ro-bind', name, name]
argv += ['--dir', '/etc']
for name in ('/etc/ssl', '/etc/ld.so.cache', '/etc/nsswitch.conf', '/etc/hosts', '/etc/resolv.conf', '/etc/passwd', '/etc/group'):
    if Path(name).exists():
        argv += ['--ro-bind', name, name]
argv += ['--ro-bind', str(toolchain), '/toolchain',
    '--bind' if phase == 'acquire' else '--ro-bind', str(base/'work'), '/work',
    '--bind', str(base/'cargo-home'), '/cargo', '--bind', str(base/'target'), '/target',
    '--bind', str(output), '/out', '--ro-bind', '/sys/fs/cgroup', '/sys/fs/cgroup',
    '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
    '--setenv', 'PATH', '/toolchain/bin:/usr/bin:/bin',
    '--setenv', 'CARGO_HOME', '/cargo', '--setenv', 'CARGO_TARGET_DIR', '/target',
    '--setenv', 'CC', '/usr/bin/gcc',
    '--setenv', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', '/usr/bin/gcc',
    '--setenv', 'CARGO_NET_GIT_FETCH_WITH_CLI', 'true',
    '--setenv', 'GIT_CONFIG_COUNT', '1', '--setenv', 'GIT_CONFIG_KEY_0', 'http.version',
    '--setenv', 'GIT_CONFIG_VALUE_0', 'HTTP/1.1',
    '--setenv', 'LANG', 'C.UTF-8',
    '--setenv', 'SSL_CERT_FILE', '/etc/ssl/certs/ca-certificates.crt',
    '--chdir', '/work', '/usr/bin/python3', '/work/run_phase.py', phase]
record = {'schema': 'kpi-public-construction-exact-launch/v1', 'phase': phase, 'attempt': attempt,
    'argv': argv, 'clearenv': True, 'host_home_or_financial_artifact_mounted': False,
    'network': 'PUBLIC_SOURCE_ACQUISITION_ONLY' if phase == 'acquire' else 'UNSHARED'}
record_path = output/('LAUNCH-'+phase+'.json')
assert not record_path.exists()
record_path.write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
print(json.dumps(record, sort_keys=True), flush=True)
result = subprocess.run(argv)
sys.exit(result.returncode)

#!/usr/bin/env python3
"""Bounded upstream recovery investigation; no upstream implementation changes.

Build the three upstream binaries first. SOURCE must be a clean git-archive
snapshot, never the original operator's working directory. WORK must be fresh
and outside Git. Only allowlisted public outputs are exported to EVIDENCE.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

EXPECTED_VK = 'd3c179aae5c2c6c013b1de1da5ad4412e4b2c8bae7288c0b9d85e0c986b5a3ec'
EXPECTED_PARAMS = '812b3bda0ec5f9b0c17fc1d530e49fc21defc9dcc5ea9c70a133ca62fec31e99'
BINARIES = ('kpi-private-native-host', 'kpi-private-note-chain-host', 'kpi-private-note-wallet')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'binaries', 'work', 'evidence'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    source, binaries, work, evidence = [getattr(args, n).resolve() for n in ('source', 'binaries', 'work', 'evidence')]
    assert not (source/'.git').exists(), 'use git archive, not the operator checkout'
    work.mkdir(mode=0o700, exist_ok=False)
    evidence.mkdir(parents=True, exist_ok=True)
    software = work/'software'
    software.mkdir()
    for name in BINARIES:
        shutil.copyfile(binaries/name, software/name)
        (software/name).chmod(0o500)
    runs = []

    def run(label, folder, command, *, public=None, source_visible=False, expect=0):
        folder.mkdir(mode=0o700, exist_ok=True)
        sandbox = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                   '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
                   '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                   '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                   '--dir', '/home/recovery', '--setenv', 'HOME', '/home/recovery',
                   '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'RAYON_NUM_THREADS', '4',
                   '--setenv', 'OMP_NUM_THREADS', '4', '--setenv', 'OPENBLAS_NUM_THREADS', '4',
                   '--ro-bind', str(software), '/software', '--bind', str(folder), '/work', '--chdir', '/work']
        if public is not None:
            sandbox += ['--ro-bind', str(public), '/public']
        if source_visible:
            sandbox += ['--ro-bind', str(source), str(source)]
        sandbox += ['--', *command]
        started = time.monotonic()
        completed = subprocess.run(sandbox, capture_output=True, timeout=900)
        (evidence/(label+'.stdout.log')).write_bytes(completed.stdout)
        (evidence/(label+'.stderr.log')).write_bytes(completed.stderr)
        row = dict(label=label, seconds=time.monotonic()-started, exitCode=completed.returncode,
                   command=sandbox, sourceSnapshotMounted=source_visible)
        runs.append(row)
        write(evidence/'isolated-runs.json', runs)
        if expect == 0:
            assert completed.returncode == 0, (label, completed.stderr.decode(errors='replace'))
        else:
            assert completed.returncode != 0 and expect.encode() in completed.stderr, (label, completed.stderr)
        return completed

    audit = '''import json,os,pathlib
assert not pathlib.Path('/home/luke/projects/kaspa-privacy-initiative').exists()
assert not pathlib.Path('/tmp/kpi-p10-recovery-run').exists()
print(json.dumps({'originalCheckoutAccessible':False,'operatorDirectoryAccessible':False,
 'pidNamespaceProcessCount':len([p for p in pathlib.Path('/proc').iterdir() if p.name.isdigit()]),
 'networkDevices':pathlib.Path('/proc/net/dev').read_text(),'mounts':pathlib.Path('/proc/mounts').read_text()},indent=2))'''
    run('namespace-audit', work/'audit', ['/usr/bin/python3', '-c', audit])
    public = work/'published-public'
    public.mkdir()
    shutil.copyfile(source/'poc/private-note-chain/pins/vk.bin', public/'vk.bin')
    run('published-state-replay', public, ['/software/kpi-private-native-host', 'bob-public', '/work/pre-exit.state.bin'], source_visible=True)
    assert (public/'pre-exit.state.bin').read_bytes() == (source/'poc/private-native/evidence/credit-transfer.state.bin').read_bytes()
    probe = work/'published-probe'
    probe.mkdir(mode=0o700)
    # This is ONLY a fresh precondition probe; it is not the original Bob backup.
    (probe/'probe-backup.bin').write_bytes(os.urandom(64))
    (probe/'probe-backup.bin').chmod(0o600)
    base = ['/software/kpi-private-native-host', 'bob-exit', '/work/probe-backup.bin', '/public/pre-exit.state.bin']
    run('missing-published-parameters', probe, base+['/public/public-proving-parameters.bin', '/work/no-result'], public=public, expect='No such file or directory')
    run('vk-is-not-proving-parameters', probe, base+['/public/vk.bin', '/work/no-result'], public=public, expect='independently expected public parameter hash')

    generation = work/'generation'
    run('new-synthetic-generation', generation, ['/software/kpi-private-note-chain-host', 'generate', '/work/instance'])
    instance = generation/'instance'
    new_vk = (instance/'vk-id.bin').read_bytes().hex()
    new_param_sha = sha(instance/'public-proving-parameters.bin')
    assert new_vk != EXPECTED_VK and new_param_sha != EXPECTED_PARAMS
    recovery = work/'synthetic-recovery'
    recovery.mkdir(mode=0o700)
    for name in ('bob-local-secret-backup.bin', 'restore-public-state.bin', 'public-proving-parameters.bin', 'exit.json'):
        shutil.copyfile(instance/name, recovery/name)
        (recovery/name).chmod(0o600)
    write(evidence/'recovery-mount-inventory.json', {
        'scope':'FRESH_SYNTHETIC_INSTANCE_NOT_PUBLISHED_INSTANCE',
        'privateBackupFiles':['bob-local-secret-backup.bin'],
        'publicFiles':['restore-public-state.bin','public-proving-parameters.bin','exit.json'],
        'softwareFiles':list(BINARIES),'originalGenerationDirectoryMounted':False,
        'sourceSnapshotMounted':False,'otherWalletBackupsMounted':False,'networkUnshared':True,
        'pidNamespaceUnshared':True})
    run('synthetic-recovery-namespace-audit', recovery, ['/usr/bin/python3', '-c', audit])
    run('new-synthetic-restore', recovery, ['/software/kpi-private-note-chain-host', 'restore', '/work', new_vk])
    reference = json.loads((instance/'exit.json').read_text())
    restored = json.loads((recovery/'restored-bob-exit.json').read_text())
    assert reference['statement'] == restored['statement'] and reference['proof'] != restored['proof']
    verification = work/'public-only-verification'
    verification.mkdir()
    for name in ('credit.json','transfer.json','competing.json','recovery.json'):
        shutil.copyfile(instance/name, verification/name)
    shutil.copyfile(instance/'vk.bin', verification/'verifying-key.bin')
    shutil.copyfile(recovery/'restored-bob-exit.json', verification/'bob-exit.json')
    run('new-exit-public-only-verification', verification, ['/software/kpi-private-note-wallet', 'verify', '/work', new_vk])
    substitute = work/'substitution-probe'
    substitute.mkdir()
    shutil.copyfile(probe/'probe-backup.bin', substitute/'probe-backup.bin')
    (substitute/'probe-backup.bin').chmod(0o600)
    public_substitute = work/'new-setup-public-only'
    public_substitute.mkdir()
    for name in ('restore-public-state.bin', 'public-proving-parameters.bin'):
        shutil.copyfile(instance/name, public_substitute/name)
    run('new-setup-rejected-by-published-cli', substitute,
        ['/software/kpi-private-native-host','bob-exit','/work/probe-backup.bin','/public/restore-public-state.bin',
         '/public/public-proving-parameters.bin','/work/no-result'], public=public_substitute,
        expect='independently expected public parameter hash')
    # Only the public proof/data allowlist leaves temporary private storage.
    exported = evidence/'synthetic-public'
    exported.mkdir()
    for name in ('credit.json','transfer.json','competing.json','recovery.json','verifying-key.bin','bob-exit.json','separate-verification.json'):
        shutil.copyfile(verification/name, exported/name)
    shutil.copyfile(recovery/'restore-report.json', evidence/'synthetic-restore-report.json')
    write(evidence/'runtime-result.json', {
        'sourceCommit':'cde2b88de3a16af401a2046bd90a124aa105418a',
        'publishedVk':EXPECTED_VK,'publishedParameterSha256':EXPECTED_PARAMS,
        'publishedStateReplayedByteIdentically':True,'publishedStateSha256':sha(public/'pre-exit.state.bin'),
        'publishedInstanceRestored':False,'publishedInstanceBlocker':'exact public proving parameters unavailable',
        'publishedProbeUsedOnlyPlaceholderBackup':True,
        'syntheticVk':new_vk,'syntheticParametersSha256':new_param_sha,
        'syntheticParametersBytes':(instance/'public-proving-parameters.bin').stat().st_size,
        'syntheticRestoreSucceeded':True,'freshProofSameStatementDifferentProofBytes':True,
        'separatePublicOnlyProofVerificationSucceeded':True,
        'newSetupRejectedByPublishedCli':True,
        'binarySha256':{name:sha(software/name) for name in BINARIES},
        'noNativeBroadcast':True,'noRealFunds':True,'physicalSecondMachine':False,
        'publicExports':{p.name:sha(p) for p in exported.iterdir()}})
    print('OK: published recovery blocked at missing parameters; separate fresh synthetic restore and public-only exit verification passed.')


if __name__ == '__main__':
    main()

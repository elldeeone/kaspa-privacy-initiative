#!/usr/bin/env python3
"""Directly re-execute a qualified public financial projection in R0.

The selection must be frozen by its caller.  This worker reopens the complete
public financial handoff, selected host/program/build identities and the host
runtime leaves, stages immutable copies, and invokes the selected host inside a
network-off namespace.  Imported success booleans never create R0 authority.

A local R0 execution is not a native candidate or accepted-head authority.  If
the selection supplies a genuine receipt, the same selected host also verifies
that receipt against the exact external journal.  A successor outpoint still
requires a separately selected native-candidate execution.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess


SCOPE = 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY'
PROJECTION_BYTES = 10685
CORE_BYTES = 10364
PROOF_BYTES = 128
JOURNAL_BYTES = 104
PINNED_PROFILE_SHA256 = '2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36'
PINNED_AGGREGATE_VK_SHA256 = '2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102'
PINNED_OUTPUT_VK_SHA256 = '8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119'
PINNED_HOST_SHA256 = 'b367575f9989dc2433357402c459249f8549c8b5ea9e9b78cdc6da94b6789068'
PINNED_NAMESPACE_SHA256 = '523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6'
PINNED_PROGRAM_SHA256 = 'af7064025876e1045a88f42119ef95a79b1a6a44334a43fcad0d2528d840450c'
PINNED_IMAGE_ID = 'd62eaf8b01ed970048bd8f2565e55ae9f2af3dcad8b7f12d94a40819805dd119'
PINNED_NATIVE_TAIL_SHA256 = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
PINNED_SELECTED_OUTER_SHA256 = 'baebe02a47700111d169583f2b30517403655761753c73d4a30c436443ccec66'
PINNED_HOST_ADMISSION_SHA256 = 'fa81315239ceba1091b479984e4430822bf90472dc2b119309bf3706c70948cd'
PINNED_HOST_SOURCE_SHA256 = 'c7b2f175edf4476334d21f82b056ad4d3c5886e7d41a970cb11c3ff48215b02f'
PINNED_HOST_BUILD_SHA256 = 'd362c034e583fa66102c91c6095eca85c3352c726b42814ffa5546120dffcb4c'
PINNED_GUEST_SOURCE_SHA256 = '79e655e55346961c9a7ec581edf4fa9d8c030efcc31dc905c0db7ae7aa5f834d'
PINNED_GUEST_BUILD_PLAN_SHA256 = 'd94e19dad0739ebf529415431553d95575a8e99dcf8a129b165c3f53014774ca'
PINNED_GUEST_BUILD_RESULT_SHA256 = 'bc06cc052e4270c8b8f798b340438c88edef92e13141bfae7c0629fc0f8458ff'
PINNED_GUEST_ELF_ADMISSION_SHA256 = 'b965cf6bb7a3d821dc07634f774a87d2299f7cd0d7e7627e6dad0d8212b080ba'
PINNED_GUEST_WRAP_SHA256 = 'cce43e58dc6daf588c0252124f0a80961e2f49f0b8c5c093d83775e9c18eafe9'
PINNED_NATIVE_PARAMETERS_SHA256 = '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751'
SOURCE_BASELINE_COMMIT = 'b58de1a182347c4223ebe84f92bb0bdd6c88d003'
PINNED_GUEST_SOURCE_SEAL_SHA256 = 'b2436fa775ea7acf849e7be427de681e005426872b048fd05e12b937f2b00d94'
PINNED_SDK_AUTHENTICATION_SHA256 = '7de8e73d68aa61a6f04ee35b6ec7b6243aa6c8e1c184167df0208a648536c0a1'
PINNED_RUNTIME_SEAL_SHA256 = 'c24a9d184fb597851e334ac3218aa1f9d1f44024fe5b01a1655e4ab14073f35c'
PINNED_IPC_WORKER_SHA256 = '2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6'
PINNED_OLD_POINT = bytes.fromhex(
    '255798360cfa4d4c6b51b7a2f2443d1668a7e5f87cd45d01c4d683bcd76b26e8'
    '00000000')
PINNED_OLD_STATE = bytes.fromhex(
    '4b50424153543031a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b035'
    '8e3bc849611186e07a57ca7b22d02b09e754543daffa55519806a71d74d36567'
    '3dd23f0a1db82a4b030000007c0266741d661e9f82372372fca9e7cdccc02000'
    '5a85e7a998b0b5c5dd61882401000000')
PINNED_OLD_RESERVE = 6_000_000_000
PINNED_OLD_SPK = bytes.fromhex(
    '0000aa2070e9dd7935b4467d5fab3f243bdafae624a8129efdb913e9d7e618057'
    '8557e1e87')
RUNTIME_ROWS = (
    {'role': 'ipc-worker', 'relative_path': 'worker/r0vm',
     'mount_path': '/worker',
     'source_path': '/home/luke/projects/kpi-intensive-2026-10-22/'
                    'proof-target/tools/r0vm',
     'sha256': PINNED_IPC_WORKER_SHA256, 'bytes': 108764424,
     'executable': True},
    {'role': 'host-worker-runtime', 'relative_path': 'runtime/libdl.so.2',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libdl.so.2',
     'source_path': '/usr/lib/x86_64-linux-gnu/libdl.so.2',
     'sha256': '59d725ca30596a9863f4fa2552a7125f834842abc86b40890231c129358965d2',
     'bytes': 14408, 'executable': False},
    {'role': 'host-worker-runtime',
     'relative_path': 'runtime/libstdc++.so.6',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libstdc++.so.6',
     'source_path': '/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.35',
     'sha256': '5bb0d21308f123b6ad46c6f35b42cedfcb8d6d439a53aa3dae04d880aaffdde3',
     'bytes': 2735712, 'executable': False},
    {'role': 'host-worker-runtime',
     'relative_path': 'runtime/libpthread.so.0',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libpthread.so.0',
     'source_path': '/usr/lib/x86_64-linux-gnu/libpthread.so.0',
     'sha256': '1327fc40710691dbd94e88b6cf4efce27fefe8fbb93f7d1164a75b4dccaea696',
     'bytes': 14408, 'executable': False},
    {'role': 'host-worker-runtime',
     'relative_path': 'runtime/libgcc_s.so.1',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
     'source_path': '/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
     'sha256': '9d339ecb409578d6a5d587e6c537a8f9589b8a13fefba30d167433a4b5758bee',
     'bytes': 187120, 'executable': False},
    {'role': 'host-worker-runtime', 'relative_path': 'runtime/libm.so.6',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libm.so.6',
     'source_path': '/usr/lib/x86_64-linux-gnu/libm.so.6',
     'sha256': '1c488db6f4fe8cecb72456bc018de000b7a9b539c2994864b0416b5e8371b3d8',
     'bytes': 1198376, 'executable': False},
    {'role': 'host-worker-runtime', 'relative_path': 'runtime/libc.so.6',
     'mount_path': '/usr/lib/x86_64-linux-gnu/libc.so.6',
     'source_path': '/usr/lib/x86_64-linux-gnu/libc.so.6',
     'sha256': '85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7',
     'bytes': 2190608, 'executable': False},
    {'role': 'host-worker-runtime',
     'relative_path': 'runtime/ld-linux-x86-64.so.2',
     'mount_path': '/lib64/ld-linux-x86-64.so.2',
     'source_path': '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
     'sha256': 'bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14',
     'bytes': 254864, 'executable': False},
    {'role': 'namespace-runtime',
     'relative_path': 'namespace/libselinux.so.1', 'mount_path': None,
     'source_path': '/usr/lib/x86_64-linux-gnu/libselinux.so.1',
     'sha256': '7538ee77765a27966563c0d22437a3080dcdb346ff76cc16d71a3ce3379a716a',
     'bytes': 199120, 'executable': False},
    {'role': 'namespace-runtime', 'relative_path': 'namespace/libcap.so.2',
     'mount_path': None,
     'source_path': '/usr/lib/x86_64-linux-gnu/libcap.so.2.75',
     'sha256': 'c5b463a8136dabb152bad8b04e89bf67bd2049ef49777ed0b96bdbc6cb5b9565',
     'bytes': 51616, 'executable': False},
    {'role': 'namespace-runtime',
     'relative_path': 'namespace/libpcre2-8.so.0', 'mount_path': None,
     'source_path': '/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0',
     'sha256': '4a6b6b2078685b074869d75cb068664d7da6b3036df7bca0442b1bbbd4ac7e65',
     'bytes': 699056, 'executable': False},
)
HOST_RUNTIME_ROWS = tuple(row for row in RUNTIME_ROWS
                          if row['role'] == 'host-worker-runtime')
NAMESPACE_RUNTIME_ROWS = tuple(row for row in RUNTIME_ROWS
                               if row['role'] == 'namespace-runtime')
ARTIFACT_NAMES = (
    'financial_result', 'released_core', 'released_proof',
    'released_projection', 'native_tail', 'retained_projection', 'journal',
    'host_cross_check', 'component_profile', 'outer_selection',
    'public_host', 'namespace_tool', 'qualifier_source',
)
SELECTION_FIELDS = (
    'schema', 'scope', 'reexecutor_source_sha256', 'financial_artifacts',
    'financial_result', 'selected_outer_selection', 'program',
    'host_admission', 'host_source_manifest', 'host_build_result',
    'guest_source_before', 'guest_source_after', 'guest_source_root',
    'guest_build_plan',
    'guest_build_result', 'guest_elf_admission', 'guest_wrap_admission',
    'native_parameters', 'runtime_root', 'receipt',
)
ARTIFACT_FIELDS = (
    'schema', 'status', 'run_id', 'component_profile_sha256', 'head',
    'successor', 'artifacts', 'effects_sha256', 'core_sha256',
    'aggregate_proof_sha256', 'projection_sha256',
    'egress_binding_sha256', 'successor_state_sha256',
    'successor_script_public_key_hex37', 'accepted_head_authority',
    'R0_or_native_VM_executed', 'R0_receipt_verified',
    'full_native_candidate_validated', 'native_settlement_performed',
)
HANDOFF_FIELDS = (
    'schema', 'status', 'run_id', 'source_scope', 'construction_sha256',
    'validation_sha256', 'effects_sha256', 'core_sha256',
    'aggregate_proof_sha256', 'projection_sha256',
    'egress_binding_sha256', 'financial_result_sha256',
    'component_profile_sha256', 'aggregate_vk_sha256', 'output_vk_sha256',
    'host_sha256', 'namespace_tool_sha256', 'qualifier_source_sha256',
    'outer_selection_sha256', 'outer_image_id_hex32',
    'fixed_old_point_sha256', 'fixed_old_state_sha256',
    'native_tail_sha256', 'fixed_old_spk_sha256',
    'successor_state_sha256', 'successor_spk_sha256', 'journal_sha256',
    'all_three_financial_results_agreed',
    'aggregate_and_six_Output_G16_verified',
    'independent_arkworks_reference_checked',
    'public_state_and_global_balance_verified',
    'fixed_unfunded_head_and_state_matched', 'registered_financial_service',
    'accepted_head_authority', 'R0_or_native_VM_executed',
    'R0_receipt_verified', 'full_native_candidate_validated',
    'native_settlement_performed', 'payment_privacy_qualified',
    'creator_partition_read', 'private_owner_files_or_keys_read_or_hashed',
    'raw_party_diagnostics_read', 'outer_selection_changed',
    'host_namespace_isolated', 'host_network_namespace_unshared',
    'wallet_or_owner_or_host_home_mounted',
)


def need(value, category):
    if not value:
        raise ValueError('direct-public-r0-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='sha256'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def fixed_hex(value, width, category):
    need(type(value) is str and len(value) == width * 2 and
         re.fullmatch('[0-9a-f]+', value), category)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw, *, canonical=True):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('direct-public-r0-nonfinite-number')))
    if canonical:
        need(encoded(value) == raw, 'canonical-json')
    return value


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_uid)


class Leaf:
    """One stable, owned, single-link public leaf retained by descriptor."""
    def __init__(self, path, maximum=128 << 20):
        self.path = Path(path)
        need(self.path.is_absolute() and '..' not in self.path.parts and
             not any(part.is_symlink() for part in
                     (self.path, *self.path.parents)),
             'absolute-nonsymlink-leaf')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_CLOEXEC)
        try:
            before = os.fstat(self.fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 before.st_uid == os.geteuid() and
                 not stat.S_IMODE(before.st_mode) & 0o222 and
                 0 < before.st_size <= maximum,
                 'owned-single-link-readonly-bounded-leaf')
            chunks, remaining = [], before.st_size
            while remaining:
                block = os.read(self.fd, min(remaining, 1 << 20))
                need(block, 'complete-leaf-read')
                chunks.append(block); remaining -= len(block)
            self.raw = b''.join(chunks)
            self.identity = _signature(before)
            need(_signature(os.fstat(self.fd)) == self.identity,
                 'stable-leaf-read')
        except BaseException:
            os.close(self.fd); self.fd = None
            raise

    def recheck(self):
        need(_signature(os.fstat(self.fd)) == self.identity and
             _signature(self.path.lstat()) == self.identity,
             'leaf-changed-during-execution')

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


class SealedDirectory:
    """Retain an exact non-writable source-closure directory identity."""
    def __init__(self, path):
        self.path = Path(path)
        need(self.path.is_absolute() and '..' not in self.path.parts and
             not any(part.is_symlink() for part in
                     (self.path, *self.path.parents)),
             'sealed-guest-source-directory-path')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(self.fd)
            need(stat.S_ISDIR(info.st_mode) and
                 info.st_uid == os.geteuid() and
                 stat.S_IMODE(info.st_mode) == 0o500,
                 'sealed-guest-source-directory-mode')
            self.identity = _signature(info)
        except BaseException:
            os.close(self.fd); self.fd = None
            raise

    def recheck(self):
        need(_signature(os.fstat(self.fd)) == self.identity and
             _signature(self.path.lstat()) == self.identity,
             'sealed-guest-source-directory-changed')

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


def read_ref(value, category, selected, maximum=128 << 20):
    fields(value, ('path', 'sha256'), category + '-reference-fields')
    word(value['sha256'], category + '-reference-sha256')
    leaf = Leaf(value['path'], maximum)
    selected.append(leaf)
    need(hashlib.sha256(leaf.raw).hexdigest() == value['sha256'],
         category + '-reference-changed')
    return leaf.raw


def record(value, category):
    fields(value, ('path', 'sha256', 'bytes'), category + '-record-fields')
    word(value['sha256'], category + '-record-sha256')
    need(type(value['path']) is str and value['path'].startswith('/') and
         type(value['bytes']) is int and value['bytes'] > 0,
         category + '-record-shape')
    return {'path': value['path'], 'sha256': value['sha256']}


def write_new(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, 'complete-output-write'); at += count
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_pinned_source(path, sha256, size, owner_uid=None):
    """Read a reviewed live source once before sealing an immutable copy."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(part.is_symlink() for part in (path, *path.parents)),
         'source-seal-canonical-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == expected_uid and before.st_size == size,
             'source-seal-leaf-shape')
        chunks, remaining = [], size
        while remaining:
            block = os.read(fd, min(remaining, 1 << 20))
            need(block, 'source-seal-complete-read')
            chunks.append(block); remaining -= len(block)
        raw = b''.join(chunks)
        need(_signature(before) == _signature(os.fstat(fd)) and
             hashlib.sha256(raw).hexdigest() == sha256,
             'source-seal-reviewed-hash')
        return raw
    finally:
        os.close(fd)


def seal_guest_source(before_path, after_path, output_path):
    """Materialize the reviewed guest source manifest as immutable leaves."""
    before_path, after_path = Path(before_path), Path(after_path)
    before_raw = _read_pinned_source(before_path,
        PINNED_GUEST_SOURCE_SHA256, before_path.stat().st_size)
    after_raw = _read_pinned_source(after_path,
        PINNED_GUEST_SOURCE_SHA256, after_path.stat().st_size)
    need(before_raw == after_raw, 'seal-source-before-after')
    manifest = parse(before_raw, canonical=False)
    need(type(manifest) is list and manifest, 'seal-source-manifest')
    output_path = Path(output_path)
    need(output_path.is_absolute() and not output_path.exists() and
         output_path.parent.is_dir() and
         not any(part.is_symlink() for part in output_path.parents),
         'seal-fresh-output-root')
    os.mkdir(output_path, 0o700)
    root = Path(__file__).resolve().parents[4]
    total = 0
    for row in manifest:
        fields(row, ('path', 'sha256', 'bytes'), 'seal-manifest-row')
        relative = Path(row['path'])
        word(row['sha256'], 'seal-manifest-sha256')
        need(not relative.is_absolute() and '..' not in relative.parts
             and type(row['bytes']) is int and row['bytes'] > 0,
             'seal-manifest-relative-leaf')
        raw = _read_pinned_source(root / relative, row['sha256'], row['bytes'])
        target = output_path / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); total += len(raw)
    seal = {
        'schema': 'kpb-reviewed-r0-guest-source-seal/v1',
        'source_baseline_commit': SOURCE_BASELINE_COMMIT,
        'source_manifest_sha256': PINNED_GUEST_SOURCE_SHA256,
        'leaf_count': len(manifest), 'total_bytes': total,
        'source_files_modified': False,
    }
    seal_raw = encoded(seal)
    need(hashlib.sha256(seal_raw).hexdigest() ==
         PINNED_GUEST_SOURCE_SEAL_SHA256, 'pinned-source-seal-identity')
    write_new(output_path / 'SEAL.json', seal_raw, 0o400)
    directories = sorted((path for path in output_path.rglob('*')
                          if path.is_dir()), reverse=True)
    for directory in directories:
        directory.chmod(0o500)
    output_path.chmod(0o500)
    return seal


def seal_runtime_closure(output_path):
    """Copy the reviewed CPU IPC worker and exact dynamic runtime closure."""
    output_path = Path(output_path)
    need(output_path.is_absolute() and not output_path.exists() and
         output_path.parent.is_dir() and
         not any(part.is_symlink() for part in output_path.parents),
         'runtime-seal-fresh-output-root')
    os.mkdir(output_path, 0o700)
    for row in RUNTIME_ROWS:
        source = Path(row['source_path'])
        source_uid = os.geteuid() if row['role'] == 'ipc-worker' else 0
        raw = _read_pinned_source(source, row['sha256'], row['bytes'],
                                  source_uid)
        target = output_path / row['relative_path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o500 if row['executable'] else 0o400)
    seal = {
        'schema': 'kpb-direct-r0-runtime-seal/v1',
        'sdk_authentication_sha256': PINNED_SDK_AUTHENTICATION_SHA256,
        'rows': [dict(row) for row in RUNTIME_ROWS],
        'source_files_modified': False,
    }
    seal_raw = encoded(seal)
    need(hashlib.sha256(seal_raw).hexdigest() == PINNED_RUNTIME_SEAL_SHA256,
         'pinned-runtime-seal-identity')
    write_new(output_path / 'SEAL.json', seal_raw, 0o400)
    directories = sorted((path for path in output_path.rglob('*')
                          if path.is_dir()), reverse=True)
    for directory in directories:
        directory.chmod(0o500)
    output_path.chmod(0o500)
    return seal


def _runtime_closure(root, selected):
    """Reopen the exact sealed worker/loader/library closure by descriptor."""
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts and root.is_dir() and
         not any(part.is_symlink() for part in (root, *root.parents)),
         'sealed-runtime-root')
    info = root.stat()
    need(info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) == 0o500,
         'owned-private-runtime-root')
    seal_raw = read_ref({'path': str(root / 'SEAL.json'),
        'sha256': PINNED_RUNTIME_SEAL_SHA256}, 'runtime-seal', selected,
        1 << 20)
    seal = parse(seal_raw)
    need(seal == {
        'schema': 'kpb-direct-r0-runtime-seal/v1',
        'sdk_authentication_sha256': PINNED_SDK_AUTHENTICATION_SHA256,
        'rows': [dict(row) for row in RUNTIME_ROWS],
        'source_files_modified': False,
    }, 'exact-runtime-seal')
    expected_files = {row['relative_path'] for row in RUNTIME_ROWS}
    expected_directories = set()
    for relative_name in expected_files:
        parent = Path(relative_name).parent
        while parent != Path('.'):
            expected_directories.add(str(parent)); parent = parent.parent
    entries = list(root.rglob('*'))
    need(all(not path.is_symlink() for path in entries),
         'sealed-runtime-directory-alias')
    actual_files = {str(path.relative_to(root)) for path in entries
                    if path.is_file()}
    actual_directories = {str(path.relative_to(root)) for path in entries
                          if path.is_dir()}
    need(actual_files == expected_files | {'SEAL.json'} and
         actual_directories == expected_directories,
         'exact-sealed-runtime-inventory')
    for directory in (root, *(root / path
                               for path in sorted(expected_directories))):
        selected.append(SealedDirectory(directory))
    result = []
    for row in RUNTIME_ROWS:
        path = root / row['relative_path']
        raw = read_ref({'path': str(path), 'sha256': row['sha256']},
                       'runtime-' + row['relative_path'].replace('/', '-'),
                       selected, max(16 << 20, row['bytes']))
        need(stat.S_IMODE(path.stat().st_mode) ==
             (0o500 if row['executable'] else 0o400),
             'sealed-runtime-leaf-mode')
        need(len(raw) == row['bytes'], 'sealed-runtime-leaf-width')
        result.append({'row': dict(row), 'raw': raw})
    return result, hashlib.sha256(seal_raw).hexdigest()


def successor_state(core):
    need(len(core) == CORE_BYTES, 'core-width')
    result = (b'KPBAST01' + core[104:136] + core[284:316] +
              core[348:352] + core[316:348] + core[352:356])
    need(len(result) == 112, 'successor-state-width')
    return result


def reserve_spk(state, tail):
    need(len(state) == 112 and state[:8] == b'KPBAST01' and
         0 < len(tail) <= 65535 - 114, 'state-tail-shape')
    digest = hashlib.blake2b(b'\x4c\x70' + state + tail,
                             digest_size=32).digest()
    return b'\x00\x00\xaa\x20' + digest + b'\x87'


def _handoff(selection, selected):
    artifacts_raw = read_ref(selection['financial_artifacts'],
                             'financial-artifacts', selected, 8 << 20)
    result_raw = read_ref(selection['financial_result'], 'financial-result',
                          selected, 8 << 20)
    artifacts, result = parse(artifacts_raw), parse(result_raw)
    fields(artifacts, ARTIFACT_FIELDS, 'financial-artifacts-fields')
    fields(result, HANDOFF_FIELDS, 'financial-result-fields')
    need(artifacts['schema'] ==
            'kpb-qualified-public-financial-artifacts/v1' and
         artifacts['status'] ==
            'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED' and
         result['schema'] == 'kpi-financial-public-crypto-handoff/v1' and
         result['status'] ==
            'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED' and
         result['source_scope'] == SCOPE and
         artifacts['run_id'] == result['run_id'],
         'qualified-financial-identity')
    word(artifacts['run_id'], 'financial-run-id')
    fields(artifacts['head'], ('outpoint_hex36', 'state_hex112',
           'reserve_sompi', 'script_public_key_hex37'), 'head-fields')
    fields(artifacts['successor'], ('state_hex112', 'reserve_sompi',
           'script_public_key_hex37'), 'successor-fields')
    fixed_hex(artifacts['head']['outpoint_hex36'], 36, 'head-outpoint')
    fixed_hex(artifacts['head']['state_hex112'], 112, 'head-state')
    fixed_hex(artifacts['head']['script_public_key_hex37'], 37, 'head-spk')
    fixed_hex(artifacts['successor']['state_hex112'], 112,
              'successor-state')
    fixed_hex(artifacts['successor']['script_public_key_hex37'], 37,
              'successor-spk')
    need(all(type(row['reserve_sompi']) is int and
             row['reserve_sompi'] >= 0 for row in
             (artifacts['head'], artifacts['successor'])), 'reserve-shape')
    need(type(artifacts['artifacts']) is dict and
         set(artifacts['artifacts']) == set(ARTIFACT_NAMES),
         'exact-public-artifact-set')
    leaves = {}
    for name in ARTIFACT_NAMES:
        ref = record(artifacts['artifacts'][name], name)
        raw = read_ref(ref, name, selected,
            (128 << 20) if name == 'public_host' else (16 << 20))
        need(len(raw) == artifacts['artifacts'][name]['bytes'],
             name + '-record-width')
        leaves[name] = raw
    core, proof = leaves['released_core'], leaves['released_proof']
    projection = leaves['retained_projection']
    tail = leaves['native_tail']
    need(hashlib.sha256(leaves['component_profile']).hexdigest() ==
            PINNED_PROFILE_SHA256 and
         hashlib.sha256(leaves['public_host']).hexdigest() ==
            PINNED_HOST_SHA256 and
         hashlib.sha256(leaves['namespace_tool']).hexdigest() ==
            PINNED_NAMESPACE_SHA256 and
         hashlib.sha256(tail).hexdigest() == PINNED_NATIVE_TAIL_SHA256,
         'externally-frozen-profile-host-runtime-tail')
    need(len(core) == CORE_BYTES and len(proof) == PROOF_BYTES and
         len(projection) == PROJECTION_BYTES and
         leaves['released_projection'] == projection and
         projection[:193] + b'' == projection[:193] and
         projection[193:193 + CORE_BYTES] == core and
         projection[193 + CORE_BYTES:] == proof,
         'exact-projection-core-proof-join')
    core_sha = hashlib.sha256(core).hexdigest()
    proof_sha = hashlib.sha256(proof).hexdigest()
    projection_sha = hashlib.sha256(projection).hexdigest()
    new_state = successor_state(core)
    new_spk = reserve_spk(new_state, tail)
    new_reserve = int.from_bytes(core[356:364], 'little')
    profile = parse(leaves['component_profile'], canonical=False)
    unselected_outer = parse(leaves['outer_selection'], canonical=False)
    financial = parse(leaves['financial_result'], canonical=False)
    need(unselected_outer['selected'] is False and
         unselected_outer['component_profile_sha256'] ==
            hashlib.sha256(leaves['component_profile']).hexdigest() and
         profile['schema'] == 'private-batch-component-profile/v1' and
         profile['selected'] is True and
         profile['body_core_bytes'] == CORE_BYTES and
         profile['body_bytes'] == CORE_BYTES + PROOF_BYTES and
         profile['journal_bytes'] == JOURNAL_BYTES,
         'profile-unselected-outer-join')
    need(artifacts['head'] == {
             'outpoint_hex36': PINNED_OLD_POINT.hex(),
             'state_hex112': PINNED_OLD_STATE.hex(),
             'reserve_sompi': PINNED_OLD_RESERVE,
             'script_public_key_hex37': PINNED_OLD_SPK.hex()} and
         reserve_spk(PINNED_OLD_STATE, tail) == PINNED_OLD_SPK and
         core[168:204] == PINNED_OLD_POINT and
         core[204:236] == PINNED_OLD_STATE[40:72] and
         core[236:268] == PINNED_OLD_STATE[76:108] and
         core[268:272] == PINNED_OLD_STATE[72:76] and
         core[272:276] == PINNED_OLD_STATE[108:112] and
         int.from_bytes(core[276:284], 'little') == PINNED_OLD_RESERVE and
         projection[:8] == b'KPBAFX01' and
         projection[12:48] == PINNED_OLD_POINT and
         int.from_bytes(projection[56:64], 'little') == PINNED_OLD_RESERVE and
         projection[66:103] == PINNED_OLD_SPK and
         projection[115:152] == new_spk,
         'fixed-old-head')
    need(artifacts['core_sha256'] == result['core_sha256'] == core_sha and
         artifacts['effects_sha256'] == result['effects_sha256'] == core_sha and
         artifacts['aggregate_proof_sha256'] ==
            result['aggregate_proof_sha256'] == proof_sha and
         artifacts['projection_sha256'] ==
            result['projection_sha256'] == projection_sha and
         artifacts['egress_binding_sha256'] ==
            result['egress_binding_sha256'] and
         result['financial_result_sha256'] ==
            hashlib.sha256(leaves['financial_result']).hexdigest() and
         artifacts['component_profile_sha256'] ==
            result['component_profile_sha256'] ==
            hashlib.sha256(leaves['component_profile']).hexdigest() and
         result['host_sha256'] ==
            hashlib.sha256(leaves['public_host']).hexdigest() and
         result['namespace_tool_sha256'] ==
            hashlib.sha256(leaves['namespace_tool']).hexdigest() and
         result['qualifier_source_sha256'] ==
            hashlib.sha256(leaves['qualifier_source']).hexdigest() and
         result['outer_selection_sha256'] ==
            hashlib.sha256(leaves['outer_selection']).hexdigest() and
         result['native_tail_sha256'] == hashlib.sha256(tail).hexdigest() and
         result['aggregate_vk_sha256'] == PINNED_AGGREGATE_VK_SHA256 and
         result['output_vk_sha256'] == PINNED_OUTPUT_VK_SHA256 and
         result['outer_image_id_hex32'] ==
            unselected_outer['image_id_hex32'] and
         result['fixed_old_point_sha256'] ==
            hashlib.sha256(PINNED_OLD_POINT).hexdigest() and
         result['fixed_old_state_sha256'] ==
            hashlib.sha256(PINNED_OLD_STATE).hexdigest() and
         result['fixed_old_spk_sha256'] ==
            hashlib.sha256(PINNED_OLD_SPK).hexdigest() and
         result['successor_state_sha256'] ==
            artifacts['successor_state_sha256'] ==
            hashlib.sha256(new_state).hexdigest() and
         result['successor_spk_sha256'] == hashlib.sha256(new_spk).hexdigest()
         and artifacts['successor_script_public_key_hex37'] == new_spk.hex()
         and artifacts['successor'] == {
             'state_hex112': new_state.hex(),
             'reserve_sompi': new_reserve,
             'script_public_key_hex37': new_spk.hex()} and
         financial.get('schema') == 'kpi-financial-qualification-run/v1' and
         financial.get('run_id') == artifacts['run_id'] and
         financial.get('status') == 'VERIFIED_AND_DURABLE_EGRESS' and
         financial.get('scope') == SCOPE and
         type(financial.get('parties')) is list and
         len(financial['parties']) == 3 and
         all(party.get('construction_sha256') ==
                 result['construction_sha256'] and
             party.get('validation_sha256') == result['validation_sha256'] and
             party.get('effects_sha256') == core_sha and
             party.get('core_sha256') == core_sha and
             party.get('proof_sha256') == proof_sha and
             party.get('projection_sha256') == projection_sha and
             party.get('egress_binding_sha256') ==
                 result['egress_binding_sha256']
             for party in financial['parties']),
         'qualified-handoff-cross-document-join')
    true_fields = ('all_three_financial_results_agreed',
        'aggregate_and_six_Output_G16_verified',
        'independent_arkworks_reference_checked',
        'public_state_and_global_balance_verified',
        'fixed_unfunded_head_and_state_matched', 'host_namespace_isolated',
        'host_network_namespace_unshared')
    false_fields = ('registered_financial_service',
        'accepted_head_authority', 'R0_or_native_VM_executed',
        'R0_receipt_verified', 'full_native_candidate_validated',
        'native_settlement_performed', 'payment_privacy_qualified',
        'creator_partition_read', 'private_owner_files_or_keys_read_or_hashed',
        'raw_party_diagnostics_read', 'outer_selection_changed',
        'wallet_or_owner_or_host_home_mounted')
    need(all(result[name] is True for name in true_fields) and
         all(result[name] is False for name in false_fields) and
         all(artifacts[name] is False for name in (
             'accepted_head_authority', 'R0_or_native_VM_executed',
             'R0_receipt_verified', 'full_native_candidate_validated',
             'native_settlement_performed')),
         'pre-r0-authority-boundary')
    expected_journal = (b'KPBAJR01' +
        bytes.fromhex(profile['domain_hex32']) +
        bytes.fromhex(artifacts['component_profile_sha256']) +
        bytes.fromhex(projection_sha))
    need(len(expected_journal) == JOURNAL_BYTES and
         leaves['journal'] == expected_journal and
         result['journal_sha256'] ==
            hashlib.sha256(expected_journal).hexdigest(),
         'exact-external-journal')
    host_cross = parse(leaves['host_cross_check'], canonical=False)
    need(host_cross == {
        'aggregate_and_six_Output_G16_verified': True,
        'independent_arkworks_reference_checked': True,
        'public_state_and_global_balance_verified': True,
        'projection_sha256': projection_sha,
        'journal_hex104': expected_journal.hex(),
        'journal_sha256': hashlib.sha256(expected_journal).hexdigest(),
        'R0_or_native_VM_executed': False,
        'accepted_chain_authority': False,
    }, 'exact-qualified-host-cross-check')
    return {
        'artifacts_raw': artifacts_raw, 'result_raw': result_raw,
        'artifacts': artifacts, 'result': result, 'leaves': leaves,
        'projection': projection, 'journal': expected_journal,
        'profile': profile, 'unselected_outer': unselected_outer,
        'successor_state': new_state, 'successor_spk': new_spk,
        'successor_reserve': new_reserve,
    }


def _authority(selection, handoff, selected):
    fixed_refs = {
        'selected_outer_selection': PINNED_SELECTED_OUTER_SHA256,
        'program': PINNED_PROGRAM_SHA256,
        'host_admission': PINNED_HOST_ADMISSION_SHA256,
        'host_source_manifest': PINNED_HOST_SOURCE_SHA256,
        'host_build_result': PINNED_HOST_BUILD_SHA256,
        'guest_source_before': PINNED_GUEST_SOURCE_SHA256,
        'guest_source_after': PINNED_GUEST_SOURCE_SHA256,
        'guest_build_plan': PINNED_GUEST_BUILD_PLAN_SHA256,
        'guest_build_result': PINNED_GUEST_BUILD_RESULT_SHA256,
        'guest_elf_admission': PINNED_GUEST_ELF_ADMISSION_SHA256,
        'guest_wrap_admission': PINNED_GUEST_WRAP_SHA256,
        'native_parameters': PINNED_NATIVE_PARAMETERS_SHA256,
    }
    for name, digest in fixed_refs.items():
        need(type(selection[name]) is dict and
             selection[name].get('sha256') == digest,
             'externally-frozen-' + name.replace('_', '-'))
    outer_raw = read_ref(selection['selected_outer_selection'],
                         'selected-outer', selected, 1 << 20)
    program = read_ref(selection['program'], 'program', selected, 16 << 20)
    admission_raw = read_ref(selection['host_admission'], 'host-admission',
                             selected, 1 << 20)
    host_sources_raw = read_ref(selection['host_source_manifest'],
                                'host-source-manifest', selected, 8 << 20)
    host_build_raw = read_ref(selection['host_build_result'],
                              'host-build-result', selected, 1 << 20)
    guest_before_raw = read_ref(selection['guest_source_before'],
                                'guest-source-before', selected, 8 << 20)
    guest_after_raw = read_ref(selection['guest_source_after'],
                               'guest-source-after', selected, 8 << 20)
    guest_plan_raw = read_ref(selection['guest_build_plan'],
                              'guest-build-plan', selected, 8 << 20)
    guest_build_raw = read_ref(selection['guest_build_result'],
                               'guest-build-result', selected, 1 << 20)
    guest_elf_raw = read_ref(selection['guest_elf_admission'],
                             'guest-elf-admission', selected, 1 << 20)
    guest_wrap_raw = read_ref(selection['guest_wrap_admission'],
                              'guest-wrap-admission', selected, 1 << 20)
    native_parameters_raw = read_ref(selection['native_parameters'],
                                     'native-parameters', selected, 8 << 20)
    outer = parse(outer_raw, canonical=False)
    admission = parse(admission_raw, canonical=False)
    host_sources = parse(host_sources_raw, canonical=False)
    host_build = parse(host_build_raw, canonical=False)
    guest_before = parse(guest_before_raw, canonical=False)
    guest_after = parse(guest_after_raw, canonical=False)
    guest_plan = parse(guest_plan_raw, canonical=False)
    guest_build = parse(guest_build_raw, canonical=False)
    guest_elf = parse(guest_elf_raw, canonical=False)
    guest_wrap = parse(guest_wrap_raw, canonical=False)
    native_parameters = parse(native_parameters_raw, canonical=False)
    need(type(host_sources) is list and host_sources and
         type(guest_before) is list and guest_before and
         guest_before == guest_after,
         'nonempty-unchanged-source-manifests')
    root = Path(selection['guest_source_root'])
    need(root.is_absolute() and '..' not in root.parts and root.is_dir() and
         not any(part.is_symlink() for part in (root, *root.parents)),
         'sealed-guest-source-root')
    root_info = root.stat()
    need(root_info.st_uid == os.geteuid() and
         stat.S_IMODE(root_info.st_mode) == 0o500,
         'owned-private-guest-source-root')
    seal_raw = read_ref({'path': str(root / 'SEAL.json'),
        'sha256': PINNED_GUEST_SOURCE_SEAL_SHA256},
        'guest-source-seal', selected, 1 << 20)
    seal = parse(seal_raw)
    expected_relatives = {row['path'] for row in guest_before}
    expected_directories = set()
    for relative_name in expected_relatives:
        parent = Path(relative_name).parent
        while parent != Path('.'):
            expected_directories.add(str(parent)); parent = parent.parent
    entries = list(root.rglob('*'))
    need(all(not path.is_symlink() for path in entries),
         'sealed-guest-source-directory-alias')
    actual_relatives = {str(path.relative_to(root)) for path in entries
                        if path.is_file()}
    actual_directories = {str(path.relative_to(root)) for path in entries
                          if path.is_dir()}
    need(seal == {
        'schema': 'kpb-reviewed-r0-guest-source-seal/v1',
        'source_baseline_commit': SOURCE_BASELINE_COMMIT,
        'source_manifest_sha256': PINNED_GUEST_SOURCE_SHA256,
        'leaf_count': len(guest_before),
        'total_bytes': sum(row['bytes'] for row in guest_before),
        'source_files_modified': False,
    } and actual_relatives == expected_relatives | {'SEAL.json'} and
         actual_directories == expected_directories,
         'exact-sealed-guest-source-inventory')
    for directory in (root, *(root / path
                               for path in sorted(expected_directories))):
        selected.append(SealedDirectory(directory))
    for row in host_sources:
        fields(row, ('build_sha256', 'canonical_sha256', 'path',
                     'qualification_override', 'snapshot'),
               'host-source-manifest-row')
        word(row['build_sha256'], 'host-source-build-sha256')
        word(row['canonical_sha256'], 'host-source-canonical-sha256')
        need(type(row['path']) is str and Path(row['path']).is_absolute() and
             type(row['snapshot']) is str and
             Path(row['snapshot']).is_absolute() and
             type(row['qualification_override']) is bool,
             'host-source-manifest-shape')
        raw = read_ref({'path': row['snapshot'],
                        'sha256': row['build_sha256']},
                       'host-source-snapshot', selected, 8 << 20)
        need(raw, 'host-source-snapshot-nonempty')
    for row in guest_before:
        fields(row, ('path', 'sha256', 'bytes'),
               'guest-source-manifest-row')
        word(row['sha256'], 'guest-source-manifest-sha256')
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts and
             type(row['bytes']) is int and row['bytes'] > 0,
             'guest-source-manifest-shape')
        raw = read_ref({'path': str(root / relative),
                        'sha256': row['sha256']},
                       'guest-source-leaf', selected, 8 << 20)
        need(len(raw) == row['bytes'], 'guest-source-leaf-width')
    fields(outer, ('schema', 'selected', 'classification',
                   'component_profile_sha256', 'image_id_hex32',
                   'program_sha256'), 'selected-outer-fields')
    fields(admission, ('schema', 'path', 'sha256', 'bytes',
        'canonical_lower_modified', 'new_Cargo_alias_removed',
        'qualification_image_selected',
        'funding_or_native_or_R0_execution_qualified'),
        'host-admission-fields')
    host_sha = hashlib.sha256(handoff['leaves']['public_host']).hexdigest()
    program_sha = hashlib.sha256(program).hexdigest()
    unselected = handoff['unselected_outer']
    need(outer_raw and hashlib.sha256(outer_raw).hexdigest() ==
            PINNED_SELECTED_OUTER_SHA256 and
         outer['schema'] == 'private-batch-outer-selection/v1' and
         outer['selected'] is True and
         outer['classification'] == unselected['classification'] and
         outer['component_profile_sha256'] ==
            unselected['component_profile_sha256'] and
         outer['image_id_hex32'] == unselected['image_id_hex32'] and
         outer['image_id_hex32'] == PINNED_IMAGE_ID and
         outer['program_sha256'] == unselected['program_sha256'] ==
            program_sha == PINNED_PROGRAM_SHA256 and
         admission['schema'] == 'new-public-host-byte-admission/v1' and
         admission['sha256'] == host_sha and
         admission['bytes'] == len(handoff['leaves']['public_host']) and
         admission['qualification_image_selected'] is True and
         admission['funding_or_native_or_R0_execution_qualified'] is False,
         'selected-host-program-image-join')
    need(host_sha == PINNED_HOST_SHA256 and
         hashlib.sha256(handoff['leaves']['namespace_tool']).hexdigest() ==
            PINNED_NAMESPACE_SHA256 and
         host_build == {
             'canonical_sources_and_installed_compiler_metadata_unchanged':
                True,
             'exit': 0,
             'financial_or_R0_or_MPC_executed': False,
             'seconds': host_build['seconds']}
         and type(host_build['seconds']) in (int, float) and
         math.isfinite(host_build['seconds']) and host_build['seconds'] >= 0,
         'exact-host-build-result')
    need(guest_plan['schema'] == 'private-batch-public-guest-build/v1' and
         guest_plan['component_profile_sha256'] == PINNED_PROFILE_SHA256 and
         guest_plan['mode'] == 'SELECTED_COMPONENT_BUILD' and
         guest_plan['guest_execution_or_proof'] is False,
         'selected-guest-build-plan')
    need(guest_build == {
        'schema': 'private-batch-public-guest-build-result/v1',
        'exit_code': 0, 'selected_component_profile': True,
        'guest_execution_or_proof': False,
        'native_or_chain_acceptance': False,
        'seconds': guest_build['seconds']}
        and type(guest_build['seconds']) in (int, float)
        and math.isfinite(guest_build['seconds'])
        and guest_build['seconds'] >= 0, 'exact-guest-build-result')
    need(guest_wrap['schema'] ==
            'private-batch-genuine-key-guest-public-wrap/v1' and
         guest_wrap['guest_execution_proof_native_acceptance_funding']
            is False and
         guest_wrap['wrap_report'] == {
             'image_id_hex32': outer['image_id_hex32'],
             'program_sha256': program_sha,
             'proof_or_VM_execution': False, 'selected': False},
         'guest-wrap-program-image-join')
    need(guest_elf['schema'] == 'new-public-guest-elf/v1' and
         guest_elf['sha256'] ==
            '10d7f4052de6353840e213b36a15750d6b2abb92f685a7e7eacab5b081f3105b'
         and guest_elf['selected_component_profile'] is True and
         guest_elf['guest_execution_or_proof'] is False and
         native_parameters['component_profile_sha256'] ==
            PINNED_PROFILE_SHA256 and
         native_parameters['outer_image_hex32'] == PINNED_IMAGE_ID,
         'guest-elf-native-parameter-closure')
    runtime, runtime_seal_sha = _runtime_closure(
        selection['runtime_root'], selected)
    receipt = None
    if selection['receipt'] is not None:
        receipt = read_ref(selection['receipt'], 'r0-receipt', selected,
                           32 << 20)
    return {
        'outer': outer, 'program': program,
        'host': handoff['leaves']['public_host'],
        'namespace': handoff['leaves']['namespace_tool'],
        'runtime': runtime, 'runtime_seal_sha256': runtime_seal_sha,
        'receipt': receipt,
        'host_source_manifest_sha256': hashlib.sha256(
            host_sources_raw).hexdigest(),
        'guest_source_manifest_sha256': hashlib.sha256(
            guest_before_raw).hexdigest(),
        'guest_build_result_sha256': hashlib.sha256(
            guest_build_raw).hexdigest(),
        'guest_build_plan_sha256': hashlib.sha256(
            guest_plan_raw).hexdigest(),
        'guest_elf_admission_sha256': hashlib.sha256(
            guest_elf_raw).hexdigest(),
        'guest_wrap_admission_sha256': hashlib.sha256(
            guest_wrap_raw).hexdigest(),
        'native_parameters_sha256': hashlib.sha256(
            native_parameters_raw).hexdigest(),
    }


def _command(stage, authority, output, scratch, operation):
    loader = stage / 'runtime/ld-linux-x86-64.so.2'
    library_path = str(stage / 'runtime') + ':' + str(stage / 'namespace')
    command = [str(loader), '--library-path', library_path,
        str(stage / 'namespace-tool'), '--unshare-all',
        '--die-with-parent', '--new-session', '--clearenv', '--dir', '/usr',
        '--dir', '/usr/lib', '--dir', '/usr/lib/x86_64-linux-gnu',
        '--dir', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs',
        '/tmp', '--ro-bind', str(stage / 'host'), '/host', '--ro-bind',
        str(stage / 'program'), '/program', '--ro-bind',
        str(stage / 'projection'), '/projection', '--ro-bind',
        str(stage / 'journal'), '/journal', '--ro-bind',
        str(stage / 'worker/r0vm'), '/worker']
    for item in authority['runtime']:
        mount = item['row']['mount_path']
        if mount is not None:
            command += ['--ro-bind', str(stage / item['row']['relative_path']),
                        mount]
    if authority['receipt'] is not None:
        command += ['--ro-bind', str(stage / 'receipt'), '/receipt']
    command += ['--bind', str(output), '/out', '--bind', str(scratch),
        '/scratch', '--setenv', 'HOME', '/scratch/home', '--setenv',
        'XDG_CACHE_HOME', '/scratch/cache', '--setenv', 'RISC0_HOME',
        '/scratch/risc0', '--setenv', 'RISC0_WORK_DIR', '/scratch/work',
        '--setenv', 'RISC0_PROVER', 'ipc', '--setenv', 'RISC0_SERVER_PATH',
        '/worker', '--setenv', 'RAYON_NUM_THREADS', '2', '--setenv',
        'OMP_NUM_THREADS', '2', '--setenv', 'LD_LIBRARY_PATH',
        '/usr/lib/x86_64-linux-gnu', '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'RUST_BACKTRACE', '0', '--chdir', '/scratch', '/host']
    if operation == 'execute':
        return command + ['execute', '/program', '/projection', '/out/execute']
    need(operation == 'verify' and authority['receipt'] is not None,
         'known-host-operation')
    return command + ['verify', '/receipt', '/journal', '/out/verify']


def _report(path, selected, maximum=1 << 20):
    leaf = Leaf(path, maximum); selected.append(leaf)
    return parse(leaf.raw, canonical=False), leaf.raw


def _seal_worker_leaf(path):
    """Seal a completed worker leaf before admitting it as evidence."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_uid == os.geteuid(), 'worker-output-leaf-shape')
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)


def admit_execute_evidence(report, journal, projection, domain_hex32,
                           component_profile_sha256, image_id_hex32):
    """Validate direct host output; returns no standalone authority token."""
    fields(report, ('genuine_seven_G16_public_guest_execution_passed',
        'image_id_hex32', 'projection_sha256', 'journal_sha256', 'cycles',
        'seconds', 'operational_session_cycle_limit', 'proof_generation',
        'native_VM_executed'), 'execute-report-fields')
    expected = (b'KPBAJR01' + bytes.fromhex(domain_hex32) +
                bytes.fromhex(component_profile_sha256) +
                hashlib.sha256(projection).digest())
    need(len(expected) == JOURNAL_BYTES and journal == expected and
         report['genuine_seven_G16_public_guest_execution_passed'] is True and
         report['image_id_hex32'] == image_id_hex32 and
         report['projection_sha256'] ==
            hashlib.sha256(projection).hexdigest() and
         report['journal_sha256'] == hashlib.sha256(expected).hexdigest() and
         type(report['cycles']) is int and report['cycles'] > 0 and
         type(report['seconds']) in (int, float) and
         math.isfinite(report['seconds']) and report['seconds'] >= 0 and
         report['operational_session_cycle_limit'] is None and
         report['proof_generation'] is False and
         report['native_VM_executed'] is False,
         'direct-execute-report')
    return True


def reexecute(selection_path, selection_sha256, output_path):
    selected = []
    try:
        selection_raw = read_ref({'path': str(Path(selection_path)),
                                  'sha256': word(selection_sha256)},
                                 'selection', selected, 8 << 20)
        selection = parse(selection_raw)
        fields(selection, SELECTION_FIELDS, 'selection-fields')
        need(selection['schema'] ==
                'kpb-direct-public-r0-reexecution-selection/v1' and
             selection['scope'] == SCOPE and
             selection['reexecutor_source_sha256'] == source_sha256(),
             'selection-source-scope')
        handoff = _handoff(selection, selected)
        authority = _authority(selection, handoff, selected)
        output_path = Path(output_path)
        need(output_path.is_absolute() and '..' not in output_path.parts and
             not output_path.exists() and output_path.parent.is_dir() and
             not any(part.is_symlink() for part in output_path.parents),
             'fresh-absolute-output')
        os.mkdir(output_path, 0o700)
        stage = output_path / 'stage'; os.mkdir(stage, 0o700)
        public = output_path / 'public-output'; os.mkdir(public, 0o700)
        staged = (
            ('namespace-tool', authority['namespace'], 0o500),
            ('host', authority['host'], 0o500),
            ('program', authority['program'], 0o400),
            ('projection', handoff['projection'], 0o400),
            ('journal', handoff['journal'], 0o400),
        )
        for name, raw, mode in staged:
            write_new(stage / name, raw, mode)
        for item in authority['runtime']:
            target = stage / item['row']['relative_path']
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(target, item['raw'],
                      0o500 if item['row']['executable'] else 0o400)
        if authority['receipt'] is not None:
            write_new(stage / 'receipt', authority['receipt'], 0o400)
        scratch = output_path / 'scratch'; os.mkdir(scratch, 0o700)
        for name in ('home', 'cache', 'work', 'risc0'):
            (scratch / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        stage_directories = sorted((path for path in stage.rglob('*')
                                    if path.is_dir()), reverse=True)
        for directory in stage_directories:
            directory.chmod(0o500)
        stage.chmod(0o500)
        for directory in (stage, *reversed(stage_directories)):
            selected.append(SealedDirectory(directory))
        for path in (path for path in stage.rglob('*') if path.is_file()):
            selected.append(Leaf(path))
        execute_command = _command(stage, authority, public, scratch,
                                   'execute')
        process = subprocess.run(execute_command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            close_fds=True, cwd=output_path,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        need(process.returncode == 0, 'host-execute-nonzero')
        _seal_worker_leaf(public / 'execute/report.json')
        _seal_worker_leaf(public / 'execute/journal.bin')
        report, report_raw = _report(public / 'execute/report.json', selected)
        journal_leaf = Leaf(public / 'execute/journal.bin', JOURNAL_BYTES)
        selected.append(journal_leaf)
        admit_execute_evidence(report, journal_leaf.raw,
            handoff['projection'], handoff['profile']['domain_hex32'],
            handoff['artifacts']['component_profile_sha256'],
            authority['outer']['image_id_hex32'])
        receipt_verified = False
        verify_report_sha = None
        verify_stdout = verify_stderr = b''
        if authority['receipt'] is not None:
            verify_command = _command(stage, authority, public, scratch,
                                      'verify')
            verified = subprocess.run(verify_command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                close_fds=True, cwd=output_path,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            need(verified.returncode == 0, 'host-verify-nonzero')
            verify_stdout, verify_stderr = verified.stdout, verified.stderr
            _seal_worker_leaf(public / 'verify/report.json')
            verify_report, verify_raw = _report(
                public / 'verify/report.json', selected)
            fields(verify_report, ('genuine_new_image_receipt_verified',
                'image_id_hex32', 'journal_sha256', 'development_mode',
                'unresolved_assumptions', 'native_VM_executed'),
                'verify-report-fields')
            need(verify_report == {
                'genuine_new_image_receipt_verified': True,
                'image_id_hex32': authority['outer']['image_id_hex32'],
                'journal_sha256': hashlib.sha256(
                    handoff['journal']).hexdigest(),
                'development_mode': False, 'unresolved_assumptions': False,
                'native_VM_executed': False}, 'direct-receipt-report')
            receipt_verified = True
            verify_report_sha = hashlib.sha256(verify_raw).hexdigest()
        for leaf in selected:
            leaf.recheck()
        status = ('DIRECT_R0_EXECUTED_AND_RECEIPT_VERIFIED_'
                  'NATIVE_CANDIDATE_MISSING' if receipt_verified else
                  'DIRECT_R0_EXECUTED_RECEIPT_MISSING')
        result = {
            'schema': 'kpb-direct-public-r0-reexecution-result/v1',
            'status': status, 'scope': SCOPE,
            'selection_sha256': selection_sha256,
            'financial_run_id': handoff['artifacts']['run_id'],
            'financial_artifacts_sha256': hashlib.sha256(
                handoff['artifacts_raw']).hexdigest(),
            'financial_result_sha256': hashlib.sha256(
                handoff['result_raw']).hexdigest(),
            'projection_sha256': hashlib.sha256(
                handoff['projection']).hexdigest(),
            'journal_sha256': hashlib.sha256(handoff['journal']).hexdigest(),
            'host_sha256': hashlib.sha256(authority['host']).hexdigest(),
            'program_sha256': hashlib.sha256(authority['program']).hexdigest(),
            'image_id_hex32': authority['outer']['image_id_hex32'],
            'component_profile_sha256':
                handoff['artifacts']['component_profile_sha256'],
            'host_source_manifest_sha256':
                authority['host_source_manifest_sha256'],
            'guest_source_manifest_sha256':
                authority['guest_source_manifest_sha256'],
            'guest_build_result_sha256':
                authority['guest_build_result_sha256'],
            'guest_build_plan_sha256':
                authority['guest_build_plan_sha256'],
            'guest_elf_admission_sha256':
                authority['guest_elf_admission_sha256'],
            'guest_wrap_admission_sha256':
                authority['guest_wrap_admission_sha256'],
            'native_parameters_sha256':
                authority['native_parameters_sha256'],
            'host_runtime_closure_sha256':
                authority['runtime_seal_sha256'],
            'execute_report_sha256': hashlib.sha256(report_raw).hexdigest(),
            'verify_report_sha256': verify_report_sha,
            'host_execute_stdout_sha256': hashlib.sha256(
                process.stdout).hexdigest(),
            'host_execute_stderr_sha256': hashlib.sha256(
                process.stderr).hexdigest(),
            'host_verify_stdout_sha256': hashlib.sha256(
                verify_stdout).hexdigest() if receipt_verified else None,
            'host_verify_stderr_sha256': hashlib.sha256(
                verify_stderr).hexdigest() if receipt_verified else None,
            'old_outpoint_hex36': handoff['artifacts']['head'][
                'outpoint_hex36'],
            'old_state_hex112': handoff['artifacts']['head']['state_hex112'],
            'old_reserve_sompi': handoff['artifacts']['head'][
                'reserve_sompi'],
            'old_script_public_key_hex37': handoff['artifacts']['head'][
                'script_public_key_hex37'],
            'successor_state_hex112': handoff['successor_state'].hex(),
            'successor_reserve_sompi': handoff['successor_reserve'],
            'successor_script_public_key_hex37':
                handoff['successor_spk'].hex(),
            'successor_outpoint_hex36': None,
            'R0_or_native_VM_executed': True,
            'R0_receipt_verified': receipt_verified,
            'full_native_candidate_validated': False,
            'successor_outpoint_authority': False,
            'accepted_head_authority': False,
            'native_settlement_performed': False,
            'network_namespace_unshared': True,
            'wallet_owner_host_home_mounted': False,
            'python_orchestrator_runtime_fully_hermetic': False,
            'orchestrator_host_runtime_trust_boundary': True,
        }
        # Completion is written last. A partial directory never qualifies.
        write_new(output_path / 'RESULT.json', encoded(result), 0o400)
        directory = os.open(output_path, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return result
    finally:
        for leaf in selected:
            leaf.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection')
    parser.add_argument('--selection-sha256')
    parser.add_argument('--seal-guest-source', action='store_true')
    parser.add_argument('--guest-source-before')
    parser.add_argument('--guest-source-after')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.seal_guest_source:
            need(args.selection is None and args.selection_sha256 is None and
                 args.guest_source_before and args.guest_source_after,
                 'seal-cli-shape')
            result = seal_guest_source(args.guest_source_before,
                                       args.guest_source_after, args.output)
        else:
            need(args.selection and args.selection_sha256 and
                 args.guest_source_before is None and
                 args.guest_source_after is None, 'execute-cli-shape')
            result = reexecute(args.selection, args.selection_sha256,
                               args.output)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        print('direct-public-r0-reexecution-refused', file=__import__('sys').stderr)
        raise SystemExit(2)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Qualify fixed-unfunded financial EGRESS for the public proof wrapper.

This is a public cryptographic handoff, not accepted-head, R0, native, privacy,
or settlement authority. It reads only the typed public release and directly
executes the pinned public host cross-check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

SCOPE = 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY'
MODEL_SHA256 = 'f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff'
TRACE_SHA256 = '4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e'
AGGREGATE_VK_SHA256 = '2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102'
OUTPUT_VK_SHA256 = '8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119'
AUTH_EXIT_VK_SHA256 = 'e6a49ac7ece8aa501300f24c1ec4602745df6e8d38cd4eed8b1222b36f1e0414'
PROFILE_SHA256 = '2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36'
HOST_SHA256 = 'b367575f9989dc2433357402c459249f8549c8b5ea9e9b78cdc6da94b6789068'
OUTER_SELECTION_SHA256 = 'c44ac47b38bc80602b8d986e7c36527a0b139470fc5e32e00f94c59069f3d93d'
NATIVE_TAIL_SHA256 = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
BWRAP_PATH = Path('/usr/bin/bwrap')
BWRAP_SHA256 = '523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6'
CORE_BYTES, PROOF_BYTES, PREFIX_BYTES = 10364, 128, 193
PROJECTION_BYTES, JOURNAL_BYTES = 10685, 104
PUBLIC_ARTIFACT_NAMES = (
    'financial_result', 'released_core', 'released_proof', 'released_projection',
    'native_tail', 'retained_projection', 'journal', 'host_cross_check',
    'component_profile', 'outer_selection', 'public_host', 'namespace_tool',
    'qualifier_source',
)
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIXED_POINT = bytes.fromhex('255798360cfa4d4c6b51b7a2f2443d1668a7e5f87cd45d01c4d683bcd76b26e800000000')
FIXED_OLD_STATE = bytes.fromhex(
    '4b50424153543031a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
    '7a57ca7b22d02b09e754543daffa55519806a71d74d365673dd23f0a1db82a4b03000000'
    '7c0266741d661e9f82372372fca9e7cdccc020005a85e7a998b0b5c5dd61882401000000')
FIXED_OLD_RESERVE = 6_000_000_000
FIXED_OLD_SPK = bytes.fromhex('0000aa2070e9dd7935b4467d5fab3f243bdafae624a8129efdb913e9d7e6180578557e1e87')


class Refused(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value, reason='canonical SHA256'):
    need(isinstance(value, str) and len(value) == 64 and
         all(character in '0123456789abcdef' for character in value), reason)
    return value


def exact(value, names, reason):
    need(isinstance(value, dict) and set(value) == set(names), reason)


def strict_json(raw, maximum=1 << 20):
    need(len(raw) <= maximum, 'bounded JSON')

    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'duplicate JSON field')
            result[name] = value
        return result

    def reject(_):
        raise Refused('integer-only JSON')

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refused('canonical JSON') from error


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_uid)


class Snapshot:
    """Open one selected public file without following aliases and retain it."""
    def __init__(self, path, *, size=None, maximum=None, owner_uid=None):
        self.path = Path(os.path.abspath(path))
        self.fd = None
        need(self.path == self.path.resolve(strict=True), 'canonical non-symlink public path')
        before = self.path.lstat()
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == expected_uid, 'selected-owner single-link regular public file')
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened = os.fstat(self.fd)
            need(signature(before) == signature(opened), 'public file open race')
            if size is not None:
                need(opened.st_size == size, 'exact public file width')
            if maximum is not None:
                need(opened.st_size <= maximum, 'bounded public file width')
            chunks, remaining = [], opened.st_size
            while remaining:
                block = os.read(self.fd, min(remaining, 1 << 20))
                need(block, 'complete public file read')
                chunks.append(block)
                remaining -= len(block)
            self.raw, self.identity = b''.join(chunks), signature(opened)
            need(signature(os.fstat(self.fd)) == self.identity, 'public file changed while read')
        except BaseException:
            self.close()
            raise

    def recheck(self):
        need(signature(os.fstat(self.fd)) == self.identity and
             signature(self.path.lstat()) == self.identity, 'public file changed during verification')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'complete public output write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def successor_state(core):
    need(len(core) == CORE_BYTES, 'successor state core width')
    state = (b'KPBAST01' + core[104:136] + core[284:316] + core[348:352] +
             core[316:348] + core[352:356])
    need(len(state) == 112, 'successor state width')
    return state


def reserve_spk(state, tail):
    need(len(state) == 112 and state[:8] == b'KPBAST01' and
         0 < len(tail) <= 65535 - 114, 'native state/tail shape')
    digest = hashlib.blake2b(b'\x4c\x70' + state + tail, digest_size=32).digest()
    return b'\x00\x00\xaa\x20' + digest + b'\x87'


PROFILE_KEYS = {
    'schema', 'selected', 'classification', 'chain_genesis_hex32', 'pool_lineage_hex32',
    'profile_id_hex32', 'domain_hex32', 'service_policy_hex32', 'aggregate', 'output',
    'auth_exit', 'value_generator_hex64', 'blinding_generator_hex64',
    'curve_parameters_sha256', 'input_count', 'output_count', 'note_floor_sompi',
    'max_value_sompi', 'body_core_bytes', 'body_bytes', 'journal_bytes',
    'auth_exit_statement_bytes'
}
ROLE_KEYS = {'vk_hex328', 'vk_sha256', 'parameter_manifest_sha256'}


def admit_profile(raw):
    need(sha(raw) == PROFILE_SHA256, 'selected component profile identity')
    profile = strict_json(raw)
    exact(profile, PROFILE_KEYS, 'exact component profile fields')
    need(profile['schema'] == 'private-batch-component-profile/v1' and
         profile['selected'] is True and profile['classification'] == 'RESEARCH_TESTNET_ONLY' and
         profile['input_count'] == 3 and profile['output_count'] == 6 and
         profile['body_core_bytes'] == CORE_BYTES and
         profile['body_bytes'] == CORE_BYTES + PROOF_BYTES and
         profile['journal_bytes'] == JOURNAL_BYTES and profile['auth_exit_statement_bytes'] == 152,
         'selected component profile')
    expected = {'aggregate': AGGREGATE_VK_SHA256, 'output': OUTPUT_VK_SHA256,
                'auth_exit': AUTH_EXIT_VK_SHA256}
    for name, identity in expected.items():
        role = profile[name]
        exact(role, ROLE_KEYS, 'exact role profile fields')
        need(pin(role['vk_sha256']) == identity and len(role['vk_hex328']) == 656 and
             all(c in '0123456789abcdef' for c in role['vk_hex328']) and
             sha(bytes.fromhex(role['vk_hex328'])) == identity and
             pin(role['parameter_manifest_sha256']) != '0' * 64, 'selected role key')
    for name in ('chain_genesis_hex32', 'pool_lineage_hex32', 'profile_id_hex32',
                 'domain_hex32', 'service_policy_hex32'):
        need(pin(profile[name]) != '0' * 64, 'selected nonzero context')
    return profile


def admit_unselected_outer(raw):
    need(sha(raw) == OUTER_SELECTION_SHA256, 'fixed unselected outer identity')
    selection = strict_json(raw)
    exact(selection, {'schema', 'selected', 'classification', 'component_profile_sha256',
                      'image_id_hex32', 'program_sha256'}, 'exact outer selection fields')
    need(selection['schema'] == 'private-batch-outer-selection/v1' and
         selection['selected'] is False and selection['classification'] == 'RESEARCH_TESTNET_ONLY' and
         selection['component_profile_sha256'] == PROFILE_SHA256,
         'outer image remains unselected')
    pin(selection['image_id_hex32']); pin(selection['program_sha256'])
    return selection


TOP_KEYS = {
    'schema', 'run_id', 'status', 'scope', 'parties', 'independent_digest_verifier_controls',
    'registered_financial_service', 'payment_privacy_qualified', 'native_settlement_performed',
    'private_owner_files_or_keys_read_or_hashed', 'raw_party_diagnostics_read'
}
PARTY_KEYS = {
    'schema', 'status', 'scope', 'registered_financial_service', 'party', 'model_sha256',
    'trace_sha256', 'construction_sha256', 'validation_sha256', 'residual_count',
    'actual_R1CS_rows', 'trace_assertions', 'context_byte_assertions',
    'historical_NF_assertions', 'public_challenge', 'effects_sha256', 'core_sha256',
    'proof_sha256', 'projection_sha256', 'egress_binding_sha256',
    'payment_privacy_qualified', 'native_settlement_performed'
}
AGREED_KEYS = (
    'construction_sha256', 'validation_sha256', 'residual_count', 'public_challenge',
    'effects_sha256', 'core_sha256', 'proof_sha256', 'projection_sha256', 'egress_binding_sha256'
)


def admit_release(result_raw, core, proof, projection, profile, native_tail):
    result = strict_json(result_raw)
    exact(result, TOP_KEYS, 'exact financial run result fields')
    need(result['schema'] == 'kpi-financial-qualification-run/v1' and
         pin(result['run_id'], 'canonical run identity') == result['run_id'] and
         result['status'] == 'VERIFIED_AND_DURABLE_EGRESS' and result['scope'] == SCOPE and
         result['registered_financial_service'] is False and
         result['payment_privacy_qualified'] is False and
         result['native_settlement_performed'] is False and
         result['private_owner_files_or_keys_read_or_hashed'] is False and
         result['raw_party_diagnostics_read'] is False,
         'typed unregistered financial completion')
    need(result['independent_digest_verifier_controls'] == [
        {'changed_digest_limb': False, 'exit': 0},
        {'changed_digest_limb': True, 'exit': 1}], 'independent digest verifier controls')
    parties = result['parties']
    need(isinstance(parties, list) and len(parties) == 3, 'all three party results')
    for party_id, party in enumerate(parties):
        exact(party, PARTY_KEYS, 'exact financial party result fields')
        need(party['schema'] == 'kpi-financial-qualification-party/v1' and
             party['status'] == 'VERIFIED_AND_DURABLE_EGRESS' and party['scope'] == SCOPE and
             party['registered_financial_service'] is False and party['party'] == party_id and
             party['model_sha256'] == MODEL_SHA256 and party['trace_sha256'] == TRACE_SHA256 and
             party['residual_count'] == 13127204 and party['actual_R1CS_rows'] == 13093029 and
             party['trace_assertions'] == 33896 and party['context_byte_assertions'] == 276 and
             party['historical_NF_assertions'] == 0 and
             party['payment_privacy_qualified'] is False and
             party['native_settlement_performed'] is False,
             'typed financial party completion')
        for name in ('construction_sha256', 'validation_sha256', 'effects_sha256', 'core_sha256',
                     'proof_sha256', 'projection_sha256', 'egress_binding_sha256'):
            pin(party[name], 'canonical party identity')
        challenge = party['public_challenge']
        need(isinstance(challenge, str) and challenge.isdecimal() and
             str(int(challenge)) == challenge and 0 <= int(challenge) < FIELD_MODULUS,
             'canonical checked public challenge')
    for name in AGREED_KEYS:
        need(len({party[name] for party in parties}) == 1, 'all-three party agreement')
    first = parties[0]
    need(len(core) == CORE_BYTES and len(proof) == PROOF_BYTES and
         len(projection) == PROJECTION_BYTES, 'released artifact widths')
    need(sha(core) == first['core_sha256'] == first['effects_sha256'] and
         sha(proof) == first['proof_sha256'] and sha(projection) == first['projection_sha256'],
         'released artifact identities')
    need(projection[PREFIX_BYTES:PREFIX_BYTES + CORE_BYTES] == core and
         projection[PREFIX_BYTES + CORE_BYTES:] == proof, 'exact core/proof/projection join')
    need(projection[:8] == b'KPBAFX01' and projection[8:12] == b'\x01\x00\x01\x00' and
         int.from_bytes(projection[189:193], 'little') == CORE_BYTES + PROOF_BYTES and
         core[:8] == b'KPBAEF01', 'canonical released projection framing')
    context = b''.join(bytes.fromhex(profile[name]) for name in (
        'chain_genesis_hex32', 'pool_lineage_hex32', 'profile_id_hex32',
        'domain_hex32', 'service_policy_hex32'))
    need(core[8:168] == context, 'released core selected profile context')
    need(core[168:204] == FIXED_POINT and core[204:236] == FIXED_OLD_STATE[40:72] and
         core[236:268] == FIXED_OLD_STATE[76:108] and
         core[268:272] == FIXED_OLD_STATE[72:76] and
         core[272:276] == FIXED_OLD_STATE[108:112] and
         int.from_bytes(core[276:284], 'little') == FIXED_OLD_RESERVE,
         'fixed unfunded old head and state')
    need(sha(native_tail) == NATIVE_TAIL_SHA256, 'selected immutable native tail')
    old_spk = reserve_spk(FIXED_OLD_STATE, native_tail)
    new_spk = reserve_spk(successor_state(core), native_tail)
    need(old_spk == FIXED_OLD_SPK and projection[12:48] == FIXED_POINT and
         int.from_bytes(projection[56:64], 'little') == FIXED_OLD_RESERVE and
         projection[66:103] == old_spk and projection[115:152] == new_spk,
         'fixed old and derived successor native scripts')
    return result


KEY_REPORT_KEYS = {
    'component_profile_sha256', 'aggregate_vk_sha256', 'output_vk_sha256',
    'auth_exit_vk_sha256', 'domain_hex32', 'private_input_read'
}
HOST_REPORT_KEYS = {
    'aggregate_and_six_Output_G16_verified', 'independent_arkworks_reference_checked',
    'public_state_and_global_balance_verified', 'projection_sha256', 'journal_hex104',
    'journal_sha256', 'R0_or_native_VM_executed', 'accepted_chain_authority'
}


def run_host(host, projection, profile, namespace_tool):
    """Directly execute the selected host; no caller-supplied report is accepted."""
    with tempfile.TemporaryDirectory(prefix='kpb-public-release-') as temporary_name:
        temporary = Path(temporary_name)
        selected_host = temporary / 'host'
        selected_projection = temporary / 'projection.bin'
        host_output = temporary / 'public-output'
        host_output.mkdir(mode=0o700)
        write_new(selected_host, host, 0o500)
        write_new(selected_projection, projection)
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'RUST_BACKTRACE': '0'}
        sandbox = [str(namespace_tool), '--unshare-all', '--die-with-parent', '--new-session',
                   '--clearenv', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
                   '--ro-bind', '/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
                   '--tmpfs', '/tmp', '--dir', '/app', '--dir', '/input',
                   '--ro-bind', str(selected_host), '/app/host',
                   '--ro-bind', str(selected_projection), '/input/projection.bin',
                   '--bind', str(host_output), '/out', '--setenv', 'PATH', '/usr/bin:/bin',
                   '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'RUST_BACKTRACE', '0',
                   '--chdir', '/tmp']

        def invoke(arguments):
            completed = subprocess.run([*sandbox, *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, cwd=temporary, env=environment, close_fds=True)
            need(completed.returncode == 0 and len(completed.stdout) <= (1 << 20) and
                 len(completed.stderr) <= (1 << 20), 'pinned public host refused')
            return strict_json(completed.stdout)

        keys = invoke(['/app/host', 'key-check'])
        exact(keys, KEY_REPORT_KEYS, 'exact direct key-check fields')
        need(keys == {
            'component_profile_sha256': PROFILE_SHA256,
            'aggregate_vk_sha256': AGGREGATE_VK_SHA256,
            'output_vk_sha256': OUTPUT_VK_SHA256,
            'auth_exit_vk_sha256': AUTH_EXIT_VK_SHA256,
            'domain_hex32': profile['domain_hex32'],
            'private_input_read': False,
        }, 'direct host embedded key selection')
        cross = host_output / 'cross-check'
        stdout_report = invoke(['/app/host', 'cross-check', '/input/projection.bin', '/out/cross-check'])
        need(cross.is_dir() and set(os.listdir(cross)) == {'journal.bin', 'report.json'},
             'finite direct cross-check outputs')
        report_snapshot = Snapshot(cross / 'report.json', maximum=1 << 20)
        journal_snapshot = Snapshot(cross / 'journal.bin', size=JOURNAL_BYTES)
        try:
            report = strict_json(report_snapshot.raw)
            exact(report, HOST_REPORT_KEYS, 'exact direct host report fields')
            need(report == stdout_report, 'direct host stdout/report agreement')
            expected_journal = (b'KPBAJR01' + bytes.fromhex(profile['domain_hex32']) +
                                bytes.fromhex(PROFILE_SHA256) + bytes.fromhex(sha(projection)))
            need(journal_snapshot.raw == expected_journal and report == {
                'aggregate_and_six_Output_G16_verified': True,
                'independent_arkworks_reference_checked': True,
                'public_state_and_global_balance_verified': True,
                'projection_sha256': sha(projection),
                'journal_hex104': expected_journal.hex(),
                'journal_sha256': sha(expected_journal),
                'R0_or_native_VM_executed': False,
                'accepted_chain_authority': False,
            }, 'direct aggregate/six-Output/reference verification')
            report_snapshot.recheck()
            journal_snapshot.recheck()
            return report, expected_journal
        finally:
            report_snapshot.close()
            journal_snapshot.close()


def artifact(path, raw):
    return {'path': str(path), 'sha256': sha(raw), 'bytes': len(raw)}


def qualify(release_directory, component_profile, outer_selection, host_path, output_path):
    release_directory = Path(os.path.abspath(release_directory))
    need(release_directory == release_directory.resolve(strict=True) and release_directory.is_dir(),
         'canonical public release directory')
    output_path = Path(os.path.abspath(output_path))
    need(not output_path.exists() and output_path.parent == output_path.parent.resolve(strict=True),
         'fresh canonical output directory')
    selected = []
    try:
        for path, options in (
            (release_directory / 'RESULT.json', {'maximum': 1 << 20}),
            (release_directory / 'released-core.bin', {'size': CORE_BYTES}),
            (release_directory / 'released-proof.bin', {'size': PROOF_BYTES}),
            (release_directory / 'released-projection.bin', {'size': PROJECTION_BYTES}),
            (release_directory / 'native-tail.bin', {'maximum': 65535 - 114}),
            (component_profile, {'maximum': 1 << 20}),
            (outer_selection, {'maximum': 1 << 20}),
            (host_path, {'maximum': 256 << 20}),
            (BWRAP_PATH, {'maximum': 1 << 20, 'owner_uid': 0}),
            (Path(__file__), {'maximum': 1 << 20}),
        ):
            selected.append(Snapshot(path, **options))
        (result_file, core_file, proof_file, projection_file, native_tail_file,
         profile_file, outer_file, host_file, namespace_file, qualifier_file) = selected
        need(sha(host_file.raw) == HOST_SHA256, 'selected public host identity')
        need(sha(namespace_file.raw) == BWRAP_SHA256, 'selected namespace tool identity')
        profile = admit_profile(profile_file.raw)
        outer = admit_unselected_outer(outer_file.raw)
        financial = admit_release(result_file.raw, core_file.raw, proof_file.raw,
                                   projection_file.raw, profile, native_tail_file.raw)
        host_report, journal = run_host(host_file.raw, projection_file.raw, profile, namespace_file.path)
        for snapshot in selected:
            snapshot.recheck()
        party = financial['parties'][0]
        old_spk = reserve_spk(FIXED_OLD_STATE, native_tail_file.raw)
        new_state = successor_state(core_file.raw)
        new_spk = reserve_spk(new_state, native_tail_file.raw)
        new_reserve = int.from_bytes(core_file.raw[356:364], 'little')
        outcome = {
            'schema': 'kpi-financial-public-crypto-handoff/v1',
            'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
            'run_id': financial['run_id'],
            'source_scope': financial['scope'],
            'construction_sha256': party['construction_sha256'],
            'validation_sha256': party['validation_sha256'],
            'effects_sha256': party['effects_sha256'],
            'core_sha256': party['core_sha256'],
            'aggregate_proof_sha256': party['proof_sha256'],
            'projection_sha256': party['projection_sha256'],
            'egress_binding_sha256': party['egress_binding_sha256'],
            'financial_result_sha256': sha(result_file.raw),
            'component_profile_sha256': PROFILE_SHA256,
            'aggregate_vk_sha256': AGGREGATE_VK_SHA256,
            'output_vk_sha256': OUTPUT_VK_SHA256,
            'host_sha256': HOST_SHA256,
            'namespace_tool_sha256': BWRAP_SHA256,
            'qualifier_source_sha256': sha(qualifier_file.raw),
            'outer_selection_sha256': OUTER_SELECTION_SHA256,
            'outer_image_id_hex32': outer['image_id_hex32'],
            'fixed_old_point_sha256': sha(FIXED_POINT),
            'fixed_old_state_sha256': sha(FIXED_OLD_STATE),
            'native_tail_sha256': NATIVE_TAIL_SHA256,
            'fixed_old_spk_sha256': sha(old_spk),
            'successor_state_sha256': sha(new_state),
            'successor_spk_sha256': sha(new_spk),
            'journal_sha256': sha(journal),
            'all_three_financial_results_agreed': True,
            'aggregate_and_six_Output_G16_verified': True,
            'independent_arkworks_reference_checked': True,
            'public_state_and_global_balance_verified': True,
            'fixed_unfunded_head_and_state_matched': True,
            'registered_financial_service': False,
            'accepted_head_authority': False,
            'R0_or_native_VM_executed': False,
            'R0_receipt_verified': False,
            'full_native_candidate_validated': False,
            'native_settlement_performed': False,
            'payment_privacy_qualified': False,
            'creator_partition_read': False,
            'private_owner_files_or_keys_read_or_hashed': False,
            'raw_party_diagnostics_read': False,
            'outer_selection_changed': False,
            'host_namespace_isolated': True,
            'host_network_namespace_unshared': True,
            'wallet_or_owner_or_host_home_mounted': False,
        }
        os.mkdir(output_path, 0o700)
        projection_output = output_path / 'projection.bin'
        journal_output = output_path / 'journal.bin'
        report_output = output_path / 'HOST-CROSS-CHECK.json'
        write_new(projection_output, projection_file.raw)
        write_new(journal_output, journal)
        write_new(report_output, encoded(host_report))
        artifact_records = {
            'financial_result': artifact(result_file.path, result_file.raw),
            'released_core': artifact(core_file.path, core_file.raw),
            'released_proof': artifact(proof_file.path, proof_file.raw),
            'released_projection': artifact(projection_file.path, projection_file.raw),
            'native_tail': artifact(native_tail_file.path, native_tail_file.raw),
            'retained_projection': artifact(projection_output, projection_file.raw),
            'journal': artifact(journal_output, journal),
            'host_cross_check': artifact(report_output, encoded(host_report)),
            'component_profile': artifact(profile_file.path, profile_file.raw),
            'outer_selection': artifact(outer_file.path, outer_file.raw),
            'public_host': artifact(host_file.path, host_file.raw),
            'namespace_tool': artifact(namespace_file.path, namespace_file.raw),
            'qualifier_source': artifact(qualifier_file.path, qualifier_file.raw),
        }
        exact(artifact_records, PUBLIC_ARTIFACT_NAMES, 'exact public handoff artifact set')
        artifacts = {
            'schema': 'kpb-qualified-public-financial-artifacts/v1',
            'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
            'run_id': financial['run_id'],
            'component_profile_sha256': PROFILE_SHA256,
            'head': {
                'outpoint_hex36': FIXED_POINT.hex(),
                'state_hex112': FIXED_OLD_STATE.hex(),
                'reserve_sompi': FIXED_OLD_RESERVE,
                'script_public_key_hex37': old_spk.hex(),
            },
            'successor': {
                'state_hex112': new_state.hex(),
                'reserve_sompi': new_reserve,
                'script_public_key_hex37': new_spk.hex(),
            },
            'artifacts': artifact_records,
            'effects_sha256': party['effects_sha256'],
            'core_sha256': party['core_sha256'],
            'aggregate_proof_sha256': party['proof_sha256'],
            'projection_sha256': party['projection_sha256'],
            'egress_binding_sha256': party['egress_binding_sha256'],
            'successor_state_sha256': sha(new_state),
            'successor_script_public_key_hex37': new_spk.hex(),
            'accepted_head_authority': False,
            'R0_or_native_VM_executed': False,
            'R0_receipt_verified': False,
            'full_native_candidate_validated': False,
            'native_settlement_performed': False,
        }
        write_new(output_path / 'ARTIFACTS.json', encoded(artifacts))
        # RESULT is the durable completion marker and is always written last.
        write_new(output_path / 'RESULT.json', encoded(outcome))
        directory = os.open(output_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        parent = os.open(output_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return outcome
    finally:
        for snapshot in selected:
            snapshot.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-directory', required=True, type=Path)
    parser.add_argument('--component-profile', required=True, type=Path)
    parser.add_argument('--outer-selection', required=True, type=Path)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    arguments = parser.parse_args()
    try:
        print(json.dumps(qualify(arguments.release_directory, arguments.component_profile,
                                 arguments.outer_selection, arguments.host, arguments.output), sort_keys=True))
    except (Refused, OSError, ValueError, TypeError, KeyError):
        print('financial-public-crypto-handoff-refused', file=__import__('sys').stderr)
        raise SystemExit(2)


if __name__ == '__main__':
    main()

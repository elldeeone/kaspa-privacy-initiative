"""Public unfunded ADR0063 case construction through the selected native codec.

The codec's body/normalize reports do not execute the VM or verify any proof.
Callers select/authenticate its executable and new image/profile externally.
No wallet opening, private key, PK, network, funding or submission is supported.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

# This module deliberately imports the adjacent fixed public codec, not a
# caller-supplied callback or a body-selected module.
import importlib.util
import sys

_wire_spec = importlib.util.spec_from_file_location(
    "_kpx7_wire_for_native_case", Path(__file__).resolve().with_name("wire.py"))
_wire = importlib.util.module_from_spec(_wire_spec)
sys.modules[_wire_spec.name] = _wire
_wire_spec.loader.exec_module(_wire)
BODY_LEN, PROJECTION_LEN = _wire.BODY_LEN, _wire.PROJECTION_LEN
parse_body, parse_projection = _wire.parse_body, _wire.parse_projection


def need(ok, code):
    if not ok:
        raise ValueError(code)


def _hex(raw, size, code):
    need(type(raw) is bytes and len(raw) == size, code)
    return raw.hex()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate-codec-response-key')
        result[key] = value
    return result


def _hash_executable(path, expected):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'selected-codec-path')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_mode & 0o111, 'selected-codec-executable')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(opened, k) for k in fields) == tuple(getattr(before, k) for k in fields),
             'selected-codec-swapped')
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
        after = os.fstat(handle.fileno())
    need(tuple(getattr(before, k) for k in fields) == tuple(getattr(after, k) for k in fields)
         and digest == expected, 'selected-codec-identity')
    return path


@dataclass(frozen=True)
class NativeCodec:
    executable: Path
    sha256: str

    def invoke(self, request):
        executable = _hash_executable(self.executable, self.sha256)
        raw = json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        result = subprocess.run([str(executable)], input=raw, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        need(result.returncode == 0, 'native-codec-refused')
        value = json.loads(result.stdout.decode('utf-8'), object_pairs_hook=_unique,
                           parse_float=lambda _: (_ for _ in ()).throw(ValueError('codec-float')),
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('codec-number')))
        need(type(value) is dict and value.get('native_VM_executed') is False
             and value.get('component_G16_or_outer_receipt_verified') is False
             and value.get('accepted_backing_or_currentness') is False,
             'native-codec-evidence-scope')
        return value


def emit(codec, state, image, component_profile_sha):
    """Emit bytes under caller-selected new public identities; no authority claim."""
    return codec.invoke({'operation': 'emit', 'state_hex112': _hex(state, 112, 'state-width'),
                         'outer_image_hex32': _hex(image, 32, 'image-width'),
                         'component_profile_sha256': _hex(component_profile_sha, 32, 'component-profile-width')})


def project(codec, case, image, component_profile_sha, *, normalize=False):
    """Return canonical case/projection/journal after exact native framing checks."""
    result = codec.invoke({'operation': 'normalize' if normalize else 'body', 'case': case,
                           'outer_image_hex32': _hex(image, 32, 'image-width'),
                           'component_profile_sha256': _hex(component_profile_sha, 32, 'component-profile-width')})
    projection = bytes.fromhex(result['financial_projection_hex'])
    journal = bytes.fromhex(result['journal_hex104'])
    need(len(projection) == PROJECTION_LEN and len(journal) == 104, 'native-codec-width')
    parse_projection(projection)
    need(hashlib.sha256(projection).hexdigest() == result['financial_projection_sha256']
         and hashlib.sha256(journal).hexdigest() == result['journal_sha256'], 'native-codec-hash')
    need(journal == b'KPX7JR01' + bytes.fromhex('32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d')
         + component_profile_sha + hashlib.sha256(projection).digest(), 'native-codec-journal')
    return result['case'], projection, journal, result


def make_case(codec, body, image, component_profile_sha, compute_budget, *,
              outer_proof=bytes(128), block_daa_score=0):
    """Build an unfunded supplied-context case. Zero default proof is not valid."""
    parsed = parse_body(body)
    need(type(compute_budget) is int and 1 <= compute_budget <= 65535, 'proposal-compute-budget')
    need(type(block_daa_score) is int and 0 <= block_daa_score < 1 << 64, 'supplied-DAA-range')
    _hex(outer_proof, 128, 'outer-proof-width')
    current = emit(codec, parsed.old_state.raw, image, component_profile_sha)
    successor = emit(codec, parsed.new_state.raw, image, component_profile_sha)
    frame = bytes.fromhex(current['zero_proof_witness_hex'])
    need(frame[:2] == b'\x4c\x80' and len(frame) == 133 + current['redeem_bytes'], 'canonical-new-witness')
    witness = frame[:2] + outer_proof + frame[130:]
    case = {'transaction': {'version': 1, 'id': bytes(32).hex(),
             'inputs': [{'previousOutpoint': {'transactionId': parsed.point[:32].hex(),
                        'index': int.from_bytes(parsed.point[32:], 'little')},
                        'signatureScript': witness.hex(), 'sequence': (1 << 64) - 1,
                        'computeBudget': compute_budget}],
             'outputs': [{'value': parsed.new_reserve, 'scriptPublicKey': successor['script_public_key'],
                          'covenant': None}], 'lockTime': 0, 'subnetworkId': bytes(20).hex(),
             'gas': 0, 'payload': body.hex(), 'mass': 0},
            'entries': [{'amount': parsed.old_reserve, 'scriptPublicKey': current['script_public_key'],
                         'blockDaaScore': block_daa_score, 'isCoinbase': False, 'covenantId': None}]}
    return project(codec, case, image, component_profile_sha, normalize=True)


def replace_outer_proof(codec, case, proof, image, component_profile_sha):
    """Change only the outer receipt witness; financial projection must not move."""
    _hex(proof, 128, 'outer-proof-width')
    _, before, _, _ = project(codec, case, image, component_profile_sha)
    updated = deepcopy(case)
    frame = bytes.fromhex(updated['transaction']['inputs'][0]['signatureScript'])
    need(frame[:2] == b'\x4c\x80' and frame[130] == 0x4d, 'canonical-new-witness')
    updated['transaction']['inputs'][0]['signatureScript'] = (frame[:2] + proof + frame[130:]).hex()
    normalized, after, journal, result = project(codec, updated, image, component_profile_sha, normalize=True)
    need(before == after, 'outer-proof-moved-financial-projection')
    return normalized, after, journal, result

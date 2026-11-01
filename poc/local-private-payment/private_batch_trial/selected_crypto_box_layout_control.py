"""No-funds evidence for the selected crypto_box sealed-byte layout.

This control uses only a published synthetic test key and plaintext.  It makes
no confidentiality, key-privacy, source-correspondence, or production claim.
"""

import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import stat
import subprocess


SELECTED_BINARY = Path(
    '/home/luke/.local/share/kpi-private-cashout-trial-runtime/'
    'adr0054-01/crypto')
SELECTED_BINARY_SHA256 = \
    '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
FIXED_TEST_SECRET = bytes(range(1, 33))
FIXED_TEST_SECRET_SHA256 = \
    'ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9'
FIXED_TEST_PLAINTEXT = bytes((index * 17 + 3) % 256 for index in range(216))
FIXED_TEST_PLAINTEXT_SHA256 = \
    '4b6bdc1d08475896bbb71750e2f7849c2305eef637adaa2772960692555578ad'
FIXED_TEST_RECIPIENT_PUBLIC_HEX = \
    '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c'
RETAINED_VECTOR_HEX = (
    'df7bda0f83a46963d818a5ecf12be06ee10d59c9747fcbd24991f47ac7d86f0d'
    '8aca1d2ebc9c0b73e1c5f3e5e822774940073524122603782f8e2084f06598d8'
    '8eca45a73e920992c2a551a09382638ad8ed87938a783dc8bc12ea96c353e376'
    'd2af2310b5624759e5817b2183592f0771b3088e220f306273c81431f671b4dc'
    '9e3eff563a5c0fca2d7c8d62784eaca9dfda344cf3ff92316fa73573a3f00341'
    '0b6b5113aae1039d40a42881ca9b96d276b9ea69d144253f5a9cd6461cade2ee'
    'e288aae63fc67559550395e61e300d0264f79fd70730bee07e44bd03f9dcaac9'
    '4dffb0b083cbe1d71dbec310fe2b0461f732492a318f0747665a9a7a17083f4'
    '2415674184f1a73c8')
RETAINED_VECTOR_SHA256 = \
    '49bdb288a0d09f8e1ab044f486c8209fa7f2f9f70885256323af7303e13059c6'


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _invoke_binary(operation, *, secret=b'', public=b'', payload=b''):
    request = {
        'op': operation,
        'secret_hex': secret.hex(),
        'public_hex': public.hex(),
        'payload_hex': payload.hex(),
    }
    completed = subprocess.run(
        [str(SELECTED_BINARY)],
        input=json.dumps(request, sort_keys=True, separators=(',', ':')),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
        env={'LANG': 'C.UTF-8', 'TZ': 'UTC'},
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError('selected-crypto-box-layout-binary-refused')
    try:
        result = json.loads(completed.stdout)
        if set(result) != {'hex'}:
            raise ValueError
        return bytes.fromhex(result['hex'])
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(
            'selected-crypto-box-layout-binary-response') from error


def _libsodium():
    name = ctypes.util.find_library('sodium')
    if not name:
        raise RuntimeError('selected-crypto-box-layout-libsodium-missing')
    library = ctypes.CDLL(name)
    library.sodium_init.restype = ctypes.c_int
    library.sodium_version_string.restype = ctypes.c_char_p
    if library.sodium_init() < 0:
        raise RuntimeError('selected-crypto-box-layout-libsodium-init')
    version = library.sodium_version_string().decode('ascii')
    if version != '1.0.18':
        raise RuntimeError('selected-crypto-box-layout-libsodium-version')
    library.crypto_box_open_easy.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    library.crypto_box_open_easy.restype = ctypes.c_int
    return library, version


def _direct_open(library, sealed, recipient_public, combined):
    if len(sealed) != 264 or len(recipient_public) != 32 \
            or len(combined) != 232:
        raise RuntimeError('selected-crypto-box-layout-width')
    nonce = hashlib.blake2b(
        sealed[:32] + recipient_public, digest_size=24).digest()
    plaintext = (ctypes.c_ubyte * 216)()
    ciphertext = (ctypes.c_ubyte * 232).from_buffer_copy(combined)
    nonce_buffer = (ctypes.c_ubyte * 24).from_buffer_copy(nonce)
    ephemeral_public = (ctypes.c_ubyte * 32).from_buffer_copy(sealed[:32])
    recipient_secret = (ctypes.c_ubyte * 32).from_buffer_copy(
        FIXED_TEST_SECRET)
    status = library.crypto_box_open_easy(
        plaintext, ciphertext, len(combined), nonce_buffer,
        ephemeral_public, recipient_secret)
    return status, bytes(plaintext)


def _check_vector(library, sealed, recipient_public):
    prefix_status, opened = _direct_open(
        library, sealed, recipient_public, sealed[32:])
    # If the selected output were eph || ciphertext || tag, this conversion to
    # libsodium's prefix-MAC combined format would authenticate. It must not.
    reordered = sealed[-16:] + sealed[32:-16]
    reordered_status, _ = _direct_open(
        library, sealed, recipient_public, reordered)
    return (prefix_status == 0 and opened == FIXED_TEST_PLAINTEXT,
            reordered_status != 0)


def run_control():
    metadata = SELECTED_BINARY.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 \
            or _sha256_file(SELECTED_BINARY) != SELECTED_BINARY_SHA256:
        raise RuntimeError('selected-crypto-box-layout-binary-identity')
    if hashlib.sha256(FIXED_TEST_SECRET).hexdigest() != \
            FIXED_TEST_SECRET_SHA256 \
            or hashlib.sha256(FIXED_TEST_PLAINTEXT).hexdigest() != \
            FIXED_TEST_PLAINTEXT_SHA256:
        raise RuntimeError('selected-crypto-box-layout-fixed-inputs')

    recipient_public = _invoke_binary(
        'derive-delivery', secret=FIXED_TEST_SECRET)
    if recipient_public.hex() != FIXED_TEST_RECIPIENT_PUBLIC_HEX:
        raise RuntimeError('selected-crypto-box-layout-recipient-public')
    retained = bytes.fromhex(RETAINED_VECTOR_HEX)
    if len(retained) != 264 or hashlib.sha256(retained).hexdigest() != \
            RETAINED_VECTOR_SHA256:
        raise RuntimeError('selected-crypto-box-layout-retained-vector')
    if _invoke_binary(
            'unseal', secret=FIXED_TEST_SECRET,
            payload=retained) != FIXED_TEST_PLAINTEXT:
        raise RuntimeError('selected-crypto-box-layout-retained-unseal')

    library, sodium_version = _libsodium()
    retained_prefix, retained_reordered = _check_vector(
        library, retained, recipient_public)
    fresh = _invoke_binary(
        'seal', public=recipient_public, payload=FIXED_TEST_PLAINTEXT)
    fresh_prefix, fresh_reordered = _check_vector(
        library, fresh, recipient_public)
    if not all((retained_prefix, retained_reordered,
                fresh_prefix, fresh_reordered)):
        raise RuntimeError('selected-crypto-box-layout-evidence')

    return {
        'schema': 'kpb-selected-crypto-box-layout-control/v1',
        'selected_binary_sha256': SELECTED_BINARY_SHA256,
        'libsodium_version': sodium_version,
        'fixed_test_secret_sha256': FIXED_TEST_SECRET_SHA256,
        'fixed_test_plaintext_sha256': FIXED_TEST_PLAINTEXT_SHA256,
        'fixed_test_recipient_public_hex': FIXED_TEST_RECIPIENT_PUBLIC_HEX,
        'retained_vector_bytes': len(retained),
        'retained_vector_sha256': RETAINED_VECTOR_SHA256,
        'retained_vector_prefix_tag_opened': retained_prefix,
        'retained_vector_reordered_tag_refused': retained_reordered,
        'fresh_vector_bytes': len(fresh),
        'fresh_vector_sha256': hashlib.sha256(fresh).hexdigest(),
        'fresh_vector_prefix_tag_opened': fresh_prefix,
        'fresh_vector_reordered_tag_refused': fresh_reordered,
        'production_secret_material_used': False,
        'privacy_claim': False,
    }


def encode_receipt(receipt):
    return json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n'


if __name__ == '__main__':
    print(encode_receipt(run_control()), end='')

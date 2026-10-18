#!/usr/bin/env python3
"""Independent existing Python wire/journal comparison for public wallet cases."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys
import wire_format as wire
import public_binding as binding


def main():
    cases, library, output = map(Path, sys.argv[1:])
    lib = c.CDLL(str(library.resolve()))
    lib.sodium_init.argtypes = []; lib.sodium_init.restype = c.c_int
    lib.sodium_version_string.argtypes = []; lib.sodium_version_string.restype = c.c_char_p
    lib.crypto_sign_verify_detached.argtypes = [c.c_void_p, c.c_void_p, c.c_ulonglong, c.c_void_p]
    lib.crypto_sign_verify_detached.restype = c.c_int
    if lib.sodium_init() < 0: raise RuntimeError('libsodium initialization failed')
    checked = []; signatures = 0
    for case in sorted(cases.iterdir()):
        if not (case / 'intent.bin').is_file(): continue
        raw = (case / 'intent.bin').read_bytes()
        intent = wire.decode(raw)
        if wire.encode(intent) != raw: raise RuntimeError('independent intent bytes differ')
        auth = (case / 'authorization.bin').read_bytes()
        journal = binding.expected_journal(intent, auth)
        if journal != (case / 'expected-journal.bin').read_bytes():
            raise RuntimeError('independent complete wallet journal differs')
        if intent['operation_kind'] == 0:
            message = (b'KPI/credit-recovery/v1' + bytes.fromhex(intent['G_hash'])
                       + hashlib.sha256(raw).digest())
            key = bytes.fromhex(intent['deposit_reference']['recovery_public_key'])
            if lib.crypto_sign_verify_detached(c.create_string_buffer(auth[1:]),
                    c.create_string_buffer(message), len(message), c.create_string_buffer(key)) != 0:
                raise RuntimeError('independent CREDIT authorization rejected')
            signatures += 1
        checked.append(case.name)
    report = {'scope': 'PUBLIC_BYTES_AND_INDEPENDENT_SIGNATURE_INTEROP_NOT_WALLET_PROOF',
              'cases': checked, 'independentCreditSignaturesVerified': signatures,
              'libsodiumVersion': lib.sodium_version_string().decode(),
              'librarySha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'privateInputsOrBackupsRead': False, 'nativeTransactions': 0}
    with output.open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print(json.dumps(report))


if __name__ == '__main__': main()

#!/usr/bin/env python3
"""Compare public Ed25519 fixtures using the independent libsodium backend.

Only standard signing/detached verification APIs are used. This is not an
independent review of the new composition or qualification of the point policy.
"""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys


def main():
    library, rfc_path, intent_path, auth_dir, output = map(Path, sys.argv[1:])
    if output.exists(): raise FileExistsError(output)
    lib = c.CDLL(str(library.resolve()))
    lib.sodium_init.argtypes = []; lib.sodium_init.restype = c.c_int
    lib.sodium_version_string.argtypes = []; lib.sodium_version_string.restype = c.c_char_p
    lib.crypto_sign_seed_keypair.argtypes = [c.c_void_p]*3
    lib.crypto_sign_seed_keypair.restype = c.c_int
    lib.crypto_sign_detached.argtypes = [c.c_void_p,c.POINTER(c.c_ulonglong),c.c_void_p,c.c_ulonglong,c.c_void_p]
    lib.crypto_sign_detached.restype = c.c_int
    lib.crypto_sign_verify_detached.argtypes = [c.c_void_p,c.c_void_p,c.c_ulonglong,c.c_void_p]
    lib.crypto_sign_verify_detached.restype = c.c_int
    if lib.sodium_init() < 0: raise RuntimeError('libsodium initialization failed')

    def verify(pk, message, sig):
        if len(pk)!=32 or len(sig)!=64: return False
        return lib.crypto_sign_verify_detached(c.create_string_buffer(sig),
            c.create_string_buffer(message),len(message),c.create_string_buffer(pk)) == 0

    def sign(seed, message):
        if len(seed)!=32: raise ValueError('public fixture seed length')
        pk,sk=c.create_string_buffer(32),c.create_string_buffer(64)
        if lib.crypto_sign_seed_keypair(pk,sk,c.create_string_buffer(seed)): raise RuntimeError('derive failed')
        sig,length=c.create_string_buffer(64),c.c_ulonglong()
        if lib.crypto_sign_detached(sig,c.byref(length),c.create_string_buffer(message),len(message),sk):
            raise RuntimeError('sign failed')
        if length.value!=64: raise RuntimeError('unexpected signature length')
        return pk.raw,sig.raw

    rfc=json.loads(rfc_path.read_text()); tuples=json.loads((auth_dir/'credit-tuples.json').read_text())
    intents={v['label']:v for v in json.loads(intent_path.read_text())['vectors']}
    for v in rfc['vectors']:
        seed,pk,msg,sig=(bytes.fromhex(v[k]) for k in ['sk','pk','message','signature'])
        actual_pk,actual_sig=sign(seed,msg)
        if (actual_pk,actual_sig)!=(pk,sig) or not verify(pk,msg,sig):
            raise RuntimeError('independent RFC vector mismatch')
    seed=bytes.fromhex(rfc['vectors'][0]['sk'])
    for row in tuples['vectors']:
        fixture=intents[row['intentLabel']]
        intent_id=hashlib.sha256(bytes.fromhex(fixture['encodedHex'])).digest()
        g=bytes.fromhex(fixture['intent']['G_hash'])
        # Independently build the exact tuple and intent digest from frozen
        # bytes rather than adopting a Rust-produced message/hash.
        message=b'KPI/credit-recovery/v1'+g+intent_id
        if message.hex()!=row['message'] or intent_id.hex()!=row['intent_id']:
            raise RuntimeError('credit tuple bytes differ')
        pk,sig=sign(seed,message)
        if pk.hex()!=row['public_key'] or sig.hex()!=row['signature'] or not verify(pk,message,sig):
            raise RuntimeError('credit signature interoperability failed')
    negatives=json.loads((auth_dir/'negative-cases.json').read_text())['vectors']
    for row in negatives:
        pk,msg,sig=(bytes.fromhex(row[k]) for k in ['public_key','message','signature'])
        if verify(pk,msg,sig): raise RuntimeError('independent signature verifier accepted negative case')
    report={'scope':'INDEPENDENT_LIBRARY_SIGNATURE_INTEROP_NOT_COMPOSITION_REVIEW_OR_POINT_POLICY_QUALIFICATION',
        'libsodiumVersion':lib.sodium_version_string().decode(),
        'librarySha256':hashlib.sha256(library.read_bytes()).hexdigest(),
        'rfc8032SigningAndVerificationVectors':len(rfc['vectors']),
        'independentCreditBytesAndSignatures':len(tuples['vectors']),
        'negativeSignatureCasesRejected':len(negatives),
        'pointValidationApiUsedOrQualified':False,
        'nativeTransactions':0,'fullWalletRelationImplemented':False}
    with output.open('x') as f: json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report))


if __name__ == '__main__': main()

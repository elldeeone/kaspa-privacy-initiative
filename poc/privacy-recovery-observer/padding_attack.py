#!/usr/bin/env python3
"""Frozen byte31 highbit classifier. No labels, keys, RPC or fitting."""
import hashlib
import json
import sys


def analyze(public):
    if set(public) != {'schema', 'classification', 'ciphertexts'}:
        raise ValueError('public fields')
    if public['schema'] != 'kpi-padding-public/v1' or public['classification'] != 'SYNTHETIC_FORMAT_CONTROL':
        raise ValueError('public identity')
    predictions = []
    for i, row in enumerate(public['ciphertexts']):
        if set(row) != {'ordinal', 'hex'} or type(row['ordinal']) is not int or row['ordinal'] != i:
            raise ValueError('public row')
        cipher = bytes.fromhex(row['hex'])
        if len(cipher) != 264 or cipher.hex() != row['hex']:
            raise ValueError('canonical cipher264')
        predictions.append(dict(ordinal=i, not_honest_seal=bool(cipher[31] & 0x80)))
    return dict(schema='kpi-padding-predictions/v1',
        public_sha256=hashlib.sha256(json.dumps(public,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        byte_index=31, mask=128, rows=predictions)


if __name__ == '__main__':
    print(json.dumps(analyze(json.load(sys.stdin)), sort_keys=True, indent=2))

#!/usr/bin/env python3
"""PUBLIC KNOWN-SEED crypto fixture only; dummy CVs/proofs, no financial claim."""
import hashlib
import os
from pathlib import Path

import private_worker as boundary
import wallet_profile as wallet

DOMAIN = bytes.fromhex('a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0')
PROFILE = bytes.fromhex('ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700')
LEAF_MAP_SHA = '00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'
INPUT_OWNERS = ([2, 1, 0], [1, 0, 2])
CREATORS = ([2, 0, 1, 2, 1, 0], [1, 2, 0, 1, 0, 2])


def run():
    boundary.need(boundary.parse(boundary.read('/NAMESPACE.json')) == {
        'schema': 'kpb-PUBLIC-known-seed-colluder-fixture/v1', 'financial_proofs': False}, 'PUBLIC-fixture-only-marker')
    boundary.need(not Path('/original').exists() and not Path('/truth').exists(), 'PUBLIC-fixture-no-actual-inputs')
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', LEAF_MAP_SHA, '/runtime/js')
    crypto = wallet.Crypto('/runtime/crypto'); profile = wallet.Profile(DOMAIN, PROFILE)
    with boundary.NamespaceAuthority('/runtime/node', modules) as authority:
        # Deliberately public fixed test seeds. Never selected for a trial.
        receivers = [wallet.Receiver(bytes([component + 1]) * 32, profile, crypto, authority) for component in range(3)]
        for r in (1, 2):
            rows = [None] * 6; own_rows = []
            for component in range(3):
                positions = [index for index, creator in enumerate(CREATORS[r - 1]) if creator == component]
                invoices = (receivers[(component + r) % 3].invoice(2 * r - 1), receivers[component].invoice(2 * r))
                for position, invoice, value in zip(positions, invoices, (500_000_000 if r == 1 else 200_000_000, 1_000_000_000)):
                    rho = hashlib.sha256(b'PUBLIC CRYPTO FIXTURE' + bytes([r, component, position])).digest()
                    receipt = wallet.Receipt.for_invoice(invoice, value, rho)
                    ciphertext = crypto.seal(invoice.delivery_pk, receipt.encode())
                    row = receipt.commitment() + bytes(64) + ciphertext + hashlib.sha256(ciphertext).digest() + bytes(128)
                    boundary.need(len(row) == 520, 'PUBLIC-fixture-row-size'); rows[position] = row
                    if component == 1: own_rows.append(row)
            nfs = [hashlib.sha256(b'PUBLIC MODEL NF ' + bytes([r, index])).digest() for index in range(3)]
            projection = bytearray(10685); projection[:8] = b'KPBAFX01'; projection[193:201] = b'KPBAEF01'
            projection[201:477] = bytes([r]) * 276
            for index, nf in enumerate(nfs): projection[193 + 404 + index * 96:193 + 436 + index * 96] = nf
            for index, row in enumerate(rows): projection[193 + 692 + index * 520:193 + 692 + (index + 1) * 520] = row
            boundary.write('/out/PROJECTION-' + str(r) + '.bin', bytes(projection), 0o400)
            boundary.write('/out/RECORD-' + str(r) + '.json', {'schema': 'kpb-private-original-owner-record/v1',
                'owner_component': 1, 'input': {'nf_hex32': nfs[INPUT_OWNERS[r - 1].index(1)].hex()},
                'outputs': [{'tuple_hex520': row.hex()} for row in own_rows]}, 0o600)
    boundary.write('/out/PUBLIC.json', {'schema': 'kpb-PUBLIC-known-seed-crypto-fixture-result/v1',
        'actual_CF_crypto': True, 'dummy_CV_and_proofs': True, 'actual_private_Original_or_truth': False,
        'financial_or_privacy_claim': False}, 0o400)


if __name__ == '__main__':
    os.umask(0o077)
    run()

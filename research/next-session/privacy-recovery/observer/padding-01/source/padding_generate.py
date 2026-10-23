#!/usr/bin/env python3
"""ONE declared synthetic ciphertext-format experiment; fresh unfunded entropy.

No keys are persisted. Attacker input contains ciphertexts/ordinals only. Truth
labels are sealed separately and become available only after prediction sealing.
This uses established crypto_box through the existing pinned Rust adapter.
"""
import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--recipient-module', type=Path, required=True)
    p.add_argument('--crypto', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(exist_ok=False)
    sys.path.insert(0, str(args.recipient_module.parent))
    from recipient import Crypto, Receiver, Receipt
    crypto = Crypto(args.crypto)
    domain = hashlib.sha256(b'KPI/padding-format-ONLY/DO-NOT-FUND/2026-10-23').digest()
    receiver = Receiver(secrets.token_bytes(32), domain, crypto)
    rows = []
    for i in range(256):
        invoice = receiver.invoice(i)
        receipt = Receipt.for_invoice(invoice, 100_000_000+i, secrets.token_bytes(32)).encode()
        if len(receipt) != 216:
            raise ValueError('real receipt216 width')
        sealed = crypto.seal(invoice.delivery_pk, receipt)
        if receiver.open(sealed).encode() != receipt:
            raise ValueError('real receipt roundtrip')
        rows.append(('real_receipt_seal', sealed))
        rows.append(('old_raw_random_dummy', secrets.token_bytes(264)))
        # Fresh throwaway recipient per dummy; its secret is neither persisted
        # nor supplied to the attacker. Independent arbitrary216-byte plaintext.
        sink_secret = secrets.token_bytes(32)
        sink_pk = crypto.delivery_public(sink_secret)
        sink_plain = secrets.token_bytes(216)
        sink_cipher = crypto.seal(sink_pk, sink_plain)
        if crypto.unseal(sink_secret, sink_cipher) != sink_plain:
            raise ValueError('new padding roundtrip')
        rows.append(('new_throwaway_sealed_dummy', sink_cipher))
        del sink_secret, sink_plain
    secrets.SystemRandom().shuffle(rows)
    if any(len(cipher) != 264 for _, cipher in rows):
        raise ValueError('cipher264 width')
    public = dict(schema='kpi-padding-public/v1', classification='SYNTHETIC_FORMAT_CONTROL',
        ciphertexts=[dict(ordinal=i, hex=cipher.hex()) for i, (_, cipher) in enumerate(rows)])
    truth = dict(schema='kpi-padding-truth/v1', labels=[label for label, _ in rows])
    write(args.output/'public.json', public)
    write(args.output/'truth.json', truth)


if __name__ == '__main__':
    main()

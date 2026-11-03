#!/usr/bin/env python3
"""Independent Python framing/digest cross-check. No proof/signature verification."""
from hashlib import blake2b, sha256
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
PROFILE_TEXT = b'orchard:616a669df8c9a59c33d47064d3ce04b25d026b2e:FixedPostNu6_2:NoteV2:2-actions:codec-v1'
PROFILE = blake2b(PROFILE_TEXT, digest_size=32, person=b'KPIInteropPrfV1!').digest()
MAX_SOMPI = 2_900_000_000_000_000_000


class Reader:
    def __init__(self, data):
        assert len(data) <= 160_000
        self.data, self.at = data, 0

    def take(self, size):
        end = self.at + size
        assert end <= len(self.data), 'truncated'
        value = self.data[self.at:end]
        self.at = end
        return value

    def number(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize('<' + fmt)))[0]

    def count(self):
        n = self.number('H')
        assert n <= 16
        return n

    def blob(self):
        n = self.number('I')
        assert n <= 4096
        return self.take(n)


def check():
    manifest = json.loads((ROOT / 'vectors/manifest.json').read_text())
    assert manifest['profile_id'] == PROFILE.hex()
    assert manifest['cargo_lock_sha256'] == sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest()
    for row in manifest['vectors']:
        name = row['name']
        data = (ROOT / f'vectors/{name}.bin').read_bytes()
        assert len(data) == row['bytes']
        assert sha256(data).hexdigest() == row['sha256']
        r = Reader(data)
        assert r.take(8) == b'KPIOV2\0\1'
        assert r.take(32) == PROFILE and r.number('H') == 1
        domains = [r.take(32) for _ in range(4)]
        r.number('Q')  # lock time
        r.take(20)  # subnetwork
        r.number('Q')  # gas
        r.number('Q')  # storage mass
        fee = r.number('Q')
        incoming = 0
        for _ in range(r.count()):
            r.take(32)  # outpoint
            r.number('I')
            incoming += r.number('Q')
            r.number('Q')  # sequence
            kind, compute = r.number('B'), r.number('Q')
            assert kind in (0, 1) and (kind != 0 or compute <= 255)
        outgoing = 0
        for _ in range(r.count()):
            outgoing += r.number('Q')
            r.number('H')  # script version
            r.blob()
            tag = r.number('B')
            assert tag in (0, 1)
            if tag:
                r.number('I')
                r.take(32)
        r.blob()  # payload
        assert r.number('B') == 3  # V2 default spends+outputs enabled
        balance = r.number('q')
        anchor = r.take(32)
        assert r.number('B') == 2
        markers = []
        for _ in range(2):
            r.take(32)  # value commitment
            markers.append(r.take(32))
            r.take(32 * 3 + 580 + 80)  # rk, cmx, epk, ciphertexts
        prefix = data[:r.at]
        assert prefix.hex() == (ROOT / f'vectors/{name}.effects.hex').read_text().strip()
        assert blake2b(prefix, digest_size=32, person=b'KPIInteropEffV1!').hexdigest() == row['effects_digest']
        assert r.number('I') == 7264
        r.take(7264 + 2 * 64 + 64)
        assert r.at == len(data)
        context = json.loads((ROOT / f'vectors/{name}.context.json').read_text())
        assert domains == [bytes(context[k]) for k in ('network', 'genesis', 'pool', 'accepted_context')]
        assert list(anchor) in context['eligible_anchors']
        assert len(set(markers)) == 2 and all(list(n) not in context['spent'] for n in markers)
        assert incoming + balance == outgoing + fee
        assert all(0 <= v <= MAX_SOMPI for v in (incoming, outgoing, fee))
        assert 0 <= int(context['pool_balance']) - balance == int(row['expected_pool_next']) <= MAX_SOMPI
    print('3 vectors: independent Python framing, integer equations, exact prefix/digest and artifact identities OK. No cryptographic/native validation.')


if __name__ == '__main__':
    check()

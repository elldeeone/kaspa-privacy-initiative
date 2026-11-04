#!/usr/bin/env python3
"""Independent native-draft framing and signing preimages, NOT cryptography/chain validation."""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
M = 2_900_000_000_000_000_000
PROFILE = '337249a87fd85d2212fd9f8ce5727d1795017f588b73b1c76ab1c474fd02aad2'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def u16(n): return struct.pack('<H', n)
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def blob(data): return u64(len(data)) + data
def h(tag, data): return hashlib.blake2b(data, digest_size=32, key=('KNS1/' + tag).encode()).digest()


class Reader:
    def __init__(self, data):
        need(len(data) <= 262144, 'packet bound')
        self.data, self.at = data, 0

    def take(self, n):
        need(0 <= n <= len(self.data) - self.at, 'truncated')
        value = self.data[self.at:self.at + n]
        self.at += n
        return value

    def number(self, size): return int.from_bytes(self.take(size), 'little')

    def count(self):
        n = self.number(8)
        need(n <= 16, 'item bound')
        return n

    def blob(self):
        n = self.number(8)
        need(n <= 4096, 'blob bound')
        return self.take(n)


def parse(data):
    r = Reader(data)
    need(r.number(2) == 2, 'tx version')
    inputs, q = [], bytearray(data[:2])
    count = r.count()
    q.extend(u64(count))
    for _ in range(count):
        outpoint = r.take(36)
        signature = r.blob()
        suffix = r.take(10)  # sequence U64, budget U16
        q.extend(outpoint + u64(0) + suffix)
        inputs.append((outpoint, signature))
    start = r.at
    outputs = []
    for _ in range(r.count()):
        amount, version, script = r.number(8), r.number(2), r.blob()
        tag = r.number(1)
        need(tag in (0, 1), 'covenant tag')
        if tag: r.take(34)
        outputs.append((amount, version, script, tag))
    lock_time = r.number(8)
    need(r.take(20) == bytes(20) and r.number(8) == 0, 'native lane')
    r.blob()
    mass = r.number(8)
    need(r.number(2) == 1, 'bundle version')
    domain, profile = r.take(32), r.take(32)
    need(profile.hex() == PROFILE, 'fixed profile')
    fee, tree, count, root = r.number(8), r.number(8), r.number(8), r.take(32)
    need(count <= 1 << 32 and count % 2 == 0, 'anchor count')
    need(r.take(2) == bytes([3, 2]), 'flags/actions')
    actions = [r.take(820) for _ in range(2)]
    b = int.from_bytes(r.take(8), 'little', signed=True)
    need(abs(b) <= M and fee <= M, 'public range')
    q.extend(data[start:r.at])
    proof_at = r.at
    need(r.number(8) == 7264, 'proof length')
    r.take(7264 + 192)
    need(r.at == len(data), 'suffix')
    return dict(q=bytes(q), inputs=inputs, outputs=outputs, domain=domain, fee=fee,
                tree=tree, count=count, root=root, b=b, mass=mass, lock_time=lock_time,
                actions=actions, proof_at=proof_at)


def decimal(text):
    need(type(text) is str and text.isascii() and text.isdigit()
         and (text == '0' or not text.startswith('0')), 'decimal sompi')
    n = int(text)
    need(n <= M, 'sompi range')
    return n


def check(folder):
    manifest = json.loads((folder / 'manifest.json').read_text())
    for key in ('native_acceptance', 'chain_authenticated', 'mass_validated', 'portable_key_import'):
        need(manifest[key] is False, 'unsupported claim: ' + key)
    need(manifest['profile_id'] == PROFILE, 'manifest profile')
    spent = set()
    for name, expected in zip(('deposit', 'transfer', 'withdraw'), manifest['vectors'], strict=True):
        need(expected['name'] == name, 'vector order')
        wire = (folder / (name + '.bin')).read_bytes()
        t = parse(wire)
        need(len(wire) == expected['bytes'] and hashlib.sha256(wire).hexdigest() == expected['sha256'], name + ' wire')
        need(t['q'] == (folder / (name + '.q.bin')).read_bytes(), name + ' Q')
        txid = h('TxID', t['q'])
        need(txid.hex() == expected['txid'] and h('TxHash', wire).hex() == expected['txhash'], name + ' hashes')
        context = json.loads((folder / (name + '.synthetic-view.json')).read_text())
        actual = {(bytes.fromhex(u['txid']) + u32(u['index'])): u for u in context['utxos']}
        need(len(actual) == len(context['utxos']), 'duplicate synthetic UTXO')
        ic, incoming = bytearray(u64(len(t['inputs']))), 0
        for outpoint, signature in t['inputs']:
            u = actual[outpoint]
            amount = decimal(u['amount'])
            incoming += amount
            need(not u['covenant'] and not u['coinbase'] and u['script_version'] == 0, 'synthetic input policy')
            ic.extend(outpoint + u64(amount) + u16(0) + blob(bytes.fromhex(u['script'])) + b'\x00')
            need(len(signature) == 66 and signature[0] == 0x41 and signature[65] == 1, 'signature framing')
        need(ic.hex() == context['input_context'], name + ' input context')
        s = h('SigMsg', txid + h('InputCtx', ic))
        need(s.hex() == expected['signing_message'], name + ' signing message')
        need(t['domain'].hex() == context['domain'], 'domain')
        need([dict(tree=str(t['tree']), count=str(t['count']), root=t['root'].hex())] == context['anchors'], 'anchor')
        need(set(context['spent']) == {x.hex() for x in spent}, 'complete previous synthetic markers')
        markers = {a[32:64] for a in t['actions']}
        need(len(markers) == 2 and markers.isdisjoint(spent), 'synthetic current markers')
        spent |= markers
        outgoing = sum(o[0] for o in t['outputs'])
        need(incoming <= M and outgoing <= M and incoming + t['b'] == outgoing + t['fee'], 'public accounting')
        need(0 <= decimal(context['balance']) - t['b'] <= M, 'synthetic balance')
        need(str(t['b']) == expected['b'], 'signed public balance')
    # Cross-check the original independently specified hash vector as well.
    original = json.loads((ROOT / 'docs/spec/native-shielded/artifacts/conformance.json').read_text())
    wire = (ROOT / 'docs/spec/native-shielded/artifacts/native-transaction-encoding.bin').read_bytes()
    need(parse(wire)['q'].hex() == original['native_q_hex'], 'old spec comparator')
    print('3 native-draft framing/context/hash vectors and original spec comparator passed; no cryptographic or native acceptance claim')


if __name__ == '__main__':
    check(Path(sys.argv[1]) if len(sys.argv) == 2 else HERE / 'vectors')

#!/usr/bin/env python3
"""Native draft byte/hash/accounting and symbolic conformance, NOT consensus.

No Halo2/secp verification, UTXO authentication, GHOSTDAG, Sinsemilla forest
implementation, durable undo, pruning proof or native acceptance is provided.
The encoding fixture reuses PUBLIC experimental Actions/proof; its signatures
DO NOT authorize the proposed new signing message. Its inputs/header are fake.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'docs/spec/native-shielded'
CAP = 1 << 32
M = 2_900_000_000_000_000_000
PALLAS_BASE = int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def u16(n): return struct.pack('<H', n)
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def v64(data): return u64(len(data)) + data
def h(tag, data): return hashlib.blake2b(data, digest_size=32, key=('KNS1/' + tag).encode('ascii')).digest()
def sha(data): return hashlib.sha256(data).hexdigest()


def sparse(kind, mapping):
    empty = {256: h(kind + 'Empty', b'')}
    for d in range(255, -1, -1):
        empty[d] = h(kind + 'Node', u16(d) + empty[d + 1] * 2)
    nodes = {int.from_bytes(k, 'big'): h(kind + 'Leaf', k + v) for k, v in mapping.items()}
    for d in range(255, -1, -1):
        parents = {index >> 1 for index in nodes}
        nodes = {p: h(kind + 'Node', u16(d) + nodes.get(p * 2, empty[d + 1])
                      + nodes.get(p * 2 + 1, empty[d + 1])) for p in parents}
    return nodes.get(0, empty[0])


def event_root(events):
    empty = h('EventEmpty', b'')
    nodes = {i: h('EventLeaf', event) for i, event in enumerate(events)}
    for d in range(63, -1, -1):
        nodes = {p: h('EventNode', u16(d) + nodes.get(p * 2, empty)
                      + nodes.get(p * 2 + 1, empty)) for p in {i >> 1 for i in nodes}}
        empty = h('EventNode', u16(d) + empty * 2)
    return nodes.get(0, empty)


def anchor(tree, count, root):
    need(0 <= tree < 1 << 64 and 0 <= count <= CAP and len(root) == 32, 'anchor range')
    need(int.from_bytes(root, 'little') < PALLAS_BASE, 'anchor encoding')
    value = u64(tree) + u64(count) + root
    return h('AKey', value), value


def public_experimental_bundle(name):
    folder = ROOT / 'poc/orchard-interop/vectors'
    packet = (folder / (name + '.bin')).read_bytes()
    prefix = bytes.fromhex((folder / (name + '.effects.hex')).read_text())
    first = len(prefix) - 1640
    return dict(actions=prefix[first:], root=prefix[first - 33:first - 1],
                b=struct.unpack('<q', prefix[first - 41:first - 33])[0],
                auth=packet[len(prefix) + 4:])


def header(native_root, timestamp=11, nonce=7):
    # New commitment form; this is neither a mined nor a chain-qualified header.
    return (u16(3) + u64(1) + u64(1) + bytes([0x22]) * 32
            + bytes([0x33]) * 32 + bytes([0x44]) * 32 + bytes([0x55]) * 32
            + native_root + u64(timestamp) + u32(0x1d00ffff) + u64(nonce)
            + u64(1000) + u64(5) + v64(bytes.fromhex('010000')) + bytes([0x66]) * 32)


def build_vectors():
    profile = (SPEC / 'artifacts/profile.bin').read_bytes()
    profile_id = h('Profile', profile)
    need(profile_id.hex() == '337249a87fd85d2212fd9f8ce5727d1795017f588b73b1c76ab1c474fd02aad2', 'fixed profile')
    capsule = (SPEC / 'artifacts/fixed-post-nu6-2.vk-capsule.bin').read_bytes()
    need(sha(capsule) == '743fa19c541fa2c7881c4ed0e3340c82d88780dbbc549cc2f3bfd982c2e517e0', 'fixed key')
    need(profile[10:42] == hashlib.sha256(capsule).digest() and len(profile) == 72, 'key/profile mapping')
    genesis = bytes(range(32))
    # EXAMPLE ONLY: these coefficients and score configure no real network.
    schedule = u16(1) + b''.join(u64(n) for n in range(1, 14))
    manifest = b'KNSACT01' + u16(1) + genesis + u64(1000) + u16(2) + u16(3) + profile_id + schedule
    activation = h('Activation', manifest)
    domain = h('Domain', genesis + activation)
    deposit = public_experimental_bundle('deposit')
    empty_c = deposit['root']
    akey, aval = anchor(0, 0, empty_c)
    nr, ar, lr = sparse('N', {}), sparse('A', {akey: aval}), event_root([])
    frontier = u64(0) + u64(0) + empty_c + u32(0)
    state = (b'KNSSTA01' + u16(1) + domain + profile_id + activation
             + u64(0) * 4 + empty_c + h('Frontier', frontier)
             + u64(0) + nr + u64(1) + ar + u64(0) + lr)
    need(len(state) == 322 and len(frontier) == 52 and len(manifest) == 192, 'fixed record widths')
    state_root = h('State', state)
    # Public G key: structurally standard Schnorr script, no funded outpoint.
    key = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    locking_script = b'\x20' + key + b'\xac'
    outpoint = bytes([0x11]) * 32 + u32(2)
    sigscript = b'\x41' + bytes(64) + b'\x01'  # invalid placeholder signature
    common_end = (u64(0) + bytes(20) + u64(0) + v64(b'PUBLIC NATIVE ENCODING VECTOR')
                  + u64(123))  # storage stub: no pricing validity claim
    extension = (u16(1) + domain + profile_id + u64(1) + u64(0) + u64(0)
                 + empty_c + b'\x03\x02' + deposit['actions'] + struct.pack('<q', -100))
    def body(unlocking):
        return (u16(2) + u64(1) + outpoint + v64(unlocking) + u64((1 << 64) - 1)
                + u16(100) + u64(0) + common_end + extension)
    q = body(b'')
    wire = body(sigscript) + u64(7264) + deposit['auth']
    txid = h('TxID', q)
    input_context = u64(1) + outpoint + u64(101) + u16(0) + v64(locking_script) + b'\x00'
    ic = h('InputCtx', input_context)
    signing = h('SigMsg', txid + ic)
    schnorr = h('InputSig', signing + u32(0) + b'\x01')
    ecdsa = hashlib.sha256(hashlib.sha256(b'TransactionSigningHashECDSA').digest() + schnorr).digest()
    example_event = u64(0) + bytes([0x77]) * 32 + u32(1) + u64(0) + v64(wire)
    markers = [deposit['actions'][32:64], deposit['actions'][852:884]]
    n2 = sparse('N', {n: b'\x01' for n in markers})
    header_bytes = header(state_root)
    blockhash = hashlib.blake2b(header_bytes, digest_size=32, key=b'BlockHash').digest()
    # Empty-state snapshot encoding example; fake header is NOT chain-qualified.
    snapshot_file = akey + aval
    snapshot = (b'KNSSNP01' + u16(1) + blockhash + bytes([0x55]) * 32 + state_root + activation
                + v64(state) + v64(frontier) + u64(0) + u64(1) + u64(0) + u64(1)
                + b'\x01' + u64(0) + u64(1) + u64(len(snapshot_file)) + hashlib.sha256(snapshot_file).digest())
    return dict(
        scope='Encoding/hash/accounting and symbolic conformance only. Inputs/header are fake; original signatures do not authorize native v2; storage mass is a stub. No native acceptance or bootstrap validation.',
        profile_id=profile_id.hex(), activation_manifest_hex=manifest.hex(), activation_id=activation.hex(), domain_id=domain.hex(),
        genesis_state_record_hex=state.hex(), genesis_frontier_hex=frontier.hex(), genesis_native_root=state_root.hex(),
        genesis_nf_root=nr.hex(), genesis_anchor_root=ar.hex(), genesis_event_root=lr.hex(),
        native_q_hex=q.hex(), native_wire_bytes=len(wire), native_wire_sha256=sha(wire), native_txid=txid.hex(), native_txhash=h('TxHash', wire).hex(),
        input_context_hex=input_context.hex(), input_context_hash=ic.hex(), shielded_signing_message=signing.hex(),
        input_schnorr_hash=schnorr.hex(), input_ecdsa_hash=ecdsa.hex(), header_hex=header_bytes.hex(), blockhash=blockhash.hex(),
        pow_prehash_hex=header(state_root, 0, 0).hex(),
        example_event_root=event_root([example_event]).hex(), example_nf_markers=[n.hex() for n in markers], example_two_marker_root=n2.hex(),
        snapshot_manifest_hex=snapshot.hex(), snapshot_file_hex=snapshot_file.hex(),
        native_acceptance=False), wire


def check_equation(tin, tout, sin, sout, fee, balance):
    need(all(type(n) is int and 0 <= n <= M for n in (tin, tout, sin, sout, fee, balance)), 'monetary range')
    b = sin - sout
    need(-M <= b <= M and tin + b == tout + fee, 'balance')
    after = balance - b
    need(0 <= after <= M, 'pool range')
    need((tout - tin) + (after - balance) == -fee, 'stock change')
    return after


def logical_append(tree, count, global_count, markers, spent):
    """Topology/count/spentness model only: does not compute Orchard roots/proofs."""
    need(global_count == tree * CAP + count and 0 <= count <= CAP and count % 2 == 0, 'predecessor counters')
    need(len(markers) == 2 and len(set(markers)) == 2 and set(markers).isdisjoint(spent), 'current markers')
    need(global_count + 2 < 1 << 64, 'global counter overflow')
    if count == CAP:
        tree, count = tree + 1, 0
    return tree, count + 2, global_count + 2, spent | set(markers)


def snapshot_coverage(counts, files):
    previous = None
    positions = {0: 0, 1: 0, 2: 0}
    for kind, start, count, size in files:
        need(kind in positions and count > 0 and 0 < size <= 16 * 1024 * 1024, 'chunk fields')
        need(previous is None or (kind, start) > previous, 'chunk ordering')
        need(start == positions[kind], 'chunk hole/overlap')
        positions[kind] += count
        need(positions[kind] <= counts[kind], 'chunk excess')
        previous = kind, start
    need(positions == counts, 'missing records')


def controls(vectors):
    checks = []
    def reject(name, fn):
        try: fn()
        except (ValueError, struct.error): checks.append(name)
        else: raise ValueError('negative control accepted: ' + name)
    need(check_equation(101, 0, 0, 100, 1, 0) == 100, 'deposit')
    need(check_equation(0, 0, 100, 99, 1, 100) == 99, 'transfer fee')
    need(check_equation(0, 59, 60, 0, 1, 99) == 39, 'withdraw')
    need(check_equation(M, 0, 0, M, 0, 0) == M, 'native maximum')
    reject('MAX+1', lambda: check_equation(M + 1, 0, 0, M, 1, 0))
    reject('public imbalance', lambda: check_equation(101, 0, 0, 99, 1, 0))
    reject('pool underflow', lambda: check_equation(0, 59, 60, 0, 1, 0))
    reject('floating amount', lambda: check_equation(1.0, 0, 0, 0, 1, 0))
    reject('signed minimum bound', lambda: check_equation(0, 0, 0, 1 << 63, 0, 0))
    before = {'tree': 0, 'count': CAP, 'global': CAP, 'N': {b'old-marker'}}
    after = logical_append(before['tree'], before['count'], before['global'], [b'a', b'b'], before['N'])
    need(after[:3] == (1, 2, CAP + 2) and b'old-marker' in after[3], 'rollover preserves old spentness')
    need(before['count'] == CAP and before['N'] == {b'old-marker'}, 'model predecessor unchanged')
    reject('duplicate slots', lambda: logical_append(0, 0, 0, [b'a', b'a'], set()))
    reject('cross-tree old marker', lambda: logical_append(*after[:3], [b'old-marker', b'c'], after[3]))
    reject('inconsistent predecessor', lambda: logical_append(0, CAP, 0, [b'a', b'b'], set()))
    reject('global overflow', lambda: logical_append((1 << 32) - 1, CAP - 2, (1 << 64) - 2, [b'a', b'b'], set()))
    snapshot_coverage({0: 0, 1: 1, 2: 0}, [(1, 0, 1, 80)])
    reject('snapshot gap', lambda: snapshot_coverage({0: 2, 1: 0, 2: 0}, [(0, 1, 1, 32)]))
    reject('snapshot overlap', lambda: snapshot_coverage({0: 2, 1: 0, 2: 0}, [(0, 0, 1, 32), (0, 0, 1, 32)]))
    reject('snapshot missing stream', lambda: snapshot_coverage({0: 1, 1: 1, 2: 0}, [(0, 0, 1, 32)]))
    reject('snapshot over-limit chunk', lambda: snapshot_coverage({0: 1, 1: 0, 2: 0}, [(0, 0, 1, 16 * 1024 * 1024 + 1)]))
    root = bytes.fromhex(vectors['genesis_native_root'])
    changed = bytes([root[0] ^ 1]) + root[1:]
    need(header(root) != header(changed), 'header field included')
    need(hashlib.blake2b(header(root, 0, 0), digest_size=32, key=b'BlockHash').digest()
         != hashlib.blake2b(header(changed, 0, 0), digest_size=32, key=b'BlockHash').digest(), 'PoW prehash field included')
    # Explicit separation of identity from context/authentication.
    q = bytes.fromhex(vectors['native_q_hex'])
    need(h('TxID', q + b'\x00').hex() != vectors['native_txid'], 'all Q bytes bind')
    ic = bytes.fromhex(vectors['input_context_hex'])
    need(h('SigMsg', bytes.fromhex(vectors['native_txid']) + h('InputCtx', ic + b'\x00')).hex()
         != vectors['shielded_signing_message'], 'actual context binds signature')
    # Abstract undo/reapply only, not a storage or GHOSTDAG implementation.
    saved = deepcopy(before)
    restored = deepcopy(saved)
    need(logical_append(restored['tree'], restored['count'], restored['global'], [b'a', b'b'], restored['N']) == after, 'abstract reapply')
    return checks


def main():
    vectors, wire = build_vectors()
    path = SPEC / 'artifacts/conformance.json'
    if sys.argv[1:] == ['--write']:
        path.write_text(json.dumps(vectors, indent=2) + '\n')
        (SPEC / 'artifacts/native-transaction-encoding.bin').write_bytes(wire)
    else:
        need(not sys.argv[1:], 'usage: check_native_shielded_spec.py [--write]')
        need(json.loads(path.read_text()) == vectors, 'conformance artifact drift')
        need((SPEC / 'artifacts/native-transaction-encoding.bin').read_bytes() == wire, 'encoding fixture drift')
    negative = controls(vectors)
    subprocess.run([sys.executable, str(SPEC / 'key-export/check_capsule.py')], check=True)
    print(f'Native draft: profile, activation, transaction/signature/header/state/snapshot preimages and hashes, integer equations; {len(negative)} negative controls and symbolic rollover/undo obligations OK.')
    print('No native signatures/funding, Sinsemilla replay, DAG/store/undo, bootstrap authentication, mass calibration, activation or privacy qualification validated.')


if __name__ == '__main__':
    main()

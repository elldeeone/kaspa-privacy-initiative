#!/usr/bin/env python3
"""Public known-key supplied-context Exit fixtures; never use these keys for funds.

Constructs two coherent public histories with three admitted notes: the continuing
case has three unspent notes; the terminal case's other two note NFs are spent.
This does not establish actual backing, accepted history or network currentness.
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


class Tree:
    def __init__(self, depth, empty, tag, leaves):
        self.depth, self.tag = depth, tag
        self.empty = [empty]
        for _ in range(depth):
            self.empty.append(hashlib.sha256(tag + self.empty[-1] * 2).digest())
        self.levels = [dict(leaves)]
        for level in range(depth):
            previous = self.levels[-1]
            self.levels.append({index // 2: hashlib.sha256(
                tag + previous.get(index & ~1, self.empty[level])
                + previous.get(index | 1, self.empty[level])).digest()
                for index in previous})

    @property
    def root(self):
        return self.levels[-1].get(0, self.empty[-1])

    def path(self, index):
        return b''.join(level.get((index >> i) ^ 1, self.empty[i])
                        for i, level in enumerate(self.levels[:-1]))


def nf_context(wire, nf, previous):
    values = [wire.ZERO, *previous]
    indices = sorted(range(len(values)), key=lambda i: int.from_bytes(values[i], 'little'))
    links = {}
    for at, index in enumerate(indices):
        ni = indices[at + 1] if at + 1 < len(indices) else 0
        links[index] = (values[index], values[ni], ni)
    leaves = {i: wire.nf_leaf(*leaf) for i, leaf in links.items()}
    old = Tree(17, wire.NF_EMPTY, b'KPX1NFN\0', leaves)
    pred = max((i for i in indices if int.from_bytes(values[i], 'little') < int.from_bytes(nf, 'little')),
               key=lambda i: int.from_bytes(values[i], 'little'))
    pv, pn, pni = links[pred]
    middle_leaves = dict(leaves)
    middle_leaves[pred] = wire.nf_leaf(pv, nf, len(values))
    middle = Tree(17, wire.NF_EMPTY, b'KPX1NFN\0', middle_leaves)
    witness = pred.to_bytes(4, 'little') + pv + pn + pni.to_bytes(4, 'little') + old.path(pred) + middle.path(len(values))
    new_leaves = dict(middle_leaves)
    new_leaves[len(values)] = wire.nf_leaf(nf, pn, pni)
    new = Tree(17, wire.NF_EMPTY, b'KPX1NFN\0', new_leaves)
    assert wire.insert_nf(old.root, len(values), nf, witness) == new.root
    return old.root, new.root, len(values), witness


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--codec', required=True)
    parser.add_argument('--codec-sha256', required=True)
    parser.add_argument('--exit-vk-hex328', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    verification = Path(__file__).resolve().parent.parent
    wire = load('_kpx8_public_exit_wire', verification / 'wire.py')
    helper = load('_kpx8_public_exit_native', verification / 'native_case.py')
    codec = helper.NativeCodec(Path(args.codec), args.codec_sha256)
    vk = bytes.fromhex(args.exit_vk_hex328)
    assert len(vk) == 328
    out = Path(args.out)
    out.mkdir(mode=0o700)
    # Every secret in this fixture is deliberately known public test material.
    notes, witnesses, nfs = [], [], []
    pubkey = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    for i in range(3):
        s, k, incoming, rho = (bytes([v + i]) * 32 for v in (17, 34, 51, 68))
        owner = wire.sha(b'KPX1OWN\0', wire.DOMAIN, s, incoming)
        kc = wire.sha(b'KPX1KEY\0', wire.DOMAIN, k)
        note = owner + incoming + (1_000_000_000).to_bytes(8, 'little') + rho + kc + pubkey
        cm = wire.sha(b'KPX1NOT\0', wire.DOMAIN, note)
        nf = hmac.new(k, b'KPX1NF\0\0' + wire.DOMAIN + cm + i.to_bytes(4, 'little'), hashlib.sha256).digest()
        notes.append((note, cm))
        witnesses.append((s, k))
        nfs.append(nf)
    cm_tree = Tree(16, wire.CM_EMPTY, b'KPX1CMN\0', {i: cm for i, (_, cm) in enumerate(notes)})
    image = wire.sha(b'KPX8 public synthetic Exit fixture / no outer proof required')
    component = wire.sha(b'KPX8 public synthetic component fixture / not a funded profile')
    cases = []
    for mode in ('continuing', 'terminal'):
        folder = out / mode
        folder.mkdir(mode=0o700)
        old_nf, new_nf, count, nf_witness = nf_context(wire, nfs[0], [] if mode == 'continuing' else nfs[1:])
        old = b'KPX8ST01' + wire.DOMAIN + cm_tree.root + (3).to_bytes(4, 'little') + old_nf + count.to_bytes(4, 'little')
        new = b'KPX8ST01' + wire.DOMAIN + cm_tree.root + (3).to_bytes(4, 'little') + new_nf + (count + 1).to_bytes(4, 'little')
        reserve = 3_000_000_000 if mode == 'continuing' else 1_000_000_000
        remaining = reserve - 1_000_000_000
        point = wire.sha(b'KPX8 public synthetic current point', mode.encode()) + bytes(4)
        fee = 20_000_000
        for _ in range(5):
            payout = 1_000_000_000 - fee
            body = (b'KPX8XB01' + struct.pack('<4H', 1, 1, 0, 1) + wire.DOMAIN
                    + wire.sha(b'KPX8 synthetic exit session', mode.encode()) + bytes(32) + point
                    + old + reserve.to_bytes(8, 'little') + new + remaining.to_bytes(8, 'little')
                    + fee.to_bytes(8, 'little') + payout.to_bytes(8, 'little')
                    + b'\0\0\x20' + pubkey + b'\xac' + nfs[0] + nf_witness)
            assert len(body) == 1632
            case, projection, journal, info = helper.make_case(codec, body, image, component, vk, 1800)
            next_fee = info['metrics']['mining_mass'] * 100
            if next_fee == fee:
                break
            fee = next_fee
        else:
            raise ValueError('public fixture fee did not converge')
        wire.validate_exit_public(projection)
        request = {'schema': 'kpx8-owner-private-exit-witness/v1', 'note_hex168': notes[0][0].hex(),
                   's_hex32': witnesses[0][0].hex(), 'k_hex32': witnesses[0][1].hex(), 'position': 0,
                   'cm_path_hex': [cm_tree.path(0)[i:i + 32].hex() for i in range(0, 512, 32)]}
        case_sha = save(folder / 'case-zero-proof.json', case)
        statement = wire.exit_statement(projection)
        for name, raw in [('projection.bin', projection), ('body.bin', body), ('statement.bin', statement)]:
            with (folder / name).open('xb') as handle:
                handle.write(raw)
        witness_sha = save(folder / 'PUBLIC-SYNTHETIC-WITNESS.json', request)
        cases.append({'mode': mode, 'case_sha256': case_sha, 'projection_sha256': wire.sha(projection).hex(),
                      'effects_digest_hex32': wire.exit_effects_digest(projection).hex(),
                      'statement_hex152': statement.hex(), 'statement_sha256': wire.sha(statement).hex(),
                      'PUBLIC_SYNTHETIC_witness_sha256': witness_sha, 'fee_sompi': fee,
                      'payout_sompi': payout, 'remaining_reserve_sompi': remaining,
                      'metrics': info['metrics'], 'native_VM_executed': False})
    summary = {'schema': 'kpx8-public-synthetic-exit-fixtures/v1',
               'classification': 'KNOWN_PUBLIC_KEYS_SUPPLIED_CONTEXT_NOT_FUNDED_HISTORY_OR_CONFIRMATION',
               'image_hex32': image.hex(), 'component_sha256': component.hex(),
               'exit_vk_sha256': wire.sha(vk).hex(), 'codec_sha256': args.codec_sha256,
               'cases': cases, 'original_owner_secrets_read': False, 'funding_or_broadcast': False}
    save(out / 'FIXTURES.json', summary)
    print(json.dumps({'public_fixture_count': len(cases), 'native_VM_executed': False}))


if __name__ == '__main__':
    main()

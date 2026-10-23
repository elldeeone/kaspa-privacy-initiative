#!/usr/bin/env python3
"""DO_NOT_FUND: synthetic Merkle kernels, not financial authorization policies."""
from __future__ import annotations
import hashlib
import json

DEPTH = 16
NODE = b'KPX1CMN\0'
EMPTY_TAG = b'KPX1CME\0'
MAGIC = b'CMFEE001'
START = 32
BUDGET = 512  # Generous component-test budget, never a selected payment budget.
INPUT = 100_000_000_000
OUTPUT = INPUT - 100_000_000
OUTPUT_TAG = b'KPX/FEE/DO_NOT_FUND/OUTPUT\0'
OP = {'DEPTH':0x74,'NUMEQUALVERIFY':0x9d,'PAYLOADLEN':0xc4,'PAYLOAD':0xb8,
      'BIN2NUM':0xce,'CAT':0x7e,'EQUALVERIFY':0x88,'ADD':0x93,'DIV':0x96,
      'MOD':0x97,'IF':0x63,'SWAP':0x7c,'ELSE':0x67,'ENDIF':0x68,
      'SHA256':0xa8,'TOALT':0x6b,'FROMALT':0x6c,'BLAKE2B':0xaa,'OUTPUTSPK':0xc3}


def h(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def combine(left, right):
    return h(NODE, left, right)


EMPTY = [h(EMPTY_TAG)]
for _ in range(DEPTH):
    EMPTY.append(combine(EMPTY[-1], EMPTY[-1]))


class SparseTree:
    """Independent host tree; native code does not consume precomputed new subroots."""
    def __init__(self):
        self.nodes = {}

    def node(self, level, index):
        return self.nodes.get((level, index), EMPTY[level])

    @property
    def root(self):
        return self.node(DEPTH, 0)

    def path(self, index, level=0):
        result = []
        for height in range(level, DEPTH):
            result.append(self.node(height, index ^ 1))
            index //= 2
        return result

    def set(self, index, leaf):
        assert type(index) is int and 0 <= index < 1 << DEPTH and len(leaf) == 32
        self.nodes[(0, index)] = leaf
        for level in range(DEPTH):
            self.nodes[(level + 1, index // 2)] = combine(self.node(level, index & ~1),
                                                        self.node(level, index | 1))
            index //= 2


def push(value):
    if not value:
        return b'\0'
    if len(value) == 1 and 1 <= value[0] <= 16:
        return bytes([0x50 + value[0]])
    if value == b'\x81':
        return b'\x4f'
    if len(value) <= 75:
        return bytes([len(value)]) + value
    if len(value) <= 255:
        return b'\x4c' + bytes([len(value)]) + value
    if len(value) <= 65535:
        return b'\x4d' + len(value).to_bytes(2, 'little') + value
    return b'\x4e' + len(value).to_bytes(4, 'little') + value


def number(value):
    assert 0 <= value < (1 << 63)
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'little')
    if raw and raw[-1] & 0x80:
        raw += b'\0'
    return push(raw)


class Script:
    def __init__(self):
        self.raw = bytearray()

    def op(self, name):
        self.raw.append(OP[name])

    def data(self, value):
        self.raw.extend(push(value))

    def num(self, value):
        self.raw.extend(number(value))

    def payload(self, start, length):
        self.num(start); self.num(start + length); self.op('PAYLOAD')

    def unsigned(self, start):
        self.payload(start, 4); self.data(b'\0'); self.op('CAT'); self.op('BIN2NUM')

    def hash_pair(self):
        self.op('CAT'); self.data(NODE); self.op('SWAP'); self.op('CAT'); self.op('SHA256')

    def path(self, start, depth, slot=0, block=1):
        for height in range(depth):
            self.unsigned(72)
            if slot:
                self.num(slot); self.op('ADD')
            if block != 1:
                self.num(block); self.op('DIV')
            self.num(1 << height); self.op('DIV'); self.num(2); self.op('MOD'); self.op('IF')
            self.payload(start + 32 * height, 32); self.op('SWAP'); self.op('ELSE')
            self.payload(start + 32 * height, 32); self.op('ENDIF'); self.hash_pair()

    def subtree(self, first, count):
        if count == 1:
            self.payload(80 + 32 * first, 32)
        else:
            self.subtree(first, count // 2)
            self.subtree(first + count // 2, count // 2)
            self.hash_pair()


def output_spk(root, count):
    commitment = hashlib.blake2b(OUTPUT_TAG + root + count.to_bytes(4, 'little'), digest_size=32).digest()
    return (b'\0\0\xaa\x20' + commitment + b'\x87').hex()


def program(n, mode, old_root):
    assert n in (2,4,8,16,32) and mode in ('baseline','subtree') and START % n == 0
    level = n.bit_length() - 1
    path_bytes = 512 * n if mode == 'baseline' else 32 * (DEPTH - level)
    length = 80 + 32 * n + path_bytes
    s = Script(); s.op('DEPTH'); s.num(0); s.op('NUMEQUALVERIFY')
    s.op('PAYLOADLEN'); s.num(length); s.op('NUMEQUALVERIFY')
    s.payload(0, 8); s.data(MAGIC); s.op('EQUALVERIFY')
    s.payload(8, 32); s.data(old_root); s.op('EQUALVERIFY')
    s.unsigned(72); s.num(START); s.op('NUMEQUALVERIFY')
    s.unsigned(76); s.num(START + n); s.op('NUMEQUALVERIFY')
    s.payload(8, 32)
    if mode == 'baseline':
        for slot in range(n):
            s.op('TOALT'); s.data(EMPTY[0]); s.path(80 + 32*n + 512*slot, DEPTH, slot)
            s.op('FROMALT'); s.op('EQUALVERIFY')
            s.payload(80 + 32*slot, 32); s.path(80 + 32*n + 512*slot, DEPTH, slot)
    else:
        s.op('TOALT'); s.data(EMPTY[level]); s.path(80 + 32*n, DEPTH-level, block=n)
        s.op('FROMALT'); s.op('EQUALVERIFY')
        s.subtree(0, n); s.path(80 + 32*n, DEPTH-level, block=n)
    s.payload(40, 32); s.op('EQUALVERIFY')
    # Bind the computed root/count to a public synthetic successor commitment.
    # This kernel intentionally has no note ownership/value/nullifier policy.
    s.data(OUTPUT_TAG); s.payload(40, 32); s.op('CAT'); s.payload(76, 4); s.op('CAT'); s.op('BLAKE2B')
    s.data(b'\0\0\xaa\x20'); s.op('SWAP'); s.op('CAT'); s.data(b'\x87'); s.op('CAT')
    s.num(0); s.op('OUTPUTSPK'); s.op('EQUALVERIFY'); s.num(1)
    return bytes(s.raw)


def base_tree(occupied=False):
    tree = SparseTree()
    for index in range(START):
        tree.set(index, h(b'KPX/FEE/PUBLIC/PREFIX/', index.to_bytes(4, 'little')))
    if occupied:
        tree.set(START, h(b'KPX/FEE/PUBLIC/OCCUPIED'))
    return tree


def fixture(n, mode, fault='positive'):
    assert fault in ('positive','leaf','sibling','index','occupied','truncated','trailing')
    tree = base_tree(fault == 'occupied'); old = tree.root
    cms = [h(b'KPX/FEE/PUBLIC/NEW/', i.to_bytes(4, 'little')) for i in range(n)]
    paths = []
    if mode == 'subtree':
        paths = tree.path(START // n, n.bit_length() - 1)
    for slot, cm in enumerate(cms):
        if mode == 'baseline':
            paths.extend(tree.path(START + slot))
        tree.set(START + slot, cm)
    new = tree.root
    payload = bytearray(MAGIC + old + new + START.to_bytes(4,'little')
                        + (START+n).to_bytes(4,'little') + b''.join(cms) + b''.join(paths))
    if fault == 'leaf': payload[80] ^= 1
    elif fault == 'sibling': payload[80+32*n] ^= 1
    elif fault == 'index': payload[72] ^= 1
    elif fault == 'truncated': del payload[-1]
    elif fault == 'trailing': payload += b'\0'
    redeem = program(n, mode, old)
    input_spk = (b'\0\0\xaa\x20' + hashlib.blake2b(redeem,digest_size=32).digest() + b'\x87').hex()
    body = {'version':1,'id':'00'*32,'inputs':[{'previousOutpoint':{
        'transactionId':h(b'KPX/FEE/DO_NOT_FUND/OUTPOINT').hex(),'index':0},
        'signatureScript':push(redeem).hex(),'sequence':str((1<<64)-1),'computeBudget':BUDGET}],
        'outputs':[{'value':OUTPUT,'scriptPublicKey':output_spk(new,START+n),'covenant':None}],
        'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':payload.hex(),'mass':0}
    case = {'transaction':body,'entries':[{'amount':INPUT,'scriptPublicKey':input_spk,
        'blockDaaScore':0,'isCoinbase':False,'covenantId':None}]}
    metadata = {'classification':'PUBLIC_SYNTHETIC_MERKLE_KERNEL_DO_NOT_FUND','n':n,'mode':mode,
        'fault':fault,'expected_native_acceptance':fault=='positive','redeem_bytes':len(redeem),
        'payload_bytes':len(payload),'old_root':old.hex(),'new_root':new.hex(),
        'start':START,'new_count':START+n,'native_Groth16_or_ownership_nullifier_financial_checks_included':False,
        'source_native_budget_is_test_only':BUDGET,'SDK_transaction_id_recomputed':False}
    return case, metadata

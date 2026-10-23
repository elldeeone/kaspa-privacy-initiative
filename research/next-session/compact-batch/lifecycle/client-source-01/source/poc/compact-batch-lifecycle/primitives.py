"""Exact existing SHA/HMAC trees with explicit physical CM positions.

These pure data structures establish no accepted-chain authority. A caller must
authenticate/replay the exact native bodies and independently reconcile current
state before constructing a live spend. Missing physical positions are CM_EMPTY,
not zero-valued dummy notes and not renumbered receipts.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json

ZERO = bytes(32)
MAX = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
CM_MAX = 65_535
NF_MAX = 131_071


def need(condition, category):
    if not condition:
        raise ValueError(category)


def fixed(value, size=32):
    need(type(value) is bytes and len(value) == size, 'fixed-byte-width')
    return value


def uint(value, bits):
    need(type(value) is int and 0 <= value < 1 << bits, 'unsigned-integer-range')
    return value


def u32(value):
    return uint(value, 32).to_bytes(4, 'little')


def u64(value):
    return uint(value, 64).to_bytes(8, 'little')


def amount(value):
    need(type(value) is int and 0 <= value <= MAX, 'sompi-range')
    return value


def h(*parts):
    need(all(type(part) is bytes for part in parts), 'hash-bytes-required')
    return hashlib.sha256(b''.join(parts)).digest()


def parse(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate-JSON-field')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON-number')))


class SparseTree:
    def __init__(self, depth, leaves, node_tag, empty):
        need(depth in (16, 17), 'selected-tree-depth')
        self.depth, self.tag = depth, fixed(node_tag, 8)
        self.defaults = [fixed(empty)]
        for _ in range(depth):
            self.defaults.append(h(self.tag, self.defaults[-1], self.defaults[-1]))
        self.levels = [{}]
        for index, value in leaves.items():
            need(type(index) is int and 0 <= index < 1 << depth, 'physical-tree-index')
            self.levels[0][index] = fixed(value)
        for height in range(depth):
            lower = self.levels[-1]
            self.levels.append({index: h(self.tag,
                lower.get(2 * index, self.defaults[height]),
                lower.get(2 * index + 1, self.defaults[height]))
                for index in {child // 2 for child in lower}})

    @property
    def root(self):
        return self.levels[-1].get(0, self.defaults[-1])

    def path(self, index):
        need(type(index) is int and 0 <= index < 1 << self.depth, 'physical-tree-index')
        return [self.levels[level].get((index >> level) ^ 1, self.defaults[level])
                for level in range(self.depth)]

    def with_leaf(self, index, value):
        leaves = dict(self.levels[0])
        leaves[index] = fixed(value)
        return SparseTree(self.depth, leaves, self.tag, self.defaults[0])


def fold_path(leaf, index, path, tag):
    current = fixed(leaf)
    uint(index, 32)
    for level, sibling in enumerate(path):
        pair = (fixed(sibling), current) if index >> level & 1 else (current, fixed(sibling))
        current = h(fixed(tag, 8), *pair)
    return current


@dataclass(frozen=True)
class Delivery:
    position: int
    cm: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class NFEntry:
    value: bytes
    next_value: bytes
    next_index: int

    def leaf(self):
        return h(b'KPX1NFL\0', fixed(self.value), fixed(self.next_value), u32(self.next_index))


@dataclass(frozen=True)
class Snapshot:
    cm_cursor: int
    deliveries: tuple
    nullifiers: tuple

    def verify(self):
        need(type(self.cm_cursor) is int and 1 <= self.cm_cursor <= CM_MAX, 'cm-cursor')
        need(1 <= len(self.nullifiers) <= min(NF_MAX, 2 * self.cm_cursor + 1), 'nf-count')
        positions = [row.position for row in self.deliveries]
        need(positions == sorted(set(positions)) and positions
             and all(type(pos) is int and 0 <= pos < self.cm_cursor for pos in positions),
             'sparse-delivery-order-range')
        for row in self.deliveries:
            fixed(row.cm)
            fixed(row.ciphertext, 264)
        entries = self.nullifiers
        need(entries[0].value == ZERO
             and len({fixed(row.value) for row in entries}) == len(entries), 'nf-sentinel-or-duplicate')
        seen, index = set(), 0
        while True:
            need(index not in seen and 0 <= index < len(entries), 'nf-linked-list')
            seen.add(index)
            row = entries[index]
            fixed(row.next_value)
            uint(row.next_index, 32)
            if row.next_value == ZERO:
                need(row.next_index == 0, 'nf-tail')
                break
            need(0 < row.next_index < len(entries), 'nf-next-index')
            following = entries[row.next_index]
            need(following.value == row.next_value
                 and int.from_bytes(row.value, 'little') < int.from_bytes(following.value, 'little'),
                 'nf-link-order')
            index = row.next_index
        need(len(seen) == len(entries), 'nf-unreachable')
        return self

    def roots(self):
        self.verify()
        return (SparseTree(16, {row.position: row.cm for row in self.deliveries},
                           b'KPX1CMN\0', h(b'KPX1CME\0')),
                SparseTree(17, {i: row.leaf() for i, row in enumerate(self.nullifiers)},
                           b'KPX1NFN\0', h(b'KPX1NFE\0')))

    def state(self, domain):
        cm, nf = self.roots()
        return b'KPX2ST01' + fixed(domain) + cm.root + u32(self.cm_cursor) + nf.root + u32(len(self.nullifiers))

    def append(self, domain, notes, ciphertexts):
        """Authenticate one empty aligned subtree; preserve physical gaps."""
        return self.append_commitments([note_cm(domain, note) for note in notes], ciphertexts)

    def append_commitments(self, commitments, ciphertexts):
        """Public replay of commitments; private validity remains proof-owned."""
        arity = len(commitments)
        need(arity in (2, 32) and len(ciphertexts) == arity, 'selected-output-arity')
        start = (self.cm_cursor + arity - 1) // arity * arity
        need(start + arity <= CM_MAX, 'cm-append-capacity')
        cm, _ = self.roots()
        height = arity.bit_length() - 1
        boundary = cm.path(start)[height:]
        need(fold_path(cm.defaults[height], start >> height, boundary, b'KPX1CMN\0') == cm.root,
             'authenticated-empty-target-subtree')
        records = []
        for slot, (commitment, cipher) in enumerate(zip(commitments, ciphertexts)):
            records.append(Delivery(start + slot, fixed(commitment), fixed(cipher, 264)))
        need(len({row.cm for row in records}) == arity, 'distinct-ordered-output-CMs')
        after = Snapshot(start + arity, self.deliveries + tuple(records), self.nullifiers)
        after.verify()
        return after, start, boundary


def singleton(domain, note, cipher):
    return Snapshot(1, (Delivery(0, note_cm(domain, note), fixed(cipher, 264)),),
                    (NFEntry(ZERO, ZERO, 0),)).verify()


def note_cm(domain, note):
    return h(b'KPX1NOT\0', fixed(domain), fixed(note, 168))


def real_nf(domain, key, cm, position):
    return hmac.digest(fixed(key), b'KPX1NF\0\0' + fixed(domain) + fixed(cm) + u32(position), 'sha256')


def dummy_nf(domain, key, seed, slot):
    need(slot in (0, 1), 'actual-input-slot')
    return hmac.digest(fixed(key), b'KPX2DMY\0' + fixed(domain) + fixed(seed) + bytes([slot]), 'sha256')


def insert_nf(snapshot, value):
    snapshot.verify()
    fixed(value)
    need(value != ZERO and all(row.value != value for row in snapshot.nullifiers), 'spent-or-zero-NF')
    count = len(snapshot.nullifiers)
    need(count < NF_MAX, 'nf-capacity')
    _, tree = snapshot.roots()
    scalar = int.from_bytes(value, 'little')
    index, previous = max(((i, row) for i, row in enumerate(snapshot.nullifiers)
        if int.from_bytes(row.value, 'little') < scalar),
        key=lambda pair: int.from_bytes(pair[1].value, 'little'))
    need(previous.next_value == ZERO or scalar < int.from_bytes(previous.next_value, 'little'),
         'nf-current-absence')
    witness = (u32(index) + previous.value + previous.next_value + u32(previous.next_index)
               + b''.join(tree.path(index)))
    replacement = NFEntry(previous.value, value, count)
    middle = tree.with_leaf(index, replacement.leaf())
    witness += b''.join(middle.path(count))
    rows = list(snapshot.nullifiers)
    rows[index] = replacement
    rows.append(NFEntry(value, previous.next_value, previous.next_index))
    need(len(witness) == 1160, 'nf-witness-width')
    after = Snapshot(snapshot.cm_cursor, snapshot.deliveries, tuple(rows))
    after.verify()
    return after, witness

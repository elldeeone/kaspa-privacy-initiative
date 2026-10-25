"""Independent complete public-state reconstruction for ADR-0066.

Builds complete sparse levels from public leaves instead of verifying a supplied
path. No notes, owners, proofs, private history or chain authority enter here.
"""
import hashlib

DOMAIN = bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c')
MAGIC = b'KPXAST01'
ZERO = bytes(32)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


CM_EMPTY, NF_EMPTY = sha(b'KPX1CME\0'), sha(b'KPX1NFE\0')


def word(value):
    return type(value) is bytes and len(value) == 32


class SparseTree:
    def __init__(self, depth, tag, empty, leaves=()):
        need(type(depth) is int and 1 <= depth <= 17 and type(tag) is bytes
             and word(empty), 'tree-parameters')
        self.depth, self.tag, self.empty = depth, tag, empty
        self.leaves = {}
        self.defaults = [empty]
        for _ in range(depth):
            self.defaults.append(sha(tag, self.defaults[-1], self.defaults[-1]))
        for position, leaf in leaves:
            self.set(position, leaf)

    def set(self, position, leaf):
        need(type(position) is int and 0 <= position < 1 << self.depth and word(leaf), 'tree-leaf')
        if leaf == self.empty:
            self.leaves.pop(position, None)
        else:
            self.leaves[position] = leaf

    def levels(self):
        layers = [dict(self.leaves)]
        for level in range(self.depth):
            previous, current = layers[-1], {}
            for parent in {position // 2 for position in previous}:
                node = sha(self.tag, previous.get(parent * 2, self.defaults[level]),
                           previous.get(parent * 2 + 1, self.defaults[level]))
                if node != self.defaults[level + 1]:
                    current[parent] = node
            layers.append(current)
        return layers

    def root(self):
        return self.levels()[-1].get(0, self.defaults[-1])

    def path(self, position):
        need(type(position) is int and 0 <= position < 1 << self.depth, 'tree-path-position')
        layers = self.levels()
        return b''.join(layers[level].get((position // (1 << level)) ^ 1, self.defaults[level])
                        for level in range(self.depth))

    def copy(self):
        return SparseTree(self.depth, self.tag, self.empty, self.leaves.items())


class PublicState:
    """Authenticated-history structure only; no proof or chain verification."""

    def __init__(self, cms, nfs=()):
        need(type(cms) is list and 1 <= len(cms) <= 1 << 16
             and all(word(cm) and cm not in (ZERO, CM_EMPTY) for cm in cms), 'nonempty-public-CMs')
        need(type(nfs) in (list, tuple), 'public-NF-sequence')
        self.cms = list(cms)
        self.cm = SparseTree(16, b'KPX1CMN\0', CM_EMPTY, enumerate(cms))
        self.entries = [(ZERO, ZERO, 0)]
        self.nf = SparseTree(17, b'KPX1NFN\0', NF_EMPTY, [(0, self.nf_leaf(ZERO, ZERO, 0))])
        for value in nfs:
            self.insert(value)

    @staticmethod
    def nf_leaf(value, successor, position):
        need(word(value) and word(successor) and type(position) is int
             and 0 <= position < 1 << 17, 'NF-leaf-fields')
        return sha(b'KPX1NFL\0', value, successor, position.to_bytes(4, 'little'))

    @property
    def nfs(self):
        return [entry[0] for entry in self.entries[1:]]

    def copy(self):
        result = object.__new__(PublicState)
        result.cms, result.entries = list(self.cms), list(self.entries)
        result.cm, result.nf = self.cm.copy(), self.nf.copy()
        return result

    def state(self, domain=DOMAIN, magic=MAGIC):
        need(type(domain) is bytes and type(magic) is bytes
             and domain == DOMAIN and magic == MAGIC, 'selected-state-identity')
        return (magic + domain + self.cm.root() + len(self.cms).to_bytes(4, 'little')
                + self.nf.root() + len(self.entries).to_bytes(4, 'little'))

    def insert(self, value):
        need(word(value) and value != ZERO and value not in {entry[0] for entry in self.entries},
             'distinct-nonzero-original-NF')
        count = len(self.entries)
        need(count < 1 << 17, 'NF-capacity')
        number = int.from_bytes(value, 'little')
        predecessor = max((position for position, entry in enumerate(self.entries)
                           if int.from_bytes(entry[0], 'little') < number),
                          key=lambda position: int.from_bytes(self.entries[position][0], 'little'))
        previous, successor, successor_position = self.entries[predecessor]
        need(successor == ZERO or number < int.from_bytes(successor, 'little'), 'NF-predecessor-interval')
        before = self.nf.path(predecessor)
        self.entries[predecessor] = (previous, value, count)
        self.nf.set(predecessor, self.nf_leaf(previous, value, count))
        append = self.nf.path(count)
        self.entries.append((value, successor, successor_position))
        self.nf.set(count, self.nf_leaf(value, successor, successor_position))
        return (predecessor.to_bytes(4, 'little') + previous + successor
                + successor_position.to_bytes(4, 'little') + before + append)

    def append(self, cm):
        # The statement's NF is position-bound. Consensus requires distinct
        # output CMs inside one payment, not a global CM nonmembership proof.
        need(word(cm) and cm not in (ZERO, CM_EMPTY), 'nonempty-output-CM')
        position = len(self.cms)
        need(position < 1 << 16, 'CM-capacity')
        path = self.cm.path(position)
        self.cm.set(position, cm)
        self.cms.append(cm)
        return path

    def transition(self, mode, nfs, cms, old, new, domain=DOMAIN, magic=MAGIC):
        """Atomic check against supplied accepted state; no mutation on failure."""
        need(mode in ('batch', 'exit') and type(nfs) is list and type(cms) is list,
             'transition-shape')
        need((len(nfs), len(cms)) == ((1, 2) if mode == 'batch' else (1, 0)), 'transition-counts')
        need(mode != 'batch' or cms[0] != cms[1], 'distinct-payment-output-CMs')
        need(old == self.state(domain, magic), 'current-public-state-required')
        following = self.copy()
        witnesses = [following.insert(nf) for nf in nfs]
        paths = [following.append(cm) for cm in cms]
        need(new == following.state(domain, magic), 'exact-successor-state')
        return following, witnesses, paths

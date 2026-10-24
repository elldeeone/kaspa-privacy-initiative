"""Public sparse-tree builder, independent of the verifier's path consumer.

Inputs are admitted public CMs and published NFs only. No wallet filesystem.
"""
import hashlib


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(*parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


ZERO = bytes(32)
CM_EMPTY = sha(b'KPX1CME\0')
NF_EMPTY = sha(b'KPX1NFE\0')


class SparseTree:
    def __init__(self, depth, tag, empty, leaves=()):
        need(type(depth) is int and 1 <= depth <= 17, 'tree-depth')
        self.depth, self.tag, self.empty = depth, tag, empty
        self.leaves = {}
        self.defaults = [empty]
        for _ in range(depth):
            self.defaults.append(sha(tag, self.defaults[-1], self.defaults[-1]))
        for index, leaf in leaves:
            self.set(index, leaf)

    def set(self, index, leaf):
        need(type(index) is int and 0 <= index < 1 << self.depth and
             type(leaf) is bytes and len(leaf) == 32, 'tree-leaf')
        if leaf == self.empty:
            self.leaves.pop(index, None)
        else:
            self.leaves[index] = leaf

    def levels(self):
        levels = [dict(self.leaves)]
        for level in range(self.depth):
            current, following = levels[-1], {}
            for parent in {index >> 1 for index in current}:
                left = current.get(2 * parent, self.defaults[level])
                right = current.get(2 * parent + 1, self.defaults[level])
                value = sha(self.tag, left, right)
                if value != self.defaults[level + 1]:
                    following[parent] = value
            levels.append(following)
        return levels

    def root(self):
        return self.levels()[-1].get(0, self.defaults[-1])

    def path(self, index):
        need(type(index) is int and 0 <= index < 1 << self.depth, 'tree-path-index')
        levels = self.levels()
        return b''.join(levels[level].get((index >> level) ^ 1,
                                         self.defaults[level])
                        for level in range(self.depth))


class PublicState:
    def __init__(self, cms):
        need(type(cms) is list and len(cms) == 3 and len(set(cms)) == 3 and
             all(type(cm) is bytes and len(cm) == 32 and cm != CM_EMPTY for cm in cms),
             'three-distinct-occupied-genesis-CMs')
        self.cms = list(cms)
        self.cm = SparseTree(16, b'KPX1CMN\0', CM_EMPTY, enumerate(cms))
        self.entries = [(ZERO, ZERO, 0)]
        self.nf = SparseTree(17, b'KPX1NFN\0', NF_EMPTY,
                             [(0, self.nf_leaf(*self.entries[0]))])

    @staticmethod
    def nf_leaf(value, successor, index):
        return sha(b'KPX1NFL\0', value, successor, index.to_bytes(4, 'little'))

    def state(self, domain):
        need(type(domain) is bytes and len(domain) == 32, 'domain-width')
        return (b'KPX7ST01' + domain + self.cm.root() + len(self.cms).to_bytes(4, 'little')
                + self.nf.root() + len(self.entries).to_bytes(4, 'little'))

    def insert(self, value):
        need(type(value) is bytes and len(value) == 32 and value != ZERO and
             value not in {entry[0] for entry in self.entries}, 'distinct-nonzero-original-NF')
        target = int.from_bytes(value, 'little')
        predecessor = max((i for i, entry in enumerate(self.entries)
                           if int.from_bytes(entry[0], 'little') < target),
                          key=lambda i: int.from_bytes(self.entries[i][0], 'little'))
        previous, successor, successor_index = self.entries[predecessor]
        need(successor == ZERO or target < int.from_bytes(successor, 'little'),
             'NF-strict-predecessor-interval')
        before_path = self.nf.path(predecessor)
        count = len(self.entries)
        self.entries[predecessor] = (previous, value, count)
        self.nf.set(predecessor, self.nf_leaf(previous, value, count))
        append_path = self.nf.path(count)
        self.entries.append((value, successor, successor_index))
        self.nf.set(count, self.nf_leaf(value, successor, successor_index))
        return (predecessor.to_bytes(4, 'little') + previous + successor
                + successor_index.to_bytes(4, 'little') + before_path + append_path)

    def append(self, cm):
        need(type(cm) is bytes and len(cm) == 32 and cm != CM_EMPTY and
             cm not in self.cms and len(self.cms) < 1 << 16, 'fresh-output-CM')
        index = len(self.cms)
        path = self.cm.path(index)
        self.cm.set(index, cm)
        self.cms.append(cm)
        return path

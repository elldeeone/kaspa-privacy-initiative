"""Public CM/indexed-NF construction for the integrated lifecycle.

Adapted from the executed owner-private prototype's independent public tree
builder. These objects contain only admitted/published commitments and
nullifiers; they never open a wallet or establish proof/chain acceptance.
"""
import hashlib


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


ZERO = bytes(32)
CM_EMPTY = sha(b'KPX1CME\0')
NF_EMPTY = sha(b'KPX1NFE\0')


def word(value):
    return type(value) is bytes and len(value) == 32


class SparseTree:
    def __init__(self, depth, tag, empty, leaves=()):
        need(type(depth) is int and 1 <= depth <= 17, 'tree-depth')
        need(type(tag) is bytes and word(empty), 'tree-hash-domain')
        self.depth, self.tag, self.empty = depth, tag, empty
        self.leaves = {}
        self.defaults = [empty]
        for _ in range(depth):
            self.defaults.append(sha(tag, self.defaults[-1], self.defaults[-1]))
        for index, leaf in leaves:
            self.set(index, leaf)

    def set(self, index, leaf):
        need(type(index) is int and 0 <= index < 1 << self.depth and word(leaf), 'tree-leaf')
        if leaf == self.empty:
            self.leaves.pop(index, None)
        else:
            self.leaves[index] = leaf

    def levels(self):
        result = [dict(self.leaves)]
        for level in range(self.depth):
            previous, current = result[-1], {}
            for index in {index >> 1 for index in previous}:
                value = sha(self.tag, previous.get(index * 2, self.defaults[level]),
                            previous.get(index * 2 + 1, self.defaults[level]))
                if value != self.defaults[level + 1]:
                    current[index] = value
            result.append(current)
        return result

    def root(self):
        return self.levels()[-1].get(0, self.defaults[-1])

    def path(self, index):
        need(type(index) is int and 0 <= index < 1 << self.depth, 'tree-path-index')
        levels = self.levels()
        return b''.join(levels[level].get((index >> level) ^ 1, self.defaults[level])
                        for level in range(self.depth))


class PublicState:
    """Reconstructible full public prefix; private note choices are absent."""

    def __init__(self, cms, nfs=()):
        need(type(cms) is list and 3 <= len(cms) <= 1 << 16 and len(set(cms)) == len(cms)
             and all(word(cm) and cm != CM_EMPTY for cm in cms), 'distinct-public-CMs')
        need(type(nfs) in (list, tuple), 'public-nullifier-sequence')
        self.cms = list(cms)
        self.cm = SparseTree(16, b'KPX1CMN\0', CM_EMPTY, enumerate(cms))
        self.entries = [(ZERO, ZERO, 0)]
        self.nf = SparseTree(17, b'KPX1NFN\0', NF_EMPTY,
                             [(0, self.nf_leaf(*self.entries[0]))])
        for value in nfs:
            self.insert(value)

    @staticmethod
    def nf_leaf(value, successor, index):
        return sha(b'KPX1NFL\0', value, successor, index.to_bytes(4, 'little'))

    @property
    def nfs(self):
        return [entry[0] for entry in self.entries[1:]]

    def copy(self):
        return PublicState(self.cms, self.nfs)

    def state(self, domain, magic):
        need(word(domain) and type(magic) is bytes and len(magic) == 8, 'selected-state-domain')
        return (magic + domain + self.cm.root() + len(self.cms).to_bytes(4, 'little')
                + self.nf.root() + len(self.entries).to_bytes(4, 'little'))

    def insert(self, value):
        need(word(value) and value != ZERO and value not in {entry[0] for entry in self.entries},
             'distinct-nonzero-original-NF')
        count = len(self.entries)
        need(count < 1 << 17, 'NF-capacity')
        target = int.from_bytes(value, 'little')
        predecessor = max((i for i, entry in enumerate(self.entries)
                           if int.from_bytes(entry[0], 'little') < target),
                          key=lambda i: int.from_bytes(self.entries[i][0], 'little'))
        previous, successor, successor_index = self.entries[predecessor]
        need(successor == ZERO or target < int.from_bytes(successor, 'little'),
             'NF-strict-predecessor-interval')
        before_path = self.nf.path(predecessor)
        self.entries[predecessor] = (previous, value, count)
        self.nf.set(predecessor, self.nf_leaf(previous, value, count))
        append_path = self.nf.path(count)
        self.entries.append((value, successor, successor_index))
        self.nf.set(count, self.nf_leaf(value, successor, successor_index))
        return (predecessor.to_bytes(4, 'little') + previous + successor
                + successor_index.to_bytes(4, 'little') + before_path + append_path)

    def append(self, cm):
        need(word(cm) and cm != CM_EMPTY and cm not in self.cms
             and len(self.cms) < 1 << 16, 'fresh-output-CM')
        position = len(self.cms)
        path = self.cm.path(position)
        self.cm.set(position, cm)
        self.cms.append(cm)
        return path

    def transition(self, mode, nfs, cms, old, new, domain, magic):
        """Atomic structural check only: caller separately verifies G16/native facts."""
        need(mode in ('batch', 'exit') and type(nfs) is list and type(cms) is list,
             'selected-transition-shape')
        need((len(nfs), len(cms)) == ((3, 6) if mode == 'batch' else (1, 0)),
             'exact-transition-counts')
        need(old == self.state(domain, magic), 'current-public-state-required')
        following = self.copy()
        witnesses = [following.insert(nf) for nf in nfs]
        paths = [following.append(cm) for cm in cms]
        need(new == following.state(domain, magic), 'exact-public-successor-state')
        return following, witnesses, paths

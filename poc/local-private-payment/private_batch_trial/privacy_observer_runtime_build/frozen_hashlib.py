"""Finite SHA-256-only hashlib surface for the unselected observer runtime.

The byte-pinned native ``kpb_sha256`` module delegates to OpenSSL SHA-256.
The selected privacy model uses only SHA-256; every other algorithm is absent.
"""

import kpb_sha256


algorithms_guaranteed = frozenset(('sha256',))
algorithms_available = algorithms_guaranteed


class _Sha256:
    digest_size = 32
    block_size = 64
    name = 'sha256'

    def __init__(self, value=b'', *, usedforsecurity=True):
        del usedforsecurity
        self._value = bytearray(value)

    def update(self, value):
        self._value.extend(value)

    def digest(self):
        return kpb_sha256.digest(self._value)

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        return _Sha256(self._value)


def sha256(value=b'', *, usedforsecurity=True):
    return _Sha256(value, usedforsecurity=usedforsecurity)


def new(name, value=b'', **kwargs):
    if name.lower().replace('-', '') != 'sha256':
        raise ValueError('unsupported hash type ' + name)
    return sha256(value, **kwargs)

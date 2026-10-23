#!/usr/bin/env python3
"""Independent PUBLIC same-length sentinel swap at restore's two-pass seam.

No private bytes or actual software packages are opened. The injected event
occurs after the real verification pass and before the real restore pass.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'poc/recovery-coldbuild'))
import software_bundle as bundle


def run():
    source = (ROOT / 'poc/recovery-coldbuild/software_bundle.py').read_bytes()
    with tempfile.TemporaryDirectory(prefix='PUBLIC-restore-swap-') as temporary:
        directory = Path(temporary)
        original = directory / 'bundle'
        original.mkdir()
        public = original / 'public.txt'
        public.write_bytes(b'A' * 32)
        sentinel = directory / 'DECLARED-FORBIDDEN-PUBLIC-SENTINEL'
        sentinel.write_bytes(b'B' * 32)
        raw = bundle.encoded(bundle.inventory(original, [('source', 'public.txt')]))
        expected = bundle.digest(raw)
        real_verify, real_read = bundle.verify, bundle.read_public
        reads = []

        def after_verification(*args, **kwargs):
            receipt = real_verify(*args, **kwargs)
            public.unlink()
            os.link(sentinel, public)
            return receipt

        def returned_read(path, *args, **kwargs):
            value = real_read(path, *args, **kwargs)
            if Path(path).stat().st_ino == sentinel.stat().st_ino:
                reads.append(True)
            return value

        bundle.verify, bundle.read_public = after_verification, returned_read
        try:
            bundle.restore(original, raw, expected, directory / 'restored',
                           forbidden_inputs=(p for p in [sentinel]))
        except bundle.Invalid as error:
            rejection = str(error)
        else:
            rejection = 'ACCEPTED'
        finally:
            bundle.verify, bundle.read_public = real_verify, real_read
    assert rejection == 'public-private-inode-alias' and not reads
    return {'schema': 'independent-coldrestore-iterator/v1',
            'classification': 'PUBLIC_SENTINEL_ONLY_NO_OWNER_INPUT',
            'source_sha256': hashlib.sha256(source).hexdigest(),
            'between_pass_swap_injected': True, 'forbidden_iterator_one_shot': True,
            'sentinel_same_length_as_expected_public': True,
            'forbidden_public_sentinel_read_count': len(reads),
            'rejection': rejection, 'actual_private_bytes_read': False,
            'postfix_expected_outcome': True}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))

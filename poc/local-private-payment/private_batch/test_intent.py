from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from intent import RestrictedIntent, INTENT_BYTES, UINT32_MAX, UINT64_MAX


def fixture() -> RestrictedIntent:
    return RestrictedIntent(
        b'G' * 32, b'L' * 32, b'P' * 32, b'D' * 32, b'S' * 32,
        b'T' * 32 + (2).to_bytes(4, 'little'), b'C' * 32, b'N' * 32,
        4, 1, 6_000_000_000, b'F' * 32, b'V' * 64, 10_000_000,
        b'I' * 32, (b'A' * 32 + b'O' * 488, b'B' * 32 + b'Q' * 488),
    )


class RestrictedIntentTests(unittest.TestCase):
    def test_exact_offsets_and_round_trip(self):
        intent = fixture()
        encoded = intent.encode()
        self.assertEqual(len(encoded), INTENT_BYTES)
        self.assertEqual(encoded[:8], b'KPBINT01')
        self.assertEqual(encoded[8:168], b'G' * 32 + b'L' * 32 + b'P' * 32 + b'D' * 32 + b'S' * 32)
        self.assertEqual(encoded[168:204], intent.reserve_outpoint)
        self.assertEqual(encoded[268:272], (4).to_bytes(4, 'little'))
        self.assertEqual(encoded[272:276], (1).to_bytes(4, 'little'))
        self.assertEqual(encoded[276:284], (6_000_000_000).to_bytes(8, 'little'))
        self.assertEqual(encoded[284:316], intent.nullifier)
        self.assertEqual(encoded[316:380], intent.input_cv)
        self.assertEqual(encoded[380:388], (10_000_000).to_bytes(8, 'little'))
        self.assertEqual(encoded[388:420], intent.nonce)
        self.assertEqual(encoded[420:940], intent.outputs[0])
        self.assertEqual(encoded[940:1460], intent.outputs[1])
        self.assertEqual(RestrictedIntent.decode(encoded), intent)

    def test_all_approved_bytes_are_in_digest(self):
        intent = fixture()
        encoded = intent.encode()
        digest = intent.authorization_digest()
        for offset in range(8, INTENT_BYTES):
            modified = bytearray(encoded)
            modified[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertNotEqual(hashlib.sha256(modified).digest(), digest)

    def test_signature_limb_order(self):
        intent = fixture()
        lo, hi = intent.authorization_limbs()
        self.assertLess(lo, 1 << 128)
        self.assertLess(hi, 1 << 128)
        self.assertEqual(lo.to_bytes(16, 'little') + hi.to_bytes(16, 'little'), intent.authorization_digest())

    def test_uint64_boundaries_and_types(self):
        for name in ('fee_sompi', 'old_reserve'):
            for allowed in (0, UINT64_MAX):
                with self.subTest(name=name, allowed=allowed):
                    self.assertEqual(RestrictedIntent.decode(replace(fixture(), **{name:allowed}).encode()).__getattribute__(name), allowed)
            for denied in (-1, UINT64_MAX + 1, True, False, 1.0, '1'):
                with self.subTest(name=name, denied=denied):
                    with self.assertRaises(ValueError):
                        replace(fixture(), **{name:denied}).encode()

    def test_uint32_boundaries(self):
        for name in ('old_cm_count', 'old_nf_count'):
            for allowed in (0, UINT32_MAX):
                self.assertEqual(RestrictedIntent.decode(replace(fixture(), **{name:allowed}).encode()).__getattribute__(name), allowed)
            for denied in (-1, UINT32_MAX + 1, True):
                with self.assertRaises(ValueError):
                    replace(fixture(), **{name:denied}).encode()

    def test_context_changes_change_authorization(self):
        for name in ('chain_genesis', 'pool_lineage', 'profile_id', 'domain', 'service_policy', 'old_cm_root', 'old_nf_root', 'nonce'):
            with self.subTest(context=name):
                self.assertNotEqual(replace(fixture(), **{name:b'Z' * 32}).authorization_digest(), fixture().authorization_digest())

    def test_malformed_noncanonical_and_legacy_bytes_refuse(self):
        encoded = fixture().encode()
        for denied in (encoded[:-1], encoded + b'\x00', b'KPXA0001' + encoded[8:], bytearray(encoded)):
            with self.assertRaises(ValueError):
                RestrictedIntent.decode(denied)
        with self.assertRaises(ValueError):
            replace(fixture(), nullifier=bytes(32)).encode()
        with self.assertRaises(ValueError):
            replace(fixture(), outputs=(fixture().outputs[0], fixture().outputs[0])).encode()
        with self.assertRaises(ValueError):
            replace(fixture(), outputs=list(fixture().outputs)).encode()
        with self.assertRaises(ValueError):
            replace(fixture(), input_cv=b'bad').encode()

    def test_shape_does_not_assert_cryptographic_validity(self):
        # These are deliberately fictional tuples/points. Passing the codec is
        # never a signature, output-proof or recipient-spendability verdict.
        self.assertEqual(RestrictedIntent.decode(fixture().encode()), fixture())


if __name__ == '__main__':
    unittest.main()

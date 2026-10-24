"""Meaningful byte-boundary and transcript controls; no MPC/proof substitution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

import codec
import backend


class CodecTests(unittest.TestCase):
    def test_complete_row_preserves_every_byte(self):
        raw = bytes(range(256)) * 2 + bytes(range(8))
        limbs = codec.pack_row(raw)
        self.assertEqual(len(limbs), 17)
        self.assertTrue(all(x < codec.Q for x in limbs))
        self.assertEqual(codec.unpack_row(limbs), raw)
        changed = list(limbs); changed[8] ^= 1
        self.assertNotEqual(codec.unpack_row(changed), raw)

    def test_limb_padding_and_canonical_boundaries(self):
        for raw in (b'', bytes(519), bytes(521)):
            with self.assertRaises(ValueError): codec.pack_row(raw)
        for change in (-1, 1 << 248, True):
            limbs = codec.pack_row(bytes(520)); limbs[0] = change
            with self.assertRaises(ValueError): codec.unpack_row(limbs)
        limbs = codec.pack_row(bytes(520)); limbs[-1] = 1 << (24 * 8)
        with self.assertRaises(ValueError): codec.unpack_row(limbs)
        for v in (-1, codec.Q, True):
            with self.assertRaises(ValueError): codec.scalar(v)
        self.assertEqual(codec.scalar(codec.Q - 1), codec.Q - 1)

    def test_owner_private_stream_shape(self):
        raw = codec.owner_input([bytes(520), bytes([255]) * 520], codec.Q - 1)
        self.assertEqual(len(raw.splitlines()), 35)
        self.assertEqual(int(raw.splitlines()[-1]), codec.Q - 1)
        with self.assertRaises(ValueError): codec.owner_input([bytes(520)], 0)

    def session_value(self):
        return {'schema': 'kpx7-private-construction-session/v1', 'session_id': '01' * 32,
                'domain_hex': '02' * 32, 'prior_state_digest': '03' * 32,
                'circuit_profile_sha256': '04' * 32, 'public_effects_context_sha256': '05' * 32,
                'roster': ['06' * 32, '07' * 32, '08' * 32], 'program_source_sha256': '09' * 32,
                'tuple_bytes': 520, 'outputs_per_party': 2, 'mpc_prime': str(codec.Q)}

    def test_session_program_and_shape_are_bound(self):
        value = self.session_value(); _, digest = codec.session(codec.canonical_json(value), '09' * 32)
        other = dict(value, session_id='10' * 32)
        self.assertNotEqual(digest, codec.session(codec.canonical_json(other), '09' * 32)[1])
        for change in ({'mpc_prime': str(codec.Q + 2)}, {'tuple_bytes': 519},
                       {'outputs_per_party': 1}, {'roster': ['06' * 32] * 3},
                       {'program_source_sha256': '11' * 32}, {'extra': 0}):
            with self.assertRaises(ValueError):
                codec.session(codec.canonical_json(dict(value, **change)), '09' * 32)

    def transcript(self):
        rows = [bytes([i]) * 520 for i in range(6)]
        return ('engine public setup prompts\nKPX7_SESSION ' + 'ab' * 32 + '\n' +
                ''.join('KPX7_ROW ' + str(i) + ' ' + ' '.join(map(str, codec.pack_row(row))) + '\n'
                        for i, row in enumerate(rows)) + 'KPX7_DELTA ' + str(codec.Q - 1) + '\n').encode()

    def test_only_complete_same_session_checked_projection(self):
        raw = self.transcript(); output = codec.engine_output(raw, 'ab' * 32)
        self.assertEqual(len(output['rows_hex']), 6)
        self.assertEqual(output['delta_decimal'], str(codec.Q - 1))
        for bad in (raw.replace(b'KPX7_ROW 4 ', b'KPX7_ROW 3 '),
                    raw.replace(b'KPX7_DELTA', b'OTHER_DELTA'),
                    raw.replace(b'KPX7_ROW 0 ', b'KPX7_ROW 0 999 '),
                    raw + b'INSECURE preprocessing\n', raw + raw):
            with self.assertRaises(ValueError): codec.engine_output(bad, 'ab' * 32)
        with self.assertRaises(ValueError): codec.engine_output(raw, 'bc' * 32)

    def test_original_alias_guard_before_any_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots = [root / 'trial0', root / 'trial1']
            for trial in roots:
                for role in 'ABCD':
                    p = trial / 'owners' / role / 'backup.json'; p.parent.mkdir(parents=True)
                    p.write_bytes(b'PUBLIC SENTINEL NOT A WALLET')
            guard = backend.PublicGuard(roots)
            alias = root / 'public-alias'
            alias.hardlink_to(roots[0] / 'owners/A/backup.json')
            with self.assertRaisesRegex(ValueError, 'public-aliases-original-private'):
                guard.metadata(alias)
            with self.assertRaises(ValueError):
                guard.metadata(roots[1] / 'owners/D/backup.json')
            ordinary = root / 'public.json'; ordinary.write_bytes(b'{}')
            self.assertEqual(guard.read(ordinary, codec.sha(b'{}')), b'{}')
            owners = [root / ('new-owner-' + str(i)) for i in range(3)]
            for i, owner in enumerate(owners):
                owner.mkdir(); secret = owner / ('Input-P' + str(i) + '-0')
                secret.write_bytes(b'PUBLIC NEW-OWNER SENTINEL'); secret.chmod(0o400)
            guard = backend.PublicGuard(roots, owners)
            for i, owner in enumerate(owners):
                leaf = owner / ('Input-P' + str(i) + '-0')
                with self.assertRaises(ValueError): guard.metadata(leaf)
                self.assertEqual(guard.own_input_metadata(leaf, i)[0], leaf)
                with self.assertRaises(ValueError): guard.own_input_metadata(leaf, (i + 1) % 3)


if __name__ == '__main__': unittest.main()

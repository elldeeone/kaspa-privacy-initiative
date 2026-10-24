"""Known-public parser controls only; no files, identity, crypto or PK."""
import copy
import unittest

from gn2_backup import SCHEMA, SECP_N, decode_backup
from gn2_common import GENESIS, encoded

TRIAL = '40fa06bd-dd66-43e4-a8a5-2debcbed9d0b'
DOMAIN = bytes.fromhex('23' * 32)


def fixture():
    return {'schema': SCHEMA, 'network_id': 'testnet-10', 'genesis_hash_hex': GENESIS,
        'domain_hex32': DOMAIN.hex(), 'trial_id': TRIAL,
        'seed_hex32': '00' * 32, 'funding_secret_hex32': (1).to_bytes(32, 'big').hex()}


class BackupControls(unittest.TestCase):
    def test_seed_is_hmac_root_not_curve_scalar(self):
        result = decode_backup(encoded(fixture()), DOMAIN, TRIAL)
        self.assertEqual(result.seed, bytes(32))
        self.assertEqual(result.funding_key, (1).to_bytes(32, 'big'))
        self.assertNotIn(fixture()['seed_hex32'], repr(result))
        self.assertNotIn(fixture()['funding_secret_hex32'], repr(result))

    def test_wrong_context_unknown_and_missing_fields(self):
        cases = []
        for key, value in [('schema', 'kpx4-compact-batch-seed-backup/v1'),
            ('network_id', 'mainnet'), ('genesis_hash_hex', '42' * 32),
            ('domain_hex32', '24' * 32), ('trial_id', '40fa06bd-dd66-43e4-a8a5-2debcbed9d0c')]:
            row = fixture(); row[key] = value; cases.append(row)
        for key in fixture():
            row = fixture(); del row[key]; cases.append(row)
        row = fixture(); row['financial_profile_sha256'] = '11' * 32; cases.append(row)
        for row in cases:
            with self.subTest(row_keys=sorted(row)):
                with self.assertRaises(ValueError):
                    decode_backup(encoded(row), DOMAIN, TRIAL)

    def test_canonical_encodings_and_funding_scalar_bounds(self):
        for field, values in [('seed_hex32', [None, True, 5, 'a' * 63, 'AA' * 32, 'zz' * 32]),
            ('funding_secret_hex32', [None, '00' * 32, SECP_N.to_bytes(32, 'big').hex(),
                                     'ff' * 32, '1', '01' * 33]),
            ('trial_id', [None, TRIAL.upper(), '{' + TRIAL + '}',
                           '40fa06bd-dd66-13e4-a8a5-2debcbed9d0b'])]:
            for value in values:
                row = fixture(); row[field] = value
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        decode_backup(encoded(row), DOMAIN, TRIAL)
        row = fixture(); row['funding_secret_hex32'] = (SECP_N - 1).to_bytes(32, 'big').hex()
        self.assertEqual(decode_backup(encoded(row), DOMAIN, TRIAL).funding_key,
                         (SECP_N - 1).to_bytes(32, 'big'))

    def test_duplicate_fields_and_external_authority(self):
        raw = encoded(fixture())
        duplicate = b'{"schema":"wrong",' + raw[1:]
        for invalid in (duplicate, b'NaN', b'null', b'[]', b'{'):
            with self.assertRaises(ValueError):
                decode_backup(invalid, DOMAIN, TRIAL)
        for domain, trial in [(DOMAIN.hex(), TRIAL), (DOMAIN, None), (bytes(31), TRIAL)]:
            with self.assertRaises(ValueError):
                decode_backup(raw, domain, trial)


if __name__ == '__main__':
    unittest.main()

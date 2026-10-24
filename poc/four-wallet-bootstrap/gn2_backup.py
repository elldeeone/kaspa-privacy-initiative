"""Exact original compound backup format; call only inside the owning process."""
from dataclasses import dataclass, field
from gn2_common import GENESIS, fields, hx, need, parse, uuid_text

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SCHEMA = 'kpx6-four-wallet-backup/v1'
NAMES = {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'trial_id',
         'seed_hex32', 'funding_secret_hex32'}


@dataclass(frozen=True, repr=False)
class Backup:
    seed: bytes = field(repr=False)
    funding_key: bytes = field(repr=False)
    domain: bytes
    trial_id: str


def decode_backup(raw, expected_domain, expected_trial_id):
    """Neither the backup nor a mirror chooses domain/trial authority."""
    need(type(expected_domain) is bytes and len(expected_domain) == 32, 'expected-backup-domain')
    uuid_text(expected_trial_id)
    value = parse(raw)
    fields(value, NAMES, 'compound-backup-fields')
    need(value['schema'] == SCHEMA and value['network_id'] == 'testnet-10'
         and value['genesis_hash_hex'] == GENESIS
         and hx(value['domain_hex32'], 32) == expected_domain
         and uuid_text(value['trial_id']) == expected_trial_id, 'compound-backup-context')
    seed, funding = hx(value['seed_hex32'], 32), hx(value['funding_secret_hex32'], 32)
    # The HMAC root seed is not a curve scalar. Only the independent funding
    # key must satisfy secp256k1's established scalar interval.
    need(0 < int.from_bytes(funding, 'big') < SECP_N, 'funding-scalar-range')
    return Backup(seed, funding, expected_domain, expected_trial_id)

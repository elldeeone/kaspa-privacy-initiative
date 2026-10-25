"""Externally pinned GN3 financial selection; never accepted-chain authority."""
from gn3_common import GENESIS, digest, encoded, fields, hx, need, parse, public_bytes
from gn3 import EntrySelection


NAMES = {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
         'state_magic_hex8', 'financial_profile_sha256', 'native_tail_hex',
         'native_tail_sha256','output_relation','output_vk_hex328','initial_cv_hex64'}


def document(financial_profile_sha256, native_tail, output_relation, output_vk_hex328, initial_cv_hex64):
    selected = EntrySelection(financial_profile_sha256, bytes.fromhex(
        'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'),
        native_tail,output_relation,output_vk_hex328,initial_cv_hex64).check()
    return {'schema': 'kpxa-GN3-selection/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'domain_hex32': selected.domain.hex(),
        'state_magic_hex8': selected.state_magic.hex(),
        'financial_profile_sha256': selected.profile_sha256,
        'native_tail_hex':native_tail.hex(),'native_tail_sha256':digest(native_tail),
        'output_relation':output_relation,'output_vk_hex328':output_vk_hex328,'initial_cv_hex64':initial_cv_hex64}


def decode(raw, expected_sha256):
    hx(expected_sha256, 32)
    need(digest(raw) == expected_sha256, 'external-GN3-selection-SHA')
    value = parse(raw)
    fields(value, NAMES, 'GN3-selection-fields')
    need(value['schema'] == 'kpxa-GN3-selection/v1'
         and value['network_id'] == 'testnet-10'
         and value['genesis_hash_hex'] == GENESIS, 'GN3-testnet-selection')
    tail = hx(value['native_tail_hex'])
    need(digest(tail) == value['native_tail_sha256'], 'GN3-selected-tail-hash')
    return EntrySelection(value['financial_profile_sha256'], hx(value['domain_hex32'], 32),
        tail,value['output_relation'],value['output_vk_hex328'],value['initial_cv_hex64'],hx(value['state_magic_hex8'],8)).check()


def load(path, expected_sha256, forbidden=()):
    return decode(public_bytes(path, forbidden), expected_sha256)

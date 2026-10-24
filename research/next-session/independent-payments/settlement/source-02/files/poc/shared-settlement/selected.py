"""Install a publicly selected child profile; never called by a proof request."""
import json
from pathlib import Path

from policy import Policy
from wire import h, hexbytes, need

FIELDS = {'schema', 'selected', 'classification', 'trial_id', 'wrapper_domain_hex32',
          'child_domain_hex32', 'child_role', 'child_mode', 'child_count', 'child_vk_hex328',
          'child_vk_sha256', 'child_parameter_manifest_sha256', 'child_template_tail_hex',
          'journal_bytes', 'payload_bytes', 'owner_witness_or_funding_authority'}


def parse(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate_public_JSON_field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_public_JSON')))


def child_profile(path, externally_selected_sha256, *, allow_no_append_exit=False):
    """Hash authority must come from installed selection, not a transcript."""
    path = Path(path)
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'installed_profile_symlink')
    hexbytes(externally_selected_sha256, 32)
    raw = path.read_bytes()
    need(h(raw).hex() == externally_selected_sha256, 'externally_selected_child_profile')
    data = parse(raw)
    need(type(data) is dict and set(data) == FIELDS
         and data['schema'] == 'kpx5-public-virtual-settlement-child-profile/v1'
         and data['selected'] is True and data['child_role'] == 'compact2'
         and type(data['child_mode']) is int and data['child_mode'] == 2
         and type(data['child_count']) is int and data['child_count'] == 2
         and data['journal_bytes'] == 424 and data['payload_bytes'] == 8108
         and data['owner_witness_or_funding_authority'] is False,
         'selected_public_compact_P0_profile')
    vk = hexbytes(data['child_vk_hex328'], 328)
    domain = hexbytes(data['child_domain_hex32'], 32)
    wrapper = hexbytes(data['wrapper_domain_hex32'], 32)
    need(h(vk).hex() == data['child_vk_sha256'], 'selected_child_VK')
    hexbytes(data['child_parameter_manifest_sha256'], 32)
    tail = hexbytes(data['child_template_tail_hex'])
    policy = Policy(tail, vk, domain=domain, expected_tail_sha256=h(tail).hex(),
                    allow_no_append_exit=allow_no_append_exit)
    return policy, {'child_profile_sha256': externally_selected_sha256,
                    'child_domain_hex32': domain.hex(), 'wrapper_domain_hex32': wrapper.hex(),
                    'child_vk_sha256': h(vk).hex(), 'child_template_tail_sha256': h(tail).hex(),
                    'child_parameter_manifest_sha256': data['child_parameter_manifest_sha256'],
                    'classification': data['classification']}

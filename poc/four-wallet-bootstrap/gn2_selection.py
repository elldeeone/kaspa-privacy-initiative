"""Externally pinned public identity/profile selection, never trial authority."""
from gn2_common import (CLASS, GENESIS, digest, fields, hx, need, parse, public_bytes,
                    uuid_text)
from gn2 import EntrySelection

IDENTITY_NAMES = {'schema', 'financial_profile_id', 'classification', 'network_id',
    'genesis_hash_hex', 'child_domain_hex32', 'wrapper_domain_hex32',
    'source_baseline_commit', 'keys_parameters_currentness_or_funding_selected_by_this_file',
    'profile_identity_is_not_a_trial_identity'}
PROFILE_NAMES = {'schema', 'financial_profile_id', 'classification', 'network_id',
    'genesis_hash_hex', 'child_domain_hex32', 'wrapper_domain_hex32', 'compact',
    'settlement', 'W', 'private', 'executables'}


def context(value):
    need(value['classification'] == CLASS and value['network_id'] == 'testnet-10'
         and value['genesis_hash_hex'] == GENESIS, 'selected-testnet-only-profile')
    uuid_text(value['financial_profile_id'])
    domain = hx(value['child_domain_hex32'], 32)
    wrapper = hx(value['wrapper_domain_hex32'], 32)
    need(domain != bytes(32) and wrapper != bytes(32) and domain != wrapper,
         'distinct-financial-domains')
    return domain


def decode_identity(raw, expected_sha256):
    hx(expected_sha256, 32)
    need(digest(raw) == expected_sha256, 'external-profile-identity-pin')
    value = parse(raw)
    fields(value, IDENTITY_NAMES, 'financial-identity-fields')
    need(value['schema'] == 'kpx6-four-wallet-financial-identity/v1'
         and value['keys_parameters_currentness_or_funding_selected_by_this_file'] is False
         and value['profile_identity_is_not_a_trial_identity'] is True, 'identity-not-financial-assets')
    context(value)
    hx(value['source_baseline_commit'], 20)
    return value


def load_identity(path, expected_sha256, forbidden=()):
    return decode_identity(public_bytes(path, forbidden), expected_sha256)


# Set only to the independently reviewed canonical profile-loader source.
# Identity creation does not require this final financial parser or any setup.
PROFILE_LOADER_SHA = '425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553'


def profile_loader():
    import importlib.util
    import sys
    from gn2_common import ROOT
    need(type(PROFILE_LOADER_SHA) is str and len(PROFILE_LOADER_SHA) == 64,
         'canonical-profile-loader-source-not-yet-selected')
    name = '_gn2_financial_profile'
    if name in sys.modules:
        return sys.modules[name]
    path = ROOT / 'poc/four-wallet-profile/selection.py'
    raw = public_bytes(path)
    need(digest(raw) == PROFILE_LOADER_SHA, 'canonical-profile-loader-source')
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def decode_profile(raw, expected_sha256):
    return profile_loader().load(raw, expected_sha256)


def load_profile(path, expected_sha256, forbidden=()):
    return decode_profile(public_bytes(path, forbidden), expected_sha256)


def entry_selection(profile):
    return EntrySelection(profile.profile_sha256, profile.domain, profile.w_tail).check()

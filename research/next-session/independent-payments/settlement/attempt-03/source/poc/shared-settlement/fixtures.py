"""Finite externally pinned PUBLIC fixtures; no witness/PK/history discovery."""
from pathlib import Path
import json

from policy import Head, Policy
from wire import h, hexbytes, need

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / 'research/next-session/compact-batch'
CASES = {
    'wide': ('lifecycle/public-native-canaries-01/wide32/validation-case.json',
             '308e841e4b212bfc67aad79bcab0a61698c0ce294fdbded7d3697137809b3f23', 'wide32'),
    'compact': ('lifecycle/competition-01/native-01/compact2-positive/validation-case.json',
                'ae757a390a0a630e1b0678335536580cf9f82a5f10bdfe790503b0216252fc06', 'compact2'),
    'wide_alternative': ('lifecycle/competition-01/native-01/wide32-positive/validation-case.json',
                        'c96a4eb95480839ae5446993b683ffd596f1d91954ae1b55f90169435dcdf2ed', 'wide32'),
    'occupied': ('lifecycle/competition-01/finish-01/genuine-current-compact-after-REVEAL-NF-duplicate/validation-case.json',
                 'ab39c204efb45952d17896882fc07d197edc2893eb91807197ec0ccabaa321a6', 'compact2'),
    'stale_compact': ('lifecycle/competition-01/native-01/old-compact2-proof-rebased-after-wide32-STALE-AUTH/validation-case.json',
                      '153c7005769793b7562a5506f48e22a4cfd677431924c46065dbda6539d3e270', 'compact2'),
    'terminal': ('lifecycle/public-native-canaries-01/compact-terminal/validation-case.json',
                 'aa46095441a6c3efeeac31c57d736d19d05c848832ab1745ef2cbbd517bf8efe', 'compact2'),
    'wrong_next_CM_root': ('lifecycle/public-native-boundary-01/validation-case.json',
                          '7e3771d8919eabcb5fbeefbbfa4789dafdf79ec2c92f300ee318f914d8f32861', 'compact2'),
}
MANIFESTS = {
    'compact2': 'f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043',
    'wide32': 'b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149',
}


def read_selected(path, expected):
    # Only fixed package-selected public paths are ever passed here. No file
    # walks, profiles, private diagnostics, relative request paths or PK reads.
    need(not any(parent.is_symlink() for parent in (path, *path.parents)), 'selected_fixture_symlink')
    raw = path.read_bytes()
    need(h(raw).hex() == expected, 'selected_public_fixture_identity')
    return json.loads(raw)


def given_head(case):
    """Only for an externally pinned synthetic fixture, not transcript authority."""
    auth = hexbytes(case['transaction']['payload'])[:528]
    return Head(auth[40:72].hex(), int.from_bytes(auth[72:76], 'little'), auth[76:188],
                int.from_bytes(auth[188:196], 'little'))


def install():
    cases = {name: read_selected(OLD / path, digest) for name, (path, digest, _) in CASES.items()}
    keys = {}
    for role, digest in MANIFESTS.items():
        manifest = read_selected(OLD / f'prover/parameters-{role}-01/public-parameters.json', digest)
        need(manifest['role'] == role, 'selected_manifest_role')
        keys[role] = hexbytes(manifest['vk_hex328'], 328)
        need(h(keys[role]).hex() == manifest['vk_sha256'], 'selected_manifest_key')
    frame = hexbytes(cases['wide']['transaction']['inputs'][0]['signatureScript'])
    policy = Policy(frame[313:], keys['compact2'], keys['wide32'])
    return policy, cases


def public_inventory():
    return [{'path': str((OLD / path).relative_to(ROOT)), 'sha256': digest,
             'classification': 'EXISTING_PUBLIC_SYNTHETIC_DO_NOT_FUND_NOT_MAIN'}
            for path, digest, _ in CASES.values()]

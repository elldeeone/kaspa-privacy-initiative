"""Select exact historical sources for replay; never claim a current binary build."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile

from package import ROOT, checked_archive, sha, write


PROFILES = {
    'lifecycle': (
        'poc/private-native-proof/evidence/package-identity.json',
        'bfbcaa79ca849d202a1096526327bc6012a11098274c7f097ea23d4a3426df79',
        'b83ce3e3ba7543cc5d870a755ddc5185b9f660daa03bd642bda7c3ddf7cb4efc',
    ),
    'recovery': (
        'poc/recovery-proof/evidence/package-identity.json',
        'cf10673cb40e6d36308d3a227a60bc7faf3b2633fb868b8e0bed8c881a24563a',
        'a02c80b30eb28d6acff98755b6ace823529f05fbeba7b140a1cb53625353646a',
    ),
}


@contextmanager
def source_closure(profile):
    """Yield only the independently pinned, complete original source table."""
    identity_path, identity_sha, archive_sha = PROFILES[profile]
    identity_raw = (ROOT / identity_path).read_bytes()
    assert sha(identity_raw) == identity_sha, 'historical identity changed'
    identity = json.loads(identity_raw)
    contents = checked_archive(
        ROOT / 'poc/remote-cuda/historical-sources' / (profile + '.tar.gz'),
        archive_sha,
    )
    assert set(contents) == set(identity['sourceFiles']), 'historical source closure'
    for name, data in contents.items():
        assert sha(data) == identity['sourceFiles'][name], 'historical source drift: ' + name
    with tempfile.TemporaryDirectory(prefix='historical-proof-sources-') as directory:
        root = Path(directory)
        for name, data in contents.items():
            write(root / name, data)
        yield root

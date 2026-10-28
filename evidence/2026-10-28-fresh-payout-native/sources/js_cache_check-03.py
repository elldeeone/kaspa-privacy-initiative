"""Body-check only the already admitted unchanged public JS cache, no wallet."""
import hashlib
import json
import os
from pathlib import Path
import stat

raw=Path('/public/LEAF-MAP.json').read_bytes()
pin='00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'
assert hashlib.sha256(raw).hexdigest()==pin
value=json.loads(raw)
assert value['installedFileMapSha256']=='25737bfa889a940d41db50612f3a99dffd5c673dedd62288224c4bec80b91b02'
assert len(value['files'])==3567
files={**value['files'],'node_modules/.package-lock.json':'e52d29a883e7f4b80d79ee1b7bdc29d3b96f65ea5905daf203241b158c6b02cb'}
for relative,expected in files.items():
    path=Path('/public')/relative
    assert path.is_relative_to('/public/node_modules') and '..' not in path.parts
    assert not any(p.is_symlink() for p in (path,*path.parents))
    before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        opened=os.fstat(f.fileno());digest=hashlib.file_digest(f,'sha256').hexdigest();after=os.fstat(f.fileno())
    assert all(getattr(before,k)==getattr(opened,k)==getattr(after,k) for k in
               ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink'))
    assert digest==expected
print(json.dumps({'schema':'kpb-public-mature-JS-cache-check/v1','leaves':3567,'map_sha256':pin,'auxiliary_metadata_leaves':1}))

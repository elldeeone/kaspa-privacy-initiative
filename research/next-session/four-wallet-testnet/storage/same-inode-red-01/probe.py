"""Public same-inode/mtime-restored finalization calibration; no network or secrets."""
from pathlib import Path
from unittest.mock import patch
import hashlib,json,sys,tempfile
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'poc/four-wallet-storage'))
import restore
from test_storage import fixture,encoded,PublicFixtureFetch,PUBLIC
source=(ROOT/'poc/four-wallet-storage/restore.py').read_bytes()
original_link=restore.os.link

def changed_contents(source,target,**kwargs):
    source=Path(source);before=source.stat();raw=source.read_bytes()
    source.write_bytes(b'X'+raw[1:])
    restore.os.utime(source,ns=(before.st_atime_ns,before.st_mtime_ns))
    return original_link(source,target,**kwargs)

with tempfile.TemporaryDirectory(prefix='four-wallet-storage-same-inode-public-') as td:
    output=Path(td)/'out';raw=encoded(fixture())
    with patch.object(restore.os,'link',side_effect=changed_contents):
        result=restore.restore(raw,restore.digest(raw),output,excluded=('issuer',),
            denied_hosts=('issuer.invalid',),fetch=PublicFixtureFetch(),
            observed_at='2026-10-24T00:00:00Z')
    mismatches=sum((output/item['relative_path']).read_bytes()!=PUBLIC[item['asset_id']]
                   for item in result['restored_objects'])
    print(json.dumps({'schema':'four-wallet-storage-public-same-inode-finalization/v1',
        'source_sha256':hashlib.sha256(source).hexdigest(),
        'restore_reported_status':result['status'],
        'exported_objects':len(result['restored_objects']),
        'wrong_final_public_payloads':mismatches,
        'network_PK_backup_seed_witness_or_funding':False,
        'attacker_model':'LOCAL_SAME_INODE_WRITE_WITH_RESTORED_MTIME_BETWEEN_VERIFICATION_AND_LINK; no arbitrary-host or remote TLS claim'},sort_keys=True))

"""Cheap public runtime boundary checks; no study seeds or datasets."""
import errno
import json
from pathlib import Path
import socket
import subprocess
import sys
from run import HERE,ROOT,PYTHON,OBSERVER,SCORER,sandbox
from schema import canonical

if __name__=='__main__':
    out=Path(sys.argv[1]).resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    errors=[]
    for family in (socket.AF_INET,socket.AF_INET6):
        try:s=socket.socket(family,socket.SOCK_STREAM)
        except OSError as error:
            assert error.errno in (errno.EPERM,errno.EACCES,errno.EAFNOSUPPORT);errors.append(error.errno)
        else:s.close();raise AssertionError('Internet sockets allowed')
    software=out/'software';software.mkdir(mode=0o700)
    for f in sorted(HERE.glob('*.py')):
        target=software/f.relative_to(ROOT);target.parent.mkdir(exist_ok=True,parents=True);target.write_bytes(f.read_bytes());target.chmod(0o400)
    # All probe strings contain public path canaries only, not actual wallet paths.
    code="from pathlib import Path; import z3; assert not Path('/work/generate.py').exists(); assert not Path('/seeds.json').exists(); assert not Path('/truth.json').exists(); assert not Path('/home/luke/.codex').exists(); print('NARROW_OBSERVER_OK')"
    result=subprocess.run(sandbox(software,OBSERVER)+['--chdir','/work',str(PYTHON),'-B','-c',code],capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    code="from pathlib import Path; import score; assert not Path('/work/observe.py').exists(); assert not Path('/work/model.py').exists(); assert not Path('/work/generate.py').exists(); assert not Path('/seeds.json').exists(); print('KEYLESS_SCORER_OK')"
    scored=subprocess.run(sandbox(software,SCORER)+['--chdir','/work',str(PYTHON),'-B','-c',code],capture_output=True)
    assert scored.returncode==0,scored.stderr.decode()
    payload={'schema':'kpx3-linkage-public-namespace-controls/v1','internet_socket_errors':errors,
      'observer_source_data_mounts_narrow':True,'scorer_cannot_import_model_observer_or_generator':True,
      'study_seeds_or_existing_private_sources_read':False,'heldout_generation_scoring':False}
    (out/'RESULTS.json').write_bytes(canonical(payload));print(json.dumps(payload))

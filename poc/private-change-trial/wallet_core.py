"""Authenticate the new owner core before the local controller imports it."""
from pathlib import Path
import sys
from types import SimpleNamespace, ModuleType

import phase

# Execute only the exact archived development core; later cold selection pins
# can change in their own package without changing this local rehearsal source.
SELECTED_CORE_SHA256='e05922ea0e561412ef9e0c258fcc1807b37fc6547cb85883a3b5a2d9442bdf3b'
CORE_FREEZE=phase.PHASE/'wallet/source-01/SOURCE-FREEZE.json'
NAMES=('owner_rules','owner_runtime','receiver_tools','owner_selection','change_action','change_wallet')


def load():
    phase.selected()
    phase.require(type(SELECTED_CORE_SHA256) is str and len(SELECTED_CORE_SHA256)==64,
                  'reviewed-owner-core-selection-required')
    raw=CORE_FREEZE.read_bytes()
    phase.require(phase.digest(raw)==SELECTED_CORE_SHA256,'selected-owner-core-freeze')
    selection=phase.parse(raw)
    phase.require(selection['schema']=='kpx3-private-change-wallet-source-freeze/v1',
                  'owner-core-source-freeze-schema')
    directory=phase.ROOT/'poc/private-change-wallet'
    records={row['path']:row for row in selection['files']}
    expected={'poc/private-change-wallet/'+name+'.py' for name in NAMES}
    phase.require(len(records)==len(selection['files']) and expected<=set(records),
                  'exact-owner-core-source-allowlist')
    owned={}
    for relative in expected:
        row=records[relative];archive=Path(row['archive_path'])
        phase.require(not archive.is_absolute() and '..' not in archive.parts
            and archive.parts[:7]==('research','next-session','private-change','wallet',
                                    'source-01','source','poc'), 'owner-core-archive-path')
        path=phase.ROOT/archive
        phase.require(not any(part.is_symlink() for part in (path,*path.parents)),
                      'owner-core-symlink')
        data=path.read_bytes()
        phase.require(len(data)==row['bytes'] and phase.digest(data)==row['sha256'],
                      'owner-core-source-changed')
        owned[relative]=data
    modules={}
    for name in NAMES:
        relative='poc/private-change-wallet/'+name+'.py'
        phase.require(name not in sys.modules,'fresh-local-owner-core-module-namespace')
        module=ModuleType(name)
        # This logical canonical path preserves ROOT-relative authenticated V2
        # resources. The executed bytes are owned archive bytes, never a reopen
        # of the mutable canonical source or of later cold software selections.
        module.__file__=str(directory/(name+'.py'))
        sys.modules[name]=module
        try:exec(compile(owned[relative],module.__file__,'exec'),module.__dict__)
        except BaseException:
            sys.modules.pop(name,None)
            raise
        modules[name]=module
    return SimpleNamespace(**modules)

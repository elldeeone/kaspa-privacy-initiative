"""Host-only public guard; private workers never import this module's policy."""
import os
from pathlib import Path
import runpy
import stat

ROOT=Path(__file__).absolute().parents[3]
PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private')

def need(value,code):
    if not value:raise ValueError(code)

def checked(value):
    value=Path(value).absolute()
    need('..' not in value.parts and not any(p.is_symlink() for p in (value,*value.parents)),'unsafe-path')
    return value

def stable_read(path, before=None, forbidden=()):
    return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(checked(path)))

class HostPolicy:
    def __init__(self,old_trials=(),new_directories=(PRIVATE,)):
        self.helper=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
        self.new_directories=tuple(checked(p) for p in new_directories)
        need(PRIVATE in self.new_directories,'whole-private-parent-excluded')
        self.directories=tuple(Path(p) for p in self.helper['m'].GUARD.directories)
        self.identities=frozenset(self.helper['m'].GUARD.inodes)
    def guard(self,paths):
        self.helper['refresh']()
        return tuple(self.helper['m'].GUARD.metadata(checked(p)) for p in paths)
    def read(self,path,expected=None):
        return self.helper['read'](str(checked(path)),expected)

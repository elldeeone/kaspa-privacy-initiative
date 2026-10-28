#!/usr/bin/env python3
"""Execute the selected release controller from admitted immutable source bytes.

The entry/helper are externally selected. Standard-only guard bootstrap runs
before any project import. Project imports and source reads then use the exact
selected copies with their original canonical filenames; no live-code fallback.
This entry has no Original/key/proving or financial-authority API.
"""
import argparse
import hashlib
import importlib.machinery
import os
from pathlib import Path
import runpy
import sys

CANONICAL = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment/private_batch_trial')
sys.path.insert(0, str(CANONICAL))
from payout_linkage_guard import load_guard


def main():
    guarded = load_guard()
    read = guarded['read']
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--program', choices=('generator', 'release'), default='release')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    import json
    selected = json.loads(read(Path(args.selection), args.selection_sha256))
    shared = Path(selected['public']) / 'selected-public'
    frozen = {str(Path(row['path']).absolute()): read(shared / ('source-' + str(row['index'])), row['sha256'])
              for row in selected['source_members']}
    original_get_code = importlib.machinery.SourceFileLoader.get_code
    original_exec_module = importlib.machinery.SourceFileLoader.exec_module
    def get_code(loader, fullname):
        path = str(Path(loader.path).absolute())
        if path in frozen:
            return compile(frozen[path], path, 'exec')
        if path.startswith(str(CANONICAL.parent) + '/'):
            raise ImportError('unselected project source')
        return original_get_code(loader, fullname)
    importlib.machinery.SourceFileLoader.get_code = get_code
    original_run_path = runpy.run_path
    def selected_read(path, expected=None):
        canonical = str(Path(path).absolute())
        if canonical in frozen:
            raw = frozen[canonical]
            if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('selected source digest')
            return raw
        return read(path, expected)
    # All selected host modules, including late native/measurement imports,
    # receive the same admitted memory authority for source paths. Non-source
    # reads still pass through the unchanged fresh-per-read qualified guard.
    import payout_linkage_guard
    selected_guard = lambda: {**guarded, 'read': selected_read}
    payout_linkage_guard.load_guard = selected_guard
    def exec_module(loader, module):
        original_exec_module(loader, module)
        if str(Path(loader.path).absolute()) == str(CANONICAL / 'payout_linkage_guard.py'):
            # The measurement entry may admit the same selected helper under
            # its own module name. Keep its source reads on this memory map.
            module.load_guard = selected_guard
    importlib.machinery.SourceFileLoader.exec_module = exec_module
    def run_path(path, *a, **kw):
        if str(path) == '/var/tmp/kpi-root-guard-helper-09.py':
            return {**guarded, 'read': selected_read}
        return original_run_path(path, *a, **kw)
    runpy.run_path = run_path
    entry = str(CANONICAL / ('payout_linkage_original.py' if args.program == 'generator' else 'exit_release.py'))
    if entry not in frozen:
        raise ValueError('missing selected release entry')
    sys.argv = [entry, *args.arguments]
    exec(compile(frozen[entry], entry, 'exec'), {'__name__': '__main__', '__file__': entry})


if __name__ == '__main__':
    main()

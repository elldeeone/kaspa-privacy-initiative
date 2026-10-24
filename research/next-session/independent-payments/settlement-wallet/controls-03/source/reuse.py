"""Exact, isolated existing public helpers; no seed/PK/process API on load."""
import builtins
import hashlib
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = {
    'primitives': '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
    'receiver': '9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b',
    'actions': 'a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484',
    'native_runtime': 'dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af'}
PUBLIC = {
    'wire': '64598cb094f8821c66777278169a33a8a0b15c05f220f0d990a8d0c793360044',
    'policy': '982ec706f6a3d5d85b223e1c642ee0466e1d35e5047e339da039414930e40b68',
    'virtual': '6e0fd44e27ddabd45c32cbb9a019948b831d70331c1bd5cd5213faf50182c222'}
_cache = {}


def source_paths():
    return [ROOT / directory / (name + '.py') for directory, pins in (
        ('poc/compact-batch-lifecycle', PRIVATE), ('poc/shared-settlement', PUBLIC)) for name in pins]


def _load(directory, pins, group):
    if group in _cache:
        return _cache[group]
    owned, modules = {}, {}
    for name, expected in pins.items():
        path = ROOT / directory / (name + '.py')
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('selected-source-symlink')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('selected-source-identity')
        owned[name] = raw
        full = '_kpx5_owner_' + group + '_' + name
        if full in sys.modules:
            raise ValueError('fresh-selected-source-namespace')
        module = types.ModuleType(full)
        module.__file__ = str(path)
        modules[name] = module
        sys.modules[full] = module

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    try:
        for name, module in modules.items():
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imported)
            exec(compile(owned[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    _cache[group] = types.SimpleNamespace(**modules)
    return _cache[group]


def core():
    return _load('poc/compact-batch-lifecycle', PRIVATE, 'core')


def public():
    # Use only pure public helpers. wire.transaction_id's sealed-FD lazy
    # adapter is deliberately NOT called in the owner namespace.
    return _load('poc/shared-settlement', PUBLIC, 'public')

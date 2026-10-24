"""Load exact existing public helpers under isolated module aliases.

No backup, PK, native process or network API is invoked by loading these bytes.
The owner/controller must authenticate its installed configuration and perform
the existing metadata alias guard before any caller-selected public input read.
"""
import builtins
import hashlib
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'poc/compact-batch-lifecycle'
PINS = {
    'primitives': '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
    'receiver': '9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b',
    'actions': 'a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484',
    'native_runtime': 'dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af',
    'history': 'b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202',
    'owner': '8d6a0bfedc9072039ad6a8d126af78ef2222274d8aa14b493c15968c6c2b1a49',
}
_cached = None


def load():
    global _cached
    if _cached is not None:
        return _cached
    owned = {}
    for name, expected in PINS.items():
        path = BASE / (name + '.py')
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('selected-helper-symlink')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('selected-helper-source-identity')
        owned[name] = raw
    modules = {}
    prefix = '_kpi_independent_single_payment_compat'
    for name in PINS:
        full = prefix + '_' + name
        if full in sys.modules:
            raise ValueError('fresh-helper-alias-required')
        module = types.ModuleType(full)
        module.__file__ = str(BASE / (name + '.py'))
        modules[name] = module
        sys.modules[full] = module

    def selected_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    try:
        for name, module in modules.items():
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=selected_import)
            exec(compile(owned[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    _cached = types.SimpleNamespace(**modules)
    return _cached


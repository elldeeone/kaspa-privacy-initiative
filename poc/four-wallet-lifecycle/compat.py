"""Hash-authenticated, isolated reuse of established public helper sources.

Loading these bytes opens no backup/PK and starts no prover/native/network job.
Old financial emitter/genesis/descriptor functions are not new-profile APIs.
The selected new Runtime supplies actual W and accepted-context operations.
"""
import builtins
import hashlib
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    'core': ('poc/compact-batch-lifecycle', {
        'primitives': '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
        'receiver': '9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b',
        'actions': 'a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484',
        'native_runtime': 'dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af',
        'history': 'b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202',
    }),
    'public': ('poc/shared-settlement', {
        'wire': '64598cb094f8821c66777278169a33a8a0b15c05f220f0d990a8d0c793360044',
        'policy': '982ec706f6a3d5d85b223e1c642ee0466e1d35e5047e339da039414930e40b68',
        'virtual': '6e0fd44e27ddabd45c32cbb9a019948b831d70331c1bd5cd5213faf50182c222',
    }),
    'payment': ('poc/independent-single-payment', {
        'payment': 'a13bdf48deb034acb2d6c8a7985243041857cb6b741548614ec247f791596480',
    }),
}
_cache = {}


def source_paths():
    return [ROOT / directory / (name + '.py')
            for directory, pins in SOURCES.values() for name in pins]


def _load(group):
    if group in _cache:
        return _cache[group]
    directory, pins = SOURCES[group]
    raw_sources, modules = {}, {}
    for name, expected in pins.items():
        path = ROOT / directory / (name + '.py')
        if '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('selected-helper-path')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('selected-helper-identity')
        raw_sources[name] = raw
        full = '_kpx6_four_wallet_' + group + '_' + name
        if full in sys.modules:
            raise ValueError('fresh-helper-module-namespace')
        module = types.ModuleType(full)
        module.__file__ = str(path)
        modules[name] = module
        sys.modules[full] = module
    # The original pure payment source imports only load() from reuse.
    # Its selected helpers stay byte-identical; no old synthetic owner runs.
    payment_reuse = types.SimpleNamespace(load=core)

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        if level == 0 and name == 'reuse' and group == 'payment':
            return payment_reuse
        return builtins.__import__(name, globals, locals, fromlist, level)

    try:
        for name, module in modules.items():
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imported)
            exec(compile(raw_sources[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    result = types.SimpleNamespace(**modules)
    _cache[group] = result
    return result


def core():
    return _load('core')


def public():
    return _load('public')


def payment():
    return _load('payment').payment

"""Fixed source identities for shared new-profile contracts; no caller code."""
import builtins
import hashlib
from pathlib import Path
import sys
import types

from paths import checked, need

ROOT = Path(__file__).resolve().parents[2]
FINANCIAL_SOURCE = ROOT / 'poc/four-wallet-profile/selection.py'
FINANCIAL_SOURCE_SHA256 = '425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553'
CHAIN_SOURCE = ROOT / 'poc/four-wallet-chain/chain_replay.py'
# Fail closed until the independent chain author freezes/reviews this source.
CHAIN_SOURCE_SHA256 = '2f8985eb7138ddd24a745f601b4f9c062f07e132728d1c4088c65d97a45edb56'
BACKUP_SOURCES = {
    'gn2_common': '2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b',
    'gn2_backup': '8fdf5e01d9b81c99802406276704ddaacd4927d4f48b8432240ec18e6a17efc0',
}
GENESIS_SOURCES = {
    'gn2_common': '2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b',
    'gn2': 'cdfcebe9edf2a44306284a38892e44d347a0d68ad901bed03b394e9ce9e51f8c',
}
_cache = {}


def selected_module(path, expected, name):
    """Execute only authenticated owned bytes from a fixed installed path."""
    if name in _cache:
        return _cache[name]
    path = checked(path)
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, 'selected-shared-contract-source')
    need(name not in sys.modules, 'fresh-shared-contract-namespace')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    _cache[name] = module
    return module


def financial(raw, external_sha256):
    return selected_module(FINANCIAL_SOURCE, FINANCIAL_SOURCE_SHA256,
                           '_kpx6_lifecycle_financial_contract').load(raw, external_sha256)


def chain():
    need(type(CHAIN_SOURCE_SHA256) is str and len(CHAIN_SOURCE_SHA256) == 64,
         'accepted-chain-contract-not-selected')
    return selected_module(CHAIN_SOURCE, CHAIN_SOURCE_SHA256,
                           '_kpx6_lifecycle_accepted_chain_contract')


def backup_source_paths():
    return [ROOT / 'poc/four-wallet-bootstrap' / (name + '.py') for name in BACKUP_SOURCES]


def genesis_source_paths():
    return [ROOT / 'poc/four-wallet-bootstrap' / (name + '.py') for name in GENESIS_SOURCES]


def genesis():
    key = '_kpx6_lifecycle_GN2'
    if key in _cache:
        return _cache[key]
    modules, sources = {}, {}
    for name, expected in GENESIS_SOURCES.items():
        path = checked(ROOT / 'poc/four-wallet-bootstrap' / (name + '.py'))
        source = path.read_bytes()
        need(hashlib.sha256(source).hexdigest() == expected, 'selected-GN2-source')
        full = key + '_' + name
        need(full not in sys.modules, 'fresh-GN2-contract-namespace')
        module = types.ModuleType(full); module.__file__ = str(path)
        sys.modules[full] = module
        modules[name], sources[name] = module, source

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    try:
        for name, module in modules.items():
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imported)
            exec(compile(sources[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    _cache[key] = modules['gn2']
    return _cache[key]


def own_backup(raw, expected_domain, expected_trial_id):
    key = '_kpx6_lifecycle_compound_backup'
    if key not in _cache:
        modules, sources = {}, {}
        for name, expected in BACKUP_SOURCES.items():
            path = checked(ROOT / 'poc/four-wallet-bootstrap' / (name + '.py'))
            source = path.read_bytes()
            need(hashlib.sha256(source).hexdigest() == expected, 'selected-compound-backup-source')
            full = key + '_' + name
            need(full not in sys.modules, 'fresh-compound-backup-namespace')
            module = types.ModuleType(full)
            module.__file__ = str(path)
            sys.modules[full] = module
            modules[name], sources[name] = module, source

        def imported(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name in modules:
                return modules[name]
            return builtins.__import__(name, globals, locals, fromlist, level)

        try:
            for name, module in modules.items():
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imported)
                exec(compile(sources[name], module.__file__, 'exec'), module.__dict__)
        except BaseException:
            for module in modules.values():
                sys.modules.pop(module.__name__, None)
            raise
        _cache[key] = modules['gn2_backup']
    return _cache[key].decode_backup(raw, expected_domain, expected_trial_id)

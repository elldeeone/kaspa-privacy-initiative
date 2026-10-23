"""Explicit immutable imports from the existing public KPX2 implementation."""
import hashlib
import importlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / "poc/independent-recovery"
PINS = {
    "replay.py": "f8be03c47008dd3b06ef601bd6da67ba42be47dec3f7c43a0d28dfe68e9b773d",
    "policy_template.py": "867c340348d25ecdec7c31e406d93b0f07d7b57005380216f575332f8bd2bd05",
    "native_validation.py": "a30a775a40cf53fd062f3d2325dbd5df079e78e8c42931a42fd26e34d6946876",
    "kpx2-policy-template.json": "5f8e5354565c0545cfd6e6455958cbf955daa14d7982ac5c338673cc5a5a19bf",
    "kpx2-policy-template.bin": "8b0e6dd802b58400fdfd9fcc11cff2ef6e4a27659c973ff3d0b1bf946fcfda46",
}
for name, expected in PINS.items():
    if hashlib.sha256((OLD / name).read_bytes()).hexdigest() != expected:
        raise ValueError("immutable-public-replay-dependency-identity")
sys.path.insert(0, str(OLD))
try:
    old = importlib.import_module("replay")
    native = importlib.import_module("native_validation")
    for module, name in ((old, "replay.py"), (native, "native_validation.py")):
        if Path(module.__file__).resolve() != OLD / name:
            raise ValueError("immutable-public-module-location")
finally:
    sys.path.pop(0)

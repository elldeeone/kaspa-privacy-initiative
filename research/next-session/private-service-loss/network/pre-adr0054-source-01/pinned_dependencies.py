"""Exact public source imports. No old module or module global is modified."""
import hashlib
import importlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "poc/private-exit-recovery"
PINS = {
    "public_adapter.py": "be415bef7eb98360a27b92f94343e3392766f950b43804aad2a89528058b35c0",
    "dependencies.py": "1708768c3123a2f766e80e970a8f31ce79dd787a60b0deff93eea120ffcb1197",
    "approved_template.py": "32e043eab5aef9b32495735a9d0c15f5b51ec47845204484c9a15c9d88c210a9",
    "selected_identities.py": "6e03517749e56efb73fef2c43ff8daebbcd471628bbc8ed8bdd52492a3845c18",
    "kpx3-policy-template.json": "6f9b71043db6cbea271585b9c2853125b601b71ad2eccad9d65ddc35db7e49c7",
    "kpx3-policy-template.bin": "731eb10da7a96a3f1f67b3c3fb0da6d45294820c8c610dc9d7d0d0fd1dd10556",
}
for name, expected in PINS.items():
    if hashlib.sha256((PACKAGE / name).read_bytes()).hexdigest() != expected:
        raise ValueError("frozen-private-public-source-identity")
    if name.endswith(".py") and name[:-3] in sys.modules:
        if Path(sys.modules[name[:-3]].__file__).resolve() != PACKAGE / name:
            raise ValueError("frozen-private-public-import-collision")
sys.path.insert(0, str(PACKAGE))
try:
    adapter = importlib.import_module("public_adapter")
    dependencies = importlib.import_module("dependencies")
    for name in ("public_adapter", "dependencies", "approved_template", "selected_identities"):
        if Path(sys.modules[name].__file__).resolve() != PACKAGE / (name + ".py"):
            raise ValueError("frozen-private-public-import-location")
finally:
    sys.path.pop(0)
old, native = dependencies.old, dependencies.native

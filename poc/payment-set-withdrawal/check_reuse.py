"""Verify the original full wallet relation survives outside public packing."""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def tokens(text):
    return re.sub(r"\s+", "", text)


def check():
    manifest = json.loads((HERE / "REUSE.json").read_text())
    for path, expected in manifest["sources"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
    old = (ROOT / "poc/private-note-wallet/src/circuit.rs").read_text()
    new = (HERE / "src/circuit.rs").read_text()
    # Struct plumbing imports the original Witness unchanged. Everything after
    # the public-input allocation is the exact original constraint code.
    split = "        public[0].enforce_equal"
    assert tokens(old.split(split, 1)[1]) == tokens(new.split(split, 1)[1])
    start = "fn digest("
    end = "impl WalletCircuit"
    assert tokens(old[old.index(start):old.index(end)]) == tokens(new[new.index(start):new.index(end)])
    original_struct = old[old.index("pub struct WalletCircuit"):old.index(start)]
    packed_struct = new[new.index("pub struct WalletCircuit"):new.index(start)]
    assert tokens(original_struct) == tokens(packed_struct)
    allocation = new[new.index("let bytes = self.statement.bytes();"):new.index(split)]
    assert "Sha256Gadget::digest(&public)?.0" in allocation
    assert "expected.chunks(16).zip(statement_digest.chunks(16))" in allocation
    assert "Boolean::le_bits_to_fp(&bits)?.enforce_equal(&p)?;" in allocation
    assert "UInt8::new_witness_vec(cs.clone(), &bytes)?" in allocation
    assert allocation.count("FpVar::new_input") == 1
    print("Original wallet source identities and complete relation outside input packing: unchanged.")


if __name__ == "__main__":
    check()

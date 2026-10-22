#!/usr/bin/env python3
"""One fixed public ADMIT ID/preimage check; no ledger/replayer/owner API."""
import ctypes
import hashlib
import json
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE/"blake3-id-check"
PUBLIC = Path("/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-native-20261022T1431/public")
ARCHIVE = Path("/home/luke/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/blake3-1.8.7.crate")
ARCHIVE_SHA = "6d9e454fc11f76977dc803893aff6304ed33d6a26efae8696573bea74baa27ae"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    OUT.mkdir(exist_ok=False)
    archive = ARCHIVE.read_bytes()
    assert sha(archive) == ARCHIVE_SHA
    vendor = OUT/"vendor"
    vendor.mkdir()
    sources = {}
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        for name in ("blake3.c", "blake3_dispatch.c", "blake3_portable.c", "blake3.h", "blake3_impl.h"):
            member = tar.getmember("blake3-1.8.7/c/"+name)
            assert member.isfile()
            raw = tar.extractfile(member).read()
            (vendor/name).write_bytes(raw)
            sources[name] = {"bytes": len(raw), "sha256": sha(raw)}
    cc = Path(shutil.which("cc")).resolve()
    wrapper = HERE/"blake3_public_wrapper.c"
    library = OUT/"libpublic_blake3.so"
    flags = ["-shared", "-fPIC", "-O2", "-DBLAKE3_NO_AVX512", "-DBLAKE3_NO_AVX2",
             "-DBLAKE3_NO_SSE41", "-DBLAKE3_NO_SSE2", "-DBLAKE3_USE_NEON=0"]
    command = [str(cc), *flags, "-I", str(vendor), str(wrapper),
               *[str(vendor/name) for name in ("blake3.c", "blake3_dispatch.c", "blake3_portable.c")],
               "-o", str(library)]
    run = subprocess.run(command, capture_output=True, timeout=30)
    (OUT/"compiler.stdout").write_bytes(run.stdout)
    (OUT/"compiler.stderr").write_bytes(run.stderr)
    assert run.returncode == 0, run.stderr.decode()
    lib = ctypes.CDLL(str(library))
    lib.kpi_public_keyed_hash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.kpi_public_keyed_hash.restype = None

    def keyed(label, data):
        key = label.encode().ljust(32, b"\0")
        assert len(key) == 32
        key_buffer = ctypes.create_string_buffer(key, 32)
        input_buffer = ctypes.create_string_buffer(data, max(1, len(data)))
        output = ctypes.create_string_buffer(32)
        lib.kpi_public_keyed_hash(key_buffer, input_buffer, len(data), output)
        return output.raw

    # Official pinned Kaspa ZERO_PAYLOAD_DIGEST; its upstream test checks hash([]).
    expected_empty = "9c0ca2acb45e92ffe6ceb4ae29188b35c82d9676cdd3ce067fd6ccd30a9c4a38"
    assert keyed("PayloadDigest", b"").hex() == expected_empty
    opened = {}

    def read(name):
        assert name in {"admit.json", "admit-v1-rest-preimage.bin", "admit-txid-raw.bin",
                        "oracle-pair-context.json", "admit-outpoint-provenance.json"}
        path = PUBLIC/name
        assert not path.is_symlink()
        raw = path.read_bytes()
        opened[name] = {"bytes": len(raw), "sha256": sha(raw)}
        return raw

    body_raw = read("admit.json")
    body = json.loads(body_raw)
    assert set(body) == {"version", "inputs", "outputs", "lockTime", "subnetworkId", "gas", "payload", "storageMass", "id"}
    assert body["version"] == 1 and body["lockTime"] == body["gas"] == body["storageMass"] == "0"
    assert body["subnetworkId"] == "00"*20 and len(body["inputs"]) == 2 and len(body["outputs"]) == 1
    u16, u32, u64 = lambda n: struct.pack("<H", n), lambda n: struct.pack("<I", n), lambda n: struct.pack("<Q", n)
    # Fixed source-defined V1 rest preimage: empty signatures/payload, no mass.
    rest = u16(1)+u64(2)
    for item in body["inputs"]:
        point = item["previousOutpoint"]
        raw_id = bytes.fromhex(point["transactionId"])
        assert len(raw_id) == 32 and point["index"] == 0 and item["sequence"] == "18446744073709551615"
        rest += raw_id+u32(0)+u64(0)+u64(int(item["sequence"]))
    output = body["outputs"][0]
    spk = bytes.fromhex(output["scriptPublicKey"])
    assert output["covenant"] is None and output["value"] == "1660000000" and spk[:2] == bytes(2) and len(spk) == 37
    rest += u64(1)+u64(1_660_000_000)+u16(0)+u64(35)+spk[2:]+b"\0"
    rest += u64(0)+bytes(20)+u64(0)+u64(0)
    supplied_rest = read("admit-v1-rest-preimage.bin")
    assert len(rest) == 220 and rest == supplied_rest
    payload = bytes.fromhex(body["payload"])
    assert len(payload) == 5231
    payload_digest = keyed("PayloadDigest", payload)
    rest_digest = keyed("TransactionRest", rest)
    txid = keyed("TransactionV1Id", payload_digest+rest_digest)
    assert txid == read("admit-txid-raw.bin") and txid.hex() == body["id"]
    assert txid != txid[::-1]
    context = json.loads(read("oracle-pair-context.json"))
    assert context == {"prior_outpoint_hex": (txid+u32(0)).hex(), "reserve_sompi": "1660000000"}
    provenance = json.loads(read("admit-outpoint-provenance.json"))
    assert provenance["native_body_sha256"] == sha(body_raw)
    assert provenance["payload_sha256"] == sha(payload) and provenance["v1_rest_preimage_sha256"] == sha(rest)
    assert provenance["id_as_bytes_hex"] == provenance["display_transaction_id"] == txid.hex()
    assert provenance["raw_outpoint_hex"] == context["prior_outpoint_hex"] and provenance["index"] == 0
    report = {"scope": "Independent fixed public ADMIT JSON field/preimage/ID arithmetic, not a ledger parser or native validation",
              "official_zero_payload_vector_passed": True, "rest_preimage_matches_source_field_encoding": True,
              "recomputed_transaction_id": txid.hex(), "id_is_nonpalindromic": True,
              "raw_outpoint": context["prior_outpoint_hex"], "payload_digest": payload_digest.hex(), "rest_digest": rest_digest.hex(),
              "opened_public_files": opened, "crate_version": "1.8.7", "crate_archive_sha256": ARCHIVE_SHA,
              "official_c_sources": sources, "compiler": str(cc), "compiler_sha256": sha(cc.read_bytes()),
              "compiler_version": subprocess.check_output([str(cc), "--version"]).decode(), "compiler_command": command,
              "wrapper_sha256": sha(wrapper.read_bytes()), "library_sha256": sha(library.read_bytes()),
              "source_sha256": sha(Path(__file__).read_bytes()), "native_full_validation_by_this_checker": False,
              "accepted_ancestry_or_backing": False, "owner_workflow_parked": True, "full_lifecycle_claim": False}
    raw = (json.dumps(report, indent=2, sort_keys=True)+"\n").encode()
    (OUT/"report.json").write_bytes(raw)
    print(json.dumps({"report_sha256": sha(raw), "transaction_id": txid.hex(), "raw_outpoint": context["prior_outpoint_hex"]}))


if __name__ == "__main__":
    main()

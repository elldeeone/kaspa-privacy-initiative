"""Independent transport integration controls; synthetic public objects only.

The tiny opaque parameter object is NOT a proving key. Native semantics,
consensus/currentness, PK decoding and private recovery are not exercised here.
Run only in the reviewed network-off public-source sandbox after API freeze.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(os.environ.get("CAPSULE_SOURCE", "/work/capsule.py"))
spec = importlib.util.spec_from_file_location("_independent_public_capsule", SOURCE)
capsule = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = capsule
spec.loader.exec_module(capsule)

GENESIS = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"
DOMAIN = hashlib.sha256(b"DO_NOT_FUND/public-capsule-fault-fixture").hexdigest()
PROGRAM = "AUTH528_COMPACT_BATCH/v1"
MAGIC = b"KPX4AU01".hex()
COMPACT_VK = b"C" * 328
WIDE_VK = b"W" * 328
OPAQUE_PUBLIC_PARAMETERS = b"OPAQUE_PUBLIC_TRANSPORT_FIXTURE_NOT_AN_ARK_PROVING_KEY"
SMALL = {"descriptor", "parameters_manifest", "history", "software_inventory"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class OpenWatch:
    """Kernel IN_OPEN observation, including opens through a hardlink alias."""
    def __init__(self, path):
        self.library = ctypes.CDLL(None, use_errno=True)
        self.library.inotify_init1.argtypes = [ctypes.c_int]
        self.library.inotify_init1.restype = ctypes.c_int
        self.library.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.library.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.library.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify-init-unavailable")
        if self.library.inotify_add_watch(self.fd, os.fsencode(path), 0x20) < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), "inotify-watch-unavailable")

    def count(self):
        count = 0
        while True:
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            at = 0
            while at < len(raw):
                _, mask, _, length = struct.unpack_from("iIII", raw, at)
                count += bool(mask & 0x20)
                at += 16 + length
        return count

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Fixture:
    """Builds independent canonical fixtures; imports no implementation helpers."""
    def __init__(self, root, *, parameters_change=None, descriptor_change=None,
                 history_change=None, software_change=None):
        self.root = root
        self.root.mkdir()
        self.mirrors = [root / "preferred", root / "replacement"]
        identity = {"network_id": "testnet-10", "genesis_hash_hex": GENESIS,
                    "domain_hex32": DOMAIN}
        parameters = {"schema": "kpx4-public-proving-parameters/v1", "role": "compact2",
            "output_arity": 2, "auth_magic_hex8": MAGIC, "program_label": PROGRAM,
            "trial_id": "DO_NOT_FUND_PUBLIC_TRANSPORT_FIXTURE", **identity,
            "format": "arkworks0.6-bn254-uncompressed", "pk_bytes": len(OPAQUE_PUBLIC_PARAMETERS),
            "pk_sha256": sha(OPAQUE_PUBLIC_PARAMETERS), "vk_hex328": COMPACT_VK.hex(),
            "vk_sha256": sha(COMPACT_VK),
            "core_source_identity": {name: "a" * 64 for name in (
                "lib_rs_sha256", "circuit_rs_sha256", "exact_sha256_rs_sha256", "request_rs_sha256",
                "parameters_rs_sha256", "main_rs_sha256", "setup_rs_sha256", "build_rs_sha256")},
            "compiled_build_identity_sha256": "b" * 64,
            "constraint_shape": {"constraints": 7, "witness_variables": 8,
                "instances_including_one": 3, "matrix_sha256": "c" * 64, "fft_domain_size": 16},
            "queries": {"a": 11, "b_g1": 11, "b_g2": 11, "l": 8, "h": 15,
                "instances_including_one": 3},
            "setup_provenance": {name: "d" * 64 for name in (
                "executable_sha256", "source_freeze_sha256", "public_setup_report_sha256")}}
        if parameters_change:
            parameters_change(parameters)
        parameters_raw = encode(parameters)
        state = b"KPX2ST01" + bytes.fromhex(DOMAIN) + bytes(72)
        tail = b"SYNTHETIC_PUBLIC_POLICY_NOT_EXECUTABLE"
        descriptor = {"schema": "kpx4-compact-batch-descriptor/v1", **identity,
            "founding_outpoint": {"transactionId": "1" * 64, "index": 0},
            "birth_start_hash": "2" * 64, "initial_redeem_hex": (b"\x4c\x70" + state + tail).hex(),
            "compact_vk_hex328": COMPACT_VK.hex(), "wide_vk_hex328": WIDE_VK.hex(),
            "immutable_policy_sha256": sha(tail),
            "compact_public_params_manifest_sha256": sha(parameters_raw),
            "wide_public_params_manifest_sha256": "3" * 64}
        if descriptor_change:
            descriptor_change(descriptor)
        descriptor_raw = encode(descriptor)
        # Structurally shaped records are deliberately unverified. They are
        # never a source of proof/native/accepted-history evidence.
        transaction = {"version": 1, "id": "1" * 64,
            "inputs": [{"previousOutpoint": {"transactionId": "4" * 64, "index": 0},
                "signatureScript": "", "sequence": 0, "computeBudget": 10}],
            "outputs": [{"value": 1, "scriptPublicKey": "000020" + "5" * 64 + "ac",
                         "covenant": None}],
            "lockTime": 0, "subnetworkId": "0" * 40, "gas": 0, "payload": "", "mass": 0}
        history = {"schema": "kpx4-compact-batch-history/v1",
            "classification": "PUBLIC_STRUCTURE_ONLY_DO_NOT_FUND",
            "descriptor_sha256": sha(descriptor_raw),
            "records": [{"transaction": transaction, "entries": [{"amount": 2,
                "scriptPublicKey": "000020" + "6" * 64 + "ac", "blockDaaScore": 0,
                "isCoinbase": False, "covenantId": None}]}]}
        if history_change:
            history_change(history)
        software = {"schema": "kpx4-recovery-software-inventory/v1", "program_label": PROGRAM,
            "source_base_commit": "7" * 40, "source_freeze_sha256": "8" * 64,
            "components": [{"component": "trusted_verifier", "sha256": "9" * 64}]}
        if software_change:
            software_change(software)
        self.raw = {"descriptor": descriptor_raw, "parameters_manifest": parameters_raw,
            "history": encode(history), "software_inventory": encode(software),
            "public_parameters": OPAQUE_PUBLIC_PARAMETERS}
        self.refs = {kind: {"kind": kind, "sha256": sha(raw), "bytes": len(raw)}
                     for kind, raw in self.raw.items()}
        self.index = {"schema": "kpx4-public-recovery-capsule/v1", **identity,
            "program_label": PROGRAM, "role": "compact2",
            "objects": [self.refs[kind] for kind in sorted(self.refs)]}
        self.manifest = root / "capsule.json"
        self.manifest.write_bytes(encode(self.index))
        self.expected = sha(self.manifest.read_bytes())
        self.selection_data = {"schema": "kpx4-recovery-capsule-selection/v1", **identity,
            "program_label": PROGRAM, "role": "compact2", "auth_magic_hex8": MAGIC,
            "descriptor_sha256": sha(descriptor_raw), "parameters_manifest_sha256": sha(parameters_raw),
            "public_parameters_sha256": sha(OPAQUE_PUBLIC_PARAMETERS),
            "public_parameters_bytes": len(OPAQUE_PUBLIC_PARAMETERS), "vk_sha256": sha(COMPACT_VK),
            "software_inventory_sha256": sha(self.raw["software_inventory"])}
        self.selection = capsule.TrustedSelection.from_dict(self.selection_data)
        for mirror in self.mirrors:
            objects = mirror / "objects/sha256"
            objects.mkdir(parents=True)
            for kind, raw in self.raw.items():
                self.object(mirror, kind).write_bytes(raw)
        self.calls = 0

    def object(self, mirror, kind):
        return mirror / "objects/sha256" / self.refs[kind]["sha256"]

    def output(self):
        self.calls += 1
        return self.root / f"client-{self.calls:02}"

    def stage(self, *, mode="recognition", forbidden=(), expected=None, mirrors=None):
        return capsule.stage_capsule(self.manifest, expected or self.expected,
            self.selection, self.mirrors if mirrors is None else mirrors,
            self.output(), forbidden, mode=mode)

    def rewrite_index(self):
        self.manifest.write_bytes(encode(self.index))
        self.expected = sha(self.manifest.read_bytes())


class IndependentCapsuleFaults(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="public-capsule-fault-")
        self.root = Path(self.temporary.name)
        self.sequence = 0

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, **changes):
        self.sequence += 1
        return Fixture(self.root / f"fixture-{self.sequence:02}", **changes)

    def no_current_authority(self, staged):
        receipt = staged.public_receipt()
        for name in ("current_state_verified", "spend_authorized", "native_semantics_verified",
                     "selected_node_acceptance_verified", "executable_selected_or_run"):
            self.assertIs(receipt[name], False)
        self.assertNotIn("balance", receipt)
        self.assertNotIn("reserve_sompi", receipt)
        self.assertNotIn("terminal", receipt)
        return receipt

    def sentinel(self, raw=b"PUBLIC_NON_SEED_SENTINEL_ONLY"):
        path = self.root / f"non-seed-sentinel-{self.sequence}"
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_recognition_survives_operator_preferred_source_and_PK_absence(self):
        fixture = self.fixture()
        shutil.rmtree(fixture.mirrors[0])  # Owned synthetic mirror only.
        fixture.object(fixture.mirrors[1], "public_parameters").unlink()
        staged = fixture.stage()
        receipt = self.no_current_authority(staged)
        self.assertEqual(receipt["status"], "PUBLIC_RECOGNITION_MATERIAL_VERIFIED_AT_COPY")
        self.assertEqual(set(staged.owned_json), SMALL)
        self.assertEqual(set(staged.staged_paths), SMALL)
        self.assertFalse(receipt["public_PK_staged"])
        with self.assertRaises(capsule.Incomplete):
            fixture.stage(mode="spend_material")

    def test_readonly_owned_copy_survives_later_mirror_loss(self):
        fixture = self.fixture()
        staged = fixture.stage(mode="spend_material")
        self.no_current_authority(staged)
        shutil.rmtree(fixture.mirrors[0])
        shutil.rmtree(fixture.mirrors[1])
        self.assertEqual(set(staged.staged_paths), set(fixture.raw))
        for kind, path in staged.staged_paths.items():
            self.assertEqual(path.read_bytes(), fixture.raw[kind])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        for kind in SMALL:
            self.assertEqual(staged.owned_json[kind], fixture.raw[kind])
        copied_receipt = staged.public_receipt()
        copied_receipt["current_state_verified"] = True
        self.assertIs(staged.public_receipt()["current_state_verified"], False)

    def test_bad_preferred_mirror_falls_back_to_exact_selected_history(self):
        fixture = self.fixture()
        raw = fixture.raw["history"]
        corrupt = bytes([raw[0] ^ 1]) + raw[1:]
        fixture.object(fixture.mirrors[0], "history").write_bytes(corrupt)
        staged = fixture.stage()
        receipt = self.no_current_authority(staged)
        self.assertEqual(staged.owned_json["history"], raw)
        history = next(x for x in receipt["objects"] if x["kind"] == "history")
        self.assertEqual(history["mirror_ordinal"], 1)
        self.assertTrue(any(x["kind"] == "history" and x["mirror_ordinal"] == 0
                            for x in receipt["rejected_mirror_candidates"]))
        self.assertNotIn(sha(corrupt), json.dumps(receipt))

    def test_required_history_missing_truncated_corrupt_or_appended_never_becomes_zero(self):
        for fault in ("missing", "truncated", "same_size_corruption", "appended"):
            with self.subTest(fault=fault):
                fixture = self.fixture()
                raw = fixture.raw["history"]
                for mirror in fixture.mirrors:
                    path = fixture.object(mirror, "history")
                    if fault == "missing":
                        path.unlink()
                    else:
                        bad = raw[:-1] if fault == "truncated" else (
                            bytes([raw[0] ^ 1]) + raw[1:] if fault == "same_size_corruption" else raw + b"x")
                        path.write_bytes(bad)
                with self.assertRaises(capsule.Incomplete):
                    fixture.stage()
                self.assertFalse(any(fixture.root.glob("client-*/PUBLIC-RECEIPT.json")))

    def test_outside_root_is_required_before_any_object_read(self):
        fixture = self.fixture()
        object_path = fixture.object(fixture.mirrors[0], "descriptor")
        with OpenWatch(object_path) as watch:
            with self.assertRaises(capsule.Invalid):
                fixture.stage(expected="0" * 64)
            self.assertEqual(watch.count(), 0)

    def test_rehashed_capsule_cannot_replace_static_selected_descriptor(self):
        fixture = self.fixture()
        descriptor = json.loads(fixture.raw["descriptor"])
        descriptor["domain_hex32"] = "a" * 64
        raw = encode(descriptor)
        new_ref = {"kind": "descriptor", "sha256": sha(raw), "bytes": len(raw)}
        fixture.index["objects"] = [new_ref if r["kind"] == "descriptor" else r
                                    for r in fixture.index["objects"]]
        for mirror in fixture.mirrors:
            (mirror / "objects/sha256" / sha(raw)).write_bytes(raw)
        fixture.rewrite_index()  # Even a new snapshot root cannot replace static selection.
        with self.assertRaises(capsule.Invalid):
            fixture.stage()

    def test_selected_hashes_do_not_waive_role_domain_VK_or_PK_identity(self):
        changes = {
            "wide_role": lambda p: p.update(role="wide32", output_arity=32),
            "foreign_domain": lambda p: p.update(domain_hex32="a" * 64),
            "foreign_VK_same_dimensions": lambda p: p.update(vk_hex328=WIDE_VK.hex(), vk_sha256=sha(WIDE_VK)),
            "different_PK_digest_same_dimensions": lambda p: p.update(pk_sha256="e" * 64),
        }
        for name, change in changes.items():
            with self.subTest(fault=name):
                fixture = self.fixture(parameters_change=change)
                with self.assertRaises(capsule.Invalid):
                    fixture.stage()

    def test_capsule_claims_cannot_authorize_currentness_or_code(self):
        fixture = self.fixture(history_change=lambda h: h.update(classification="SELECTED_NODE_ACCEPTED_HISTORY"))
        self.no_current_authority(fixture.stage())
        for field, value in (("current_state_verified", True), ("spend_authorized", True),
                             ("executable", "/not-an-authorized-component")):
            with self.subTest(field=field):
                fixture = self.fixture()
                fixture.index[field] = value
                fixture.rewrite_index()
                with self.assertRaises(capsule.Invalid):
                    fixture.stage()

    def test_duplicate_inventory_and_duplicate_JSON_names_rejected(self):
        fixture = self.fixture()
        fixture.index["objects"][0] = copy.deepcopy(fixture.index["objects"][1])
        fixture.rewrite_index()
        with self.assertRaises(capsule.Invalid):
            fixture.stage()
        fixture = self.fixture()
        raw = fixture.manifest.read_bytes()
        raw = b'{"role":"compact2",' + raw[1:]
        fixture.manifest.write_bytes(raw)
        fixture.expected = sha(raw)
        with self.assertRaises(capsule.Invalid):
            fixture.stage()

    def test_manifest_and_object_hardlinks_rejected_before_sentinel_open(self):
        for target in ("manifest", "history"):
            with self.subTest(target=target):
                fixture = self.fixture()
                raw = fixture.manifest.read_bytes() if target == "manifest" else fixture.raw["history"]
                sentinel = self.sentinel(raw)
                paths = [fixture.manifest] if target == "manifest" else [
                    fixture.object(mirror, "history") for mirror in fixture.mirrors]
                for path in paths:
                    path.unlink()
                    os.link(sentinel, path)
                with OpenWatch(sentinel) as watch:
                    # Calibrate this kernel watch through the hardlink first.
                    # The sentinel holds public fixture bytes, never a seed.
                    with paths[0].open("rb"):
                        pass
                    self.assertGreaterEqual(watch.count(), 1)
                    with self.assertRaises(capsule.Invalid):
                        fixture.stage(forbidden=[sentinel])
                    self.assertEqual(watch.count(), 0)

    def test_recognition_skips_PK_alias_while_spend_stage_rejects_it(self):
        fixture = self.fixture()
        sentinel = self.sentinel(OPAQUE_PUBLIC_PARAMETERS)
        for mirror in fixture.mirrors:
            path = fixture.object(mirror, "public_parameters")
            path.unlink()
            os.link(sentinel, path)
        with OpenWatch(sentinel) as watch:
            self.no_current_authority(fixture.stage(forbidden=[sentinel]))
            self.assertEqual(watch.count(), 0)
            with self.assertRaises(capsule.Incomplete):
                fixture.stage(mode="spend_material", forbidden=[sentinel])
            self.assertEqual(watch.count(), 0)

    def test_public_CLI_guards_selection_alias_before_opening_sentinel(self):
        fixture = self.fixture()
        sentinel = self.sentinel(encode(fixture.selection_data))
        selection_path = fixture.root / "installed-selection.json"
        os.link(sentinel, selection_path)
        command = [sys.executable, "-B", str(SOURCE), str(fixture.manifest), fixture.expected,
                   str(selection_path), str(fixture.output()), "--mode", "recognition",
                   "--forbidden", str(sentinel)]
        for mirror in fixture.mirrors:
            command.extend(["--mirror", str(mirror)])
        with OpenWatch(sentinel) as watch:
            result = subprocess.run(command, capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}, timeout=60)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(watch.count(), 0)
        self.assertEqual(json.loads(result.stderr), {"status": "INCOMPLETE_OR_INVALID",
            "current_state_verified": False, "spend_authorized": False})
        self.assertNotIn(str(sentinel), result.stdout + result.stderr)

    def test_symlink_source_is_rejected_and_valid_mirror_remains_available(self):
        fixture = self.fixture()
        path = fixture.object(fixture.mirrors[0], "descriptor")
        path.unlink()
        path.symlink_to(fixture.object(fixture.mirrors[1], "descriptor"))
        staged = fixture.stage()
        receipt = self.no_current_authority(staged)
        self.assertEqual(next(x for x in receipt["objects"] if x["kind"] == "descriptor")["mirror_ordinal"], 1)


if __name__ == "__main__":
    print(json.dumps({"scope": "SYNTHETIC_PUBLIC_TRANSPORT_ONLY_NO_PK_DECODE_NATIVE_PROOF_OR_PRIVATE_BACKUP",
        "production_source_sha256": sha(SOURCE.read_bytes()),
        "test_source_sha256": sha(Path(__file__).read_bytes()),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "old_operator_and_parameter_cache_absent": not Path("/home/luke/.cache/kpi-sdk").exists()
            and not Path("/home/luke/projects/kpi-intensive-2026-10-22/private-change-tn10-01").exists()}, sort_keys=True), flush=True)
    unittest.main(verbosity=2)

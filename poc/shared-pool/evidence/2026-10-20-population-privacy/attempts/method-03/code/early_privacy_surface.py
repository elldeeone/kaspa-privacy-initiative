#!/usr/bin/env python3
"""Frozen public-byte calibration runner. No wallets, proofs, funds or network.

The native replay binary validates transactions. This decoder is a second,
public-field projection, not a substitute proof/consensus verifier. Its observer
input contains only the four named public source files and their reduction.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
INPUT = HERE / "evidence/2026-10-20-wallet-lifecycle/positive"
FILES = ("descriptor.json", "vk.bin", "lineage.json", "parents.json")
SOURCES = ("early_privacy_surface.py", "early_privacy_amounts.py",
           "two_input_privacy_observer.py", "two_input_privacy_z3.py")
SPEC = "EARLY-PRIVACY-SPEC.md"
SPEC_SHA = "1b21810517d21d1221364e4c63f258710022100c8942dcc795c200266142e96e"
SCHEMA = "kpi-early-privacy-public-v1"
MAX = 2_900_000_000_000_000_000
VENV = Path("/home/luke/.local/share/kpi-shared-pool-tools")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def save(path, value):
    with path.open("x") as out:
        json.dump(value, out, indent=2)
        out.write("\n")


def read(path):
    return json.loads(path.read_bytes())


def fields(value, expected, name):
    need(isinstance(value, dict) and set(value) == set(expected.split()), name + " fields")


def integer(value, upper=MAX):
    need(type(value) is int and 0 <= value <= upper, "integer/range")
    return value


def decimal(value, upper=MAX):
    need(isinstance(value, str) and value.isascii() and value.isdecimal()
         and str(int(value)) == value, "canonical decimal")
    return integer(int(value), upper)


def unhex(value, length=None):
    need(isinstance(value, str), "hex type")
    data = bytes.fromhex(value)
    need(data.hex() == value and (length is None or len(data) == length), "canonical hex/length")
    return data


def harray(value):
    need(isinstance(value, list) and len(value) == 32, "hash array")
    return bytes(integer(v, 255) for v in value)


def point(value):
    fields(value, "transactionId index", "outpoint")
    unhex(value["transactionId"], 32)
    return value["transactionId"], integer(value["index"], 2**32 - 1)


def native_shape(tx):
    fields(tx, "version id inputs outputs lockTime subnetworkId gas payload storageMass", "native")
    need(type(tx["version"]) is int and tx["version"] == 1, "native version")
    unhex(tx["id"], 32)
    need(tx["lockTime"] == tx["gas"] == "0" and tx["subnetworkId"] == "0" * 40,
         "native envelope")
    decimal(tx["storageMass"], 2**64 - 1)
    unhex(tx["payload"])
    need(isinstance(tx["inputs"], list) and tx["inputs"]
         and isinstance(tx["outputs"], list) and tx["outputs"], "native shape")
    for entry in tx["inputs"]:
        fields(entry, "previousOutpoint signatureScript sequence sigOpCount computeBudget", "input")
        point(entry["previousOutpoint"])
        unhex(entry["signatureScript"])
        decimal(entry["sequence"], 2**64 - 1)
        need(type(entry["sigOpCount"]) is int and entry["sigOpCount"] == 0, "sigop encoding")
        integer(entry["computeBudget"], 65535)
    for output in tx["outputs"]:
        fields(output, "value scriptPublicKey covenant", "output")
        need(decimal(output["value"]) > 0 and output["covenant"] is None, "ordinary output")
        need(len(unhex(output["scriptPublicKey"])) >= 2, "script public key")


def state(data):
    need(len(data) == 105, "state length")
    if data == bytes(105):
        return None
    need(data[0] == 6, "state version")
    return dict(cm_count=int.from_bytes(data[1:5], "little"),
                nf_count=int.from_bytes(data[5:9], "little"),
                cm_root=data[9:41].hex(), nf_root=data[41:73].hex(),
                history_root=data[73:105].hex())


def p2sh(redeem):
    return (b"\0\0\xaa\x20" + hashlib.blake2b(redeem, digest_size=32).digest() + b"\x87").hex()


def append_commitments(commitments, mode, outputs):
    """Positions are append-only; equal bytes at different positions survive."""
    need(mode in (0, 1, 2) and len(outputs) == 2, "commitment slots")
    for cm in outputs:
        unhex(cm, 32)
    if mode == 2:
        need(outputs == ["0" * 64] * 2, "DRAIN commitments")
        return []
    need(all(cm != "0" * 64 for cm in outputs) and outputs[0] != outputs[1],
         "nonzero distinct within-pair commitments")
    positions = [len(commitments), len(commitments) + 1]
    commitments.extend(outputs)
    return positions


def equality_groups(items):
    groups = {}
    for label, value in items:
        groups.setdefault(value, []).append(label)
    return [dict(value=value, occurrences=labels) for value, labels in groups.items()
            if len(labels) > 1]


def witness(data, mode):
    need(len(data) == 4368, "settlement witness length")
    updates = []
    for slot in range(2):
        part = data[512 + slot * 1160:512 + (slot + 1) * 1160]
        updates.append(dict(
            active=mode != 0,
            predecessor_index=int.from_bytes(part[:4], "little"),
            previous_leaf=dict(value=part[4:36].hex(),
                               next_index=int.from_bytes(part[36:40], "little"),
                               next_value=part[40:72].hex()),
            predecessor_path=part[72:616].hex(),
            insertion_path=part[616:1160].hex(),
        ))
    return dict(
        meaning="public anchor-history membership and nullifier/commitment/history updates; not private input-note membership paths",
        anchor_history_path=data[:512].hex(),
        nullifier_updates=updates,
        commitment_append_paths=[data[2832:3344].hex(), data[3344:3856].hex()],
        history_append_path=data[3856:].hex(),
    )


def project(raw):
    """Decode only public bytes. Call pinned native replay before using results."""
    fields(raw, "descriptor vk_hex lineage parents", "raw public input")
    descriptor = raw["descriptor"]
    fields(descriptor, "format network genesis domain initial_commitment initial_value_sompi "
           "vk_sha256 funding_txid funding_full_hash", "descriptor")
    need(descriptor["format"] == "kpi-v6-public-replay-v1"
         and descriptor["network"] == "testnet-10"
         and descriptor["genesis"] == "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370",
         "descriptor identity")
    domain = harray(descriptor["domain"])
    initial_cm = harray(descriptor["initial_commitment"]).hex()
    vk = unhex(raw["vk_hex"], 328)
    need(digest(vk) == descriptor["vk_sha256"], "VK identity")
    for key in ("vk_sha256", "funding_txid", "funding_full_hash"):
        unhex(descriptor[key], 32)
    initial_value = decimal(descriptor["initial_value_sompi"])
    need(initial_value >= 60_000_000, "initial value floor")
    need(isinstance(raw["lineage"], list) and len(raw["lineage"]) >= 2
         and isinstance(raw["parents"], list), "public lineage/parents")
    parents = {}
    for parent in raw["parents"]:
        native_shape(parent)
        need(parent["payload"] == "", "ordinary funding parent payload")
        need(parent["id"] not in parents or parents[parent["id"]] == parent, "conflicting parent")
        parents[parent["id"]] = parent
    consumed = set()

    def funding(outpoint):
        key = point(outpoint)
        need(key not in consumed, "reused funding outpoint")
        need(key[0] in parents and key[1] < len(parents[key[0]]["outputs"]), "missing funding output")
        output = parents[key[0]]["outputs"][key[1]]
        spk = unhex(output["scriptPublicKey"], 36)
        need(spk[:3] == b"\0\0\x20" and spk[-1] == 0xac, "funding P2PK")
        consumed.add(key)
        return dict(transaction_id=key[0], index=key[1],
                    amount_sompi=output["value"], script_public_key=spk.hex())

    founding = raw["lineage"][0]
    native_shape(founding)
    need(founding["id"] == descriptor["funding_txid"] and len(founding["inputs"]) == 1
         and len(founding["outputs"]) == 2 and founding["payload"] == "", "founding shape/ID")
    need(decimal(founding["outputs"][0]["value"]) == initial_value, "initial reserve")
    first_funding = funding(founding["inputs"][0]["previousOutpoint"])
    balance = initial_value
    expected = (founding["id"], 0)
    expected_spk = founding["outputs"][0]["scriptPublicKey"]
    commitments = [initial_cm]
    events, surface = [], []
    roots, nullifiers, seen = {}, set(), {founding["id"]}
    suffix = previous_state = None
    nf_count = 0
    for ordinal, tx in enumerate(raw["lineage"][1:]):
        native_shape(tx)
        need(balance > 0 and tx["id"] not in seen, "history after terminal/duplicate")
        seen.add(tx["id"])
        payload = unhex(tx["payload"], 5228)
        need(payload[:8] == b"KPICR06\0", "payload domain")
        a, ciphers, successor, public_witness = payload[8:385], payload[385:755], payload[755:860], payload[860:]
        need(a[:8] == b"KPICU06\0" and a[8:40] == domain, "authorization domain")
        need(hashlib.sha256(ciphers).digest() == a[345:377], "ciphertext binding")
        mode = a[204]
        need(mode in (0, 1, 2) and len(tx["inputs"]) == (2 if mode == 0 else 1), "mode/input shape")
        native_input = tx["inputs"][0]
        need(point(native_input["previousOutpoint"]) == expected
             and native_input["sequence"] == str(2**64 - 1)
             and native_input["computeBudget"] == 3000, "reserve ancestry/input metadata")
        sig = unhex(native_input["signatureScript"], 24709)
        need(sig[:2] == b"\x4c\x80" and sig[130:133] == b"\x4d\x00\x60", "proof/redeem framing")
        proof, redeem = sig[2:130], sig[133:]
        old = state(redeem[36:141])
        need(old is not None and p2sh(redeem) == expected_spk and redeem[1:33] == domain,
             "reserve script/state binding")
        if ordinal == 0:
            suffix = redeem[141:]
            roots[1] = old["cm_root"]
        else:
            need(redeem[36:141] == previous_state and redeem[141:] == suffix, "covenant continuity")
        before = len(commitments)
        need(old["cm_count"] == before and old["nf_count"] == nf_count, "old state counts")
        anchor_count = int.from_bytes(a[40:44], "little")
        anchor = a[44:76].hex()
        nf_slots = [a[76:108].hex(), a[108:140].hex()]
        if mode == 0:
            need(ordinal > 0 and a[40:140] == bytes(100), "ADMIT anchor/nullifiers")
        else:
            need(anchor_count in roots and anchor == roots[anchor_count], "historical anchor")
            for nf in nf_slots:
                need(nf != "0" * 64 and nf not in nullifiers, "zero/reused nullifier")
                nullifiers.add(nf)
                nf_count += 1
        payout, fee, deposit, bootstrap = [int.from_bytes(a[start:start + 8], "little")
                                           for start in (205, 213, 257, 337)]
        for value in (payout, fee, deposit, bootstrap):
            integer(value)
        need(fee > 0 and bootstrap == (initial_value if ordinal == 0 else 0), "fee/bootstrap")
        destination = a[221:257].hex() if payout else None
        need(payout > 0 or a[221:257] == bytes(36), "zero payout script")
        admitted = None
        if mode == 0:
            admitted = funding(tx["inputs"][1]["previousOutpoint"])
            encoded = bytes.fromhex(admitted["transaction_id"]) + admitted["index"].to_bytes(4, "little")
            need(encoded == a[265:301] and admitted["script_public_key"] == a[301:337].hex()
                 and int(admitted["amount_sompi"]) == deposit and payout == 0, "actual funding binding")
        else:
            need(a[257:337] == bytes(80), "SPEND/DRAIN funding fields")
        outputs = [a[140:172].hex(), a[172:204].hex()]
        new = append_commitments(commitments, mode, outputs)
        if mode == 2:
            need(ciphers == bytes(370) and payout > 0, "DRAIN padding/payout")
        balance += deposit - payout - fee
        need(0 <= balance <= MAX and (balance > 0 or mode == 2), "native reserve")
        need(len(tx["outputs"]) == int(balance > 0) + int(payout > 0), "native output count")
        need(sum(decimal(o["value"]) for o in tx["outputs"]) == balance + payout, "native output accounting")
        if payout:
            need(decimal(tx["outputs"][-1]["value"]) == payout
                 and tx["outputs"][-1]["scriptPublicKey"] == destination, "native payout binding")
        next_state = state(successor)
        if balance == 0:
            need(next_state is None, "terminal successor")
        else:
            need(next_state is not None and next_state["cm_count"] == len(commitments)
                 and next_state["nf_count"] == nf_count, "successor counts")
            need(tx["outputs"][0]["value"] == str(balance)
                 and tx["outputs"][0]["scriptPublicKey"] == p2sh(redeem[:36] + successor + suffix),
                 "successor reserve/script")
            roots[len(commitments)] = next_state["cm_root"]
            expected_spk = tx["outputs"][0]["scriptPublicKey"]
        events.append(dict(
            id=tx["id"], minute=0, mode=mode, anchor_count=anchor_count, count_before=before,
            new=new, fee=fee, deposit=deposit, payout=payout, reserve_out=balance,
            destination=destination, funding_group=admitted["transaction_id"] if admitted else None,
        ))
        surface.append(dict(
            ordinal=ordinal, transaction_id=tx["id"], mode=mode, anchor_count=anchor_count,
            anchor_root=anchor, nullifier_slots=nf_slots, commitment_slots=outputs,
            appended_positions=new, payout_sompi=str(payout), fee_sompi=str(fee),
            deposit_sompi=str(deposit), bootstrap_sompi=str(bootstrap),
            payout_script=destination, funding=admitted, reserve_after_sompi=str(balance),
            authorization_hex=a.hex(), authorization_sha256=digest(a),
            proof_hex=proof.hex(), proof_sha256=digest(proof),
            ciphertexts=[ciphers[:185].hex(), ciphers[185:].hex()],
            ciphertext_sha256=digest(ciphers), old_state=old, successor_state=next_state,
            public_settlement_witness=witness(public_witness, mode),
        ))
        previous_state = successor
        expected = (tx["id"], 0)
    algebra = dict(schema="kpi-h14-public-v1",
                   initial=dict(id=founding["id"], value=initial_value,
                                funding_group=first_funding["transaction_id"]), events=events)
    scripts = [("founding-input", first_funding["script_public_key"])]
    for row in surface:
        if row["funding"]:
            scripts.append((f'event-{row["ordinal"]}-funding', row["funding"]["script_public_key"]))
        if row["payout_script"]:
            scripts.append((f'event-{row["ordinal"]}-payout', row["payout_script"]))
    cipher_items = [(f'event-{row["ordinal"]}-slot-{slot}', cipher)
                    for row in surface for slot, cipher in enumerate(row["ciphertexts"])]
    nf_items = [(f'event-{row["ordinal"]}-slot-{slot}', nf)
                for row in surface for slot, nf in enumerate(row["nullifier_slots"])]
    cm_slots = [(f'event-{row["ordinal"]}-slot-{slot}', cm)
                for row in surface for slot, cm in enumerate(row["commitment_slots"])]
    summary = dict(
        order="dependency ordinal only; algebra.minute is constant zero and unused",
        funding_group_meaning="same parent transaction only; not a common-controller or user-identity claim",
        chain_acceptance_verified=False,
        validation="pinned native replay is required; this decoder alone is not a proof verifier",
        witness_check="native replay reconstructs the complete public settlement witness and compares exact transaction bytes",
        funding=first_funding,
        payload_regions=[
            dict(name=name, start=start, end_exclusive=end)
            for name, start, end in [
                ("framing", 0, 8), ("authorization", 8, 385), ("ciphertexts", 385, 755),
                ("successor_state", 755, 860), ("public_settlement_witness", 860, 5228)]
        ],
        events=surface,
        equality=dict(
            commitment_positions=equality_groups(list(enumerate(commitments))),
            nonzero_nullifiers=equality_groups([(label, value) for label, value in nf_items if value != "0" * 64]),
            nonzero_ciphertexts=equality_groups([(label, value) for label, value in cipher_items if value != "0" * 370]),
            nonzero_ciphertext_ephemeral_prefixes=equality_groups(
                [(label, value[:64]) for label, value in cipher_items if value != "0" * 370]),
            proofs=equality_groups([(row["ordinal"], row["proof_hex"]) for row in surface]),
            funding_and_payout_scripts=equality_groups(scripts),
        ),
        zero_padding=dict(
            authorization_commitment_slots=[label for label, value in cm_slots if value == "0" * 64],
            authorization_nullifier_slots=[label for label, value in nf_items if value == "0" * 64],
            ciphertext_slots=[label for label, value in cipher_items if value == "0" * 370],
            note_values="not decoded; positive and zero encrypted note values are inferred only by the declared arithmetic profiles",
        ),
    )
    return dict(schema=SCHEMA, algebra=algebra, commitments=commitments, surface=summary, raw=raw)


def validate_projection(data):
    fields(data, "schema algebra commitments surface raw", "observer input")
    need(data["schema"] == SCHEMA, "observer input schema")
    need(project(data["raw"]) == data, "projection differs from raw public bytes")


def load_raw(directory):
    return dict(descriptor=read(directory / "descriptor.json"),
                vk_hex=(directory / "vk.bin").read_bytes().hex(),
                lineage=read(directory / "lineage.json"), parents=read(directory / "parents.json"))


def sandbox():
    return ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--setenv", "PYTHONPYCACHEPREFIX", "/tmp/observer-pycache"]


def native_replay(binary, inputs):
    command = sandbox() + ["--ro-bind", str(binary), "/replay",
                           "--ro-bind", str(inputs), "/input", "--", "/replay", "replay"]
    command += ["/input/" + name for name in FILES]
    return subprocess.run(command, capture_output=True, text=True)


def dependency_manifest(venv):
    """Exact installed dependency files, not just package version labels."""
    files = {str(path.relative_to(venv)): sha(path)
             for path in sorted(venv.rglob("*"))
             if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
    need(files, "empty dependency tree")
    return dict(files=files, python_executable_sha256=sha((venv / "bin/python").resolve()),
                bwrap_sha256=sha(Path(shutil.which("bwrap"))))


def prepare(output, binary, venv):
    need(sha(HERE / SPEC) == SPEC_SHA, "frozen specification changed")
    output.mkdir(mode=0o700)
    for name in ("inputs", "code", "bin"):
        (output / name).mkdir(mode=0o700)
    for name in FILES:
        shutil.copyfile(INPUT / name, output / "inputs" / name)
    for name in SOURCES + (SPEC,):
        shutil.copyfile(HERE / name, output / "code" / name)
    shutil.copyfile(binary, output / "bin/replay")
    (output / "bin/replay").chmod(0o700)
    frozen = dict(
        schema="kpi-early-privacy-freeze-v1", specification_sha256=SPEC_SHA,
        sources={name: sha(output / "code" / name) for name in SOURCES + (SPEC,)},
        inputs={name: sha(output / "inputs" / name) for name in FILES},
        replay_sha256=sha(output / "bin/replay"), dependency_root=str(venv),
        dependencies=dependency_manifest(venv),
        scope="public M2 calibration only; published truth excluded from observer input",
    )
    # Freeze precedes native projection, controls, and amount inference.
    save(output / "freeze.json", frozen)
    checked = native_replay(output / "bin/replay", output / "inputs")
    (output / "native-stderr.txt").write_text(checked.stderr)
    need(checked.returncode == 0, "native replay failed; retained stderr")
    replayed = json.loads(checked.stdout)
    raw = load_raw(output / "inputs")
    need([r["transaction"] for r in replayed["records"]] == raw["lineage"]
         and replayed["chain_acceptance_verified"] is False, "native replay records")
    save(output / "native-replay.json", replayed)
    projection = project(raw)
    validate_projection(projection)
    save(output / "public-input.json", projection)
    save(output / "projection-pins.json", dict(
        public_input_sha256=sha(output / "public-input.json"),
        native_replay_sha256=sha(output / "native-replay.json"),
        complete_endpoint=dict(transaction_count=len(replayed["records"]),
                               last_full_hash=replayed["records"][-1]["full_hash"]),
    ))
    return dict(prepared=True, inference_executed=False, output=str(output),
                public_input_sha256=sha(output / "public-input.json"))


def check_freeze(output):
    frozen = read(output / "freeze.json")
    need(frozen["specification_sha256"] == SPEC_SHA, "unexpected frozen spec")
    need(sha(Path(__file__).resolve()) == frozen["sources"]["early_privacy_surface.py"],
         "running runner differs from frozen source")
    for name, expected in frozen["sources"].items():
        need(sha(output / "code" / name) == expected, "frozen source changed: " + name)
    for name, expected in frozen["inputs"].items():
        need(sha(output / "inputs" / name) == expected, "frozen input changed: " + name)
    need(sha(output / "bin/replay") == frozen["replay_sha256"], "frozen binary changed")
    need(dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "frozen dependencies changed")
    pins = read(output / "projection-pins.json")
    need(sha(output / "public-input.json") == pins["public_input_sha256"]
         and sha(output / "native-replay.json") == pins["native_replay_sha256"], "projection pins")
    return frozen


def isolated(output, frozen, mode):
    destination = output / ("observer-" + mode)
    destination.mkdir(mode=0o700)
    command = sandbox() + ["--ro-bind", frozen["dependency_root"], "/venv",
                           "--ro-bind", str(output / "public-input.json"), "/input.json",
                           "--bind", str(destination), "/output"]
    for name in SOURCES:
        command += ["--ro-bind", str(output / "code" / name), "/" + name]
    probe = (
        "import pathlib,json;"
        "denied=['/home','/truth.json','/result.json','/receive.json','/backup.json','/actions.json'];"
        "assert all(not pathlib.Path(p).exists() for p in denied);"
        "interfaces=[x.split(':')[0].strip() for x in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
        "assert interfaces==['lo'];"
        "print(json.dumps({'inaccessible':denied,'interfaces':interfaces,"
        "'inputs':['/input.json'],'limits':'OS/runtime and author-written code remain trusted; no independent audit'}))"
    )
    audited = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                             capture_output=True, text=True, check=True)
    save(destination / "isolation.json", json.loads(audited.stdout))
    with (destination / "stdout.log").open("x") as stdout, (destination / "stderr.log").open("x") as stderr:
        status = subprocess.run(command + ["--", "/venv/bin/python", "/early_privacy_surface.py",
                                          "_observe", mode, "/input.json", "/output/result.json"],
                                stdout=stdout, stderr=stderr)
    need(status.returncode == 0, "observer failed; preserve incomplete attempt and logs")
    result = read(destination / "result.json")
    need(result["input_sha256"] == sha(output / "public-input.json"), "observer input identity")
    return result


def projection_controls(data):
    validate_projection(data)
    tests = []
    for name, mutate in [
        ("wrapper-truth", lambda bad: bad.update(truth={})),
        ("algebra-role", lambda bad: bad["algebra"]["events"][0].update(private_owner="poison")),
        ("raw-role", lambda bad: bad["raw"].update(participant={})),
        ("native-role", lambda bad: bad["raw"]["lineage"][0].update(role="poison")),
        ("changed-reduction", lambda bad: bad["algebra"]["events"][0].update(fee=1)),
    ]:
        bad = copy.deepcopy(data)
        mutate(bad)
        try:
            validate_projection(bad)
        except ValueError:
            tests.append(name)
        else:
            raise ValueError("projection control accepted " + name)
    commitments = ["01" * 32]
    positions = append_commitments(commitments, 1, ["02" * 32, "01" * 32])
    need(positions == [1, 2] and len(commitments) == 3
         and equality_groups(list(enumerate(commitments)))[0]["occurrences"] == [0, 2],
         "equal commitment positions lost")
    tests.append("equal-commitments-distinct-positions-decoder-only")
    return dict(passed=True, tests=tests,
                limit="decoder-level controls; no modified transaction is claimed to have a valid proof")


def native_controls(output):
    base = load_raw(output / "inputs")
    directory = output / "native-controls"
    directory.mkdir(mode=0o700)
    tests = []
    for name in ("missing-interior", "authorization", "ciphertext", "proof", "wrong-parent"):
        raw = copy.deepcopy(base)
        if name == "missing-interior":
            del raw["lineage"][2]
        elif name in ("authorization", "ciphertext"):
            payload = bytearray.fromhex(raw["lineage"][1]["payload"])
            payload[8 + 213 if name == "authorization" else 385] ^= 1
            raw["lineage"][1]["payload"] = payload.hex()
        elif name == "proof":
            signature = bytearray.fromhex(raw["lineage"][1]["inputs"][0]["signatureScript"])
            signature[2] ^= 1
            raw["lineage"][1]["inputs"][0]["signatureScript"] = signature.hex()
        else:
            first = point(raw["lineage"][0]["inputs"][0]["previousOutpoint"])
            raw["parents"] = [p for p in raw["parents"] if p["id"] != first[0]]
        case = directory / name
        case.mkdir(mode=0o700)
        save(case / "descriptor.json", raw["descriptor"])
        (case / "vk.bin").write_bytes(bytes.fromhex(raw["vk_hex"]))
        save(case / "lineage.json", raw["lineage"])
        save(case / "parents.json", raw["parents"])
        process = native_replay(output / "bin/replay", case)
        (case / "stderr.txt").write_text(process.stderr)
        need(process.returncode != 0 and not process.stdout.strip(), "native control accepted " + name)
        if name == "proof":
            need("native validation" in process.stderr, "proof mutation missed native execution")
        tests.append(dict(name=name, rejected=True, diagnostic=process.stderr.strip(),
                          limit="canonical framing or native rejection; no replacement valid proof generated"))
    return dict(passed=True, tests=tests)


def controls(output):
    frozen = check_freeze(output)
    need(not (output / "controls.json").exists(), "controls already recorded; use a fresh attempt")
    native = native_controls(output)
    observer = isolated(output, frozen, "controls")
    need(observer["controls"]["passed"], "observer controls failed")
    check_freeze(output)
    result = dict(passed=True, native=native, observer=observer)
    save(output / "controls.json", result)
    return result


def run(output):
    frozen = check_freeze(output)
    need(read(output / "controls.json")["passed"], "controls must pass first")
    observed = isolated(output, frozen, "infer")
    check_freeze(output)
    save(output / "completion.json", dict(
        complete=observed["analysis"].get("complete", False),
        input_sha256=observed["input_sha256"],
        result_sha256=sha(output / "observer-infer/result.json"),
        classification="published-trace amount calibration; no held-out privacy or owner-anonymity verdict",
    ))
    return observed


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "_observe":
        mode, source, destination = sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
        data = read(source)
        validate_projection(data)
        import early_privacy_amounts as amounts
        if mode == "controls":
            arithmetic = amounts.controls()
            result = dict(controls=dict(passed=arithmetic.get("passed") is True
                                               and arithmetic.get("complete") is True,
                                       projection=projection_controls(data), arithmetic=arithmetic))
        else:
            need(mode == "infer", "observer mode")
            result = dict(analysis=amounts.analyze(data["algebra"], data["commitments"]))
        result["input_sha256"] = sha(source)
        save(destination, result)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "controls", "run"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path, default=HERE / "target/release/kpi-two-input-replay")
    parser.add_argument("--venv", type=Path, default=VENV)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.command == "prepare":
        result = prepare(output, args.binary.resolve(), args.venv.resolve())
    elif args.command == "controls":
        result = controls(output)
    else:
        result = run(output)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()

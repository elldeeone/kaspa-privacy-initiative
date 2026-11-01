#!/usr/bin/env python3
"""Resume-safe component builder for the offline two-round W1 fixture.

This entrypoint generates fresh synthetic Originals, genuine Output proofs,
genuine restricted-intent signatures and normalized signature witnesses.  It
publishes immutable checkpoints only through ``round-2-close``.  It never
loads the aggregate proving key, proves the 13M-row relation, uses a network,
funds an owner, or mints a live W0/C1/Close/admission authority.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import uuid

import exit_wire
import offline_w1_fixture as fixture
import output_producer
import prepare_unfunded_batch as retained
import wallet_history
import wallet_profile as wallet


HERE = Path(__file__).resolve().parent
COMPONENT_STAGES = fixture.STAGES[:7]
WORK_DIRECTORY = ".component-builder-work"
CACHE_SCHEMA = "kpb-offline-w1-component-cache/v1"


def _dynamic(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


trees = _dynamic("_kpb_offline_w1_public_trees",
                 HERE.parent / "integration/trees.py")
intent_codec = _dynamic("_kpb_offline_w1_restricted_intent",
                        HERE.parent / "private_batch/intent.py")


def safe_name(value, category="cache-name"):
    fixture.need(type(value) is str and value
                 and all(character.isalnum() or character in "-_."
                         for character in value)
                 and value not in (".", ".."), category)
    return value


def _mkdir_new(path):
    path = Path(path)
    path.mkdir(mode=0o700)
    fixture.fsync_directory(path.parent)
    return path


def _cache_root(root):
    path = Path(root) / WORK_DIRECTORY
    if not path.exists():
        _mkdir_new(path)
    fixture.need(path.is_dir() and not path.is_symlink(),
                 "component-cache-directory")
    return path


def _cache_receipt(plan, stage, key, paths):
    return {
        "schema": CACHE_SCHEMA,
        "classification": fixture.CLASSIFICATION,
        "run_id": plan["run_id"],
        "source_instance_epoch_id": plan["source_instance_epoch_id"],
        "plan_identity_sha256": plan["plan_identity_sha256"],
        "source_closure_sha256": plan["source_closure_sha256"],
        "stage": stage,
        "key": key,
        "files": {
            name: {
                "sha256": fixture.sha_file(path),
                "bytes": path.stat().st_size,
            }
            for name, path in sorted(paths.items())
        },
        "admitted_checkpoint": False,
        "authorization": False,
    }


def load_cached_bundle(root, plan, stage, key, expected):
    stage, key = safe_name(stage), safe_name(key)
    target = _cache_root(root) / stage / key
    if not target.exists():
        return None
    fixture.need(target.is_dir() and not target.is_symlink(),
                 "component-cache-bundle-directory")
    ready = target / "READY.json"
    value = fixture.parse(fixture.read_exact(ready))
    fixture.need(fixture.canonical(value) == ready.read_bytes()
                 and value == _cache_receipt(
                     plan, stage, key,
                     {name: target / name for name in expected}),
                 "component-cache-receipt-binding")
    fixture.need(set(path.name for path in target.iterdir())
                 == set(expected) | {"READY.json"},
                 "component-cache-exact-file-set")
    result = {}
    for name in sorted(expected):
        path = fixture.checked_file(target / name)
        selected = value["files"][name]
        fixture.need(path.stat().st_size == selected["bytes"]
                     and fixture.sha_file(path) == selected["sha256"],
                     "component-cache-content-substitution")
        result[name] = path
    return result


def cached_bundle(root, plan, stage, key, expected, producer):
    """Publish/reopen one immutable substage; incomplete attempts are inert."""
    expected = tuple(sorted(safe_name(name, "cache-file-name")
                            for name in expected))
    fixture.need(expected and len(expected) == len(set(expected)),
                 "component-cache-expected-files")
    existing = load_cached_bundle(root, plan, stage, key, expected)
    if existing is not None:
        return existing
    stage_root = _cache_root(root) / safe_name(stage)
    if not stage_root.exists():
        _mkdir_new(stage_root)
    target = stage_root / safe_name(key)
    temporary = stage_root / ("." + safe_name(key) + ".tmp-" + str(uuid.uuid4()))
    _mkdir_new(temporary)
    producer(temporary)
    actual = {path.name for path in temporary.iterdir()}
    fixture.need(actual == set(expected), "component-cache-producer-file-set")
    paths = {name: fixture.checked_file(temporary / name)
             for name in expected}
    fixture.write_new(temporary / "READY.json",
                      _cache_receipt(plan, stage, key, paths))
    fixture.fsync_directory(temporary)
    fixture.rename_no_replace(temporary, target)
    fixture.fsync_directory(stage_root)
    return load_cached_bundle(root, plan, stage, key, expected)


def completed_component_prefix(root):
    """Return the exact admitted prefix; a gap or aggregate stage refuses."""
    root = Path(root)
    completed = []
    for stage in fixture.STAGES:
        path = fixture.stage_path(root, stage)
        if path.exists():
            fixture.need(stage in COMPONENT_STAGES
                         and len(completed) == COMPONENT_STAGES.index(stage),
                         "component-builder-checkpoint-gap-or-scope")
            completed.append(stage)
        elif stage in COMPONENT_STAGES[len(completed):]:
            break
    for stage in fixture.STAGES[len(completed):]:
        fixture.need(not fixture.stage_path(root, stage).exists(),
                     "component-builder-checkpoint-gap-or-scope")
    return completed


def _strict_read(path, expected=None):
    return fixture.read_exact(path, expected)


def _write(path, value, mode=0o400):
    return fixture.write_new(path, value, mode)


def _copy_new(source, destination, mode=0o400):
    source = fixture.checked_file(source)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, mode)
    with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output:
        shutil.copyfileobj(input_file, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())


def _profile(plan):
    _, raw = fixture.read_ref(plan["profile"])
    value = fixture.parse(raw)
    descriptor = value["profile_descriptor"]
    return wallet.Profile(bytes.fromhex(descriptor["domain_hex32"]),
                          bytes.fromhex(value["profile_id_hex32"]))


def _history_head(value, plan, verifier):
    identity = fixture.expected_history_identity(plan)
    profile = wallet.Profile(identity[3], identity[2])
    rows = [bytes.fromhex(row)
            for row in value["genesis"]["outputs_hex520"]]
    fixture.need(len(rows) == 3 and all(len(row) == 520 for row in rows),
                 "builder-history-genesis")
    _, tail = fixture.read_ref(
        plan["selected_build"]["aggregate_feasibility_only"]["native_tail"])
    cache = {}

    def verify(row):
        digest = fixture.sha(row)
        if digest not in cache:
            cache[digest] = verifier.verify(row)
        return cache[digest]

    return wallet_history.load_supplied(
        value, profile, identity, tail, verify, rows[0][32:96])


def _state_bytes(domain, cm_root, cm_count, nf_root, nf_count):
    raw = (exit_wire.STATE_TAG + domain + cm_root
           + cm_count.to_bytes(4, "little") + nf_root
           + nf_count.to_bytes(4, "little"))
    fixture.need(len(raw) == 112, "builder-state-width")
    return raw


def _fresh_outpoint(excluded=()):
    excluded = set(excluded)
    fixture.need(all(type(value) is bytes and len(value) == 36
                     for value in excluded),
                 "builder-excluded-outpoints")
    while True:
        value = secrets.token_bytes(32) + (0).to_bytes(4, "little")
        if value[:32] != bytes(32) and value not in excluded:
            return value


def _projection_prefix(context, core, tail):
    old = exit_wire.HeadContext.parse(context)
    new_state = _state_bytes(
        old.domain, core[284:316], int.from_bytes(core[348:352], "little"),
        core[316:348], int.from_bytes(core[352:356], "little"))
    new_reserve = int.from_bytes(core[356:364], "little")
    raw = (b"KPBAFX01\x01\0\x01\0" + old.point + b"\xff" * 8
           + old.reserve.to_bytes(8, "little") + (37).to_bytes(2, "little")
           + exit_wire.state_spk(old.state(), tail) + (1).to_bytes(2, "little")
           + new_reserve.to_bytes(8, "little") + (37).to_bytes(2, "little")
           + exit_wire.state_spk(new_state, tail) + b"\0" + bytes(36)
           + (10_492).to_bytes(4, "little"))
    fixture.need(len(raw) == 193, "builder-payment-projection-prefix")
    return raw


class Builder:
    def __init__(self, root, plan, plan_sha256):
        self.root = Path(root)
        self.plan = plan
        self.plan_sha256 = plan_sha256
        self.profile = _profile(plan)
        self.prover = fixture.output_verifier_from_plan(plan)
        self.modules = wallet.authenticate_js(
            retained.LEAF_MAP, retained.LEAF_MAP_SHA, retained.JS_ROOT)
        self.crypto = wallet.Crypto(retained.CRYPTO)
        self.authority = wallet.Authority(retained.NODE, self.modules)
        self._receivers = None

    def close(self):
        self.authority.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def owner_receiver(self, owner):
        fixture.need(owner in range(3), "builder-owner")
        if self._receivers is None:
            checkpoint = fixture.checkpoint_from_root(self.root, "bootstrap")
            receivers = []
            for selected in range(3):
                backup, _ = fixture.json_artifact(
                    checkpoint["artifacts"], f"owner-{selected}-backup.json")
                seed = bytes.fromhex(backup["seed_hex32"])
                fixture.need(len(seed) == 32 and seed != bytes(32),
                             "builder-owner-seed")
                receivers.append(wallet.Receiver(
                    seed, self.profile, self.crypto, self.authority))
            self._receivers = receivers
        return self._receivers[owner]

    def history_value(self, round_number):
        if round_number == 1:
            checkpoint = fixture.checkpoint_from_root(self.root, "bootstrap")
            return fixture.json_artifact(
                checkpoint["artifacts"], "public-history.json")[0]
        fixture.need(round_number == 2, "builder-round")
        checkpoint = fixture.checkpoint_from_root(self.root, "round-1-close")
        return fixture.json_artifact(
            checkpoint["artifacts"], "public-history-after.json")[0]

    def bootstrap(self):
        owner_paths = {}
        for owner in range(3):
            generation_id = self.plan["owner_generation_ids"][owner]

            def produce(directory, owner=owner,
                        generation_id=generation_id):
                seed = secrets.token_bytes(32)
                while seed == bytes(32):
                    seed = secrets.token_bytes(32)
                receiver = wallet.Receiver(
                    seed, self.profile, self.crypto, self.authority)
                created = self.prover.create(
                    self.crypto, receiver.invoice(0), 2_000_000_000,
                    blind=bytes(32))
                _write(directory / "backup.json", {
                    "schema": "kpb-offline-w1-fresh-owner/v1",
                    "owner_generation_id": generation_id,
                    "logical_owner": owner,
                    "seed_hex32": seed.hex(),
                    "synthetic_unfunded": True,
                })
                _write(directory / "initial.json", {
                    "schema": "kpb-offline-w1-initial-output/v1",
                    "owner_generation_id": generation_id,
                    "logical_owner": owner,
                    "invoice_hex208": receiver.invoice(0).encode().hex(),
                    "tuple_hex520": created.row.hex(),
                    "note_hex168": created.receipt.note_bytes().hex(),
                    "blind_hex32": created.blind.hex(),
                    "genuine_output_proof": True,
                    "funding_or_backing": False,
                })

            owner_paths[owner] = cached_bundle(
                self.root, self.plan, "bootstrap", f"owner-{owner}",
                ("backup.json", "initial.json"), produce)

        def shared(directory):
            initial = [fixture.parse(fixture.read_exact(
                owner_paths[owner]["initial.json"])) for owner in range(3)]
            rows = [bytes.fromhex(value["tuple_hex520"])
                    for value in initial]
            state = trees.PublicState([row[:32] for row in rows])
            identity = fixture.expected_history_identity(self.plan)
            point = _fresh_outpoint()
            context = exit_wire.HeadContext(
                *identity, point, state.cm.root(), state.nf.root(),
                len(state.cms), len(state.entries), 6_000_000_000)
            genesis = {
                "outpoint_hex36": point.hex(),
                "state_hex112": context.state().hex(),
                "reserve_sompi": context.reserve,
                "outputs_hex520": [row.hex() for row in rows],
            }
            history = {
                "schema": "kpb-private-batch-public-history/v1",
                "scope": wallet_history.SCOPE,
                **dict(zip((
                    "chain_hex32", "pool_hex32", "profile_hex32",
                    "domain_hex32", "service_hex32",
                ), (value.hex() for value in identity))),
                "genesis": genesis,
                "transitions": [],
                "head": {name: genesis[name] for name in (
                    "outpoint_hex36", "state_hex112", "reserve_sompi")},
            }
            _write(directory / "public-history.json", history)
            _, tail = fixture.read_ref(
                self.plan["selected_build"]
                ["aggregate_feasibility_only"]["native_tail"])
            _write(directory / "native-tail.bin", tail)

        shared_paths = cached_bundle(
            self.root, self.plan, "bootstrap", "shared",
            ("native-tail.bin", "public-history.json"), shared)
        artifacts = {
            "public-history.json": shared_paths["public-history.json"],
            "native-tail.bin": shared_paths["native-tail.bin"],
        }
        for owner in range(3):
            artifacts[f"owner-{owner}-backup.json"] = owner_paths[owner]["backup.json"]
            artifacts[f"owner-{owner}-initial.json"] = owner_paths[owner]["initial.json"]
        return fixture.write_checkpoint(
            self.root, self.plan, "bootstrap", artifacts, {
                "owner_generation_ids": self.plan["owner_generation_ids"],
                "physical_to_w1_logical": [2, 1, 0],
                "genuine_initial_output_proofs": 3,
            })

    def round_inputs(self, number):
        stage = f"round-{number}-inputs"
        history_value = self.history_value(number)
        history = _history_head(history_value, self.plan, self.prover)
        attempt = fixture.round_attempt(self.plan, number)
        owners = {}
        for owner in range(3):
            def produce(directory, owner=owner):
                receiver = self.owner_receiver(owner)
                claim = wallet_history.select_for_round(
                    history.recover(receiver), number, owner)
                row = history.rows[claim.position]
                blind = secrets.randbelow(output_producer.Q).to_bytes(
                    32, "little")
                derived = self.prover._call("derive-output", b"", {
                    "note_hex168": claim.receipt.note_bytes().hex(),
                    "blinding_hex32": blind.hex(),
                    "cf_hash_hex32": row[360:392].hex(),
                })
                statement = bytes.fromhex(derived["statement_hex168"])
                keys = receiver.keys(claim.receipt.index)
                value = {
                    "schema": "kpb-offline-w1-owner-input/v1",
                    "round": number,
                    "logical_owner": owner,
                    "input_attempt_id": attempt["input_attempt_id"],
                    "note_hex168": claim.receipt.note_bytes().hex(),
                    "nk_hex32": keys.nf_secret.hex(),
                    "position": claim.position,
                    "path_hex32": [part.hex() for part in claim.path],
                    "cv_hex64": statement[72:136].hex(),
                    "blind_hex32": blind.hex(),
                    "ak_hex64": keys.owner_key.hex(),
                    "nf_hex32": claim.nf.hex(),
                    "selected_tuple_sha256": fixture.sha(row),
                    "input_value_sompi": claim.receipt.value_sompi,
                    "receipt_index": claim.receipt.index,
                    "source_history_sha256": fixture.sha(
                        fixture.canonical(history_value)),
                }
                fixture.need(
                    value["input_value_sompi"]
                    == fixture.ROUND_VALUES[number]["input"][owner],
                    "builder-fixed-round-input-value")
                _write(directory / "owner-input.json", value)

            owners[owner] = cached_bundle(
                self.root, self.plan, stage, f"owner-{owner}",
                ("owner-input.json",), produce)
        return fixture.write_checkpoint(
            self.root, self.plan, stage,
            {f"owner-{owner}-input.json":
             owners[owner]["owner-input.json"] for owner in range(3)},
            {"round": number, "attempt": attempt, "input_count": 3})

    def _owner_component(self, number, history, input_value, owner,
                         directory):
        receiver = self.owner_receiver(owner)
        target = (owner + number) % 3
        payment = fixture.ROUND_VALUES[number]["payment"][owner]
        change = fixture.ROUND_VALUES[number]["change"][owner]
        outputs = [
            self.prover.create(
                self.crypto,
                self.owner_receiver(target).invoice(2 * number - 1),
                payment),
            self.prover.create(
                self.crypto, receiver.invoice(2 * number), change),
        ]
        nonce = secrets.token_bytes(32)
        head = history.head
        raw_intent = intent_codec.RestrictedIntent(
            head.chain, head.pool, head.profile, head.domain, head.service,
            head.point, head.cm_root, head.nf_root, head.cm_count,
            head.nf_count, head.reserve,
            bytes.fromhex(input_value["nf_hex32"]),
            bytes.fromhex(input_value["cv_hex64"]), fixture.FEE, nonce,
            tuple(output.row for output in outputs)).encode()
        expected_index = 0 if number == 1 else (2 if owner == 1 else 1)
        fixture.need(input_value["receipt_index"] == expected_index,
                     "builder-fixed-input-receipt-index")
        keys = receiver.keys(expected_index)
        signature = self.authority.sign(keys.signing_seed, raw_intent)
        fixture.need(self.authority.verify(raw_intent, signature),
                     "builder-restricted-intent-signature")
        signature_inputs = self.authority.signature_inputs(
            raw_intent, signature)
        input_blind = int.from_bytes(bytes.fromhex(
            input_value["blind_hex32"]), "little")
        private_delta = (input_blind - sum(int.from_bytes(
            output.blind, "little") for output in outputs)) % output_producer.Q
        record = {
            "schema": "kpb-private-original-owner-record/v1",
            "owner_component": owner,
            "input": {name: input_value[name] for name in (
                "note_hex168", "nk_hex32", "position", "path_hex32",
                "cv_hex64", "blind_hex32", "ak_hex64", "nf_hex32")},
            "fee_sompi": fixture.FEE,
            "nonce_hex32": nonce.hex(),
            "outputs": [{
                "tuple_hex520": output.row.hex(),
                "note_hex168": output.receipt.note_bytes().hex(),
                "blind_hex32": output.blind.hex(),
            } for output in outputs],
            "private_delta_hex32": private_delta.to_bytes(
                32, "little").hex(),
            "intent_hex1460": raw_intent.hex(),
            "signature": {name: signature[name] for name in (
                "owner_key_hex64", "R8", "S")},
            "signature_inputs": signature_inputs,
        }
        _write(directory / "OWNER-LOCAL-RECORD.json", record)
        witness_sha = retained.normalize_signature(
            directory, signature_inputs, self.modules, _strict_read)
        request = {
            "schema": "kpi-owner-local-aux-request/v1",
            "owner_component": owner,
            "context_hex": head.encode().hex(),
            "owner_record_path": "OWNER-LOCAL-RECORD.json",
            "signature_matrix_path": "SIGNATURE-MATRIX.json",
            "signature_witness_path": "SIGNATURE-WITNESS.json",
            "expected_matrix_sha256": fixture.SIGNATURE_MATRIX_SHA,
            "expected_mapping_sha256": fixture.SIGNATURE_MAP_SHA,
            "expected_witness_sha256": witness_sha,
        }
        _write(directory / "OWNER-AUX-REQUEST.json", request)
        build = self.plan["selected_build"]["output"]
        auxiliary = retained.owner_auxiliary({
            "owner_aux_binary": build["owner_aux_binary"]["path"],
            "owner_aux_sha256": build["owner_aux_binary"]["sha256"],
        }, directory, _strict_read)
        fixture.need(auxiliary["owner_component"] == owner
                     and auxiliary["context_sha256"]
                     == fixture.sha(head.encode()),
                     "builder-owner-aux-context")

    @staticmethod
    def _component_cache_files():
        return (
            "OWNER-LOCAL-RECORD.json",
            "SIGNATURE-INPUT.json",
            "SIGNATURE-MATRIX.json",
            "SIGNATURE-MAP.json",
            "SIGNATURE-WITNESS.json",
            "SIGNATURE.wtns",
            "OWNER-AUX-REQUEST.json",
            "OWNER-PRIVATE-INPUT-V2.bin",
            "PUBLIC-OWNER-AUX.json",
        )

    def _build_effects(self, history, records, output_order):
        context = history.head.encode()
        state = history.state.copy()
        input_order = sorted(range(3), key=lambda owner: int.from_bytes(
            bytes.fromhex(records[owner]["input"]["nf_hex32"]), "little"))
        fixture.need(sorted(input_order) == list(range(3))
                     and sorted(output_order) == list(range(6)),
                     "builder-joint-permutation")
        inputs = []
        nf_witnesses = []
        for owner in input_order:
            nf = bytes.fromhex(records[owner]["input"]["nf_hex32"])
            cv = bytes.fromhex(records[owner]["input"]["cv_hex64"])
            inputs.append(nf + cv)
            nf_witnesses.append(state.insert(nf))
        flat_outputs = [bytes.fromhex(output["tuple_hex520"])
                        for record in records for output in record["outputs"]]
        ordered_outputs = [flat_outputs[source] for source in output_order]
        cm_paths = [state.append(output[:32]) for output in ordered_outputs]
        total_fee = sum(record["fee_sompi"] for record in records)
        delta_sum = sum(int.from_bytes(bytes.fromhex(
            record["private_delta_hex32"]), "little") for record in records)
        quotient, delta = divmod(delta_sum, output_producer.Q)
        fixture.need(quotient in (0, 1, 2), "builder-delta-quotient")
        core = bytearray(b"KPBAEF01" + context)
        core.extend(state.cm.root())
        core.extend(state.nf.root())
        core.extend(len(state.cms).to_bytes(4, "little"))
        core.extend(len(state.entries).to_bytes(4, "little"))
        core.extend((history.reserve - total_fee).to_bytes(8, "little"))
        core.extend(total_fee.to_bytes(8, "little"))
        core.extend(delta.to_bytes(32, "little"))
        for row in inputs:
            core.extend(row)
        for row in ordered_outputs:
            core.extend(row)
        for witness in nf_witnesses:
            core.extend(witness)
        for path in cm_paths:
            core.extend(path)
        fixture.need(len(core) == 10_364, "builder-effects-width")
        return bytes(core), input_order, quotient

    def _c1_residual(self, number, records, projection):
        attempt = fixture.round_attempt(self.plan, number)
        creator = 0 if number == 1 else 2
        outgoing_target = (1 + number) % 3
        operations = [attempt[name] for name in (
            "invoice_operation_id", "payment_operation_id",
            "scan_operation_id")]
        contacts = [creator, outgoing_target, creator]
        incoming = bytes.fromhex(
            records[creator]["outputs"][0]["tuple_hex520"])
        outgoing = bytes.fromhex(
            records[1]["outputs"][0]["tuple_hex520"])
        change = bytes.fromhex(
            records[1]["outputs"][1]["tuple_hex520"])
        incoming_note = bytes.fromhex(
            records[creator]["outputs"][0]["note_hex168"])
        change_note = bytes.fromhex(
            records[1]["outputs"][1]["note_hex168"])
        issued_invoice = self.owner_receiver(1).invoice(
            2 * number - 1).encode()
        outgoing_invoice = self.owner_receiver(outgoing_target).invoice(
            2 * number - 1).encode()
        value = {
            "schema": "kpb-offline-w1-c1-residual/v2",
            "round": number,
            "c1_owner": 1,
            "capture_attempt_id": attempt["c1_capture_attempt_id"],
            "capture_attempt_hex32": fixture.capture_attempt_word(
                attempt["c1_capture_attempt_id"]),
            "capture_identity_id": attempt["c1_capture_identity_id"],
            "c1_cohort_hex32": attempt["c1_cohort_hex32"],
            "c1_financial_run_hex32": attempt["c1_financial_run_hex32"],
            "contact_value_authority_preimage": {},
            "contact_value_authority_preimage_sha256": "00" * 32,
            "contact_value_authority_was_live": False,
            "stages": [{
                "stage": stage,
                "operation_id": operation,
                "operation_hex32": fixture.operation_word(operation),
                "contact_owner": contact,
                "stage_config": {},
                "stage_config_hex32": "00" * 32,
            } for stage, operation, contact in zip(
                ("invoice", "pay", "scan"), operations, contacts)],
            "original": {
                "source_operation_id": attempt["payment_operation_id"],
                "source_operation_hex32": fixture.operation_word(
                    attempt["payment_operation_id"]),
                "input_nf_hex32": records[1]["input"]["nf_hex32"],
                "input_value_sompi": fixture.ROUND_VALUES[number]["input"][1],
                "created": [
                    {"kind": "outgoing-payment",
                     "tuple_sha256": fixture.sha(outgoing),
                     "cm_hex32": outgoing[:32].hex(),
                     "value_sompi": fixture.ROUND_VALUES[number]
                     ["payment"][1]},
                    {"kind": "own-change",
                     "tuple_sha256": fixture.sha(change),
                     "cm_hex32": change[:32].hex(),
                     "value_sompi": fixture.ROUND_VALUES[number]
                     ["change"][1]},
                ],
            },
            "invoices": [
                {"kind": "issued-incoming",
                 "source_operation_id": attempt["invoice_operation_id"],
                 "invoice_operation_id": attempt["invoice_operation_id"],
                 "source_owner": 1, "target_owner": creator,
                 "invoice_index": 2 * number - 1,
                 "value_sompi": fixture.ROUND_VALUES[number]
                 ["payment"][creator],
                 "invoice_hex208": issued_invoice.hex(),
                 "invoice_sha256": fixture.sha(issued_invoice)},
                {"kind": "accepted-outgoing",
                 "source_operation_id": attempt["payment_operation_id"],
                 "invoice_operation_id": attempt["invoice_operation_id"],
                 "source_owner": outgoing_target, "target_owner": 1,
                 "invoice_index": 2 * number - 1,
                 "value_sompi": fixture.ROUND_VALUES[number]
                 ["payment"][1],
                 "invoice_hex208": outgoing_invoice.hex(),
                 "invoice_sha256": fixture.sha(outgoing_invoice)},
            ],
            "receipts": [
                {"kind": "decrypted-incoming",
                 "source_operation_id": attempt["scan_operation_id"],
                 "receipt_index": 2 * number - 1,
                 "creator_owner": creator,
                 "tuple_sha256": fixture.sha(incoming),
                 "cm_hex32": incoming[:32].hex(),
                 "note_sha256": fixture.sha(incoming_note),
                 "value_sompi": fixture.ROUND_VALUES[number]
                 ["payment"][creator]},
                {"kind": "decrypted-own-change",
                 "source_operation_id": attempt["scan_operation_id"],
                 "receipt_index": 2 * number,
                 "creator_owner": 1,
                 "tuple_sha256": fixture.sha(change),
                 "cm_hex32": change[:32].hex(),
                 "note_sha256": fixture.sha(change_note),
                 "value_sompi": fixture.ROUND_VALUES[number]
                 ["change"][1]},
            ],
            "incoming_key_commitment_hex32": incoming_note[104:136].hex(),
            "incoming_ciphertext_hex264": incoming[96:360].hex(),
            "retry_history_closed": True,
            "retries": [],
            "lineage": {},
            "manifest_or_digest_is_authority": False,
        }
        preimage = fixture.expected_c1_authority_preimage(value, self.plan)
        authority = fixture.c1_authority_preimage_word(preimage)
        value["contact_value_authority_preimage"] = preimage
        value["contact_value_authority_preimage_sha256"] = authority
        for sequence, row in enumerate(value["stages"]):
            row["stage_config"] = fixture.expected_stage_config(
                value, self.plan, sequence, authority)
            row["stage_config_hex32"] = fixture.stage_config_word(
                row["stage_config"])
        value["lineage"] = fixture.expected_c1_lineage(
            value, self.plan, projection)
        return value

    def round_components(self, number):
        stage = f"round-{number}-components"
        history_value = self.history_value(number)
        history = _history_head(history_value, self.plan, self.prover)
        inputs_checkpoint = fixture.checkpoint_from_root(
            self.root, f"round-{number}-inputs")
        inputs = [fixture.json_artifact(
            inputs_checkpoint["artifacts"], f"owner-{owner}-input.json")[0]
                  for owner in range(3)]
        owner_paths = {}
        for owner in range(3):
            owner_paths[owner] = cached_bundle(
                self.root, self.plan, stage, f"owner-{owner}",
                self._component_cache_files(),
                lambda directory, owner=owner: self._owner_component(
                    number, history, inputs[owner], owner, directory))

        records = [fixture.parse(fixture.read_exact(
            owner_paths[owner]["OWNER-LOCAL-RECORD.json"]))
                   for owner in range(3)]

        def shared(directory):
            keys = []
            while len(keys) < 6:
                candidate = secrets.token_bytes(16)
                if candidate not in keys:
                    keys.append(candidate)
            output_order = sorted(range(6), key=lambda source: int.from_bytes(
                keys[source], "little"))
            core, input_order, quotient = self._build_effects(
                history, records, output_order)
            context = history.head.encode()
            _, tail = fixture.read_ref(
                self.plan["selected_build"]
                ["aggregate_feasibility_only"]["native_tail"])
            projection = _projection_prefix(
                context, core, tail) + core + bytes(128)
            fixture.need(len(projection) == 10_685,
                         "builder-projection-width")
            w0, actual = fixture.derive_graph(records, core)
            selected = {
                "schema": "kpb-offline-w1-selected-w0/v1",
                "round": number,
                "fixed_rewire_identity_sha256":
                    self.plan["fixed_rewire"]["identity_sha256"],
                "w0_graph": w0,
                "w1_graph": actual,
                "caller_digest_is_common_origin_authority": False,
            }
            ordering = {
                "schema": "kpb-offline-w1-joint-ordering/v1",
                "round": number,
                "input_source_order": input_order,
                "output_source_order": output_order,
                "delta_quotient": quotient,
                "random_output_keys_retained": False,
                "ordering_is_live_w0_authority": False,
            }
            _write(directory / "context.bin", context)
            _write(directory / "effects-core.bin", core)
            _write(directory / "projection.bin", projection)
            _write(directory / "w0-selection.json", selected)
            _write(directory / "joint-ordering.json", ordering)
            _write(directory / "c1-residual.json",
                   self._c1_residual(number, records, projection))

        shared_paths = cached_bundle(
            self.root, self.plan, stage, "shared", (
                "context.bin", "effects-core.bin", "projection.bin",
                "w0-selection.json", "joint-ordering.json",
                "c1-residual.json",
            ), shared)
        artifacts = dict(shared_paths)
        for owner in range(3):
            paths = owner_paths[owner]
            for source, target in (
                ("OWNER-LOCAL-RECORD.json", "record.json"),
                ("SIGNATURE-MATRIX.json", "signature-matrix.json"),
                ("SIGNATURE-MAP.json", "signature-map.json"),
                ("SIGNATURE-WITNESS.json", "signature-witness.json"),
                ("OWNER-AUX-REQUEST.json", "owner-aux-request.json"),
                ("OWNER-PRIVATE-INPUT-V2.bin", "private-input-v2.bin"),
                ("PUBLIC-OWNER-AUX.json", "aux-receipt.json"),
            ):
                artifacts[f"owner-{owner}-{target}"] = paths[source]
        return fixture.write_checkpoint(
            self.root, self.plan, stage, artifacts, {
                "round": number,
                "attempt": fixture.round_attempt(self.plan, number),
                "genuine_output_proofs": 6,
                "genuine_signature_witnesses": 3,
                "aggregate_proof_present": False,
            })

    def round_close(self, number):
        stage = f"round-{number}-close"
        component = fixture.checkpoint_from_root(
            self.root, f"round-{number}-components")
        context = fixture.bytes_artifact(
            component["artifacts"], "context.bin", 276)
        core = fixture.bytes_artifact(
            component["artifacts"], "effects-core.bin", 10_364)
        projection = fixture.bytes_artifact(
            component["artifacts"], "projection.bin", 10_685)
        if number == 1:
            bootstrap = fixture.checkpoint_from_root(self.root, "bootstrap")
            before, before_raw = fixture.json_artifact(
                bootstrap["artifacts"], "public-history.json")
        else:
            prior = fixture.checkpoint_from_root(self.root, "round-1-close")
            before, before_raw = fixture.json_artifact(
                prior["artifacts"], "public-history-after.json")

        def shared(directory):
            prior_outpoints = {
                bytes.fromhex(before["genesis"]["outpoint_hex36"]),
                *(bytes.fromhex(event["successor_outpoint_hex36"])
                  for event in before["transitions"]
                  if event["successor_outpoint_hex36"] is not None),
            }
            successor = _fresh_outpoint(prior_outpoints)
            after = copy.deepcopy(before)
            after["transitions"].append({
                "kind": "payment",
                "projection_hex": projection.hex(),
                "successor_outpoint_hex36": successor.hex(),
            })
            state = _state_bytes(
                context[96:128], core[284:316],
                int.from_bytes(core[348:352], "little"),
                core[316:348], int.from_bytes(core[352:356], "little"))
            after["head"] = {
                "outpoint_hex36": successor.hex(),
                "state_hex112": state.hex(),
                "reserve_sompi": int.from_bytes(core[356:364], "little"),
            }
            _write(directory / "public-history-before.json", before_raw)
            _write(directory / "public-history-after.json", after)
            _write(directory / "context.bin", context)
            _write(directory / "projection.bin", projection)
            _write(directory / "successor-outpoint.bin", successor)
            after_raw = fixture.canonical(after)
            _write(directory / "close-source.json", {
                "schema": "kpb-offline-w1-structural-close-source/v1",
                "round": number,
                "context_sha256": fixture.sha(context),
                "projection_sha256": fixture.sha(projection),
                "history_before_sha256": fixture.sha(before_raw),
                "history_after_sha256": fixture.sha(after_raw),
                "successor_outpoint_hex36": successor.hex(),
                "aggregate_proof_verified": False,
                "accepted_public_terminal_projection_history_close": False,
                "manifest_or_digest_mints_close_authority": False,
            })

        paths = cached_bundle(
            self.root, self.plan, stage, "shared", (
                "public-history-before.json", "public-history-after.json",
                "context.bin", "projection.bin", "successor-outpoint.bin",
                "close-source.json",
            ), shared)
        return fixture.write_checkpoint(
            self.root, self.plan, stage, paths, {
                "round": number,
                "attempt": fixture.round_attempt(self.plan, number),
                "structural_close_only": True,
                "aggregate_verified": False,
                "accepted_close_authority_minted": False,
            })

    def build_stage(self, stage):
        fixture.need(stage in COMPONENT_STAGES, "component-stage-scope")
        if stage == "bootstrap":
            return self.bootstrap()
        number = int(stage[6])
        if stage.endswith("-inputs"):
            return self.round_inputs(number)
        if stage.endswith("-components"):
            return self.round_components(number)
        fixture.need(stage.endswith("-close"), "component-stage-kind")
        return self.round_close(number)

    def run(self, max_new_stages=None):
        fixture.need(max_new_stages is None
                     or type(max_new_stages) is int and max_new_stages >= 0,
                     "component-max-new-stages")
        validated = fixture.validate_chain(self.root)
        completed = completed_component_prefix(self.root)
        fixture.need(validated["completed_stages"] == completed,
                     "component-builder-validated-prefix")
        built = 0
        for stage in COMPONENT_STAGES[len(completed):]:
            if max_new_stages is not None and built >= max_new_stages:
                break
            self.build_stage(stage)
            built += 1
            completed = completed_component_prefix(self.root)
        return {
            "schema": "kpb-offline-w1-component-builder-result/v1",
            "classification": fixture.CLASSIFICATION,
            "run_id": self.plan["run_id"],
            "completed_stages": completed,
            "next_stage": (None if len(completed) == len(COMPONENT_STAGES)
                           else COMPONENT_STAGES[len(completed)]),
            "new_stages_built": built,
            "genuine_transfer_output_proofs": (
                6 * sum(stage.endswith("-components")
                        for stage in completed)),
            "genuine_signature_witnesses": (
                3 * sum(stage.endswith("-components")
                        for stage in completed)),
            "aggregate_proving_key_read": False,
            "aggregate_proof_started": False,
            "network_or_funds_used": False,
            "authorization": False,
        }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--max-new-stages", type=int)
    args = parser.parse_args()
    root, plan, plan_sha = fixture.load_plan(args.root)
    fixture.need(not any(fixture.stage_path(root, stage).exists()
                         for stage in fixture.STAGES[7:]),
                 "component-builder-refuses-aggregate-or-handoff-stage")
    with Builder(root, plan, plan_sha) as builder:
        result = builder.run(args.max_new_stages)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(json.dumps({
            "status": "OFFLINE_W1_COMPONENTS_REFUSED",
            "category": type(error).__name__,
        }, sort_keys=True), flush=True)
        raise SystemExit(1)

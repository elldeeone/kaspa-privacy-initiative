#!/usr/bin/env python3
"""Strict, non-authorizing validator for the production 10x6 artifact table."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


HERE = Path(__file__).resolve().parent
CONTRACT_PATH = HERE / "privacy_measurement_selected_parent_artifact_contract.json"
MISSING_REPORT_PATH = HERE / "privacy_measurement_selected_parent_artifact_missing.json"
SCHEMA = "kpb-selected-parent-artifact-table-input/v1"
REPORT_SCHEMA = "kpb-selected-parent-artifact-missing-report/v1"
COMPONENT_NAMES = (
    "financial-core", "p1-capture", "c1-supervisor", "terminal-capture",
    "dispatcher", "producer", "observer", "owner-score", "aggregate",
    "owner-comparison",
)
FIELD_ROWS = (
    ("source", "canonical-source-archive", False),
    ("build", "reproducible-build-receipt", False),
    ("runtime", "transitive-runtime-closure", False),
    ("assets", "canonical-assets-archive", False),
    ("pinned-executable", "final-selected-child-image", True),
    ("launcher", "source-owned-launch-plan", False),
)
HEX64 = re.compile(r"[0-9a-f]{64}")


def _need(condition, label):
    if not condition:
        raise ValueError("selected-parent-artifact-table-" + label)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode()


def _repo_relative(value, label):
    _need(type(value) is str and value, label)
    parsed = PurePosixPath(value)
    _need(not parsed.is_absolute() and str(parsed) == value and
          all(part not in ("", ".", "..") for part in parsed.parts), label)
    return value


def load(path=CONTRACT_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(value, *, check_files=False):
    _need(type(value) is dict and set(value) == {
        "schema", "status", "components", "fields",
        "selected_snapshot_root", "artifacts", "enablement",
    }, "top-level")
    _need(value["schema"] == SCHEMA, "schema")
    status = value["status"]
    _need(type(status) is dict and set(status) == {
        "production_table_selected", "selected_launcher_callsite",
        "configured", "blocker",
    }, "status-fields")
    for key in ("production_table_selected", "selected_launcher_callsite",
                "configured"):
        _need(type(status[key]) is bool, "status-type")
    _need(type(status["blocker"]) is str and status["blocker"],
          "status-blocker")

    components = value["components"]
    _need(type(components) is list and len(components) == 10,
          "component-count")
    origins = {}
    for index, component in enumerate(components, 1):
        _need(type(component) is dict and set(component) == {
            "id", "name", "owner", "origin_contracts",
        }, "component-fields")
        _need(component["id"] == index and
              component["name"] == COMPONENT_NAMES[index - 1],
              "component-order")
        _need(type(component["owner"]) is str and component["owner"],
              "component-owner")
        contracts = component["origin_contracts"]
        _need(type(contracts) is list and contracts and
              len(contracts) == len(set(contracts)),
              "component-origin-contracts")
        for contract in contracts:
            _repo_relative(contract, "component-origin-contract")
        origins[index] = frozenset(contracts)

    fields = value["fields"]
    _need(type(fields) is list and len(fields) == 6, "field-count")
    for index, (field, expected) in enumerate(zip(fields, FIELD_ROWS), 1):
        _need(type(field) is dict and set(field) == {
            "id", "name", "kind", "final_executable",
        }, "field-fields")
        _need((field["id"], field["name"], field["kind"],
               field["final_executable"]) == (index, *expected),
              "field-order")

    root = value["selected_snapshot_root"]
    _need(root is None or (type(root) is str and Path(root).is_absolute() and
                           Path(root) == Path(root).resolve()),
          "snapshot-root")
    artifacts = value["artifacts"]
    _need(type(artifacts) is list, "artifacts-type")
    seen = set()
    for artifact in artifacts:
        _need(type(artifact) is dict and set(artifact) == {
            "component", "field", "path", "sha256", "origin_contract",
            "origin_contract_sha256", "final_executable",
        }, "artifact-fields")
        component, field = artifact["component"], artifact["field"]
        _need(type(component) is int and 1 <= component <= 10 and
              type(field) is int and 1 <= field <= 6 and
              (component, field) not in seen, "artifact-slot")
        seen.add((component, field))
        path = artifact["path"]
        _need(type(path) is str and root is not None and
              Path(path).is_absolute() and Path(path) == Path(path).resolve()
              and Path(path).is_relative_to(Path(root)), "artifact-path")
        _need(type(artifact["sha256"]) is str and
              HEX64.fullmatch(artifact["sha256"]) is not None,
              "artifact-sha256")
        origin = _repo_relative(
            artifact["origin_contract"], "artifact-origin-contract")
        _need(origin in origins[component], "artifact-origin-owner")
        _need(type(artifact["origin_contract_sha256"]) is str and
              HEX64.fullmatch(artifact["origin_contract_sha256"]) is not None,
              "artifact-origin-sha256")
        _need(artifact["final_executable"] is FIELD_ROWS[field - 1][2],
              "artifact-final-executable")
        if check_files:
            selected = Path(path)
            _need(selected.is_file() and not selected.is_symlink(),
                  "artifact-regular")
            _need(hashlib.sha256(selected.read_bytes()).hexdigest() ==
                  artifact["sha256"], "artifact-content")
            origin_path = HERE.parents[2] / origin
            _need(origin_path.is_file() and not origin_path.is_symlink() and
                  hashlib.sha256(origin_path.read_bytes()).hexdigest() ==
                  artifact["origin_contract_sha256"],
                  "artifact-origin-content")

    enablement = value["enablement"]
    _need(type(enablement) is dict and set(enablement) == {
        "required_entry_count", "require_exact_component_field_cross_product",
        "require_openat2_no_symlinks",
        "require_expected_sha256_before_and_after_copy",
        "require_final_executable_hashes",
        "require_same_sealed_descriptors_consumed_by_child",
        "require_verified_child_eof_and_zero_exit",
        "require_independent_review_after_complete_table",
    }, "enablement-fields")
    _need(enablement["required_entry_count"] == 60 and
          all(enablement[key] is True for key in enablement
              if key != "required_entry_count"), "enablement-policy")
    missing = 60 - len(seen)
    if missing:
        _need(not status["production_table_selected"] and
              not status["selected_launcher_callsite"] and
              not status["configured"] and
              status["blocker"] == "exact-final-artifacts-missing",
              "missing-status")
    else:
        _need(root is not None, "complete-root")
    return value


def missing_report(value):
    validate(value)
    present = {(row["component"], row["field"])
               for row in value["artifacts"]}
    missing = []
    for component in value["components"]:
        fields = []
        for field in value["fields"]:
            if (component["id"], field["id"]) not in present:
                fields.append(field["name"])
        if fields:
            missing.append({
                "component": component["id"],
                "component_name": component["name"],
                "owner": component["owner"],
                "fields": fields,
            })
    missing_count = sum(len(row["fields"]) for row in missing)
    return {
        "schema": REPORT_SCHEMA,
        "contract_sha256": hashlib.sha256(_canonical(value)).hexdigest(),
        "missing_count": missing_count,
        "complete": missing_count == 0,
        "production_table_selected":
            value["status"]["production_table_selected"],
        "selected_launcher_callsite":
            value["status"]["selected_launcher_callsite"],
        "configured": value["status"]["configured"],
        "missing": missing,
    }


def require_complete(value, *, check_files=True):
    validate(value, check_files=check_files)
    report = missing_report(value)
    _need(report["missing_count"] == 0, "missing-entries")
    _need(value["status"]["production_table_selected"],
          "table-not-selected")
    _need(value["status"]["selected_launcher_callsite"],
          "callsite-not-selected")
    _need(value["status"]["configured"], "not-configured")
    return value


if __name__ == "__main__":
    print(json.dumps(missing_report(load()), sort_keys=True, indent=2))

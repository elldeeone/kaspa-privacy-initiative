"""Public source controls only. No pipeline, private input or network access."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import controller_metadata as metadata


def run(module_source):
    checks = []
    transport = {
        "schema": "kpb-exit-transport-status/v1",
        "transport_receipt": True,
        "financial_or_chain_acceptance": False,
    }
    raw = (json.dumps(transport) + "\n").encode()
    original_decoder = metadata.json.loads
    decode_times = []

    def delayed_decoder(*args, **kwargs):
        decode_times.append(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        time.sleep(0.02)  # A PUBLIC decoder-delay control, never production scheduling.
        return original_decoder(*args, **kwargs)

    metadata.json.loads = delayed_decoder
    try:
        observation = metadata.read_observation(
            io.BytesIO(raw), reader_id="controller/transport/0", role="transport/0"
        )
    finally:
        metadata.json.loads = original_decoder
    queued = observation.copy()
    observed = queued["reader_observed_monotonic_ns"]
    consumed = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    assert observed <= decode_times[0] < consumed
    assert queued == observation and queued["value"] == transport
    checks.append({"check": "read-before-delayed-json-and-consumption", "passed": True,
                   "observed_monotonic_ns": observed, "decoder_started_monotonic_ns": decode_times[0],
                   "consumed_monotonic_ns": consumed})

    owner = {"schema": "kpb-owner-exit-pipe-status/v1", "status": "FRAME_WRITTEN",
             "financial_or_chain_acceptance": False}
    receiver = {"schema": "kpb-probe-listener-summary/v1", "accepted": 6,
                "completed": 6, "monotonic_ns": 10}
    fd = {"schema": "kpb-owner-transport-input-fd/v1", "inherited_fd": 0, "reader_fd": 3}
    for role, value in [("owner/5", owner), ("receiver/0", receiver), ("transport/3", fd)]:
        line = (json.dumps(value) + "\n").encode()
        result = metadata.read_observation(io.BytesIO(line), reader_id="controller/" + role, role=role)
        assert result["value"] == value and result["reader_pid"] == os.getpid()
    assert metadata.read_observation(io.BytesIO(b""), reader_id="controller/transport/0", role="transport/0") is None
    checks.append({"check": "selected-owner-receiver-fd-statuses-and-eof", "passed": True})

    malformed = [
        ("transport/0", dict(transport, exit_id="PUBLIC_TRIPWIRE")),
        ("transport/0", dict(transport, projection_hex="PUBLIC_TRIPWIRE")),
        ("transport/0", dict(transport, transport_receipt=False)),
        ("transport/0", dict(transport, financial_or_chain_acceptance=True)),
        ("transport/0", dict(fd, inherited_fd=True)),
        ("transport/0", dict(fd, reader_fd=0)),
        ("receiver/0", dict(receiver, completed=7)),
        ("receiver/0", dict(receiver, accepted=True)),
        ("owner/0", transport),
    ]
    refused = 0
    for role, value in malformed:
        try:
            metadata.read_observation(io.BytesIO((json.dumps(value) + "\n").encode()),
                                      reader_id="controller/" + role, role=role)
        except metadata.MetadataError as error:
            assert "PUBLIC_TRIPWIRE" not in str(error)
            refused += 1
        else:
            raise AssertionError("malformed status accepted")
    duplicate = b'{"schema":"kpb-exit-transport-status/v1","transport_receipt":false,"transport_receipt":true,"financial_or_chain_acceptance":false}\n'
    try:
        metadata.read_observation(io.BytesIO(duplicate), reader_id="controller/transport/0", role="transport/0")
    except metadata.MetadataError:
        refused += 1
    else:
        raise AssertionError("duplicate status field accepted")
    for role, reader in [("transport/6", "controller/transport/6"),
                         ("transport/01", "controller/transport/01"),
                         ("transport/0", "controller/transport/1")]:
        try:
            metadata.read_observation(io.BytesIO(raw), reader_id=reader, role=role)
        except metadata.MetadataError:
            refused += 1
        else:
            raise AssertionError("unselected role/reader accepted")
    checks.append({"check": "malformed-extra-field-cross-role-duplicate-and-label-refusals",
                   "passed": True, "refusals": refused})

    assert metadata._offsets(b"monotonic -1 999999999\nboottime 2 1\n") == {
        "monotonic_ns": -1, "boottime_ns": 2_000_000_001}
    bad_offsets = [b"monotonic 0 0\n", b"monotonic 0 0\nmonotonic 0 0\n",
                   b"monotonic 0 1000000000\nboottime 0 0\n",
                   b"monotonic 0 -1\nboottime 0 0\n",
                   b"monotonic 0.0 0\nboottime 0 0\n"]
    for offset in bad_offsets:
        try:
            metadata._offsets(offset)
        except metadata.MetadataError:
            pass
        else:
            raise AssertionError("malformed offset accepted")
    checks.append({"check": "exact-negative-second-offset-and-malformed-offset-refusals",
                   "passed": True, "refusals": len(bad_offsets)})

    parent = metadata.clock_snapshot("controller")
    child_code = module_source.decode() + "\nprint(json.dumps(clock_snapshot('transport/0'),sort_keys=True))\n"
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    child = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child_code],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, close_fds=True,
                           env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
    ended = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    assert child.returncode == 0 and not child.stderr
    snapshot = json.loads(child.stdout)
    assert snapshot["pid"] != parent["pid"] and snapshot["boot_id"] == parent["boot_id"]
    assert snapshot["time_namespace"] == parent["time_namespace"]
    assert snapshot["time_for_children_namespace"] == parent["time_for_children_namespace"]
    assert snapshot["timens_offsets"] == parent["timens_offsets"]
    assert started <= snapshot["sample"]["monotonic_before_ns"] <= snapshot["sample"]["monotonic_after_ns"] <= ended
    checks.append({"check": "actual-public-parent-and-child-kernel-clock-evidence", "passed": True,
                   "public_control_only_not_pipeline_capture": True,
                   "parent": parent, "child": snapshot})

    original_namespace = metadata._namespace
    metadata._namespace = lambda name: {"link": "time:[" + ("101" if name == "time" else "202") + "]",
                                        "inode": 101 if name == "time" else 202}
    try:
        ambiguous = metadata.clock_snapshot("receiver/0")
    finally:
        metadata._namespace = original_namespace
    assert ambiguous["time_namespace"] != ambiguous["time_for_children_namespace"]
    assert "clockQualified" not in ambiguous and "normalized_monotonic_ns" not in ambiguous
    checks.append({"check": "synthetic-current-child-namespace-difference-retained-without-qualification",
                   "passed": True})
    return {"schema": "kpb-method03-controller-metadata-public-controls/v1",
            "classification": "SOURCE_PUBLIC_CONTROLS_ONLY_NOT_METHOD03_EXECUTION",
            "private_input": False, "pipeline_execution": False, "network": False,
            "checks": checks, "all_passed": True}

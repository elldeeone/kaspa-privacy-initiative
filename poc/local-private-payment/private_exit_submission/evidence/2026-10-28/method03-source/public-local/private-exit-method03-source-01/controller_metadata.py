"""Source-only METHOD03 fixed-status and kernel-clock capture.

The selected caller admits this stdlib-only file before importing it. This
module reads only a selected fixed-status pipe or fixed public procfs leaves.
It never opens a candidate/frame, derives a content identifier, launches a
role, chooses a schedule, normalizes clocks, or grants qualification.
"""

import json
import os
from pathlib import Path
import re
import time
import uuid


class MetadataError(ValueError):
    """A fixed category only; never include the rejected line or value."""


_ROLE = re.compile(r"(?:controller|receiver/0|(?:transport|owner)/[0-5])\Z")
_NAMESPACE = re.compile(r"time:\[([1-9][0-9]*)\]\Z")
_SIGNED_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _need(condition, category):
    if not condition:
        raise MetadataError(category)


def _role(role):
    _need(type(role) is str and _ROLE.fullmatch(role) is not None, "fixed-role-key")
    return role


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _fixed_status(value, role):
    """Only existing role statuses, with no extension/body/digest fields."""
    _need(type(value) is dict, "fixed-status-object")
    kind = role.split("/", 1)[0]
    schema = value.get("schema")
    if kind == "owner" and schema == "kpb-owner-exit-pipe-status/v1":
        valid = (
            set(value) == {"schema", "status", "financial_or_chain_acceptance"}
            and value["status"] in ("FRAME_WRITTEN", "REFUSED")
            and value["financial_or_chain_acceptance"] is False
        )
    elif kind == "transport" and schema == "kpb-exit-transport-status/v1":
        valid = (
            set(value) == {"schema", "transport_receipt", "financial_or_chain_acceptance"}
            and value["transport_receipt"] is True
            and value["financial_or_chain_acceptance"] is False
        )
    elif kind == "transport" and schema == "kpb-owner-transport-input-fd/v1":
        valid = (
            set(value) == {"schema", "inherited_fd", "reader_fd"}
            and type(value["inherited_fd"]) is int and value["inherited_fd"] == 0
            and _integer(value["reader_fd"], 3)
        )
    elif kind == "receiver" and schema == "kpb-probe-listener/v1":
        valid = (
            set(value) == {"schema", "port", "monotonic_ns"}
            and _integer(value["port"], 1) and value["port"] <= 65535
            and _integer(value["monotonic_ns"])
        )
    elif kind == "receiver" and schema == "kpb-probe-listener-summary/v1":
        valid = (
            set(value) == {"schema", "accepted", "completed", "monotonic_ns"}
            and all(_integer(value[key]) for key in ("accepted", "completed", "monotonic_ns"))
            and value["completed"] <= value["accepted"]
        )
    else:
        valid = False
    _need(valid, "unselected-or-malformed-fixed-status")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate-fixed-status-field")
        result[key] = value
    return result


def read_observation(stream, *, reader_id, role):
    """Read one selected status line; timestamp before parsing or queueing.

    Owner input MUST be its fixed-status stderr2, never its frame stdout1.
    Transport input is its fixed-status stdout, receiver input its status
    stdout. The selected launcher must prove those pipe bindings. None means
    EOF; it is not a successful receipt. Invalid lines raise a fixed category
    without returning, hashing or recording their contents.
    """
    _role(role)
    _need(reader_id == "controller/" + role, "fixed-reader-key")
    raw = stream.readline()
    # These are the first operations after the blocking read completes. In
    # particular, no JSON decoder, logging, queue or scheduler wait precedes it.
    observed_monotonic = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    observed_realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
    observed_boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if raw == b"":
        return None
    _need(type(raw) is bytes and raw.endswith(b"\n"), "fixed-status-binary-line")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except MetadataError:
        raise
    except (ValueError, UnicodeError):
        raise MetadataError("fixed-status-json") from None
    _fixed_status(value, role)
    return {
        "schema": "kpb-method03-status-observation/v1",
        "reader_id": reader_id,
        "role": role,
        "reader_pid": os.getpid(),
        "reader_observed_monotonic_ns": observed_monotonic,
        "reader_observed_realtime_ns": observed_realtime,
        "reader_observed_boottime_ns": observed_boottime,
        "value": value,
    }


def _offsets(raw):
    """Parse kernel seconds/nanoseconds exactly, including negative seconds."""
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise MetadataError("kernel-clock-offset-encoding") from None
    values = {}
    for line in lines:
        fields = line.split()
        _need(len(fields) == 3, "kernel-clock-offset-row")
        name, seconds, nanoseconds = fields
        _need(name in ("monotonic", "boottime") and name not in values,
              "kernel-clock-offset-name")
        _need(_SIGNED_INTEGER.fullmatch(seconds) is not None
              and _UNSIGNED_INTEGER.fullmatch(nanoseconds) is not None,
              "kernel-clock-offset-integer")
        nanos = int(nanoseconds)
        _need(nanos < 1_000_000_000, "kernel-clock-offset-nanosecond-range")
        values[name + "_ns"] = int(seconds) * 1_000_000_000 + nanos
    _need(set(values) == {"monotonic_ns", "boottime_ns"}, "kernel-clock-offset-closure")
    return values


def _namespace(name):
    path = Path("/proc/self/ns") / name
    link = os.readlink(path)
    match = _NAMESPACE.fullmatch(link)
    _need(match is not None, "kernel-time-namespace-link")
    inode = path.stat().st_ino
    _need(inode == int(match.group(1)), "kernel-time-namespace-inode")
    return {"link": link, "inode": inode}


def clock_snapshot(role):
    """Capture the actual calling role's clocks; never a proxy process.

    timens_offsets describes time_for_children. It can describe this role's
    current clock only when both namespace identities agree. Both identities
    remain in the record even when different; the independent extractor must
    refuse ambiguous comparison unless Root froze separate calibration first.
    This function makes no clockQualified assertion and applies no offsets.
    """
    _role(role)
    try:
        current = _namespace("time")
        children = _namespace("time_for_children")
        offsets = _offsets(Path("/proc/self/timens_offsets").read_bytes())
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        _need(str(uuid.UUID(boot_id)) == boot_id, "kernel-boot-identity")
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
        boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        after = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        _need(after >= before, "kernel-monotonic-sample-order")
        _need(current == _namespace("time") and children == _namespace("time_for_children")
              and offsets == _offsets(Path("/proc/self/timens_offsets").read_bytes()),
              "kernel-clock-evidence-changed")
    except MetadataError:
        raise
    except (OSError, ValueError, AttributeError):
        raise MetadataError("kernel-clock-evidence-unavailable") from None
    return {
        "schema": "kpb-method03-clock-snapshot/v1",
        "role": role,
        "pid": os.getpid(),
        "boot_id": boot_id,
        "clock_id": "CLOCK_MONOTONIC",
        "time_namespace": current,
        "time_for_children_namespace": children,
        "timens_offsets": offsets,
        "sample": {
            "monotonic_before_ns": before,
            "realtime_ns": realtime,
            "boottime_ns": boottime,
            "monotonic_after_ns": after,
        },
    }


def _clock_record(value, role):
    """Validate a finite raw clock record, without qualifying its clocks."""
    _need(type(value) is dict and set(value) == {
        "schema", "role", "pid", "boot_id", "clock_id", "time_namespace",
        "time_for_children_namespace", "timens_offsets", "sample",
    }, "exact-clock-record-fields")
    _need(value["schema"] == "kpb-method03-clock-snapshot/v1"
          and value["role"] == role and _integer(value["pid"], 1)
          and value["clock_id"] == "CLOCK_MONOTONIC", "clock-record-role-and-kind")
    try:
        valid_boot = type(value["boot_id"]) is str and str(uuid.UUID(value["boot_id"])) == value["boot_id"]
    except ValueError:
        valid_boot = False
    _need(valid_boot, "clock-record-boot-identity")
    for key in ("time_namespace", "time_for_children_namespace"):
        namespace = value[key]
        _need(type(namespace) is dict and set(namespace) == {"link", "inode"}
              and type(namespace["link"]) is str and _integer(namespace["inode"], 1),
              "clock-record-namespace-fields")
        match = _NAMESPACE.fullmatch(namespace["link"])
        _need(match is not None and int(match.group(1)) == namespace["inode"],
              "clock-record-namespace-identity")
    offsets = value["timens_offsets"]
    _need(type(offsets) is dict and set(offsets) == {"monotonic_ns", "boottime_ns"}
          and all(type(number) is int for number in offsets.values()), "clock-record-offset-fields")
    sample = value["sample"]
    _need(type(sample) is dict and set(sample) == {
        "monotonic_before_ns", "realtime_ns", "boottime_ns", "monotonic_after_ns",
    } and all(type(number) is int for number in sample.values()), "clock-record-sample-fields")
    _need(sample["monotonic_before_ns"] <= sample["monotonic_after_ns"], "clock-record-sample-order")
    # A mismatch is faithfully retained. Only the independently selected
    # extractor/calibration may decide whether any comparison is supported.


def read_public_event(stream, *, reader_id, role):
    """Same immediate-read envelope, with a strict clock-or-status union.

    NEW wrappers emit their clock first on the existing selected status pipe:
    owner stderr2; transport stdout1; receiver stdout1. Never owner frame1.
    Existing read_observation remains the status-only API unchanged.
    """
    _role(role)
    _need(type(reader_id) is str and reader_id == "controller/" + role, "fixed-reader-key")
    raw = stream.readline()
    observed_monotonic = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    observed_realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
    observed_boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if raw == b"":
        return None
    _need(type(raw) is bytes and raw.endswith(b"\n"), "fixed-status-binary-line")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except MetadataError:
        raise
    except (ValueError, UnicodeError):
        raise MetadataError("fixed-status-json") from None
    if type(value) is dict and value.get("schema") == "kpb-method03-clock-snapshot/v1":
        _clock_record(value, role)
    else:
        _fixed_status(value, role)
    return {
        "schema": "kpb-method03-status-observation/v1",
        "reader_id": reader_id,
        "role": role,
        "reader_pid": os.getpid(),
        "reader_observed_monotonic_ns": observed_monotonic,
        "reader_observed_realtime_ns": observed_realtime,
        "reader_observed_boottime_ns": observed_boottime,
        "value": value,
    }

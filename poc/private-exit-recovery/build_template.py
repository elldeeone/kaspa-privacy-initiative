#!/usr/bin/env python3
"""Prepare the new template from already compiled public source; no VM/setup."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / "research/next-session/privacy-recovery/native/private-native-inspection-01/union-redeem.bin"
SOURCE_SHA = "a15eaccad2a314a40216d11d525f98b4b6b820d9dd1230407fb5c9a49ed20454"
DOMAIN = bytes.fromhex("aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2")


def pushes(raw):
    at = 0
    while at < len(raw):
        opcode_at, opcode = at, raw[at]
        at += 1
        if 1 <= opcode <= 75:
            length = opcode
        elif opcode in (76, 77, 78):
            width = {76: 1, 77: 2, 78: 4}[opcode]
            if at + width > len(raw):
                raise ValueError("truncated-template-push-length")
            length = int.from_bytes(raw[at:at + width], "little")
            at += width
            if length < {76: 76, 77: 256, 78: 65536}[opcode]:
                raise ValueError("noncanonical-template-push")
        else:
            continue
        if at + length > len(raw):
            raise ValueError("truncated-template-push-data")
        yield opcode_at, at, raw[at:at + length]
        at += length


def main():
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA or len(raw) != 24417 or raw[:10] != b"\x4c\x70KPX2ST01":
        raise ValueError("selected-source-program-identity")
    template = bytearray(raw[114:])
    slots = []
    for opcode, data, value in pushes(template):
        kind = "domain" if value == DOMAIN and template[opcode] == 32 else "vk" if len(value) == 328 else None
        if kind:
            if kind == "vk" and (value != bytes(328) or template[opcode:data] != b"\x4d\x48\x01"):
                raise ValueError("source-VK-operand")
            slots.append({"kind": kind, "opcode_offset": opcode, "data_offset": data, "bytes": len(value)})
            template[data:data + len(value)] = bytes(len(value))
    if sum(slot["kind"] == "domain" for slot in slots) != 10 or sum(slot["kind"] == "vk" for slot in slots) != 1:
        raise ValueError("source-template-slot-count")
    metadata = {"schema": "kpx3-approved-policy-template/v1", "whole_program_bytes": 24417,
                "state_prefix_bytes": 114, "template_bytes": len(template), "domain_push_count": 10,
                "vk_push_count": 1, "patch_slots": slots, "source_program_sha256": SOURCE_SHA,
                "source_program": str(SOURCE.relative_to(ROOT)), "template_sha256": hashlib.sha256(template).hexdigest()}
    for name, data in (("kpx3-policy-template.bin", bytes(template)),
                       ("kpx3-policy-template.json", (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode())):
        with (HERE / name).open("xb") as file:
            file.write(data)
    print(json.dumps({"template_sha256": metadata["template_sha256"],
                      "manifest_sha256": hashlib.sha256((HERE / "kpx3-policy-template.json").read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()

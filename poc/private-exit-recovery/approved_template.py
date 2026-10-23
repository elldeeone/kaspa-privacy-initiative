"""Entire new native program authority, with explicit state/domain/VK slots."""
import hashlib
import json
from pathlib import Path

from selected_identities import TEMPLATE_SHA, TEMPLATE_MANIFEST_SHA

HERE = Path(__file__).resolve().parent


def approved_policy(domain, vk):
    if type(domain) is not bytes or len(domain) != 32 or type(vk) is not bytes or len(vk) != 328:
        raise ValueError("new-approved-policy-parameter-width")
    raw = (HERE / "kpx3-policy-template.json").read_bytes()
    template = (HERE / "kpx3-policy-template.bin").read_bytes()
    if hashlib.sha256(raw).hexdigest() != TEMPLATE_MANIFEST_SHA or hashlib.sha256(template).hexdigest() != TEMPLATE_SHA:
        raise ValueError("new-approved-policy-software-identity")
    manifest = json.loads(raw)
    if (manifest["schema"] != "kpx3-approved-policy-template/v1" or manifest["whole_program_bytes"] != 24417
            or manifest["template_bytes"] != len(template) or len(template) != 24303):
        raise ValueError("new-approved-policy-shape")
    result, seen, counts = bytearray(template), set(), {"domain": 0, "vk": 0}
    for slot in manifest["patch_slots"]:
        kind, at, opcode = slot["kind"], slot["data_offset"], slot["opcode_offset"]
        value = domain if kind == "domain" else vk if kind == "vk" else None
        if (value is None or len(value) != slot["bytes"] or at in seen
                or not 0 <= opcode < at < len(template) or template[at:at + len(value)] != bytes(len(value))
                or kind == "domain" and (at != opcode + 1 or template[opcode] != 32)
                or kind == "vk" and (at != opcode + 3 or template[opcode:at] != b"\x4d\x48\x01")):
            raise ValueError("new-approved-policy-patch-slot")
        seen.add(at)
        counts[kind] += 1
        result[at:at + len(value)] = value
    if counts != {"domain": 10, "vk": 1}:
        raise ValueError("new-approved-policy-patch-count")
    return bytes(result)

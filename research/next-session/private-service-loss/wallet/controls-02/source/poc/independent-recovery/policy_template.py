"""Approved stateless KPX2 policy; no operator state or key material."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
MANIFEST_SHA256 = "5f8e5354565c0545cfd6e6455958cbf955daa14d7982ac5c338673cc5a5a19bf"
TEMPLATE_SHA256 = "8b0e6dd802b58400fdfd9fcc11cff2ef6e4a27659c973ff3d0b1bf946fcfda46"


def approved_policy(domain: bytes, vk: bytes) -> bytes:
    if type(domain) is not bytes or len(domain) != 32 or type(vk) is not bytes or len(vk) != 328:
        raise ValueError("approved-policy-parameter-width")
    raw = (HERE / "kpx2-policy-template.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("approved-policy-manifest-identity")
    manifest = json.loads(raw)
    template = (HERE / "kpx2-policy-template.bin").read_bytes()
    if (manifest["schema"] != "kpx2-approved-policy-template/v1"
            or hashlib.sha256(template).hexdigest() != TEMPLATE_SHA256
            or len(template) != manifest["template_bytes"]
            or manifest["domain_push_count"] != 10 or manifest["vk_push_count"] != 1):
        raise ValueError("approved-policy-template-identity")
    result = bytearray(template)
    seen = set()
    counts = {"domain": 0, "vk": 0}
    for slot in manifest["patch_slots"]:
        kind = slot["kind"]
        value = domain if kind == "domain" else vk if kind == "vk" else None
        at = slot["data_offset"]
        opcode = slot["opcode_offset"]
        if (value is None or len(value) != slot["bytes"] or at in seen
                or not 0 <= opcode < at < len(template)
                or template[at:at + len(value)] != bytes(len(value))
                or (kind == "domain" and (at != opcode + 1 or template[opcode] != 32))
                or (kind == "vk" and (at != opcode + 3 or template[opcode:at] != b"\x4d\x48\x01"))):
            raise ValueError("approved-policy-patch-slot")
        seen.add(at)
        counts[kind] += 1
        result[at:at + len(value)] = value
    if counts != {"domain": 10, "vk": 1}:
        raise ValueError("approved-policy-patch-count")
    return bytes(result)

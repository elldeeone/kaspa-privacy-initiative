"""Close this lane's public source/data packet after all owned jobs stop.

Never follows symlinks or includes compiled executables/proving keys. Manifest
and allowlist indices exclude themselves from payload hashing, then list both
indices explicitly. Existing indices are never overwritten.
"""
from pathlib import Path
import datetime
import hashlib
import json

REPO = Path(__file__).resolve().parents[2]
EVIDENCE = REPO / "research/next-session/private-integration/lifecycle"
ROOTS = [REPO / "poc/future-lifecycle", EVIDENCE]


def main():
    manifest_path = EVIDENCE / "MANIFEST.json"
    allowlist_path = EVIDENCE / "PUBLIC-FILES.txt"
    if manifest_path.exists() or allowlist_path.exists():
        raise ValueError("publication indices already exist; do not overwrite")
    files = []
    for root in ROOTS:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError("symlink in public packet")
            if path.is_dir():
                if path.name in ("target", "__pycache__", ".git"):
                    raise ValueError("build/cache directory in public packet")
                continue
            data = path.read_bytes()
            if (path.suffix in (".pk", ".elf", ".pyc") or data[:4] == b"\x7fELF"
                    or len(data) >= 100 * 1024 * 1024):
                raise ValueError("private key/compiled/oversized output in public packet")
            relative = str(path.relative_to(REPO))
            if "\n" in relative or "\r" in relative:
                raise ValueError("ambiguous publication path")
            files.append({"path": relative, "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    files.sort(key=lambda item: item["path"])
    manifest = {
        "schema": "future-private-native-lifecycle-public-packet/v1",
        "classification": "PUBLIC_SYNTHETIC_DO_NOT_FUND",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "baseline_commit": "0c2f4c788a4274b381c4838e05cce5e9c32e8536",
        "files": files, "payload_members": len(files),
        "payload_bytes": sum(item["bytes"] for item in files),
        "indices_excluded_from_payload_hashing": ["MANIFEST.json", "PUBLIC-FILES.txt"],
        "PK_or_compiled_executable_included": False,
        "accepted_chain_backing_or_privacy_qualification": False,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    paths = [item["path"] for item in files] + [str(manifest_path.relative_to(REPO)),
                                               str(allowlist_path.relative_to(REPO))]
    allowlist_path.write_text("\n".join(sorted(paths)) + "\n")
    print(json.dumps({"payload_members": len(files), "publication_paths": len(paths),
        "payload_bytes": manifest["payload_bytes"],
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "allowlist_sha256": hashlib.sha256(allowlist_path.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()

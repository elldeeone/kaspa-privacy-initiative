#!/usr/bin/env python3
"""Run the read-only JS client from the ordinary SHA-authenticated trusted-release Node ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
raw = (HERE / "trusted_runtime.py").read_bytes()
if hashlib.sha256(raw).hexdigest() != "3ce31ae0eb8f942009a4108f9a5dbb6a08df6c7f0925f06a952315091e1bbd1c":
    raise ValueError("selected-network-runtime-source")
runtime = types.ModuleType("_kpx3_fetch_trusted_runtime")
exec(compile(raw, str(HERE / "trusted_runtime.py"), "exec"), vars(runtime))
NODE_SHA256 = "d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c"


def main():
    parser = argparse.ArgumentParser(description="Public descriptor/manifest only; never a key or backup")
    parser.add_argument("descriptor"); parser.add_argument("public_manifest"); parser.add_argument("new_output")
    parser.add_argument("--rpc", action="append", default=[])
    args = parser.parse_args()
    command = ["--use-openssl-ca", HERE / "fetch.mjs", args.descriptor, args.public_manifest, args.new_output]
    for endpoint in args.rpc:
        command.extend(["--rpc", endpoint])
    with runtime.TrustedExecutable("/node", NODE_SHA256) as node:
        receipt = {**node.receipt(), "node_cli_ca_option": "--use-openssl-ca",
                   "public_parameter_blob_read": False, "network_read_only": True}
        with (Path(args.new_output).parent / "TRUSTED-NODE-RUNTIME.json").open("x") as file:
            json.dump(receipt, file, sort_keys=True, indent=2); file.write("\n")
        process = node.run(command)
        sys.stdout.write(process.stdout); sys.stderr.write(process.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()

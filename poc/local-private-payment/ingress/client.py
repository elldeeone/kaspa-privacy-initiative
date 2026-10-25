#!/usr/bin/env python3
"""CLI boundary for validated public requests; private wallets never imported."""
import argparse
import asyncio
import json
import sys

from tor_ingress import IngressError, TorIngress


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IngressError("duplicate JSON fields are not canonical")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True, help="selected public wss JSON endpoint")
    parser.add_argument("--method", required=True)
    parser.add_argument("--proxy-port", type=int, default=19050)
    parser.add_argument("--broadcast", action="store_true", help="requires root execution release")
    args = parser.parse_args()
    try:
        params = json.load(sys.stdin, object_pairs_hook=unique_object)
        result = asyncio.run(TorIngress(proxy_port=args.proxy_port).rpc(
            args.rpc, args.method, params, allow_broadcast=args.broadcast))
        json.dump({"ok": True, "params": result}, sys.stdout, separators=(",", ":"), allow_nan=False)
        sys.stdout.write("\n")
    except (IngressError, ValueError, TypeError):
        # Public request/response bodies and Tor credentials are never echoed.
        json.dump({"ok": False, "error": "public Tor request failed; no fallback or automatic replay"}, sys.stdout)
        sys.stdout.write("\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

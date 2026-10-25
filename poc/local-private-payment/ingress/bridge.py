#!/usr/bin/env python3
"""One official-SDK connection to a selected native testnet peer through Tor.

Frames are forwarded unchanged. No Borsh/JSON codec or wallet code is imported.
The controlling chain adapter must supply public SDK RPCs only, check network/
accepted history, and enforce execution release before submission or mining.
"""
import argparse
import asyncio
import json
import logging
import ssl
from urllib.parse import urlsplit

from tor_ingress import IngressError, TorIngress, _url
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve


class NoRedirectConnect(connect):
    def process_redirect(self, exc):
        return exc


async def run_bridge(upstream, proxy_port):
    _url(upstream, "wss")
    if urlsplit(upstream).path not in {
        "/kaspa/testnet-10/wrpc/borsh", "/kaspa/testnet-10/wrpc/json"
    }:
        raise IngressError("selected testnet-10 native RPC path required")
    ingress = TorIngress(proxy_port=proxy_port, timeout=None)
    quiet = logging.Logger("public-tor-frame-bridge", level=logging.CRITICAL + 1)
    quiet.addHandler(logging.NullHandler())
    completed = asyncio.Event()
    accepted = False
    result = {"ok": False}

    async def forward(source, target):
        async for frame in source:
            await target.send(frame)  # bytes remain bytes; text remains text.

    async def handle(local):
        nonlocal accepted
        if accepted:
            await local.close(code=1008)
            return
        accepted = True
        # Stop new listeners while preserving this already accepted connection.
        server.close(close_connections=False)
        try:
            async with NoRedirectConnect(
                upstream, proxy=ingress._proxy(), ssl=ssl.create_default_context(),
                user_agent_header=None, additional_headers=None, compression=None,
                open_timeout=None, ping_interval=None, ping_timeout=None,
                max_size=None, logger=quiet,
            ) as remote:
                tasks = [asyncio.create_task(forward(local, remote)),
                         asyncio.create_task(forward(remote, local))]
                try:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        task.result()
                    result["ok"] = True
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            # No peer messages, connection addresses or isolation labels logged.
            await local.close(code=1011, reason="Tor upstream unavailable; no fallback")
        finally:
            completed.set()

    async with serve(handle, "127.0.0.1", 0, compression=None, ping_interval=None,
                     max_size=None, logger=quiet) as server:
        port = server.sockets[0].getsockname()[1]
        print(json.dumps({"ready": True, "url": f"ws://127.0.0.1:{port}",
                          "transport": "TOR_SOCKS5H_TLS", "sessions": 1}), flush=True)
        await completed.wait()
    return result["ok"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--proxy-port", type=int, default=19050)
    args = parser.parse_args()
    try:
        ok = asyncio.run(run_bridge(args.upstream, args.proxy_port))
    except Exception:
        ok = False
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

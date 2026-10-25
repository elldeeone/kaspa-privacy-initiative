"""Local public-frame bridge controls; no external requests or wallet data."""
import asyncio
import contextlib
import io
import json
import ssl
import unittest
from unittest.mock import patch

from bridge import run_bridge
from websockets.asyncio.client import connect


class BridgeControls(unittest.IsolatedAsyncioTestCase):
    async def start(self):
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()
        self.task = asyncio.create_task(run_bridge(
            "wss://public-fixture.invalid/kaspa/testnet-10/wrpc/borsh", 19050))
        for _ in range(100):
            if self.output.getvalue():
                return json.loads(self.output.getvalue())["url"]
            await asyncio.sleep(0.001)
        raise AssertionError("local bridge did not become ready")

    async def asyncTearDown(self):
        if hasattr(self, "task") and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        if hasattr(self, "capture"):
            self.capture.__exit__(None, None, None)

    async def test_frames_remain_unchanged_and_only_one_local_session(self):
        options = []
        received = []

        class Remote:
            def __init__(self, url, **kwargs):
                options.append(kwargs)
                self.frames = asyncio.Queue()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def __aiter__(self):
                return self

            async def __anext__(self):
                return await self.frames.get()

            async def send(self, frame):
                received.append(frame)
                await self.frames.put(frame)

        with patch("bridge.NoRedirectConnect", Remote):
            url = await self.start()
            async with connect(url, proxy=None) as local:
                for frame in [b"\x00\xffpublic binary fixture", '{"public":"text fixture"}']:
                    await local.send(frame)
                    self.assertEqual(await local.recv(), frame)
                with self.assertRaises(OSError):
                    async with connect(url, proxy=None):
                        pass
            self.assertTrue(await asyncio.wait_for(self.task, 2))
        self.assertEqual(received, [b"\x00\xffpublic binary fixture", '{"public":"text fixture"}'])
        self.assertEqual(len(options), 1)
        self.assertTrue(options[0]["proxy"].startswith("socks5h://"))
        self.assertEqual(options[0]["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(options[0]["ssl"].check_hostname)
        self.assertIsNone(options[0]["additional_headers"])
        self.assertIsNone(options[0]["user_agent_header"])

    async def test_upstream_failure_closes_session_without_retry(self):
        attempts = []

        class Unavailable:
            def __init__(self, *args, **kwargs):
                attempts.append(kwargs)

            async def __aenter__(self):
                raise OSError("public fixture unavailable")

            async def __aexit__(self, *args):
                return False

        with patch("bridge.NoRedirectConnect", Unavailable):
            url = await self.start()
            async with connect(url, proxy=None) as local:
                with self.assertRaises(Exception):
                    await local.recv()
            self.assertFalse(await asyncio.wait_for(self.task, 2))
        self.assertEqual(len(attempts), 1)

    async def test_bridge_rejects_mainnet_or_identified_upstream(self):
        for upstream in ["wss://public-fixture.invalid/kaspa/mainnet/wrpc/borsh",
                         "wss://user:pass@public-fixture.invalid/kaspa/testnet-10/wrpc/borsh"]:
            with self.subTest(upstream=upstream), self.assertRaises(Exception):
                await run_bridge(upstream, 19050)

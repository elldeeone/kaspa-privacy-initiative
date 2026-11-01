#!/usr/bin/env python3
"""Black-box controls for the private C03 preservation worker."""

import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
SINK = HERE.parent / 'control_only_p1_capture_sink.py'


def frame(sequence, message, record_type, semantic, payload, now):
    header = bytearray(112)
    header[:8] = b'KPBP1C03'
    header[8:13] = bytes((record_type, semantic, 3, 255, 3))
    header[16:24] = struct.pack('>Q', now)
    header[24:32] = struct.pack('>Q', sequence)
    header[32:40] = struct.pack('>Q', message)
    header[40:44] = struct.pack('>I', 0)
    header[44:48] = struct.pack('>I', len(payload))
    header[80:112] = hashlib.sha256(payload).digest()
    return bytes(header) + payload


class ControlOnlyP1CaptureSinkControls(unittest.TestCase):
    def test_complete_stream_is_preserved_privately_without_authority(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-control-p1-sink-') as temporary:
            root = Path(temporary)
            socket_path = root / 'capture.sock'
            raw_path = root / 'private.c03'
            receipt_path = root / 'PUBLIC.json'
            process = subprocess.Popen([
                sys.executable, str(SINK), '--socket', str(socket_path),
                '--raw-output', str(raw_path), '--receipt', str(receipt_path),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True)
            for _ in range(100):
                if socket_path.exists():
                    break
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            self.assertTrue(socket_path.exists())
            hello = bytes(236)
            expected = (frame(0, 0, 1, 1, hello, 1) +
                        frame(1, 1, 5, 9, b'', 2))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(expected)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual((process.returncode, stdout, stderr),
                             (0, b'', b''))
            self.assertEqual(raw_path.read_bytes(), expected)
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(receipt, {
                'schema': 'kpb-p1-control-only-private-capture/v1',
                'status': 'CONTROL_ONLY_UNREGISTERED_CAPTURED',
                'c03_sha256': hashlib.sha256(expected).hexdigest(),
                'c03_bytes': len(expected),
                'frame_count': 2,
                'configured': False,
                'launch_authorized': False,
                'actual_receipt_enabled': False,
                'serialized_receipt_is_authority': False,
                'raw_capture_path_exported': False,
                'raw_capture_body_exported': False,
            })

    def test_truncation_is_retained_but_never_receipted_as_complete(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-control-p1-sink-truncated-') as temporary:
            root = Path(temporary)
            socket_path = root / 'capture.sock'
            raw_path = root / 'private.c03'
            receipt_path = root / 'PUBLIC.json'
            process = subprocess.Popen([
                sys.executable, str(SINK), '--socket', str(socket_path),
                '--raw-output', str(raw_path), '--receipt', str(receipt_path),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True)
            for _ in range(100):
                if socket_path.exists():
                    break
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b'KPBP1C03' + bytes(7))
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(receipt_path.exists())
            self.assertFalse(raw_path.exists())
            self.assertTrue(raw_path.with_suffix('.c03.incomplete').exists())

    def test_target_race_never_overwrites_existing_private_file(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-control-p1-sink-race-') as temporary:
            root = Path(temporary)
            socket_path = root / 'capture.sock'
            raw_path = root / 'private.c03'
            receipt_path = root / 'PUBLIC.json'
            process = subprocess.Popen([
                sys.executable, str(SINK), '--socket', str(socket_path),
                '--raw-output', str(raw_path), '--receipt', str(receipt_path),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True)
            for _ in range(100):
                if socket_path.exists():
                    break
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            raw_path.write_bytes(b'do-not-overwrite')
            expected = (frame(0, 0, 1, 1, bytes(236), 1) +
                        frame(1, 1, 5, 9, b'', 2))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(expected)
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(raw_path.read_bytes(), b'do-not-overwrite')
            self.assertFalse(receipt_path.exists())
            self.assertEqual(
                raw_path.with_suffix('.c03.incomplete').read_bytes(),
                expected)


if __name__ == '__main__':
    unittest.main()

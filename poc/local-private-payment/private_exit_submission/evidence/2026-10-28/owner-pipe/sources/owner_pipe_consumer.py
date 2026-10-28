#!/usr/bin/env python3
"""Network-off functionality consumer. It exports fixed status, never bytes/IDs."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, '/app')
import packet


def main():
    good = False
    try:
        interfaces = [line.split(':', 1)[0].strip()
                      for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
        if interfaces != ['lo'] or Path('/candidate').exists() or Path('/original').exists():
            raise ValueError('network-off-empty-consumer-namespace')
        frame = bytearray()
        while len(frame) <= packet.FRAME_BYTES:
            part = os.read(0, packet.FRAME_BYTES + 1 - len(frame))
            if not part:
                break
            frame.extend(part)
        os.close(0)
        packet.decode(bytes(frame))
        good = True
    except BaseException:
        pass
    print(json.dumps({'schema': 'kpb-owner-pipe-consumer-status/v1', 'frame_decoded': good,
                      'financial_or_chain_acceptance': False}, sort_keys=True), flush=True)
    raise SystemExit(0 if good else 1)


if __name__ == '__main__':
    main()

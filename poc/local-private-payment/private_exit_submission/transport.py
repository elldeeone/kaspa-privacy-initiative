"""Public-candidate-only Tor transport role; no signer, wallet or broadcaster.

An eventual selected launcher must supply the empty no-Original namespace and
authenticate curl/runtime before this entry. This prototype grants no acceptance
authority. No network invocation has been qualified merely by defining it.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from urllib.parse import urlsplit

import packet


def endpoint(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or parsed.path != '/exit'
        or not re.fullmatch('[a-z2-7]{56}\\.onion', parsed.hostname or '')
        or parsed.port not in (None, 80)):
        raise ValueError('fixed onion Exit endpoint required')
    return value


def proxy(value):
    if not re.fullmatch('127\\.0\\.0\\.1:[1-9][0-9]{0,4}', value):
        raise ValueError('selected loopback SOCKS endpoint required')
    if int(value.rsplit(':', 1)[1]) > 65535:
        raise ValueError('SOCKS port range')
    return value


def sealed(raw, label):
    fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), 'wb') as output:
            output.write(raw)
            output.flush()
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def submit(frame, destination, socks, curl):
    packet.decode(frame)
    destination, socks = endpoint(destination), proxy(socks)
    # Tokens are private to this transport process and never appear in argv,
    # public receipts or dispatcher data. They distinguish independent streams.
    isolation = secrets.token_hex(32) + ':' + secrets.token_hex(32)
    config = ('proxy-user = "' + isolation + '"\n').encode('ascii')
    frame_fd, config_fd = None, None
    try:
        frame_fd = sealed(frame, 'kpb-public-exit-frame')
        config_fd = sealed(config, 'kpb-socks-isolation')
        argv = [str(curl), '-q', '--silent', '--show-error', '--http1.0',
            '--socks5-hostname', socks, '--noproxy', '', '--socks5-basic',
            '--config', '/proc/self/fd/' + str(config_fd),
            '--proto', '=http', '--max-redirs', '0', '--retry', '0',
            '--user-agent', 'kpb-exit-transport/1', '--header', 'Accept: application/octet-stream',
            '--header', 'Content-Type: application/octet-stream', '--header', 'Expect:',
            '--data-binary', '@/proc/self/fd/' + str(frame_fd),
            '--output', '/dev/null', '--write-out', '%{http_code}', destination]
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(frame_fd, config_fd),
            env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'HOME':'/tmp'})
        # 202 is receipt of an UNTRUSTED packet only. No proof/chain/transaction
        # acceptance or candidate identifier is exported to the controller.
        if done.returncode != 0 or done.stdout != b'202':
            raise RuntimeError('anonymous transport did not return a receipt')
    finally:
        if frame_fd is not None:
            os.close(frame_fd)
        if config_fd is not None:
            os.close(config_fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frame-fd', required=True, type=int)
    parser.add_argument('--onion-endpoint', required=True)
    parser.add_argument('--socks', required=True)
    parser.add_argument('--selected-curl', required=True)
    args = parser.parse_args()
    marker = Path('/NO-ORIGINAL-PUBLIC-TRANSPORT')
    if not marker.is_file() or Path('/original').exists() or Path('/candidate').exists():
        raise RuntimeError('selected no-Original transport namespace required')
    frame = bytearray()
    while len(frame) <= packet.FRAME_BYTES:
        part = os.read(args.frame_fd, packet.FRAME_BYTES + 1 - len(frame))
        if not part:
            break
        frame.extend(part)
    os.close(args.frame_fd)
    submit(bytes(frame), args.onion_endpoint, args.socks, args.selected_curl)
    print(json.dumps({'schema':'kpb-exit-transport-status/v1', 'transport_receipt':True,
                      'financial_or_chain_acceptance':False}, sort_keys=True))

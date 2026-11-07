#!/usr/bin/env python3
"""One unprivileged role; no Docker socket or access to sibling wallet volumes."""
import json, pathlib, signal, socket, struct, subprocess, sys, threading, time
from network_request import exact

ROOT = pathlib.Path('/state')

def proxy():
    listener = socket.create_server(('0.0.0.0', 19091))
    for_log = ROOT / 'direct-network.jsonl'
    while True:
        incoming, peer = listener.accept()
        with incoming, socket.create_connection(('127.0.0.1', 19090), timeout=600) as outgoing:
            incoming.settimeout(600)
            data = exact(incoming, struct.unpack('!I', exact(incoming, 4))[0])
            timestamp = time.time()
            outgoing.sendall(struct.pack('!I', len(data)) + data)
            response = exact(outgoing, struct.unpack('!I', exact(outgoing, 4))[0])
            with for_log.open('a') as log:
                log.write(json.dumps({'peer': peer[0], 'timestampUnix': timestamp,
                                      'request': json.loads(data), 'response': json.loads(response)}) + '\n')
            incoming.sendall(struct.pack('!I', len(response)) + response)

def main():
    role = sys.argv[1]
    data = ROOT / 'tor'
    data.mkdir(mode=0o700)
    options = f'DataDirectory {data}\nLog notice stdout\nAvoidDiskWrites 1\nClientOnly 1\n'
    if role == 'service':
        options += f'SocksPort 0\nHiddenServiceDir {data}/onion\nHiddenServicePort 80 127.0.0.1:19090\n'
        threading.Thread(target=proxy, daemon=True).start()
    else:
        options += 'SocksPort 127.0.0.1:19050 IsolateSOCKSAuth\nSafeSocks 1\n'
    rc = ROOT / 'torrc'
    rc.write_text(options)
    with (ROOT / 'tor.log').open('x') as log:
        tor = subprocess.Popen(['/runtime/tor', '-f', str(rc)], stdout=log, stderr=subprocess.STDOUT)
        def stop(*_):
            tor.terminate()
            raise SystemExit()
        signal.signal(signal.SIGTERM, stop)
        while 'Bootstrapped 100%' not in (ROOT / 'tor.log').read_text():
            if tor.poll() is not None:
                raise RuntimeError('Tor stopped; no fallback')
            time.sleep(0.5)
        (ROOT / 'READY.json').write_text(json.dumps({'torBootstrapped': True, 'role': role}))
        while tor.poll() is None:
            time.sleep(1)
        raise RuntimeError('Tor stopped')

if __name__ == '__main__':
    main()

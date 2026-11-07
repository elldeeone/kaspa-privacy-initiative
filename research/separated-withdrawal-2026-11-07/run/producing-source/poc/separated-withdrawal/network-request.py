#!/usr/bin/env python3
"""Client-local transport. Direct mode exists only for the labelled control."""
import json, os, secrets, socket, struct, sys, time

def exact(s, n):
    result = b''
    while len(result) < n:
        part = s.recv(n - len(result))
        if not part:
            raise ConnectionError('truncated response')
        result += part
    return result

def request(r):
    # Independent local choice; no actual redemption schedule is sent to service.
    if r['message']['kind'] == 'redeem':
        time.sleep(secrets.randbelow(3001) / 1000)
    with socket.socket() as s:
        s.settimeout(600)
        direct = os.environ.get('KPI_TEST_DIRECT_SERVICE')
        if direct:
            s.connect((direct, 19091))
        else:
            if not r['host'].endswith('.onion'):
                raise ValueError('onion required; no direct fallback')
            s.connect(('127.0.0.1', r['socks']))
            s.sendall(b'\x05\x01\x02')
            assert exact(s, 2) == b'\x05\x02'
            user, password = b'<torS0X>0', secrets.token_hex(24).encode()
            s.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            assert exact(s, 2) == b'\x01\x00'
            name = r['host'].encode('ascii')
            s.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', 80))
            reply = exact(s, 4)
            assert reply[:2] == b'\x05\x00', reply.hex()
            length = {1: 4, 4: 16}.get(reply[3])
            exact(s, (length if length is not None else exact(s, 1)[0]) + 2)
        data = json.dumps(r['message'], separators=(',', ':')).encode()
        s.sendall(struct.pack('!I', len(data)) + data)
        return json.loads(exact(s, struct.unpack('!I', exact(s, 4))[0]))

if __name__ == '__main__':
    print(json.dumps(request(json.load(sys.stdin))))

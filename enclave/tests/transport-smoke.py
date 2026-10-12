"""Run after tsc -p enclave/tsconfig.json; uses only synthetic health RPCs."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0))
    PORT = probe.getsockname()[1]

def connect():
    return socket.create_connection(('127.0.0.1', PORT), timeout=2)

def frame(value):
    payload = json.dumps(value).encode()
    return struct.pack('!I', len(payload)) + payload

def receive(sock, size):
    result = b''
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise AssertionError('Unexpected EOF')
        result += data
    return result

# Use a temporary port without touching the existing developer service.
script = f"import {{startServer}} from {json.dumps((ROOT / 'enclave/dist/server.js').as_uri())}; startServer({PORT});"
process = subprocess.Popen(['node', '--input-type=module', '-e', script],
                           env={**os.environ, 'NODE_ENV': 'production'},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for attempt in range(40):
        try:
            with connect():
                break
        except OSError:
            if process.poll() is not None:
                raise AssertionError('Server exited during startup')
            time.sleep(0.05)
    else:
        raise AssertionError('Server did not start')
    with connect() as sock:
        sock.sendall(frame({'id': 0, 'method': 'health', 'params': {}}))
        size = struct.unpack('!I', receive(sock, 4))[0]
        assert size < 1024
        response = json.loads(receive(sock, size))
        assert response['id'] == 0 and response['result']['attested'] is False
        sock.sendall(frame({'id': 1, 'method': 'encrypt', 'params': {}}))
        size = struct.unpack('!I', receive(sock, 4))[0]
        assert 'error' in json.loads(receive(sock, size))
    with connect() as sock:
        sock.sendall(struct.pack('!I', 16 * 1024 * 1024 + 1))
        assert sock.recv(1) == b''
    with connect() as sock:
        sock.settimeout(8)
        sock.sendall(b'\0')
        assert sock.recv(1) == b''  # incomplete frames expire
    print('PASS: health, production refusal, oversized-frame close, partial-frame timeout')
finally:
    process.terminate()
    try:
        process.wait(timeout=7)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

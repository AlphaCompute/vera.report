"""One bounded frame over vsock; intended to run behind authenticated SSH."""
import socket
import struct
import sys

size_bytes = sys.stdin.buffer.read(4)
if len(size_bytes) != 4:
    raise SystemExit('Missing frame')
size = struct.unpack('!I', size_bytes)[0]
if not 0 < size <= 16384:
    raise SystemExit('Invalid frame')
payload = sys.stdin.buffer.read(size)
if len(payload) != size:
    raise SystemExit('Truncated frame')
with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
    connection.settimeout(10)
    connection.connect((int(sys.argv[1]), 5001))
    connection.sendall(size_bytes + payload)
    response = b''
    while len(response) < 4:
        part = connection.recv(4 - len(response))
        if not part:
            raise SystemExit('Truncated response')
        response += part
    expected = struct.unpack('!I', response)[0]
    if not 0 < expected <= 32768:
        raise SystemExit('Invalid response')
    while len(response) < expected + 4:
        part = connection.recv(expected + 4 - len(response))
        if not part:
            raise SystemExit('Truncated response')
        response += part
    sys.stdout.buffer.write(response)

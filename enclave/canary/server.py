"""Synthetic-data attestation canary. No persistence, KMS or production API."""
import base64
import ctypes
import hashlib
import json
import os
import socket
import struct
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONTEXT = b'VERA-NITRO-CANARY-v1'
MAX_FRAME = 16384
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
sessions = {}


def decode(value, length=None):
    if not isinstance(value, str) or len(value) > MAX_FRAME:
        raise ValueError('Invalid encoding')
    result = base64.b64decode(value, validate=True)
    if length is not None and len(result) != length:
        raise ValueError('Invalid length')
    return result


def attest(nonce):
    if not os.path.exists('/dev/nsm'):
        raise RuntimeError('NSM unavailable')
    lib = ctypes.CDLL('/usr/lib64/libnsm.so')
    lib.nsm_lib_init.restype = ctypes.c_int
    lib.nsm_lib_exit.argtypes = [ctypes.c_int]
    lib.nsm_get_attestation_doc.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.nsm_get_attestation_doc.restype = ctypes.c_int
    fd = lib.nsm_lib_init()
    if fd < 0:
        raise RuntimeError('NSM unavailable')
    try:
        output = ctypes.create_string_buffer(16384)
        size = ctypes.c_uint32(len(output))
        result = lib.nsm_get_attestation_doc(fd, CONTEXT, len(CONTEXT), nonce, len(nonce), public_key, len(public_key), output, ctypes.byref(size))
        if result != 0 or size.value > len(output):
            raise RuntimeError('Attestation failed')
        return output.raw[:size.value]
    finally:
        lib.nsm_lib_exit(fd)


def handle(request):
    now = time.monotonic()
    for key, (created, _) in list(sessions.items()):
        if now - created > 60:
            del sessions[key]
    nonce = decode(request.get('nonce'), 32)
    if request.get('method') == 'attest':
        if len(sessions) >= 32 or nonce in sessions:
            raise ValueError('Session unavailable')
        document = attest(nonce)
        sessions[nonce] = (now, hashlib.sha256(document).digest())
        return {'document': base64.b64encode(document).decode()}
    if request.get('method') == 'confirm':
        # Consume even on authentication failure: a session is single use.
        _, transcript = sessions.pop(nonce)
        peer = X25519PublicKey.from_public_bytes(decode(request.get('publicKey'), 32))
        shared = private_key.exchange(peer)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript, info=CONTEXT).derive(shared)
        ciphertext = decode(request.get('ciphertext'))
        if not 16 <= len(ciphertext) <= 2064:
            raise ValueError('Invalid canary size')
        plaintext = AESGCM(key).decrypt(decode(request.get('iv'), 12), ciphertext, CONTEXT)
        return {'digest': hashlib.sha256(plaintext).hexdigest()}
    raise ValueError('Unknown operation')


def receive(connection, count):
    output = b''
    while len(output) < count:
        part = connection.recv(count - len(output))
        if not part:
            raise ValueError('Truncated frame')
        output += part
    return output


if __name__ == '__main__':
    if not os.path.exists('/dev/nsm'):
        raise SystemExit('NSM required')
    if os.geteuid() == 0:
        os.chown('/dev/nsm', 1000, 1000)
        os.chmod('/dev/nsm', 0o600)
        os.setgroups([])
        os.setgid(1000)
        os.setuid(1000)
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((socket.VMADDR_CID_ANY, 5001))
    listener.listen(8)
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(5)
            try:
                size = struct.unpack('!I', receive(connection, 4))[0]
                if not 0 < size <= MAX_FRAME:
                    raise ValueError('Invalid frame')
                response = {'result': handle(json.loads(receive(connection, size)))}
            except Exception:
                response = {'error': 'Canary request rejected'}
            payload = json.dumps(response).encode()
            try:
                connection.sendall(struct.pack('!I', len(payload)) + payload)
            except OSError:
                pass

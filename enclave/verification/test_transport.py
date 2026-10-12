"""Local TCP fixtures; signed responses use synthetic PKI, never real hardware."""
import base64
from contextlib import contextmanager, redirect_stdout
import io
import json
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from enclave.verification import verify_identity as verifier
from enclave.verification.test_identity import SyntheticIdentityFixture


@contextmanager
def responder(reply, tls_context=None, after_reply=None):
    failures = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    def serve():
        try:
            raw = listener.accept()[0]
            raw.settimeout(5)
            connection = tls_context.wrap_socket(raw, server_side=True) if tls_context else raw
            with connection:
                connection.settimeout(5)
                def read(size):
                    value = bytearray()
                    while len(value) < size:
                        chunk = connection.recv(size - len(value))
                        if not chunk:
                            raise ValueError('Incomplete test request')
                        value.extend(chunk)
                    return bytes(value)
                size = struct.unpack('!I', read(4))[0]
                if size > 1024:
                    raise ValueError('Oversized test request')
                request = json.loads(read(size))
                connection.sendall(reply(request))
                if after_reply is not None:
                    after_reply(connection)
        except Exception as error:
            failures.append(error)
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        thread.join(6)
        listener.close()
        if thread.is_alive():
            raise AssertionError('Test responder did not stop')
        if failures:
            raise failures[0]


def frame(value):
    payload = json.dumps(value).encode()
    return struct.pack('!I', len(payload)) + payload


class TransportTests(SyntheticIdentityFixture, unittest.TestCase):
    def test_cli_uses_a_fresh_challenge_and_verifies_the_signed_response(self):
        observed = []
        def reply(request):
            self.assertEqual(request['method'], 'attestIdentity')
            nonce = bytes.fromhex(request['params']['nonce'])
            observed.append(nonce)
            document = self.document({**self.body, 'nonce': nonce})
            return frame({'id': request['id'], 'result': {'document': base64.b64encode(document).decode()}})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, 'synthetic.pem')
            root.write_bytes(self.root_pem)
            with patch.object(verifier, 'ROOT_PATH', root), patch.object(verifier, 'ROOT_FINGERPRINT', self.root.fingerprint(hashes.SHA256()).hex()):
                for _ in range(2):
                    with responder(reply) as port, patch.object(sys, 'argv', ['verify_identity', '--port', str(port),
                         '--pcr0', self.pcrs[0].hex(), '--pcr1', self.pcrs[1].hex(), '--pcr2', self.pcrs[2].hex()]):
                        output = io.StringIO()
                        with redirect_stdout(output):
                            verifier.main()
                        self.assertEqual(json.loads(output.getvalue())['scope'], 'enclave-identity-only')
        self.assertEqual(len(observed), 2)
        self.assertNotEqual(observed[0], observed[1])
        self.assertTrue(all(len(nonce) == 32 for nonce in observed))

    def test_replayed_document_fails_after_transport_succeeds(self):
        document = self.document()
        def reply(request):
            return frame({'id': request['id'], 'result': {'document': base64.b64encode(document).decode()}})
        with responder(reply) as port:
            replay = verifier.request_document(port, b'x' * 32)
        with self.assertRaisesRegex(ValueError, 'protocol mismatch'):
            self.check(replay, nonce=b'x' * 32)

    def test_rejects_hostile_framing_and_rpc_responses(self):
        def duplicate(request):
            payload = ('{"id":' + json.dumps(request['id']) + ',"id":' + json.dumps(request['id']) + ',"result":{"document":"AQID"}}').encode()
            return struct.pack('!I', len(payload)) + payload
        replies = [lambda _: struct.pack('!I', 24577), lambda _: struct.pack('!I', 10) + b'{}',
                   lambda _: frame({'id': 'wrong', 'result': {'document': 'AQID'}}), duplicate,
                   lambda r: frame({'id': r['id'], 'error': {'code': -32000}}),
                   lambda r: frame({'id': r['id'], 'result': {'document': 'AQID!'}})]
        for reply in replies:
            with self.subTest(reply=reply), responder(reply) as port, self.assertRaises(ValueError):
                verifier.request_document(port, self.nonce)

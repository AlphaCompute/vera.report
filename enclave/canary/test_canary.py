"""Offline rejection and transcript-binding tests; hardware proof is separate."""
import base64
import hashlib
import unittest
from unittest.mock import patch
import server
import verify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encoded(data):
    return base64.b64encode(data).decode()


class CanaryTests(unittest.TestCase):
    def setUp(self):
        server.sessions.clear()
        self.nonce = b'n' * 32

    def message(self, transcript=b'synthetic document'):
        with patch.object(server, 'attest', return_value=transcript):
            server.handle({'method': 'attest', 'nonce': encoded(self.nonce)})
        peer = X25519PrivateKey.generate()
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=hashlib.sha256(transcript).digest(), info=server.CONTEXT).derive(peer.exchange(server.private_key.public_key()))
        return {'method': 'confirm', 'nonce': encoded(self.nonce),
                'publicKey': encoded(peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                'iv': encoded(b'i' * 12),
                'ciphertext': encoded(AESGCM(key).encrypt(b'i' * 12, b'synthetic', server.CONTEXT))}

    def test_encrypted_confirmation_and_replay(self):
        message = self.message()
        self.assertEqual(server.handle(message), {'digest': hashlib.sha256(b'synthetic').hexdigest()})
        with self.assertRaises(KeyError):
            server.handle(message)

    def test_authentication_failure_consumes_session(self):
        message = self.message()
        original = message['ciphertext']
        message['ciphertext'] = encoded(b'x' * 25)
        with self.assertRaises(Exception):
            server.handle(message)
        message['ciphertext'] = original
        with self.assertRaises(KeyError):
            server.handle(message)

    def test_expired_session(self):
        message = self.message()
        with patch.object(server.time, 'monotonic', return_value=server.time.monotonic() + 61):
            with self.assertRaises(KeyError):
                server.handle(message)

    def test_transcript_binding(self):
        message = self.message()
        created, _ = server.sessions[self.nonce]
        server.sessions[self.nonce] = (created, hashlib.sha256(b'different document').digest())
        with self.assertRaises(Exception):
            server.handle(message)

    def test_session_capacity_and_duplicate_nonce(self):
        with patch.object(server, 'attest', return_value=b'doc'):
            request = {'method': 'attest', 'nonce': encoded(self.nonce)}
            server.handle(request)
            with self.assertRaises(ValueError):
                server.handle(request)
            for i in range(31):
                server.handle({'method': 'attest', 'nonce': encoded(bytes([i]) * 32)})
            with self.assertRaises(ValueError):
                server.handle({'method': 'attest', 'nonce': encoded(b'z' * 32)})

    def test_strict_cbor(self):
        with self.assertRaises(ValueError):
            verify.cbor(b'\x01\x02')

    def test_debug_measurement_rejected_before_trust(self):
        with self.assertRaisesRegex(ValueError, 'Invalid verification inputs'):
            verify.verify(b'', self.nonce, b'\0' * 48, b'')


if __name__ == '__main__':
    unittest.main()

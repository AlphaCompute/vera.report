"""Real local TLS with synthetic signed NSM documents; no hardware evidence."""
import base64
import hashlib
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from enclave.verification import verify_identity, verify_channel
from enclave.verification.test_identity import SyntheticIdentityFixture
from enclave.verification.test_transport import responder, frame


class ChannelTests(SyntheticIdentityFixture, unittest.TestCase):
    def test_tls_peer_binding_and_signed_rejections(self):
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory, 'tls.pem')
            key = Path(directory, 'tls.key')
            cert.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
            key.write_bytes(self.leaf_key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            digest = hashlib.sha256(self.leaf.public_bytes(serialization.Encoding.DER)).digest()
            for kind in ['valid', 'valid', 'different-certificate', 'identity-context', 'replay', 'wrong-pcr']:
                def reply(request):
                    self.assertEqual(request['method'], 'attestChannel')
                    self.assertEqual(set(request['params']), {'nonce'})
                    nonce = bytes.fromhex(request['params']['nonce'])
                    observed.append(nonce)
                    body = {**self.body, 'nonce': nonce, 'user_data': verify_channel.CONTEXT + digest}
                    if kind == 'different-certificate':
                        body['user_data'] = verify_channel.CONTEXT + hashlib.sha256(self.root_pem).digest()
                    elif kind == 'identity-context':
                        body['user_data'] = verify_identity.CONTEXT
                    elif kind == 'replay':
                        body['nonce'] = observed[0]
                    elif kind == 'wrong-pcr':
                        body['pcrs'] = {**self.pcrs, 0: b'x' * 48}
                    return frame({'id': request['id'], 'result': {'document': base64.b64encode(self.document(body)).decode()}})
                with self.subTest(kind=kind), patch.object(verify_identity, 'ROOT_FINGERPRINT', self.root.fingerprint(hashes.SHA256()).hex()), responder(reply, context) as port:
                    if kind == 'valid':
                        result = verify_channel.verify_channel(port, self.pcrs, self.root_pem)
                        self.assertEqual(result['scope'], 'attested-tls-peer')
                        self.assertEqual(result['certificate_sha256'], digest.hex())
                        self.assertEqual(result['nonce'], observed[-1].hex())
                    else:
                        with self.assertRaises(ValueError):
                            verify_channel.verify_channel(port, self.pcrs, self.root_pem)
        self.assertEqual(len(set(observed)), 6)

    def test_verified_socket_is_retained_and_invalid_peers_receive_no_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory, 'tls.pem')
            key = Path(directory, 'tls.key')
            cert.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
            key.write_bytes(self.leaf_key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            digest = hashlib.sha256(self.leaf.public_bytes(serialization.Encoding.DER)).digest()
            for kind in ['valid', 'wrong-binding', 'consumer-failure']:
                observed = []
                def reply(request):
                    nonce = bytes.fromhex(request['params']['nonce'])
                    binding = digest if kind != 'wrong-binding' else bytes(32)
                    body = {**self.body, 'nonce': nonce, 'user_data': verify_channel.CONTEXT + binding}
                    return frame({'id': request['id'], 'result': {'document': base64.b64encode(self.document(body)).decode()}})
                def after_reply(connection):
                    operation = connection.recv(128)
                    observed.append(operation)
                    if operation:
                        connection.sendall(b'ack')
                connection = None
                with self.subTest(kind=kind), patch.object(verify_identity, 'ROOT_FINGERPRINT', self.root.fingerprint(hashes.SHA256()).hex()), responder(reply, context, after_reply) as port:
                    if kind == 'wrong-binding':
                        with self.assertRaises(ValueError):
                            with verify_channel.verified_channel(port, self.pcrs, self.root_pem):
                                self.fail('Invalid peer reached privileged consumer')
                    else:
                        def consume():
                            nonlocal connection
                            with verify_channel.verified_channel(port, self.pcrs, self.root_pem) as (connection, evidence):
                                self.assertEqual(evidence['certificate_sha256'], digest.hex())
                                self.assertEqual(hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest(), evidence['certificate_sha256'])
                                if kind == 'consumer-failure':
                                    raise RuntimeError('synthetic consumer failure')
                                connection.sendall(b'synthetic-privileged-operation')
                                self.assertEqual(connection.recv(3), b'ack')
                        if kind == 'consumer-failure':
                            with self.assertRaises(RuntimeError):
                                consume()
                        else:
                            consume()
                        self.assertEqual(connection.fileno(), -1)
                self.assertEqual(observed, [b'synthetic-privileged-operation' if kind == 'valid' else b''])


if __name__ == '__main__':
    unittest.main()

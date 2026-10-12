"""Local TLS and real AES-GCM with synthetic PKI/keys; no AWS hardware evidence."""
import base64
import hashlib
import io
import json
import ssl
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from enclave.verification import read_report_verification as reader, verify_identity, verify_channel
from enclave.verification.test_identity import SyntheticIdentityFixture
from enclave.verification.test_transport import responder, frame


def b64(value):
    return base64.b64encode(value).decode()


class ReportVerificationReaderTests(SyntheticIdentityFixture, unittest.TestCase):
    def request(self, port=1):
        record = 'report:VRA-1234567890ABCDEF'
        aad = json.dumps([record, 'verification'], separators=(',', ':')).encode()
        encrypted = AESGCM(b'k' * 32).encrypt(b'i' * 12, b'{"credibilityScore":80}', aad)
        return {'trackingId': record[len('report:'):], 'port': port,
                'keyArn': 'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012',
                'pcrs': {str(k): v.hex() for k, v in self.pcrs.items()},
                'credentials': {'accessKeyId': 'synthetic-access', 'secretAccessKey': 'synthetic-secret',
                                'sessionToken': 'synthetic-token', 'expiration': (self.now + timedelta(minutes=5)).isoformat()},
                'envelope': 'private:v1:' + json.dumps({'key': 'enc:kms:v2:' + b64(b'opaque-kms-wrapper'),
                                                      'iv': b64(b'i' * 12), 'tag': b64(encrypted[-16:]), 'data': b64(encrypted[:-16])})}

    def test_same_verified_socket_handles_only_the_bound_private_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root, cert, key = [Path(directory, name) for name in ['root.pem', 'tls.pem', 'tls.key']]
            root.write_bytes(self.root_pem)
            cert.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
            key.write_bytes(self.leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            digest = hashlib.sha256(self.leaf.public_bytes(serialization.Encoding.DER)).digest()
            for kind in ['valid', 'wrong-tls-binding', 'wrong-record', 'wrong-field', 'bad-tag', 'kms-refused']:
                observed = []
                request = self.request()
                if kind == 'bad-tag':
                    envelope = json.loads(request['envelope'][len('private:v1:'):])
                    envelope['tag'] = b64(bytes(16))
                    request['envelope'] = 'private:v1:' + json.dumps(envelope)

                def reply(attestation):
                    self.assertEqual(attestation['method'], 'attestChannel')
                    binding = bytes(32) if kind == 'wrong-tls-binding' else digest
                    body = {**self.body, 'nonce': bytes.fromhex(attestation['params']['nonce']),
                            'user_data': verify_channel.CONTEXT + binding}
                    return frame({'id': attestation['id'], 'result': {'document': b64(self.document(body))}})

                def after_reply(connection):
                    def read(size):
                        output = b''
                        while len(output) < size:
                            chunk = connection.recv(size - len(output))
                            if not chunk:
                                return output
                            output += chunk
                        return output
                    if kind == 'wrong-tls-binding':
                        self.assertEqual(connection.recv(1), b'')
                        return
                    for method in ['openRecipient', 'bootstrapLegacyPrivate', 'decryptLegacyPrivate']:
                        header = read(4)
                        self.assertEqual(len(header), 4)
                        message = json.loads(read(struct.unpack('!I', header)[0]))
                        self.assertEqual(message['method'], method)
                        observed.append(method)
                        params = message['params']
                        if method == 'openRecipient':
                            self.assertEqual(params, request['credentials'])
                            result = {'kind': 'sessionOpened'}
                        else:
                            self.assertEqual(params['record'], 'report:' + request['trackingId'])
                            self.assertEqual(params['field'], 'verification')
                            if method == 'bootstrapLegacyPrivate':
                                self.assertEqual(params['keyArn'], request['keyArn'])
                                self.assertTrue(params['wrappedKey'].startswith('enc:kms:v2:'))
                                if kind == 'kms-refused':
                                    connection.sendall(frame({'id': message['id'], 'error': {'code': -32000}}))
                                    return
                                result = {'handle': b64(b'h' * 32)}
                            else:
                                self.assertEqual(params['handle'], b64(b'h' * 32))
                                record = 'report:VRA-FFFFFFFFFFFFFFFF' if kind == 'wrong-record' else params['record']
                                field = 'different' if kind == 'wrong-field' else params['field']
                                aad = json.dumps([record, field], separators=(',', ':')).encode()
                                try:
                                    plaintext = AESGCM(b'k' * 32).decrypt(base64.b64decode(params['iv']),
                                        base64.b64decode(params['ciphertext']) + base64.b64decode(params['tag']), aad)
                                except InvalidTag:
                                    connection.sendall(frame({'id': message['id'], 'error': {'code': -32000}}))
                                    return
                                result = {'plaintext': b64(plaintext)}
                        connection.sendall(frame({'id': message['id'], 'result': result}))

                with self.subTest(kind=kind), patch.object(reader, 'ROOT_PATH', root), patch.object(verify_identity, 'ROOT_FINGERPRINT', self.root.fingerprint(hashes.SHA256()).hex()), responder(reply, context, after_reply) as port:
                    request['port'] = port
                    if kind == 'valid':
                        self.assertEqual(reader.read_report_verification(request), {'credibilityScore': 80})
                    else:
                        with self.assertRaises(ValueError):
                            reader.read_report_verification(request)
                self.assertEqual(observed, [] if kind == 'wrong-tls-binding' else
                                 ['openRecipient', 'bootstrapLegacyPrivate'] if kind == 'kms-refused' else
                                 ['openRecipient', 'bootstrapLegacyPrivate', 'decryptLegacyPrivate'])

    def test_bad_profiles_and_duplicate_fields_never_open_a_channel(self):
        original = self.request()
        envelope = json.loads(original['envelope'][len('private:v1:'):])
        bad = ['plaintext', original['envelope'].replace('enc:kms:v2:', 'enc:local:v1:'),
               original['envelope'].replace('enc:kms:v2:', 'enc:kms:recipient:v1:'),
               'private:v1:' + json.dumps({**envelope, 'field': 'other'}),
               'private:v1:' + json.dumps({**envelope, 'iv': b64(bytes(16))}),
               'private:v1:{"key":"ignored",' + json.dumps(envelope)[1:]]
        with patch.object(reader, 'recipient_channel') as channel:
            for value in bad:
                with self.subTest(value=value[:24]), self.assertRaises(ValueError):
                    reader.read_report_verification({**original, 'envelope': value})
            channel.assert_not_called()

    def test_cli_rejects_oversize_duplicate_and_sensitive_provider_errors_without_diagnostics(self):
        for raw in [b'x' * (reader.MAX_INPUT + 1), b'{"a":1,"a":2}', json.dumps(self.request()).encode()]:
            output = io.StringIO()
            with patch.object(reader.sys, 'stdin', io.TextIOWrapper(io.BytesIO(raw))), redirect_stdout(output), patch.object(reader, 'read_report_verification', side_effect=ValueError('synthetic-secret-provider-detail')):
                self.assertEqual(reader.main(), 1)
            self.assertEqual(output.getvalue(), '{"error":"Report verification reader unavailable"}')


if __name__ == '__main__':
    unittest.main()

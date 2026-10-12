"""Synthetic PKI tests; successful fixtures are not AWS/hardware evidence."""
import datetime
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from enclave.verification import verify_identity as verifier


class SyntheticIdentityFixture:
    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.now_ms = int(self.now.timestamp() * 1000)
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        self.root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Synthetic test root')])
        self.root = self.certificate(self.root_key, self.root_name, True)
        self.leaf = self.certificate(self.leaf_key, x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Synthetic enclave')]), False)
        self.nonce = b'n' * 32
        self.pcrs = {0: b'0' * 48, 1: b'1' * 48, 2: b'2' * 48}
        self.root_pem = self.root.public_bytes(serialization.Encoding.PEM)
        self.body = {'module_id': 'synthetic', 'digest': 'SHA384', 'timestamp': self.now_ms,
                     'nonce': self.nonce, 'user_data': verifier.CONTEXT, 'pcrs': self.pcrs,
                     'certificate': self.leaf.public_bytes(serialization.Encoding.DER),
                     'cabundle': [self.root.public_bytes(serialization.Encoding.DER)]}

    def certificate(self, key, name, ca, expired=False):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(self.root_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.now - datetime.timedelta(days=2))
                .not_valid_after(self.now + datetime.timedelta(days=-1 if expired else 1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(self.root_key, hashes.SHA384()))

    def document(self, body=None, payload=None, protected=None, tag=None):
        protected = cbor2.dumps({1: -35}) if protected is None else protected
        payload = cbor2.dumps(self.body if body is None else body) if payload is None else payload
        signature = self.leaf_key.sign(cbor2.dumps(['Signature1', protected, b'', payload]), ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(signature)
        cose = [protected, {}, payload, r.to_bytes(48, 'big') + s.to_bytes(48, 'big')]
        return cbor2.dumps(cbor2.CBORTag(tag, cose) if tag is not None else cose)

    def check(self, document, **overrides):
        args = dict(nonce=self.nonce, expected_pcrs=self.pcrs, root_pem=self.root_pem, now_ms=self.now_ms)
        args.update(overrides)
        # Tests alone replace the trust pin. The CLI has no root override.
        with patch.object(verifier, 'ROOT_FINGERPRINT', self.root.fingerprint(hashes.SHA256()).hex()):
            return verifier.verify_identity(document, **args)


class IdentityTests(SyntheticIdentityFixture, unittest.TestCase):
    def indefinite(self, value):
        """Encode test-only legal indefinite containers and string chunks."""
        if isinstance(value, dict):
            return b'\xbf' + b''.join(self.indefinite(k) + self.indefinite(v)
                                      for k, v in value.items()) + b'\xff'
        if isinstance(value, list):
            return b'\x9f' + b''.join(self.indefinite(v) for v in value) + b'\xff'
        if isinstance(value, (bytes, str)):
            middle = len(value) // 2
            return (b'\x5f' if isinstance(value, bytes) else b'\x7f') + \
                cbor2.dumps(value[:middle]) + cbor2.dumps(value[middle:]) + b'\xff'
        return cbor2.dumps(value)

    def test_signed_indefinite_maps_arrays_and_chunked_strings(self):
        payload = self.indefinite(self.body)
        protected = self.indefinite({1: -35})
        document = self.document(payload=payload, protected=protected)
        # The outer envelope and embedded byte strings can independently use
        # indefinite encodings; the embedded signed bytes must stay unchanged.
        outer = self.indefinite(cbor2.loads(document))
        for encoded in (document, outer, b'\xd2' + outer):
            with self.subTest(tagged=encoded[:1] == b'\xd2'):
                self.assertEqual(self.check(encoded)['nonce'], self.nonce.hex())

    def test_indefinite_payload_signature_cannot_be_reencoded_or_forged(self):
        document = self.document(payload=self.indefinite(self.body))
        cose = cbor2.loads(document)
        cose[2] = cbor2.dumps(self.body)
        # Semantically equal maps are not equal signed bytes.
        with self.assertRaises(Exception):
            self.check(cbor2.dumps(cose))
        with self.assertRaises(Exception):
            self.check(document[:-1] + bytes([document[-1] ^ 1]))

    def test_indefinite_duplicates_trailing_depth_and_malformed_chunks_rejected(self):
        duplicate_payload = self.indefinite(self.body)[:-1] + \
            cbor2.dumps('nonce') + cbor2.dumps(self.nonce) + b'\xff'
        # Also reject equal keys whose encodings differ (definite/indefinite).
        duplicate_headers = b'\xbf\x01\x38\x22\x01\x38\x22\xff'
        documents = [self.document(payload=duplicate_payload),
                     self.document(protected=duplicate_headers),
                     self.document(payload=self.indefinite(self.body) + b'\x00'),
                     self.document(protected=self.indefinite({1: -35}) + b'\x00'),
                     self.indefinite(cbor2.loads(self.document())) + b'\x00',
                     b'\x9f' * 17 + b'\x00' + b'\xff' * 17,
                     self.document(payload=b'\xbf\x61x\xff'),
                     self.document(payload=b'\xbf'),
                     self.document(payload=b'\x5f\x61x\xff'),
                     self.document(payload=b'\x7f\x41x\xff'),
                     self.document(payload=b'\x5f\x5f\xff\xff'),
                     b'\x9f' + b'\x00' * 16383 + b'\xff']
        for document in documents:
            with self.subTest(size=len(document)), self.assertRaises(Exception):
                self.check(document)

    def test_valid_tagged_and_untagged_identity(self):
        for tag in [None, 18]:
            result = self.check(self.document(tag=tag))
            self.assertEqual(result['scope'], 'enclave-identity-only')
            self.assertEqual(result['nonce'], self.nonce.hex())
            self.assertEqual(result['verified_at'], self.now_ms)
            self.assertEqual(result['pcrs'], {str(index): value.hex() for index, value in self.pcrs.items()})

    def test_untrusted_root_and_forged_signature(self):
        with self.assertRaisesRegex(ValueError, 'Untrusted root'):
            verifier.verify_identity(self.document(), self.nonce, self.pcrs, self.root_pem)
        document = self.document()
        with self.assertRaises(Exception):
            self.check(document[:-1] + bytes([document[-1] ^ 1]))

    def test_signed_wrong_protocol_nonce_time_and_measurements(self):
        changes = [dict(nonce=b'x' * 32), dict(user_data=b'VERA-NITRO-CANARY-v1'), dict(public_key=b'key'),
                   dict(timestamp=True), dict(timestamp=self.now_ms - 60001), dict(timestamp=self.now_ms + 5001),
                   dict(module_id=''), dict(digest='SHA256')]
        changes += [dict(pcrs={**self.pcrs, index: value}) for index in range(3) for value in [b'x' * 48, b'\0' * 48]]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(self.document({**self.body, **change}))

    def test_duplicate_keys_depth_trailing_and_unsupported_headers(self):
        pairs = list(self.body.items()) + [('nonce', self.nonce)]
        duplicate = bytes([0xa0 + len(pairs)]) + b''.join(cbor2.dumps(k) + cbor2.dumps(v) for k, v in pairs)
        documents = [self.document(payload=duplicate), self.document(protected=b'\xa2\x01\x38\x22\x01\x38\x22'),
                     self.document() + b'\0', b'\x81' * 17 + b'\0', self.document(tag=19),
                     self.document(protected=cbor2.dumps({1: -35, 2: [99]})),
                     self.document(protected=cbor2.dumps({True: -35})),
                     self.document(protected=cbor2.dumps({1: -35.0})), b'x' * 16385]
        for document in documents:
            with self.subTest(size=len(document)), self.assertRaises(Exception):
                self.check(document)

    def test_expired_or_unrelated_leaf_and_incomplete_pins(self):
        expired = self.certificate(self.leaf_key, self.leaf.subject, False, expired=True)
        wrong = self.certificate(ec.generate_private_key(ec.SECP384R1()), self.leaf.subject, False)
        for leaf in [expired, wrong]:
            with self.assertRaises(Exception):
                self.check(self.document({**self.body, 'certificate': leaf.public_bytes(serialization.Encoding.DER)}))
        with self.assertRaises(ValueError):
            self.check(self.document(), expected_pcrs={0: self.pcrs[0]})
        with self.assertRaises(ValueError):
            self.check(self.document(), expected_pcrs={**self.pcrs, 0: b'\0' * 48})

    def test_vendored_root_matches_published_aws_pin(self):
        root = x509.load_pem_x509_certificate(verifier.ROOT_PATH.read_bytes())
        self.assertEqual(root.fingerprint(hashes.SHA256()).hex(), verifier.ROOT_FINGERPRINT)

    def test_appended_root_does_not_expand_trust(self):
        with self.assertRaisesRegex(ValueError, 'certificate chain'):
            verifier.verify_identity(self.document(), self.nonce, self.pcrs,
                                     verifier.ROOT_PATH.read_bytes() + b'\n' + self.root_pem, self.now_ms)


class CapturedNsmTests(unittest.TestCase):
    def test_authentic_indefinite_document_at_recorded_time_only(self):
        # Public credential-free quote, not a reusable live authorization. Do not
        # replace the production clock or trust root to accept this stale quote.
        fixture = json.loads((Path(__file__).parent / 'fixtures' /
                              'nsm-channel-indefinite-20260915.json').read_text())
        document = base64.b64decode(fixture['documentBase64'], validate=True)
        self.assertEqual(hashlib.sha256(document).hexdigest(),
                         'cf461c21874ee59b2e7b8536a53205ea13fa10b8c5195ccd533d6833dae47cc0')
        root = verifier.ROOT_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(root).hexdigest(), fixture['rootSha256'])
        observed = int(datetime.datetime.fromisoformat(fixture['observationEnd'].replace('Z', '+00:00')).timestamp() * 1000)
        args = (document, bytes.fromhex(fixture['nonceHex']),
                {int(k): bytes.fromhex(v) for k, v in fixture['pcrs'].items()},
                root, bytes.fromhex(fixture['bindingHex']), 'offline-historical-attestation')
        result = verifier._verify_document(*args, now_ms=observed)
        self.assertEqual(result['document_sha256'], fixture['documentSha256'])
        cose = verifier.decode(document)
        if isinstance(cose, cbor2.CBORTag):
            cose = cose.value
        body = verifier.decode(cose[2])
        self.assertEqual(body['module_id'], fixture['signedModuleId'])
        # Preserve evidence of the separate CLI/NSM zero-padding discrepancy;
        # this parser compatibility fix does not relax exact identity binding.
        self.assertNotEqual(fixture['signedModuleId'], fixture['expectedEnclaveId'])
        with self.assertRaisesRegex(ValueError, 'Stale or future'):
            verifier._verify_document(*args, now_ms=body['timestamp'] + 60001)
        with self.assertRaises(Exception):
            verifier._verify_document(document[:-1] + bytes([document[-1] ^ 1]), *args[1:], now_ms=observed)


if __name__ == '__main__':
    unittest.main()

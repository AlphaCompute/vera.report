"""Synthetic PKI regressions; these do not constitute hardware attestation."""
import datetime
import time
import unittest
from pathlib import Path
import cbor2
import verify
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        self.root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Synthetic review root')])
        self.root = self.certificate(self.root_key, self.root_name, True)
        self.leaf = self.certificate(self.leaf_key, x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Synthetic leaf')]), False)
        self.nonce = b'n' * 32
        self.pcr = b'p' * 48
        self.recipient = X25519PrivateKey.generate().public_key()
        self.body = {
            'digest': 'SHA384', 'nonce': self.nonce, 'user_data': verify.CONTEXT,
            'timestamp': int(time.time() * 1000),
            'pcrs': {0: self.pcr, 1: b'1' * 48, 2: b'2' * 48},
            'certificate': self.leaf.public_bytes(serialization.Encoding.DER),
            'cabundle': [self.root.public_bytes(serialization.Encoding.DER)],
            'public_key': self.recipient.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        }

    def certificate(self, key, subject, ca, expired=False):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(self.root_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.now - datetime.timedelta(days=2))
                .not_valid_after(self.now + datetime.timedelta(days=-1 if expired else 1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(self.root_key, hashes.SHA384()))

    def document(self, body=None):
        protected = cbor2.dumps({1: -35})
        payload = cbor2.dumps(self.body if body is None else body)
        signature = self.leaf_key.sign(cbor2.dumps(['Signature1', protected, b'', payload]), ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(signature)
        return cbor2.dumps([protected, {}, payload, r.to_bytes(48, 'big') + s.to_bytes(48, 'big')])

    def check(self, document, **overrides):
        args = dict(nonce=self.nonce, expected_pcr0=self.pcr,
                    root_pem=self.root.public_bytes(serialization.Encoding.PEM),
                    root_fingerprint=self.root.fingerprint(hashes.SHA256()).hex())
        args.update(overrides)
        return verify.verify(document, **args)

    def test_valid_chain_signature_and_recipient(self):
        recipient, _ = self.check(self.document())
        self.assertEqual(recipient.public_bytes_raw(), self.recipient.public_bytes_raw())

    def test_untrusted_root_and_tampered_signature(self):
        with self.assertRaisesRegex(ValueError, 'Untrusted root'):
            self.check(self.document(), root_fingerprint='00' * 32)
        document = self.document()
        with self.assertRaises(Exception):
            self.check(document[:-1] + bytes([document[-1] ^ 1]))

    def test_appended_root_does_not_expand_trust(self):
        aws_root = Path(__file__).parents[1].joinpath('verification/aws-nitro-root.pem').read_bytes()
        with self.assertRaisesRegex(ValueError, 'certificate chain'):
            verify.verify(self.document(), self.nonce, self.pcr,
                          aws_root + b'\n' + self.root.public_bytes(serialization.Encoding.PEM))

    def test_duplicate_cbor_keys_are_rejected(self):
        with self.assertRaises(Exception):
            verify.cbor(b'\xa2\x01\x38\x22\x01\x38\x22')

    def test_signed_context_measurement_and_freshness(self):
        changes = [dict(nonce=b'x' * 32), dict(user_data=b'wrong context'),
                   dict(timestamp=int(time.time() * 1000) - 120000),
                   dict(pcrs={0: b'x' * 48, 1: b'1' * 48, 2: b'2' * 48}),
                   dict(pcrs={0: self.pcr, 1: b'\0' * 48, 2: b'2' * 48})]
        for change in changes:
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.check(self.document({**self.body, **change}))

    def test_expired_and_unrelated_leaf_are_rejected(self):
        expired = self.certificate(self.leaf_key, self.leaf.subject, False, expired=True)
        unrelated = ec.generate_private_key(ec.SECP384R1())
        wrong_key_leaf = self.certificate(unrelated, self.leaf.subject, False)
        for leaf in [expired, wrong_key_leaf]:
            with self.subTest(expired=leaf == expired), self.assertRaises(Exception):
                self.check(self.document({**self.body, 'certificate': leaf.public_bytes(serialization.Encoding.DER)}))


if __name__ == '__main__':
    unittest.main()

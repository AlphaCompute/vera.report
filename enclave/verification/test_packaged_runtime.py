"""Container-only checks for the application's installed verifier runtime."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from .verify_identity import ROOT_PATH, ROOT_FINGERPRINT


class PackagedRuntimeTest(unittest.TestCase):
    def test_fixed_runtime_and_read_only_trust(self):
        self.assertEqual(os.getuid(), 1001)
        self.assertEqual(sys.executable, '/opt/vera-attestation/venv/bin/python')
        self.assertEqual(Path.cwd(), Path('/opt/vera-attestation'))
        for path in (ROOT_PATH, Path(__file__).with_name('read_report_verification.py'), Path(__file__).with_name('narrative.py')):
            self.assertEqual(path.stat().st_uid, 0)
            self.assertFalse(os.access(path, os.W_OK))
        root = x509.load_pem_x509_certificate(ROOT_PATH.read_bytes())
        self.assertEqual(root.fingerprint(hashes.SHA256()).hex(), ROOT_FINGERPRINT)

    def test_invalid_input_reaches_packaged_reader_and_is_redacted(self):
        result = subprocess.run(
            [sys.executable, '-E', '-s', '-m', 'enclave.verification.read_report_verification'],
            input=b'{"secret":"synthetic-canary"}', capture_output=True,
            env={'PATH': '/usr/bin:/bin'}, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, b'{"error":"Report verification reader unavailable"}')

    def test_invalid_input_reaches_packaged_narrative_and_is_redacted(self):
        result = subprocess.run(
            [sys.executable, '-E', '-s', '-B', '-m', 'enclave.verification.narrative'],
            input=b'{"secret":"synthetic-canary"}', capture_output=True,
            env={'PATH': '/usr/bin:/bin'}, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, b'{"error":"Narrative unavailable"}')

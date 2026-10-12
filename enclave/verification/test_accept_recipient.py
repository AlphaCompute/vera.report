"""Synthetic runner tests, not NSM or KMS acceptance."""
from contextlib import contextmanager
import base64
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import accept_recipient as runner


class AcceptanceRunnerTests(unittest.TestCase):
    def cli(self, raw=None, args=None, failure=None):
        credentials = {'accessKeyId': 'SENSITIVE_ACCESS', 'secretAccessKey': 'SENSITIVE_SECRET',
                       'sessionToken': 'SENSITIVE_TOKEN', 'expiration': '2026-09-15T16:00:00Z'}
        arguments = ['--port', '5003', '--key-arn',
                     'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012']
        for index in range(3): arguments += [f'--pcr{index}', str(index+1) * 96]
        if args is not None: arguments = args(arguments)
        output = io.StringIO()
        with patch.object(runner.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw if raw is not None else json.dumps(credentials).encode()))), \
                patch.object(runner.sys, 'stdout', output), \
                patch.object(runner, 'accept_recipient', side_effect=failure, return_value={'scope': 'fixture'}) as run:
            status = runner.main(arguments)
        return status, json.loads(output.getvalue()), run, credentials

    def test_cli_passes_private_stdin_only_after_validating_configuration(self):
        status, result, run, credentials = self.cli()
        self.assertEqual(status, 0)
        self.assertEqual(result, {'scope': 'fixture'})
        self.assertEqual(run.call_args.args[3], credentials)
        self.assertEqual(run.call_args.args[1][0], bytes.fromhex('1' * 96))
        self.assertEqual(run.call_args.args[2], runner.ROOT_PATH.read_bytes())
        self.assertNotIn('SENSITIVE', json.dumps(result))

    def test_cli_rejects_invalid_config_or_credentials_before_connecting(self):
        for mutate in (lambda a: [v.replace('000000000000', '111111111111') for v in a],
                       lambda a: ['0' * 96 if v == '1' * 96 else v for v in a],
                       lambda a: ['65536' if v == '5003' else v for v in a]):
            status, _, run, _ = self.cli(args=mutate)
            self.assertEqual(status, 1)
            run.assert_not_called()
        for raw in (b'x' * 32769, b'{"accessKeyId":"one","accessKeyId":"two"}', b'{}', b'[]', b'not-json'):
            status, _, run, _ = self.cli(raw=raw)
            self.assertEqual(status, 1)
            run.assert_not_called()

    def test_cli_redacts_operation_failures(self):
        status, result, run, _ = self.cli(failure=RuntimeError('SENSITIVE_FAILURE'))
        self.assertEqual(status, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('SENSITIVE', json.dumps(result))
        run.assert_called_once()

    def fixture(self, bootstrap_failure=False, accept_wrong_record=False):
        key = AESGCM.generate_key(bit_length=256)
        sessions = []
        class Client:
            def __init__(self):
                self.record = None
                self.ciphertext = bytearray()
                self.output = b''
                self.closed = False
            def call(self, method, p):
                if method == 'generate':
                    self.record = p['record']
                    return {'handle':'session-handle', 'wrappedKey':'synthetic-wrapper'}
                if method == 'encrypt':
                    encrypted = AESGCM(key).encrypt(bytes(12), base64.b64decode(p['plaintext']), p['record'].encode())
                    return {'iv':base64.b64encode(bytes(12)).decode(), 'tag':base64.b64encode(encrypted[-16:]).decode(),
                            'ciphertext':base64.b64encode(encrypted[:-16]).decode()}
                if method == 'bootstrap':
                    if bootstrap_failure: raise ValueError('KMS unavailable')
                    self.record = p['record']
                    return {'handle':'new-session-handle'}
                if method == 'beginRead':
                    if p['record'] != self.record and not accept_wrong_record: raise ValueError('denied')
                    return {'kind':'readStarted'}
                if method == 'appendRead':
                    self.ciphertext.extend(base64.b64decode(p['ciphertext']))
                    return {'kind':'readAccepted'}
                if method == 'authenticateRead':
                    try:
                        self.output = AESGCM(key).decrypt(bytes(12), bytes(self.ciphertext)+base64.b64decode(p['tag']), self.record.encode())
                    except Exception:
                        raise ValueError('denied') from None
                    return {'kind':'readAuthenticated'}
                if method == 'readChunk':
                    output, self.output = self.output[:runner.READ_CHUNK], self.output[runner.READ_CHUNK:]
                    return {'plaintext':base64.b64encode(output).decode(), 'done':not self.output}
                raise AssertionError(method)
        @contextmanager
        def connect(*_):
            client = Client()
            sessions.append(client)
            try: yield client, {'scope':'synthetic-verifier'}
            finally: client.closed = True
        return connect, sessions

    def test_roundtrip_reopens_handles_and_reports_only_named_scope(self):
        connect, sessions = self.fixture()
        with patch.object(runner, 'recipient_channel', connect):
            result = runner.accept_recipient(1, {}, b'', {}, 'synthetic')
        self.assertEqual(result['bytes'], runner.READ_CHUNK + 17)
        self.assertEqual(len(sessions), 4)
        self.assertTrue(all(s.closed for s in sessions))
        self.assertEqual(result['observed_denials'], ['wrong-record', 'bad-tag'])
        self.assertNotIn('wrappedKey', result)
        self.assertTrue(result['limitations'])

    def test_setup_failure_is_not_counted_as_a_denial(self):
        connect, sessions = self.fixture(bootstrap_failure=True)
        with patch.object(runner, 'recipient_channel', connect), self.assertRaisesRegex(ValueError, 'KMS unavailable'):
            runner.accept_recipient(1, {}, b'', {}, 'synthetic')
        self.assertTrue(all(s.closed for s in sessions))

    def test_unexpected_authorization_prevents_a_success_report(self):
        connect, sessions = self.fixture(accept_wrong_record=True)
        with patch.object(runner, 'recipient_channel', connect), self.assertRaisesRegex(ValueError, 'Expected recipient denial'):
            runner.accept_recipient(1, {}, b'', {}, 'synthetic')
        self.assertTrue(all(s.closed for s in sessions))

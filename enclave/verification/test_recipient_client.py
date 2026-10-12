"""Protocol tests with explicit synthetic credentials, not hardware acceptance."""
from contextlib import contextmanager
import json
import base64
import struct
import unittest
from unittest.mock import patch
from . import recipient_client


def frame(value):
    body = json.dumps(value).encode()
    return struct.pack('!I', len(body)) + body


class Connection:
    def __init__(self, replies):
        self.replies = bytearray(replies)
        self.sent = []
        self.closed = False
    def settimeout(self, timeout):
        assert timeout > 0
    def sendall(self, data):
        self.sent.append(json.loads(data[4:]))
    def recv(self, size):
        size = min(size, 3)  # Exercise fragmented framing.
        result = bytes(self.replies[:size])
        del self.replies[:size]
        return result
    def close(self):
        self.closed = True


class RecipientClientTests(unittest.TestCase):
    credentials = dict(accessKeyId='synthetic', secretAccessKey='synthetic', sessionToken='synthetic', expiration='2099-01-01T00:00:00Z')

    def test_verification_precedes_credentials_and_operations_share_the_socket(self):
        connection = Connection(frame({'id': 1, 'result': {'kind': 'sessionOpened'}}) + frame({'id': 2, 'result': {'handle': base64.b64encode(bytes(32)).decode(), 'wrappedKey': 'enc:kms:recipient:v1:d3JhcHBlZA=='}}))
        @contextmanager
        def verified(*_):
            self.assertEqual(connection.sent, [])
            yield connection, {'scope': 'synthetic-fixture'}
        with patch.object(recipient_client, 'verified_channel', verified):
            with recipient_client.recipient_channel(1, {}, b'fixture', self.credentials) as (client, evidence):
                self.assertEqual(evidence['scope'], 'synthetic-fixture')
                self.assertEqual(client.call('generate', {}), {'handle': base64.b64encode(bytes(32)).decode(), 'wrappedKey': 'enc:kms:recipient:v1:d3JhcHBlZA=='})
            self.assertTrue(connection.closed)
        self.assertEqual([v['id'] for v in connection.sent], [1, 2])
        self.assertEqual(connection.sent[0]['params'], self.credentials)

    def test_verifier_failure_never_opens_a_recipient_session(self):
        with patch.object(recipient_client, 'verified_channel', side_effect=ValueError('Rejected peer')), patch.object(recipient_client, '_RecipientOperations') as constructor:
            with self.assertRaises(ValueError):
                with recipient_client.recipient_channel(1, {}, b'fixture', self.credentials):
                    self.fail('Consumer reached')
            constructor.assert_not_called()

    def test_malformed_replayed_and_truncated_responses_close_the_socket(self):
        values = [frame({'id': 2, 'result': {'kind': 'sessionOpened'}}), frame({'id': True, 'result': {'kind': 'sessionOpened'}}),
                  frame({'id': 1, 'result': {'kind': 'sessionOpened', 'key': 'forbidden'}}), b'\0\0\0\0',
                  struct.pack('!I', recipient_client.MAX_FRAME + 1), b'\0\0\0\x10{']
        body = b'{"id":1,"id":1,"result":{"kind":"sessionOpened"}}'
        values.append(struct.pack('!I', len(body)) + body)
        for value in values:
            with self.subTest(value=value[:60]):
                connection = Connection(value)
                client = recipient_client._RecipientOperations(connection)
                with self.assertRaisesRegex(ValueError, 'Recipient operation failed'):
                    client._exchange('openRecipient', self.credentials)
                self.assertTrue(connection.closed)
                with self.assertRaises(ValueError):
                    client.call('generate', {})
                self.assertEqual(len(connection.sent), 1)

    def test_rejects_invalid_operation_payloads_without_returning_partial_results(self):
        for method, result in [
            ('generate', {'handle': 'YQ==', 'wrappedKey': 'enc:kms:recipient:v1:YQ=='}),
            ('generate', {'handle': base64.b64encode(bytes(32)).decode(), 'wrappedKey': 'enc:kms:v2:YQ=='}),
            ('encrypt', {'iv': base64.b64encode(bytes(12)).decode(), 'tag': base64.b64encode(bytes(4)).decode(), 'ciphertext': ''}),
            ('decrypt', {'plaintext': 'YR=='}),
        ]:
            with self.subTest(method=method, result=result):
                connection = Connection(frame({'id': 1, 'result': result}))
                client = recipient_client._RecipientOperations(connection)
                with self.assertRaises(ValueError):
                    client.call(method, {})
                self.assertTrue(connection.closed)

    def test_discards_a_result_when_closed_during_the_exchange(self):
        connection = Connection(frame({'id': 1, 'result': {'plaintext': ''}}))
        client = recipient_client._RecipientOperations(connection)
        receive = connection.recv
        def close_on_last_chunk(size):
            chunk = receive(size)
            if not connection.replies:
                client.close()
            return chunk
        connection.recv = close_on_last_chunk
        with self.assertRaises(ValueError):
            client.call('decrypt', {})
        self.assertTrue(connection.closed)

    def test_explicit_historical_calls_keep_sequence_and_result_validation(self):
        handle = base64.b64encode(bytes(32)).decode()
        connection = Connection(frame({'id': 1, 'result': {'handle': handle}}) + frame({'id': 2, 'result': {'plaintext': base64.b64encode(b'historical').decode()}}))
        client = recipient_client._RecipientOperations(connection)
        self.assertEqual(client.call('bootstrapLegacyEvidence', {'salt': base64.b64encode(bytes(32)).decode()}), {'handle': handle})
        self.assertEqual(client.call('decryptLegacyEvidence', {'handle': handle}), {'plaintext': base64.b64encode(b'historical').decode()})
        self.assertEqual([r['method'] for r in connection.sent], ['bootstrapLegacyEvidence', 'decryptLegacyEvidence'])
        self.assertEqual([r['id'] for r in connection.sent], [1, 2])
        client.close()

    def test_private_field_reader_accepts_only_the_expected_reply_shape(self):
        handle = base64.b64encode(bytes(32)).decode()
        connection = Connection(frame({'id': 1, 'result': {'handle': handle}}) + frame({'id': 2, 'result': {'plaintext': 'e30='}}))
        client = recipient_client._RecipientOperations(connection)
        self.assertEqual(client.call('bootstrapLegacyPrivate', {'record': 'synthetic', 'field': 'contact'}), {'handle': handle})
        self.assertEqual(client.call('decryptLegacyPrivate', {'handle': handle}), {'plaintext': 'e30='})
        client.close()

    def read_begin(self, size=3):
        return dict(purpose='evidence', record='synthetic', handle=base64.b64encode(bytes(32)).decode(),
                    iv=base64.b64encode(bytes(16)).decode(), size=size, field=None)

    def test_chunk_read_tracks_authentication_completion_and_cancellation(self):
        results = [{'kind':'readStarted'}, {'kind':'readAccepted'}, {'kind':'readAuthenticated'},
                   {'plaintext':'YWJj', 'done':True}, {'kind':'readStarted'}, {'kind':'readCancelled'}]
        connection = Connection(b''.join(frame({'id':i+1, 'result':r}) for i,r in enumerate(results)))
        client = recipient_client._RecipientOperations(connection)
        client.call('beginRead', self.read_begin())
        client.call('appendRead', {'ciphertext':'YWJj'})
        client.call('authenticateRead', {'tag':base64.b64encode(bytes(16)).decode()})
        self.assertEqual(client.call('readChunk', {}), {'plaintext':'YWJj', 'done':True})
        self.assertIsNone(client.read)
        client.call('beginRead', self.read_begin(0))
        client.call('cancelRead', {})
        self.assertIsNone(client.read)
        self.assertEqual([r['id'] for r in connection.sent], list(range(1,7)))
        client.close()

    def test_read_request_errors_close_before_sending_unsafe_command(self):
        for method, params in [('readChunk', {}), ('authenticateRead', {'tag':base64.b64encode(bytes(16)).decode()}),
                               ('appendRead', {'ciphertext':'YWJjZA=='}), ('appendRead', {'ciphertext':'YR=='}),
                               ('beginRead', self.read_begin()), ('generate', {})]:
            with self.subTest(method=method, params=params):
                connection = Connection(frame({'id':1, 'result':{'kind':'readStarted'}}))
                client = recipient_client._RecipientOperations(connection)
                client.call('beginRead', self.read_begin())
                with self.assertRaises(ValueError): client.call(method, params)
                self.assertEqual(len(connection.sent), 1)
                self.assertTrue(connection.closed)
                self.assertIsNone(client.read)

    def test_read_response_denials_discard_state(self):
        for output in [{'plaintext':'YWI=', 'done':True}, {'plaintext':'YWJj', 'done':False},
                       {'plaintext':'YWJj', 'done':1}, {'plaintext':'YWJj', 'done':True, 'key':'forbidden'},
                       {'plaintext':'YR==', 'done':True}]:
            with self.subTest(output=output):
                results = [{'kind':'readStarted'}, {'kind':'readAccepted'}, {'kind':'readAuthenticated'}, output]
                connection = Connection(b''.join(frame({'id':i+1,'result':r}) for i,r in enumerate(results)))
                client = recipient_client._RecipientOperations(connection)
                client.call('beginRead', self.read_begin())
                client.call('appendRead', {'ciphertext':'YWJj'})
                client.call('authenticateRead', {'tag':base64.b64encode(bytes(16)).decode()})
                with self.assertRaises(ValueError): client.call('readChunk', {})
                self.assertTrue(connection.closed)
                self.assertIsNone(client.read)

    def test_read_declared_size_and_acknowledgement_are_strict(self):
        for size in [True, -1, recipient_client.MAX_READ+1, 3.0]:
            connection = Connection(b'')
            client = recipient_client._RecipientOperations(connection)
            with self.assertRaises(ValueError): client.call('beginRead', self.read_begin(size))
            self.assertEqual(connection.sent, [])
        connection = Connection(frame({'id':1, 'result':{'kind':'readAuthenticated'}}))
        client = recipient_client._RecipientOperations(connection)
        with self.assertRaises(ValueError): client.call('beginRead', self.read_begin())
        self.assertTrue(connection.closed)

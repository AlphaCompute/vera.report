"""Recipient operation client for hardware acceptance; no credential discovery."""
from contextlib import contextmanager
import json
import base64
import struct
import socket
import threading
import time
from .verify_channel import verified_channel
from .verify_identity import unique_object

MAX_FRAME = 12 * 1024 * 1024
MAX_READ = 256 * 1024 * 1024
READ_CHUNK = 1024 * 1024
READ_ACKS = {'beginRead': 'readStarted', 'appendRead': 'readAccepted',
             'authenticateRead': 'readAuthenticated', 'cancelRead': 'readCancelled'}


def binary(value, maximum, exact=False):
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError('Invalid recipient bytes')
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) > maximum or (exact and len(decoded) != maximum) or base64.b64encode(decoded).decode() != value:
        raise ValueError('Invalid recipient bytes')
    return decoded


class _RecipientOperations:
    def __init__(self, connection):
        self.connection = connection
        self.next_id = 1
        self.expires = time.monotonic() + 290
        self.closed = False
        self.lock = threading.Lock()
        self.read = None

    def close(self):
        self.closed = True
        self.read = None
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass
        self.connection.close()

    def _read_request(self, method, params):
        state = dict(self.read) if self.read is not None else None
        schemas = {'beginRead': {'purpose', 'record', 'handle', 'iv', 'size', 'field'},
                   'appendRead': {'ciphertext'}, 'authenticateRead': {'tag'},
                   'readChunk': set(), 'cancelRead': set()}
        if method not in schemas:
            if state is not None:
                raise ValueError('Read active')
            return state
        if not isinstance(params, dict) or set(params) != schemas[method]:
            raise ValueError('Invalid read request')
        if method == 'beginRead':
            if state is not None or type(params['size']) is not int or not 0 <= params['size'] <= MAX_READ:
                raise ValueError('Invalid read size or state')
            binary(params['handle'], 32, True)
            if len(binary(params['iv'], 16)) not in (12, 16):
                raise ValueError('Invalid read IV')
            if params['purpose'] not in ('evidence', 'narrative') or not isinstance(params['record'], str) or not 0 < len(params['record'].encode()) <= 256:
                raise ValueError('Invalid read scope')
            if params['field'] is not None and (not isinstance(params['field'], str) or not 0 < len(params['field'].encode()) <= 256):
                raise ValueError('Invalid read field')
            return {'size': params['size'], 'received': 0, 'emitted': 0, 'authenticated': False}
        if state is None:
            raise ValueError('No active read')
        if method == 'appendRead':
            size = len(binary(params['ciphertext'], READ_CHUNK))
            if state['authenticated'] or not 0 < size <= state['size'] - state['received']:
                raise ValueError('Invalid read chunk')
            state['received'] += size
        elif method == 'authenticateRead':
            binary(params['tag'], 16, True)
            if state['authenticated'] or state['received'] != state['size']:
                raise ValueError('Incomplete read')
            state['authenticated'] = True
        elif method == 'readChunk' and not state['authenticated']:
            raise ValueError('Read not authenticated')
        elif method == 'cancelRead':
            return None
        return state

    def _exchange(self, method, params):
        if not self.lock.acquire(blocking=False):
            raise ValueError('Recipient operation already pending')
        try:
            if self.closed or self.next_id >= 10000 or time.monotonic() >= self.expires:
                raise ValueError('Recipient session unavailable')
            read_state = self._read_request(method, params)
            request_id = self.next_id
            self.next_id += 1
            payload = json.dumps({'id': request_id, 'method': method, 'params': params}, allow_nan=False).encode()
            if not 0 < len(payload) <= MAX_FRAME:
                raise ValueError('Invalid recipient request size')
            deadline = min(self.expires, time.monotonic() + 35)
            def timeout():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Recipient operation timed out')
                self.connection.settimeout(remaining)
            def read(size):
                result = bytearray()
                while len(result) < size:
                    timeout()
                    chunk = self.connection.recv(size - len(result))
                    if not chunk:
                        raise ValueError('Truncated recipient response')
                    result.extend(chunk)
                return bytes(result)
            timeout()
            self.connection.sendall(struct.pack('!I', len(payload)) + payload)
            size = struct.unpack('!I', read(4))[0]
            if not 0 < size <= MAX_FRAME:
                raise ValueError('Invalid recipient response size')
            response = json.loads(read(size).decode('utf8'), object_pairs_hook=unique_object,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))
            if not isinstance(response, dict) or set(response) != {'id', 'result'} or type(response['id']) is not int or response['id'] != request_id:
                raise ValueError('Invalid recipient response')
            result = response['result']
            fields = {'openRecipient': {'kind'}, 'generate': {'handle', 'wrappedKey'}, 'bootstrap': {'handle'}, 'bootstrapLegacyEvidence': {'handle'}, 'bootstrapLegacyPrivate': {'handle'},
                      'encrypt': {'iv', 'tag', 'ciphertext'}, 'decrypt': {'plaintext'}, 'decryptLegacyEvidence': {'plaintext'}, 'decryptLegacyPrivate': {'plaintext'}}
            fields.update({name: {'kind'} for name in READ_ACKS})
            fields['readChunk'] = {'plaintext', 'done'}
            if not isinstance(result, dict) or set(result) != fields[method] or any(not isinstance(v, str) for k, v in result.items() if not (method == 'readChunk' and k == 'done')):
                raise ValueError('Invalid recipient result')
            if method == 'openRecipient' and result['kind'] != 'sessionOpened':
                raise ValueError('Invalid recipient session')
            if method in READ_ACKS and result['kind'] != READ_ACKS[method]:
                raise ValueError('Invalid read acknowledgement')
            if method == 'readChunk':
                size = len(binary(result['plaintext'], READ_CHUNK))
                expected = min(READ_CHUNK, read_state['size'] - read_state['emitted'])
                if size != expected or type(result['done']) is not bool or result['done'] != (read_state['emitted'] + size == read_state['size']):
                    raise ValueError('Invalid read output')
                read_state['emitted'] += size
                if result['done']:
                    read_state = None
            if method in {'generate', 'bootstrap', 'bootstrapLegacyEvidence', 'bootstrapLegacyPrivate'}:
                binary(result['handle'], 32, True)
            if method == 'generate':
                prefix = 'enc:kms:recipient:v1:'
                if not result['wrappedKey'].startswith(prefix) or not binary(result['wrappedKey'][len(prefix):], 6144):
                    raise ValueError('Invalid recipient wrapper')
            if method == 'encrypt':
                binary(result['iv'], 12, True)
                binary(result['tag'], 16, True)
                binary(result['ciphertext'], 8 * 1024 * 1024)
            if method in {'decrypt', 'decryptLegacyEvidence', 'decryptLegacyPrivate'}:
                binary(result['plaintext'], 8 * 1024 * 1024)
            if self.closed or time.monotonic() >= deadline:
                raise ValueError('Recipient session unavailable')
            self.read = read_state
            return result
        except Exception:
            self.close()
            raise ValueError('Recipient operation failed') from None
        finally:
            self.lock.release()

    def call(self, method, params):
        if method not in {'generate', 'bootstrap', 'encrypt', 'decrypt', 'bootstrapLegacyEvidence', 'decryptLegacyEvidence', 'bootstrapLegacyPrivate', 'decryptLegacyPrivate', 'beginRead', 'appendRead', 'authenticateRead', 'readChunk', 'cancelRead'}:
            raise ValueError('Unsupported recipient operation')
        return self._exchange(method, params)


@contextmanager
def recipient_channel(port, expected_pcrs, root_pem, credentials):
    """No credentials are sent until the same socket passes NSM verification.

    Credentials must be explicit temporary IAM credentials; caller owns their
    provenance and authorization. This library never writes them to artifacts.
    """
    if not isinstance(credentials, dict) or set(credentials) != {'accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'}:
        raise ValueError('Temporary credentials required')
    if any(not isinstance(v, str) or not 0 < len(v) <= 8192 for v in credentials.values()):
        raise ValueError('Temporary credentials required')
    snapshot = dict(credentials)
    with verified_channel(port, expected_pcrs, root_pem) as (connection, evidence):
        client = _RecipientOperations(connection)
        try:
            client._exchange('openRecipient', snapshot)
            yield client, evidence
        finally:
            client.close()

"""Application adapter for one historical encrypted report field; caller activation is separately gated.

The application must authorize the report before supplying this request. This
helper performs no authorization discovery, database access or persistence.
Only authenticated plaintext JSON crosses its private stdout pipe; key handles,
credentials and wrapped keys are never returned or logged.
"""
import json
import re
import sys
from datetime import datetime, timezone
from .recipient_client import recipient_channel, binary
from .verify_identity import ROOT_PATH, unique_object

MAX_FIELD = 8 * 1024 * 1024
MAX_INPUT = 12 * 1024 * 1024
FAILURE = 'Report verification reader unavailable'


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(FAILURE)
    return value


def read_report_verification(request):
    exact(request, ['trackingId', 'envelope', 'port', 'keyArn', 'pcrs', 'credentials'])
    tracking = request['trackingId']
    if not isinstance(tracking, str) or not re.fullmatch(r'VRA-[A-F0-9]{16}', tracking):
        raise ValueError(FAILURE)
    if type(request['port']) is not int or not 1 <= request['port'] <= 65535:
        raise ValueError(FAILURE)
    if not isinstance(request['keyArn'], str) or not re.fullmatch(
            r'arn:aws:kms:us-east-2:000000000000:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', request['keyArn']):
        raise ValueError(FAILURE)
    pcrs = exact(request['pcrs'], ['0', '1', '2'])
    expected = {}
    for index, value in pcrs.items():
        if not isinstance(value, str) or not re.fullmatch(r'[a-fA-F0-9]{96}', value) or not any(bytes.fromhex(value)):
            raise ValueError(FAILURE)
        expected[int(index)] = bytes.fromhex(value)
    credentials = exact(request['credentials'], ['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'])
    if any(not isinstance(value, str) or not 0 < len(value) <= 8192 for value in credentials.values()):
        raise ValueError(FAILURE)
    expires = datetime.fromisoformat(credentials['expiration'].replace('Z', '+00:00'))
    if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
        raise ValueError(FAILURE)
    envelope = request['envelope']
    if not isinstance(envelope, str) or not envelope.startswith('private:v1:') or len(envelope) > MAX_INPUT:
        raise ValueError(FAILURE)
    stored = exact(json.loads(envelope[len('private:v1:'):], object_pairs_hook=unique_object), ['key', 'iv', 'tag', 'data'])
    prefix = 'enc:kms:v2:'
    if not isinstance(stored['key'], str) or not stored['key'].startswith(prefix) or not binary(stored['key'][len(prefix):], 6144):
        raise ValueError(FAILURE)
    binary(stored['iv'], 12, True)
    binary(stored['tag'], 16, True)
    binary(stored['data'], MAX_FIELD)
    record = 'report:' + tracking
    # The same verified TLS socket carries bootstrap and read. Neither the
    # purpose nor the field can be selected by an untrusted request envelope.
    with recipient_channel(request['port'], expected, ROOT_PATH.read_bytes(), credentials) as (client, _identity):
        handle = client.call('bootstrapLegacyPrivate', {
            'record': record, 'field': 'verification', 'keyArn': request['keyArn'], 'wrappedKey': stored['key'],
        })['handle']
        result = client.call('decryptLegacyPrivate', {
            'record': record, 'field': 'verification', 'handle': handle,
            'iv': stored['iv'], 'tag': stored['tag'], 'ciphertext': stored['data'],
        })
        plaintext = bytearray(binary(result['plaintext'], MAX_FIELD))
        try:
            return json.loads(plaintext, object_pairs_hook=unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError(FAILURE)))
        finally:
            plaintext[:] = bytes(len(plaintext))


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError(FAILURE)
        request = json.loads(raw, object_pairs_hook=unique_object)
        value = read_report_verification(request)
        sys.stdout.write(json.dumps({'value': value}, separators=(',', ':'), ensure_ascii=False, allow_nan=False))
        return 0
    except Exception:
        # Do not turn provider/credential/record/JSON failures into diagnostics.
        sys.stdout.write('{"error":"Report verification reader unavailable"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

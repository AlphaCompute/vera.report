"""Synthetic recipient acceptance operations; never persist credentials or keys.

Call with explicit temporary credentials, approved PCRs, pinned AWS root and a
reviewed KMS key ARN. This function does not provision resources or activate an
endpoint. A successful result covers only the operations named in the result.
"""
import base64
import argparse
import hashlib
import json
import re
import secrets
import sys
from .recipient_client import recipient_channel, READ_CHUNK
from .verify_identity import ROOT_PATH, unique_object


def accept_recipient(port, expected_pcrs, root_pem, credentials, key_arn, *, channel_factory=None):
    record = 'acceptance-' + secrets.token_hex(16)
    scope = {'purpose': 'evidence', 'record': record}
    context = {'purpose': 'evidence', 'fileKey': record}
    # More than one transport chunk, below the current single-write bound.
    plaintext = secrets.token_bytes(READ_CHUNK + 17)
    expected_hash = hashlib.sha256(plaintext).hexdigest()
    evidence = []
    connect = channel_factory if channel_factory is not None else lambda: recipient_channel(port, expected_pcrs, root_pem, credentials)
    with connect() as (client, identity):
        evidence.append(identity)
        generated = client.call('generate', {**scope, 'keyArn': key_arn, 'context': context})
        sealed = client.call('encrypt', {**scope, 'handle': generated['handle'],
                                       'plaintext': base64.b64encode(plaintext).decode()})
    del plaintext
    ciphertext = base64.b64decode(sealed['ciphertext'], validate=True)

    def prepare(client, bound_record=record):
        # A fresh handle requires a new attested session and authorized KMS
        # unwrap. A previous session handle is never reused as a credential.
        handle = client.call('bootstrap', {**scope, 'keyArn': key_arn, 'context': context,
                                          'wrappedKey': generated['wrappedKey']})['handle']
        client.call('beginRead', {**scope, 'record': bound_record, 'handle': handle,
                                'iv': sealed['iv'], 'size': len(ciphertext), 'field': None})
        for offset in range(0, len(ciphertext), READ_CHUNK):
            client.call('appendRead', {'ciphertext': base64.b64encode(ciphertext[offset:offset+READ_CHUNK]).decode()})

    with connect() as (client, identity):
        evidence.append(identity)
        prepare(client)
        client.call('authenticateRead', {'tag': sealed['tag']})
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = client.call('readChunk', {})
            decoded = base64.b64decode(chunk['plaintext'], validate=True)
            digest.update(decoded)
            total += len(decoded)
            if chunk['done']:
                break
        if digest.hexdigest() != expected_hash or total != READ_CHUNK + 17:
            raise ValueError('Synthetic recipient roundtrip mismatch')

    # Bootstrap must succeed before a denial is counted. Connection or KMS
    # failure during setup therefore cannot masquerade as an access denial.
    for case in ('wrong-record', 'bad-tag'):
        with connect() as (client, identity):
            evidence.append(identity)
            handle = client.call('bootstrap', {**scope, 'keyArn': key_arn, 'context': context,
                                              'wrappedKey': generated['wrappedKey']})['handle']
            if case == 'bad-tag':
                client.call('beginRead', {**scope, 'handle': handle, 'iv': sealed['iv'],
                                        'size': len(ciphertext), 'field': None})
                for offset in range(0, len(ciphertext), READ_CHUNK):
                    client.call('appendRead', {'ciphertext': base64.b64encode(ciphertext[offset:offset+READ_CHUNK]).decode()})
                tag = bytearray(base64.b64decode(sealed['tag'], validate=True))
                tag[0] ^= 1
                method, params = 'authenticateRead', {'tag': base64.b64encode(tag).decode()}
            else:
                method, params = 'beginRead', {**scope, 'record': record + '-wrong', 'handle': handle,
                                              'iv': sealed['iv'], 'size': len(ciphertext), 'field': None}
            try:
                client.call(method, params)
            except ValueError:
                pass
            else:
                raise ValueError('Expected recipient denial did not occur')
    return {'scope': 'synthetic-recipient-channel-operations', 'bytes': total,
            'plaintext_sha256': expected_hash, 'sessions': evidence,
            'verified': ['generate', 'encrypt', 'fresh-session-bootstrap', 'authenticated-chunk-read'],
            'observed_denials': ['wrong-record', 'bad-tag'],
            'limitations': ['Denials are observed closed operations; correlate enclave-side evidence before attributing the failure cause.',
                            'No application deployment, migration, IAM negative-role test, debug/PCR denial or wallet transaction is covered.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--key-arn', required=True)
    for index in range(3):
        parser.add_argument(f'--pcr{index}', required=True)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.port <= 65535:
            raise ValueError('Invalid port')
        if not re.fullmatch(r'arn:aws:kms:us-east-2:000000000000:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', args.key_arn):
            raise ValueError('Explicit Vera KMS key required')
        expected = {}
        for index in range(3):
            encoded = getattr(args, f'pcr{index}')
            if not re.fullmatch(r'[a-fA-F0-9]{96}', encoded) or not any(bytes.fromhex(encoded)):
                raise ValueError('Approved non-debug PCRs required')
            expected[index] = bytes.fromhex(encoded)
        # No credential arguments, discovery, temporary files or raw diagnostics.
        # The caller provides a bounded JSON object on a private stdin pipe.
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768:
            raise ValueError('Credential input too large')
        credentials = json.loads(raw, object_pairs_hook=unique_object)
        if (not isinstance(credentials, dict)
                or set(credentials) != {'accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'}
                or any(not isinstance(value, str) or not 0 < len(value) <= 8192 for value in credentials.values())):
            raise ValueError('Explicit temporary credentials required')
        result = accept_recipient(args.port, expected, ROOT_PATH.read_bytes(), credentials, args.key_arn)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'status': 'failed', 'scope': 'synthetic-recipient-channel-operations',
                          'reason': 'Recipient acceptance failed; sensitive diagnostics omitted'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

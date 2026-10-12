"""Independent verification of VERA-ENCLAVE-IDENTITY-v1; no secret/RPC trust grant."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import time

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

CONTEXT = b'VERA-ENCLAVE-IDENTITY-v1'
# Published at https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
ROOT_FINGERPRINT = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b'
ROOT_PATH = Path(__file__).with_name('aws-nitro-root.pem')


def decode(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= 16384:
        raise ValueError('Invalid CBOR size/type')
    stream = io.BytesIO(data)
    # NSM documents can contain indefinite-length CBOR maps/containers. Their
    # original protected-header and payload bytes remain the signature input;
    # accepting this encoding does not normalize or relax attestation checks.
    value = cbor2.CBORDecoder(stream, max_depth=16, allow_duplicate_keys=False,
                             allow_indefinite=True).decode()
    if stream.tell() != len(data):
        raise ValueError('Trailing CBOR data')
    return value


def _verify_document(document, nonce, expected_pcrs, root_pem, context, scope, now_ms=None):
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise ValueError('Invalid challenge')
    if not isinstance(expected_pcrs, dict) or not {0, 1, 2}.issubset(expected_pcrs):
        raise ValueError('PCR0, PCR1 and PCR2 must be pinned')
    for index, pcr in expected_pcrs.items():
        if type(index) is not int or not 0 <= index <= 31 or not isinstance(pcr, bytes) or len(pcr) != 48 or not any(pcr):
            raise ValueError('Invalid expected PCR')
    root = x509.load_pem_x509_certificate(root_pem)
    if root.fingerprint(hashes.SHA256()).hex() != ROOT_FINGERPRINT:
        raise ValueError('Untrusted root')
    cose = decode(document)
    if isinstance(cose, cbor2.CBORTag):
        if cose.tag != 18:
            raise ValueError('Invalid COSE tag')
        cose = cose.value
    if not isinstance(cose, (list, tuple)) or len(cose) != 4:
        raise ValueError('Invalid COSE envelope')
    protected, unprotected, payload, signature = cose
    headers = decode(protected)
    if not isinstance(headers, dict) or len(headers) != 1 or any(type(key) is not int for key in headers) or \
            type(headers.get(1)) is not int or headers[1] != -35 or unprotected != {} or not isinstance(signature, bytes) or len(signature) != 96:
        raise ValueError('Unsupported COSE headers/signature')
    body = decode(payload)
    if not isinstance(body, dict) or body.get('digest') != 'SHA384':
        raise ValueError('Invalid attestation payload')
    if not isinstance(body.get('module_id'), str) or not 0 < len(body['module_id']) <= 1024:
        raise ValueError('Invalid module identity')
    if body.get('nonce') != nonce or body.get('user_data') != context or body.get('public_key') is not None:
        raise ValueError('Identity protocol mismatch')
    now = int(time.time() * 1000) if now_ms is None else now_ms
    timestamp = body.get('timestamp')
    if type(now) is not int or type(timestamp) is not int or timestamp < now - 60000 or timestamp > now + 5000:
        raise ValueError('Stale or future attestation')
    pcrs = body.get('pcrs')
    if not isinstance(pcrs, dict) or not 3 <= len(pcrs) <= 32:
        raise ValueError('Invalid PCR map')
    for index, pcr in pcrs.items():
        if type(index) is not int or not 0 <= index <= 31 or not isinstance(pcr, bytes) or len(pcr) != 48:
            raise ValueError('Invalid PCR')
    for index, expected in expected_pcrs.items():
        if pcrs.get(index) != expected:
            raise ValueError('Unapproved image measurement')
    certificate, bundle = body.get('certificate'), body.get('cabundle')
    if not isinstance(certificate, bytes) or not 0 < len(certificate) <= 1024:
        raise ValueError('Invalid certificate')
    if not isinstance(bundle, list) or not 1 <= len(bundle) <= 10 or not all(isinstance(cert, bytes) and 0 < len(cert) <= 1024 for cert in bundle):
        raise ValueError('Invalid certificate bundle')
    leaf = x509.load_der_x509_certificate(certificate)
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError('Invalid signing key')
    with tempfile.TemporaryDirectory(prefix='vera-identity-') as directory:
        root_path, chain_path, leaf_path = [Path(directory, name) for name in ('root.pem', 'chain.pem', 'leaf.pem')]
        # Trust only the fingerprint-checked certificate, not appended PEM roots.
        root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        chain_path.write_bytes(b''.join(x509.load_der_x509_certificate(cert).public_bytes(serialization.Encoding.PEM) for cert in bundle))
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        result = subprocess.run(['openssl', 'verify', '-trusted', str(root_path), '-untrusted', str(chain_path),
                                 '-attime', str(now // 1000), '-purpose', 'any', str(leaf_path)],
                                capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('Invalid attestation certificate chain')
    signed = cbor2.dumps(['Signature1', protected, b'', payload])
    der = utils.encode_dss_signature(int.from_bytes(signature[:48], 'big'), int.from_bytes(signature[48:], 'big'))
    key.verify(der, signed, ec.ECDSA(hashes.SHA384()))
    return {'scope': scope, 'document_sha256': hashlib.sha256(document).hexdigest(),
            'nonce': nonce.hex(), 'verified_at': now,
            'timestamp': timestamp, 'pcrs': {str(index): pcr.hex() for index, pcr in expected_pcrs.items()}}


def verify_identity(document, nonce, expected_pcrs, root_pem, now_ms=None):
    return _verify_document(document, nonce, expected_pcrs, root_pem, CONTEXT, 'enclave-identity-only', now_ms)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def exchange_document(connection, nonce, method, deadline):
    request_id = secrets.token_hex(16)
    payload = json.dumps({'id': request_id, 'method': method, 'params': {'nonce': nonce.hex()}}).encode()
    def read(size):
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Attestation transport timed out')
            connection.settimeout(remaining)
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise ValueError('Truncated attestation response')
            chunks.extend(chunk)
        return bytes(chunks)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Attestation transport timed out')
    connection.settimeout(remaining)
    connection.sendall(struct.pack('!I', len(payload)) + payload)
    size = struct.unpack('!I', read(4))[0]
    if not 0 < size <= 24576:
        raise ValueError('Invalid attestation response size')
    response = json.loads(read(size), object_pairs_hook=unique_object)
    if not isinstance(response, dict) or set(response) != {'id', 'result'} or response['id'] != request_id:
        raise ValueError('Invalid attestation response')
    result = response['result']
    if not isinstance(result, dict) or set(result) != {'document'} or not isinstance(result['document'], str):
        raise ValueError('Invalid attestation result')
    document = base64.b64decode(result['document'], validate=True)
    if not 0 < len(document) <= 16384 or base64.b64encode(document).decode() != result['document']:
        raise ValueError('Invalid attestation document encoding')
    return document


def request_document(port, nonce):
    deadline = time.monotonic() + 15
    with socket.create_connection(('127.0.0.1', port), timeout=15) as connection:
        return exchange_document(connection, nonce, 'attestIdentity', deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True, help='local operator-created vsock bridge')
    for index in range(3):
        parser.add_argument(f'--pcr{index}', required=True, help='approved measurement from the exact EIF build')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('invalid port')
    expected = {}
    for index in range(3):
        encoded = getattr(args, f'pcr{index}')
        if len(encoded) != 96 or any(c not in '0123456789abcdefABCDEF' for c in encoded):
            parser.error('PCRs must contain 96 hexadecimal characters')
        expected[index] = bytes.fromhex(encoded)
        if not any(expected[index]):
            parser.error('debug measurements are not accepted')
    nonce = secrets.token_bytes(32)
    document = request_document(args.port, nonce)
    print(json.dumps(verify_identity(document, nonce, expected, ROOT_PATH.read_bytes()), sort_keys=True))


if __name__ == '__main__':
    main()

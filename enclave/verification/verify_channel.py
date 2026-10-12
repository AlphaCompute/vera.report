"""Verify the peer on a fresh TLS connection using NSM certificate binding."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import secrets
import socket
import ssl
import time
from .verify_identity import ROOT_PATH, _verify_document, exchange_document

CONTEXT = b'VERA-ENCLAVE-CHANNEL-v1'


@contextmanager
def verified_channel(port, expected_pcrs, root_pem):
    """Yield only the freshly verified TLS socket; close it on every exit path.

    Consumers must keep operations on this socket, never reconnect using the
    returned evidence as a bearer credential. The caller supplies approved PCRs.
    """
    nonce = secrets.token_bytes(32)
    deadline = time.monotonic() + 20
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # Authenticate the peer with fresh NSM evidence below, not a public-web CA.
    # No secret or privileged request is sent on this unverified connection.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        with context.wrap_socket(raw) as connection:
            certificate = connection.getpeercert(binary_form=True)
            if not certificate or len(certificate) > 8192:
                raise ValueError('Invalid channel certificate')
            digest = hashlib.sha256(certificate).digest()
            document = exchange_document(connection, nonce, 'attestChannel', deadline)
            result = _verify_document(document, nonce, expected_pcrs, root_pem,
                                      CONTEXT + digest, 'attested-tls-peer')
            yield connection, {**result, 'certificate_sha256': digest.hex()}


def verify_channel(port, expected_pcrs, root_pem):
    with verified_channel(port, expected_pcrs, root_pem) as (_connection, evidence):
        return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    for index in range(3):
        parser.add_argument(f'--pcr{index}', required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('invalid port')
    expected = {}
    for index in range(3):
        encoded = getattr(args, f'pcr{index}')
        if len(encoded) != 96 or any(char not in '0123456789abcdefABCDEF' for char in encoded):
            parser.error('PCRs must contain 96 hexadecimal characters')
        expected[index] = bytes.fromhex(encoded)
        if not any(expected[index]):
            parser.error('debug measurements are not accepted')
    print(json.dumps(verify_channel(args.port, expected, ROOT_PATH.read_bytes()), sort_keys=True))


if __name__ == '__main__':
    main()

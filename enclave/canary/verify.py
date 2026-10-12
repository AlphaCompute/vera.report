"""Verify Nitro COSE/PKI/nonce/PCR and exercise encrypted synthetic intake."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import secrets
import resource
import struct
import subprocess
import tempfile
import time
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b'VERA-NITRO-CANARY-v1'
# DER certificate fingerprint, derived from the AWS root ZIP whose published
# SHA256 is 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c.
ROOT_FINGERPRINT = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b'


def cbor(data):
    stream = io.BytesIO(data)
    value = cbor2.CBORDecoder(stream, max_depth=16, allow_duplicate_keys=False, allow_indefinite=False).decode()
    if stream.tell() != len(data):
        raise ValueError('Trailing CBOR data')
    return value


def verify(document, nonce, expected_pcr0, root_pem, root_fingerprint=ROOT_FINGERPRINT):
    if len(document) > 16384 or len(nonce) != 32 or len(expected_pcr0) != 48 or not any(expected_pcr0):
        raise ValueError('Invalid verification inputs')
    root = x509.load_pem_x509_certificate(root_pem)
    if root.fingerprint(hashes.SHA256()).hex() != root_fingerprint:
        raise ValueError('Untrusted root')
    cose = cbor(document)
    if isinstance(cose, cbor2.CBORTag):
        if cose.tag != 18:
            raise ValueError('Invalid COSE tag')
        cose = cose.value
    if not isinstance(cose, list) or len(cose) != 4:
        raise ValueError('Invalid COSE envelope')
    protected, unprotected, payload, signature = cose
    headers = cbor(protected)
    if not isinstance(headers, dict) or len(headers) != 1 or any(type(key) is not int for key in headers) or \
            type(headers.get(1)) is not int or headers[1] != -35 or unprotected != {} or len(signature) != 96:
        raise ValueError('Unsupported COSE headers/signature')
    body = cbor(payload)
    if body['digest'] != 'SHA384' or body['nonce'] != nonce or body['user_data'] != CONTEXT:
        raise ValueError('Attestation context mismatch')
    if not isinstance(body['timestamp'], int) or abs(time.time() * 1000 - body['timestamp']) > 60000:
        raise ValueError('Stale attestation')
    for index in (0, 1, 2):
        if len(body['pcrs'][index]) != 48 or not any(body['pcrs'][index]):
            raise ValueError('Debug/unmeasured image')
    if body['pcrs'][0] != expected_pcr0:
        raise ValueError('Unapproved image')
    if len(body['cabundle']) > 10:
        raise ValueError('Invalid certificate chain')
    leaf = x509.load_der_x509_certificate(body['certificate'])
    public = leaf.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP384R1):
        raise ValueError('Invalid signing key')
    with tempfile.TemporaryDirectory(prefix='vera-attestation-') as directory:
        root_path, chain_path, leaf_path = [Path(directory, name) for name in ('root.pem', 'chain.pem', 'leaf.pem')]
        root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        chain_path.write_bytes(b''.join(x509.load_der_x509_certificate(cert).public_bytes(serialization.Encoding.PEM) for cert in body['cabundle']))
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        result = subprocess.run(['openssl', 'verify', '-trusted', str(root_path), '-untrusted', str(chain_path), '-purpose', 'any', str(leaf_path)], capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('Invalid attestation certificate chain')
    signed = cbor2.dumps(['Signature1', protected, b'', payload])
    der_signature = utils.encode_dss_signature(int.from_bytes(signature[:48]), int.from_bytes(signature[48:]))
    public.verify(der_signature, signed, ec.ECDSA(hashes.SHA384()))
    enclave_key = serialization.load_der_public_key(body['public_key'])
    if not isinstance(enclave_key, X25519PublicKey):
        raise ValueError('Unexpected recipient key')
    return enclave_key, body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssh-config', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--cid', type=int, required=True)
    parser.add_argument('--pcr0', required=True)
    parser.add_argument('--root', required=True)
    args = parser.parse_args()

    def rpc(message):
        payload = json.dumps(message).encode()
        command = ['ssh', '-F', args.ssh_config, '-o', 'BatchMode=yes', args.host,
                   'python3', 'vera-nitro-review/canary/proxy.py', str(args.cid)]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, input=struct.pack('!I', len(payload)) + payload, stdout=output, stderr=subprocess.DEVNULL, timeout=20,
                                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536)))
            output.seek(0)
            wire = output.read(65536)
        if result.returncode or len(wire) < 4 or len(wire) != 4 + struct.unpack('!I', wire[:4])[0]:
            raise RuntimeError('Canary transport failed')
        return json.loads(wire[4:])

    nonce = secrets.token_bytes(32)
    encoded = lambda data: base64.b64encode(data).decode()
    response = rpc({'method': 'attest', 'nonce': encoded(nonce)})
    document = base64.b64decode(response['result']['document'], validate=True)
    root = Path(args.root).read_bytes()
    expected = bytes.fromhex(args.pcr0)
    enclave_key, body = verify(document, nonce, expected, root)
    negative = []
    for name, altered_nonce, altered_pcr, altered_doc in [
        ('wrong nonce', secrets.token_bytes(32), expected, document),
        ('wrong PCR', nonce, b'\x01' * 48, document),
        ('modified signature', nonce, expected, document[:-1] + bytes([document[-1] ^ 1])),
    ]:
        try:
            verify(altered_doc, altered_nonce, altered_pcr, root)
        except Exception:
            negative.append(name)
        else:
            raise RuntimeError('Negative attestation test unexpectedly passed')
    key = X25519PrivateKey.generate()
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(document).digest(), info=CONTEXT).derive(key.exchange(enclave_key))
    plaintext, iv = secrets.token_bytes(128), secrets.token_bytes(12)
    message = {'method': 'confirm', 'nonce': encoded(nonce),
               'publicKey': encoded(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
               'iv': encoded(iv), 'ciphertext': encoded(AESGCM(session_key).encrypt(iv, plaintext, CONTEXT))}
    result = rpc(message)
    if result.get('result', {}).get('digest') != hashlib.sha256(plaintext).hexdigest():
        raise RuntimeError('Encrypted canary failed')
    if 'error' not in rpc(message):
        raise RuntimeError('Replay was accepted')
    print(json.dumps({'verified': True, 'pcr0': body['pcrs'][0].hex(), 'checks': ['AWS PKI', 'COSE signature', 'fresh nonce', 'non-debug PCRs', 'encrypted intake', 'replay rejection'] + negative,
                      'scope': 'Ephemeral synthetic canary only; no KMS, persisted keys or production integration'}, indent=2))


if __name__ == '__main__':
    main()

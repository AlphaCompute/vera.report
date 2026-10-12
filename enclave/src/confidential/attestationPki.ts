import { fromBER, ObjectIdentifier } from 'asn1js';
import { Certificate, CertificateChainValidationEngine, CryptoEngine } from 'pkijs';
import type { UnverifiedApplicationAttestation } from './attestationEvidence.ts';
import { AttestationCertificateSizeError, MAX_ATTESTATION_CERTIFICATE_BYTES } from './attestationCertificateLimit.ts';

export { AttestationCertificateSizeError, MAX_ATTESTATION_CERTIFICATE_BYTES };

function invalid(): never { throw new Error('Invalid attestation certificate or signature'); }
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function certificate(input: Uint8Array, now: number): Certificate {
  if (!(input instanceof Uint8Array) || !input.length) invalid();
  if (input.length > MAX_ATTESTATION_CERTIFICATE_BYTES) throw new AttestationCertificateSizeError();
  const data = new Uint8Array(input);
  const parsed = fromBER(data.buffer);
  if (parsed.offset !== data.length) invalid();
  const cert = new Certificate({ schema: parsed.result });
  const extensionIds = cert.extensions?.map(extension => extension.extnID) ?? [];
  if (new Set(extensionIds).size !== extensionIds.length) invalid();
  // This Nitro profile implements critical BasicConstraints and KeyUsage only.
  // A generic ASN.1 parsedValue is not proof an extension's semantics were checked.
  if (cert.extensions?.some(extension => extension.critical &&
      !['2.5.29.19', '2.5.29.15'].includes(extension.extnID))) invalid();
  const before = cert.notBefore.value.getTime(), after = cert.notAfter.value.getTime();
  if (!Number.isFinite(before) || !Number.isFinite(after) || before > now || after < now) invalid();
  return cert;
}

/** Internal PKI primitive. The application verifier supplies the hard-coded AWS
 * root; never route a root supplied in a response/configuration into this helper.
 * An explicit root parameter allows independent synthetic PKI tests without a
 * production environment flag or a bypass in the public verifier. */
export async function verifyAttestationPki(
  evidence: UnverifiedApplicationAttestation, trustedRoot: Uint8Array, now: number,
): Promise<void> {
  try {
    if (!Number.isSafeInteger(now) || now <= 0 || now > 8640000000000000 ||
        evidence.signature.length !== 96 || evidence.cabundle.length < 1 || evidence.cabundle.length > 10) invalid();
    const root = certificate(trustedRoot, now), leaf = certificate(evidence.certificate, now);
    const chain = evidence.cabundle.map(value => certificate(value, now));
    if (!equal(evidence.cabundle[0], trustedRoot)) invalid(); // AWS order: root, intermediates.
    const algorithm = leaf.subjectPublicKeyInfo.algorithm;
    if (algorithm.algorithmId !== '1.2.840.10045.2.1' || !(algorithm.algorithmParams instanceof ObjectIdentifier) ||
        algorithm.algorithmParams.valueBlock.toString() !== '1.3.132.0.34') invalid();
    if (leaf.extensions?.some(extension => extension.extnID === '2.5.29.19' && extension.parsedValue?.cA)) invalid();
    const usage = leaf.extensions?.find(extension => extension.extnID === '2.5.29.15');
    if (usage && !(usage.parsedValue?.valueBlock?.valueHexView?.[0] & 128)) invalid();
    const engine = new CryptoEngine({ name: 'Vera attestation WebCrypto', crypto: globalThis.crypto });
    const validation = await new CertificateChainValidationEngine({
      trustedCerts: [root], certs: [...chain, leaf], checkDate: new Date(now),
    }).verify({ passedWhenNotRevValues: true }, engine);
    // AWS specifies no CRL lookup here. No network or certificate-supplied URL is used.
    const path = validation.certificatePath;
    if (!validation.result || path?.[0] !== leaf || path.length !== chain.length + 1) invalid();
    for (let index = 0; index < chain.length; index++) {
      if (!equal(new Uint8Array(path[index + 1].toSchema(true).toBER(false)),
        new Uint8Array(chain[chain.length - 1 - index].toSchema(true).toBER(false)))) invalid();
    }
    const key = await globalThis.crypto.subtle.importKey('spki', leaf.subjectPublicKeyInfo.toSchema().toBER(false),
      { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    if (!await globalThis.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key,
      new Uint8Array(evidence.signature), new Uint8Array(evidence.signedBytes))) invalid();
  } catch (error) { if (error instanceof AttestationCertificateSizeError) throw error; return invalid(); }
}

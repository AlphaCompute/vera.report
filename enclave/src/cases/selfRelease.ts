import { decodeAttestationCbor } from '../confidential/attestationCbor.js';
import { readReleaseManifest } from '../confidential/releaseManifest.js';

/** The running enclave's own release digest. The manifest bytes come from the
 * untrusted host (the digest covers the EIF, so it cannot be baked in); they are
 * trusted only if their PCR0/1/2 equal the measurements in an attestation
 * document this enclave just obtained from its local NSM device, which the host
 * cannot forge. Debug (all-zero) PCRs are rejected by the manifest parser. */
export async function verifySelfRelease(manifestWire: string, nsmDocument: Uint8Array): Promise<string> {
  try {
    const { manifest, digest } = await readReleaseManifest(manifestWire);
    const cose = decodeAttestationCbor(nsmDocument, true);
    if (!Array.isArray(cose) || cose.length !== 4 || !(cose[2] instanceof Uint8Array)) throw new Error();
    const payload = decodeAttestationCbor(cose[2]);
    const pcrs = payload instanceof Map ? payload.get('pcrs') : null;
    if (!(pcrs instanceof Map)) throw new Error();
    const hex = (value: unknown) => {
      if (!(value instanceof Uint8Array) || value.length !== 48) throw new Error();
      return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
    };
    if (hex(pcrs.get(0)) !== manifest.measurements.pcr0 || hex(pcrs.get(1)) !== manifest.measurements.pcr1 ||
        hex(pcrs.get(2)) !== manifest.measurements.pcr2) throw new Error();
    return digest;
  } catch { throw new Error('Confidential release does not match this enclave'); }
}

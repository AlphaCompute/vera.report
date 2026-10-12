import { prepareApplicationAttestation } from './attestationEvidence.ts';
import type { ApplicationAttestationPolicy } from './attestationEvidence.ts';
import { verifyAttestationPki } from './attestationPki.ts';
import { AttestationCertificateSizeError } from './attestationCertificateLimit.ts';
import { approvedReleasePolicy } from './releaseManifest.ts';
import type { ApprovedReleaseInput } from './releaseManifest.ts';

// AWS commercial Nitro root G1, also checked into verification/aws-nitro-root.pem.
// No request, environment variable or served manifest may replace this trust root.
const ROOT = 'MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=';
const ROOT_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';

/** Full evidence verification, not case authorization. The caller must select
 * the PCR policy from authenticated owner-approved metadata and consume the
 * fresh challenge once. No private traffic may precede successful verification. */
export async function verifyApplicationAttestation(
  document: Uint8Array, channelPublicKey: Uint8Array, policy: ApplicationAttestationPolicy,
): Promise<{ publicKey: Uint8Array<ArrayBuffer>; timestamp: number; verifiedAt: number }> {
  try {
    const now = policy.now;
    const evidence = await prepareApplicationAttestation(document, channelPublicKey, { ...policy, now });
    const root = Uint8Array.from(atob(ROOT), char => char.charCodeAt(0));
    const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', root));
    if (Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('') !== ROOT_SHA256) throw new Error();
    // The document timestamp is signed by the leaf and already within the
    // tolerated skew of this verifier's clock; checking certificate validity at
    // that instant keeps a verifier whose clock is off by minutes from
    // rejecting a just-issued NSM certificate.
    await verifyAttestationPki(evidence, root, evidence.timestamp);
    return { publicKey: evidence.channelPublicKey, timestamp: evidence.timestamp, verifiedAt: now };
  } catch (error) {
    if (error instanceof AttestationCertificateSizeError) throw error;
    throw new Error('Application channel attestation verification failed');
  }
}

/** Existing-case entry point. Pins come only from the exact manifest authorized
 * by this owner's current checkpoint; callers do not supply a separate PCR map. */
export async function verifyApprovedCaseChannel(
  document: Uint8Array, channelPublicKey: Uint8Array, approval: ApprovedReleaseInput,
): Promise<{ publicKey: Uint8Array<ArrayBuffer>; timestamp: number; verifiedAt: number; releaseDigest: string }> {
  try {
    if (!(document instanceof Uint8Array) || !document.length || document.length > 16384 ||
        !(channelPublicKey instanceof Uint8Array) || !channelPublicKey.length || channelPublicKey.length > 1024) throw new Error();
    const quote = new Uint8Array(document), key = new Uint8Array(channelPublicKey);
    const { policy, releaseDigest } = await approvedReleasePolicy(approval);
    return { ...await verifyApplicationAttestation(quote, key, policy), releaseDigest };
  } catch (error) {
    if (error instanceof AttestationCertificateSizeError) throw error;
    throw new Error('Owner-approved channel verification failed');
  }
}

import { TRACKING_ID_PATTERN, TRACKING_ID_EXAMPLE, CREDENTIAL_EXAMPLE } from './reportStatus';
import { readReportProofStatus, type ReportProofStatus } from './reportProof';

const RETRY_MESSAGE = 'We could not confirm your submission. Your report is still here; please try again.';

/** Interpret the receipt, never exposing internal error codes to the reporter. */
export function readSubmissionReceipt(
    ok: boolean,
    body: unknown,
): {
    trackingId: string;
    proofStatus: ReportProofStatus;
    zkProof?: {
        proofHash: string;
        nullifier: string;
        publicSignals: string[];
        verified: boolean;
        txHash?: string;
        proofType?: string;
        contractAddress?: string;
        network?: string;
    };
} {
    if (!body || typeof body !== 'object') throw new Error(RETRY_MESSAGE);
    const result = body as Record<string, unknown>;
    if (!ok || result.success !== true) {
        if (typeof result.message === 'string' && result.message.trim()) {
            throw new Error(result.message);
        }
        if (result.error === 'duplicate_submission') {
            throw new Error(
                'This evidence has already been submitted. Use your existing tracking ID to check its status.',
            );
        }
        // Older endpoints put human-readable validation messages in `error`.
        if (typeof result.error === 'string' && /\s/.test(result.error.trim())) {
            throw new Error(result.error);
        }
        throw new Error(RETRY_MESSAGE);
    }
    if (
        typeof result.trackingId !== 'string' ||
        !TRACKING_ID_PATTERN.test(result.trackingId) ||
        result.trackingId.toUpperCase() === TRACKING_ID_EXAMPLE ||
        result.trackingId.toUpperCase() === CREDENTIAL_EXAMPLE
    ) {
        throw new Error(RETRY_MESSAGE);
    }
    // Proof details are optional; malformed provider data must not strand a valid receipt.
    const proof = result.zkProof as Record<string, unknown> | null | undefined;
    const zkProof =
        proof &&
        typeof proof.proofHash === 'string' &&
        typeof proof.nullifier === 'string' &&
        typeof proof.verified === 'boolean' &&
        Array.isArray(proof.publicSignals) &&
        proof.publicSignals.every((s) => typeof s === 'string')
            ? {
                  proofHash: proof.proofHash,
                  nullifier: proof.nullifier,
                  verified: proof.verified,
                  publicSignals: proof.publicSignals as string[],
                  txHash: typeof proof.txHash === 'string' ? proof.txHash : undefined,
                  proofType: typeof proof.proofType === 'string' ? proof.proofType : undefined,
                  contractAddress: typeof proof.contractAddress === 'string' ? proof.contractAddress : undefined,
                  network: typeof proof.network === 'string' ? proof.network : undefined,
              }
            : undefined;
    return { trackingId: result.trackingId, proofStatus: readReportProofStatus(result.proofStatus), zkProof };
}

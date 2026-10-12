export type ReportProofStatus = 'pending' | 'attached' | 'failed' | 'not_applicable' | 'unknown';

export interface ReportProofReference {
    verified?: boolean;
    proofType?: string;
    txHash?: string;
    contractAddress?: string;
    /** Midnight network the transaction was finalized on; absent on legacy receipts. */
    network?: string;
}

/**
 * Receipts attached before the network was recorded (#353) all come from
 * deployments that ran MIDNIGHT_NETWORK=preprod. Keep reading them that way
 * after any cutover so they are never relabeled or relinked as mainnet.
 */
export const LEGACY_RECEIPT_NETWORK = 'preprod';

const NETWORK_ID = /^[a-z0-9-]{1,32}$/;

export function readReceiptNetwork(proof: unknown): string {
    const network = proof && typeof proof === 'object' ? (proof as Record<string, unknown>).network : undefined;
    return typeof network === 'string' && NETWORK_ID.test(network) ? network : LEGACY_RECEIPT_NETWORK;
}

/** Only mainnet is labeled without a test-network qualifier. */
export function receiptNetworkLabel(network: string): string {
    if (network === 'mainnet') return 'Midnight mainnet';
    if (network === 'local') return 'Local development chain';
    return `Midnight ${network} (test network)`;
}

/**
 * Explorer link for a receipt's transaction, or null. The configured explorer
 * serves one network (`explorerNetwork`, default preprod to match the default
 * explorer URL); a receipt from any other network is shown without a link
 * rather than pointed at the wrong chain.
 */
export function receiptExplorerUrl(
    proof: ReportProofReference | null | undefined,
    explorerUrl: string | undefined,
    explorerNetwork: string | undefined,
): string | null {
    const txHash = proof?.txHash?.trim();
    const base = explorerUrl?.trim().replace(/\/+$/, '');
    if (!txHash || !base) return null;
    if (readReceiptNetwork(proof) !== (explorerNetwork?.trim() || LEGACY_RECEIPT_NETWORK)) return null;
    return `${base}/transactions/${encodeURIComponent(txHash)}`;
}

export function readReportProofStatus(value: unknown): ReportProofStatus {
    return value === 'pending' || value === 'attached' || value === 'failed' || value === 'not_applicable' ? value : 'unknown';
}

const summaries = {
    pending: {
        state: 'pending',
        label: 'Pending',
        message:
            'Your report is saved. Its blockchain proof is still pending. Check your report status again later for updates.',
    },
    failed: {
        state: 'failed',
        label: 'Failed',
        message:
            'The blockchain proof could not be confirmed. Your saved report remains available for review; you do not need to submit it again.',
    },
    // Reports accepted while blockchain proofs are switched off (MIDNIGHT_ENABLED=false).
    not_applicable: {
        state: 'not_applicable',
        label: 'Not issued',
        message:
            'Your report is saved. Blockchain proofs are not currently being issued. This does not affect review of your report.',
    },
    verified: {
        state: 'verified',
        label: 'Verified',
        message:
            'A verified blockchain transaction reference is recorded. This confirms the proof, not the outcome of a review or an external filing.',
    },
    unverified: {
        state: 'unverified',
        label: 'Not verified',
        message: 'Your report is saved, but no verified blockchain transaction reference is available.',
    },
    unknown: {
        state: 'unknown',
        label: 'Status unavailable',
        message:
            'Your report is saved. Its blockchain proof status is unavailable. Check your report status again later for updates.',
    },
} as const;

/** Attachment alone (including a legacy hash commitment) is not a verified proof. */
export function getReportProofSummary(proofStatus: unknown, proof: unknown) {
    const status = readReportProofStatus(proofStatus);
    if (status === 'pending' || status === 'failed' || status === 'not_applicable') return summaries[status];

    const reference = proof && typeof proof === 'object' ? (proof as Record<string, unknown>) : null;
    // Require a public transaction reference for confirmed proofs.
    if (
        reference?.verified === true &&
        reference.proofType === 'compact_circuit' &&
        typeof reference.txHash === 'string' &&
        reference.txHash.trim().length > 0 &&
        typeof reference.contractAddress === 'string' &&
        reference.contractAddress.trim().length > 0
    ) {
        return summaries.verified;
    }
    return status === 'attached' || reference ? summaries.unverified : summaries.unknown;
}

import {
    getReportProofSummary,
    LEGACY_RECEIPT_NETWORK,
    readReceiptNetwork,
    readReportProofStatus,
    receiptExplorerUrl,
    receiptNetworkLabel,
} from '../../../lib/reportProof';

const verifiedProof = {
    verified: true,
    proofType: 'compact_circuit',
    txHash: 'synthetic-transaction',
    contractAddress: 'synthetic-contract',
};

describe('reporter proof status (#277)', () => {
    it.each(['pending', 'failed'] as const)('shows %s without an attached proof', (state) => {
        expect(getReportProofSummary(state, null).state).toBe(state);
    });

    it('tells the reporter no proof is coming when proofs are switched off', () => {
        expect(readReportProofStatus('not_applicable')).toBe('not_applicable');
        const summary = getReportProofSummary('not_applicable', null);
        expect(summary.state).toBe('not_applicable');
        expect(summary.label).not.toBe('Pending');
        expect(summary.message).toContain('Your report is saved');
        expect(summary.message).not.toMatch(/pending|check .* later/i);
    });

    it('keeps a saved report available when proof generation fails', () => {
        const summary = getReportProofSummary('failed', null);
        expect(summary.message).toContain('saved report remains available');
        expect(summary.message).toContain('do not need to submit it again');
        expect(summary.label).not.toBe('Pending');
    });

    it('distinguishes a completed proof from review or external filing', () => {
        const summary = getReportProofSummary('attached', verifiedProof);
        expect(summary.state).toBe('verified');
        expect(summary.message).toContain('not the outcome of a review or an external filing');
    });

    it.each([
        null,
        {},
        { ...verifiedProof, verified: false },
        { ...verifiedProof, verified: 'true' },
        { ...verifiedProof, proofType: 'hash_commitment' },
        { ...verifiedProof, proofType: undefined },
        { ...verifiedProof, txHash: undefined },
        { ...verifiedProof, txHash: '   ' },
        { ...verifiedProof, contractAddress: undefined },
        { ...verifiedProof, contractAddress: '   ' },
    ])('does not label attached or incomplete metadata as verified: %j', (proof) => {
        expect(getReportProofSummary('attached', proof).state).toBe('unverified');
    });

    it.each(['pending', 'failed'] as const)('does not override explicit %s with stale proof metadata', (state) => {
        expect(getReportProofSummary(state, verifiedProof).state).toBe(state);
    });

    it('supports a complete legacy proof reference without an async status', () => {
        expect(getReportProofSummary(undefined, verifiedProof).state).toBe('verified');
    });

    it.each([undefined, null, 'new-worker-state', {}, true])(
        'does not invent progress for an unknown status: %j',
        (value) => {
            expect(readReportProofStatus(value)).toBe('unknown');
            expect(getReportProofSummary(value, null).state).toBe('unknown');
        },
    );

    it('keeps proof progress independent of the report review status', () => {
        expect(getReportProofSummary('pending', null).state).toBe('pending');
        expect(getReportProofSummary('verified', null).state).toBe('unknown');
    });
});

describe('receipt network (#353)', () => {
    const explorer = 'https://preprod.midnightexplorer.com/';
    const onChain = { ...verifiedProof, txHash: 'ab12' };

    it('reads legacy receipts without a network as preprod', () => {
        expect(LEGACY_RECEIPT_NETWORK).toBe('preprod');
        expect(readReceiptNetwork(onChain)).toBe('preprod');
        expect(readReceiptNetwork({ ...onChain, network: 'Not A Network!' })).toBe('preprod');
        expect(readReceiptNetwork(null)).toBe('preprod');
        expect(readReceiptNetwork({ ...onChain, network: 'mainnet' })).toBe('mainnet');
    });

    it('labels only mainnet receipts without a test-network qualifier', () => {
        expect(receiptNetworkLabel('mainnet')).toBe('Midnight mainnet');
        expect(receiptNetworkLabel('preprod')).toBe('Midnight preprod (test network)');
        expect(receiptNetworkLabel('testnet')).toContain('test network');
        expect(receiptNetworkLabel('local')).not.toContain('mainnet');
    });

    it('links legacy and preprod receipts to the preprod explorer', () => {
        const url = 'https://preprod.midnightexplorer.com/transactions/ab12';
        expect(receiptExplorerUrl(onChain, explorer, undefined)).toBe(url);
        expect(receiptExplorerUrl({ ...onChain, network: 'preprod' }, explorer, 'preprod')).toBe(url);
    });

    it('never links a receipt to an explorer for a different network', () => {
        expect(receiptExplorerUrl({ ...onChain, network: 'mainnet' }, explorer, 'preprod')).toBeNull();
        expect(receiptExplorerUrl(onChain, 'https://explorer.example', 'mainnet')).toBeNull();
        expect(receiptExplorerUrl({ ...onChain, network: 'mainnet' }, 'https://explorer.example', 'mainnet'))
            .toBe('https://explorer.example/transactions/ab12');
    });

    it('returns no link without a transaction or explorer', () => {
        expect(receiptExplorerUrl({ ...onChain, txHash: undefined }, explorer, 'preprod')).toBeNull();
        expect(receiptExplorerUrl(onChain, undefined, 'preprod')).toBeNull();
        expect(receiptExplorerUrl(null, explorer, 'preprod')).toBeNull();
    });
});

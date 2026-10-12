import { readSubmissionReceipt } from '../../../lib/reportSubmission';
import { getReportProofSummary } from '../../../lib/reportProof';

describe('submission receipt', () => {
    it('shows the API explanation instead of its internal proof error code', () => {
        expect(() =>
            readSubmissionReceipt(false, {
                error: 'zk_proof_unavailable',
                message: 'Unable to generate a privacy proof. Please try again later.',
            }),
        ).toThrow('Unable to generate a privacy proof. Please try again later.');
    });
    it('retains readable validation errors from older responses', () => {
        expect(() => readSubmissionReceipt(false, { error: 'Description exceeds maximum length' })).toThrow(
            'Description exceeds maximum length',
        );
    });
    it.each([
        null,
        '<html>Bad Gateway</html>',
        { error: 'internal_failure' },
        { success: true },
        { success: true, trackingId: 'bad' },
        { success: true, trackingId: 'VRA-0000000000000000' },
    ])('rejects an absent or invalid receipt while explaining how to retry: %j', (body) => {
        expect(() => readSubmissionReceipt(true, body)).toThrow('Your report is still here');
    });
    it('does not accept a success body on a failed HTTP response', () => {
        expect(() => readSubmissionReceipt(false, { success: true, trackingId: 'VRA-1234567890ABCDEF' })).toThrow(
            'could not confirm',
        );
    });
    it('returns a valid receipt even if optional proof data is malformed', () => {
        expect(readSubmissionReceipt(true, { success: true, trackingId: 'VRA-1234567890ABCDEF', zkProof: {} })).toEqual(
            {
                trackingId: 'VRA-1234567890ABCDEF',
                proofStatus: 'unknown',
                zkProof: undefined,
            },
        );
    });
    it('preserves verified proof data on a valid receipt', () => {
        const zkProof = {
            proofHash: 'hash',
            nullifier: 'nullifier',
            publicSignals: ['signal'],
            verified: true,
            txHash: 'tx',
            proofType: 'compact_circuit',
            contractAddress: 'contract',
            network: 'mainnet',
        };
        const receipt = readSubmissionReceipt(true, {
            success: true,
            trackingId: 'VRA-1234567890ABCDEF',
            proofStatus: 'attached',
            zkProof,
        });
        expect(receipt).toEqual({ trackingId: 'VRA-1234567890ABCDEF', proofStatus: 'attached', zkProof });
        expect(getReportProofSummary(receipt.proofStatus, receipt.zkProof).state).toBe('verified');
    });

    it.each(['pending', 'failed'] as const)(
        'preserves a saved receipt with %s proof and no metadata',
        (proofStatus) => {
            const receipt = readSubmissionReceipt(true, {
                success: true,
                trackingId: 'VRA-1234567890ABCDEF',
                proofStatus,
                zkProof: null,
            });
            expect(receipt.trackingId).toBe('VRA-1234567890ABCDEF');
            expect(getReportProofSummary(receipt.proofStatus, receipt.zkProof).state).toBe(proofStatus);
        },
    );

    it('preserves failed progress even when optional proof metadata is malformed', () => {
        const receipt = readSubmissionReceipt(true, {
            success: true,
            trackingId: 'VRA-1234567890ABCDEF',
            proofStatus: 'failed',
            zkProof: {},
        });
        expect(receipt.proofStatus).toBe('failed');
        expect(receipt.zkProof).toBeUndefined();
    });
});

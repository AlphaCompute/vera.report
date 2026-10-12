import express from 'express';
import request from 'supertest';
jest.mock('express-rate-limit', () => {
    const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
    return {
        __esModule: true,
        ...actual,
        default: () => (_req: unknown, _res: unknown, next: () => void) => next(),
    };
});
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: {} }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { sendAlert: jest.fn() } }));
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import router from '../../../src/api/dissemination';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { redactionService } from '../../../src/services/dissemination/redactionService';
import { packetGenerator } from '../../../src/services/dissemination/packetGenerator';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
import { makeSecureLinkToken, verifySecureLinkToken, SECURE_LINK_ENTITY_ID } from '../../../src/services/dissemination/secureLink';
import { issueRecipientCapability } from '../../../src/services/dissemination/recipientCapability';
import { evidenceSnapshot } from '../../../src/services/dissemination/packetEvidence';

useDisseminationMongo();
afterEach(() => jest.restoreAllMocks());
const app = express().use(express.json()).use('/api/dissemination', router);

async function reviewedReport(trackingId: string) {
    await reportPersistenceService.upsert({
        trackingId,
        status: 'pending',
        createdAt: new Date(),
        updatedAt: new Date(),
        encryptedDescription: encryptContactValue('Synthetic narrative for a stale-link check.'),
        consent: { agency: true, psst: { granted: false }, capturedAt: new Date(), textVersion: 'v3-legal-review-default' },
    });
    await redactionService.markReviewedClean(trackingId, 'synthetic-reviewer');
    jest.spyOn(packetGenerator, 'generate').mockImplementation(async (view, entityId) => ({
        trackingId, entityId, packetVersion: 3, pdf: Buffer.from(view.narrative),
        sidecar: {} as never, packetHash: 'f'.repeat(64), generatedAt: new Date(),
    }));
}
const revealed = async (trackingId: string) =>
    (await disseminationPersistence.getAuditForReport(trackingId)).filter(e => e.event === 'secure_packet_revealed');

// #625: a link is bound to the evidence set it was issued for.
it('refuses a link whose evidence set changed, without consuming or auditing it', async () => {
    const trackingId = 'VRA-000000000000DA11';
    await reviewedReport(trackingId);
    const token = makeSecureLinkToken(trackingId, SECURE_LINK_ENTITY_ID, undefined, 'a'.repeat(64));
    await issueRecipientCapability(token, 'securelink');

    const response = await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`);
    expect(response.status).toBe(409);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.text).toContain('out of date');
    expect(await revealed(trackingId)).toEqual([]);
    const { jti } = verifySecureLinkToken(token)!;
    expect(await disseminationPersistence.consumeSecureLink({ jti, trackingId, entityId: SECURE_LINK_ENTITY_ID })).toBe(true);
});

it('reveals and audits a link whose evidence set is unchanged', async () => {
    const trackingId = 'VRA-000000000000DA12';
    await reviewedReport(trackingId);
    const token = makeSecureLinkToken(trackingId, SECURE_LINK_ENTITY_ID, undefined, evidenceSnapshot([]));
    await issueRecipientCapability(token, 'securelink');

    const response = await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`);
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('application/zip');
    expect(await revealed(trackingId)).toHaveLength(1);
    expect((await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`)).status).toBe(410);
});

it('preserves a manual link after narrative review is cleared, then permits one reviewed reveal', async () => {
    const trackingId = 'VRA-000000000000DA13';
    await reviewedReport(trackingId);
    const token = makeSecureLinkToken(trackingId, SECURE_LINK_ENTITY_ID, undefined, evidenceSnapshot([]));
    await issueRecipientCapability(token, 'securelink');
    await disseminationPersistence.clearNarrativeReview(trackingId);

    expect((await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`)).status).toBe(409);
    expect(packetGenerator.generate).not.toHaveBeenCalled();
    expect(await revealed(trackingId)).toEqual([]);

    await redactionService.markReviewedClean(trackingId, 'synthetic-reviewer');
    expect((await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`)).status).toBe(200);
    expect(await revealed(trackingId)).toHaveLength(1);
    expect((await request(app).post(`/api/dissemination/secure-packet/${token}/reveal`)).status).toBe(410);
});

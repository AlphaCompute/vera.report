import express from 'express';
import request from 'supertest';
import { unzipSync } from 'fflate';
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
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { redactionService } from '../../../src/services/dissemination/redactionService';
import { packetGenerator } from '../../../src/services/dissemination/packetGenerator';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
import { makeSecureLinkToken } from '../../../src/services/dissemination/secureLink';
import { issueRecipientCapability } from '../../../src/services/dissemination/recipientCapability';

useDisseminationMongo();
afterEach(() => jest.restoreAllMocks());
const app = express().use(express.json()).use('/api/dissemination', router);

it.each([false, true])(
    'releases only the currently reviewed narrative (replacement during rendering=%s)',
    async (changed) => {
        const trackingId = changed ? 'VRA-000000000000DA01' : 'VRA-000000000000DA02';
        const before = 'I am Synthetic Alice, employee 112233. The records were falsified.';
        const after = '[REPORTER] observed falsified records.';
        await reportPersistenceService.upsert({
            trackingId,
            status: 'pending',
            createdAt: new Date(),
            updatedAt: new Date(),
            encryptedDescription: encryptContactValue(before),
            consent: {
                agency: true,
                psst: { granted: false },
                capturedAt: new Date(),
                textVersion: 'v3-legal-review-default',
            },
        });
        await redactionService.markReviewedClean(trackingId, 'synthetic-initial-reviewer');
        const token = makeSecureLinkToken(trackingId);
        await issueRecipientCapability(token, 'securelink');
        // Deterministically pause rendering while a reviewer corrects the disclosure.
        jest.spyOn(packetGenerator, 'generate').mockImplementation(async (view, entityId) => {
            expect(view.narrative).toBe(before);
            if (changed) {
                expect(await redactionService.accept(trackingId, after, [], 'synthetic-correcting-reviewer')).toEqual({
                    ok: true,
                });
                expect((await disseminationService.buildView(trackingId))!.view.narrative).toBe(after);
            }
            return {
                trackingId,
                entityId,
                packetVersion: 3,
                pdf: Buffer.from(view.narrative),
                sidecar: {} as never,
                packetHash: 'f'.repeat(64),
                generatedAt: new Date(),
            };
        });
        const response = await request(app)
            .post(`/api/dissemination/secure-packet/${token}/reveal`)
            .buffer(true)
            .parse((res, callback) => {
                const chunks: Buffer[] = [];
                res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
                res.on('end', () => callback(null, Buffer.concat(chunks)));
            });
        if (changed) {
            expect(response.status).toBe(409);
            expect(response.headers['content-type']).not.toContain('application/zip');
            expect(response.body.toString()).not.toContain(before);
            expect((await disseminationPersistence.getDisposition(trackingId))!.narrativeOverride!.narrative).toBe(
                after,
            );
        } else {
            expect(response.status).toBe(200);
            expect(Buffer.from(unzipSync(response.body)['report.pdf']).toString()).toBe(before);
        }
    },
);

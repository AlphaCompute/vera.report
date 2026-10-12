/** Exercise JSON middleware and multipart parsing before the real intake handler. */
import express from 'express';
import request from 'supertest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

jest.mock('express-rate-limit', () => ({
    ...jest.requireActual('express-rate-limit'),
    __esModule: true,
    default: () => (_req: express.Request, _res: express.Response, next: express.NextFunction) => next(),
}));
jest.mock('../../../src/services/attestedNarrative', () => ({
    attestedNarrativeConfiguration: () => ({ writes: false }),
}));
jest.mock('../../../src/services/evidenceEncryption', () => ({
    evidenceEncryptionService: {
        encryptEvidence: jest.fn(async () => ({
            encryptedData: 'ZmFrZQ==',
            encryptionMetadata: { salt: 'cw==', iv: 'aXY=', authTag: 'dGFn' },
            contentMetadata: { hash: 'a'.repeat(64), size: 4 },
        })),
    },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: {} }));
jest.mock('../../../src/services/veniceAI', () => ({ veniceAIService: {} }));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/reportScoringWorker', () => ({
    reportScoringWorker: { tick: jest.fn(async () => {}) },
}));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({ notifySubmission: jest.fn(async () => {}) }));
jest.mock('../../../src/services/shroudClient', () => ({ isShroudConfigured: () => false }));
jest.mock('../../../src/services/metadataExtractor', () => ({ metadataExtractorService: {} }));
jest.mock('../../../src/services/reportPersistence', () => ({
    reportPersistenceService: {
        get: jest.fn(async () => null),
        upsert: jest.fn(async () => {}),
    },
}));
jest.mock('../../../src/services/submissionEvidence', () => ({ persistSubmissionEvidence: jest.fn(async () => []) }));

import whistleblowerRouter from '../../../src/api/whistleblower';
import { validateRequestBody } from '../../../src/middleware/security';
import { evidenceEncryptionService } from '../../../src/services/evidenceEncryption';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { mapReports, computeStats } from '../../../src/services/dashboardReportsMapper';
import { buildDisseminationView } from '../../../src/services/dissemination/disseminationView';
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { evidenceCommitment } from '../../../src/utils/evidenceCommitment';
import { decryptRewardContact } from '../../../src/services/rewardContact';

function app() {
    const server = express();
    server.use(express.json({ limit: '10mb' }));
    server.use(validateRequestBody);
    server.use('/api/whistleblower', whistleblowerRouter);
    return server;
}

describe('Report input validation and integrity', () => {
    beforeEach(() => jest.clearAllMocks());

    it.each(['true', 'false'])('keeps a private contact when wantsReward=%s', async wantsReward => {
        const contactValue = 'reporter@example.invalid';
        const response = await request(app()).post('/api/whistleblower/submit')
            .field('description', 'Synthetic contact retention report')
            .field('wantsReward', wantsReward).field('contactMethod', 'email').field('contactValue', contactValue);
        expect(response.status).toBe(200);
        const saved = jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
        expect(saved.reward).toMatchObject({ wantsReward: wantsReward === 'true', contactMethod: 'email' });
        expect(JSON.stringify(saved)).not.toContain(contactValue);
        expect(await decryptRewardContact({ ciphertext: saved.reward!.encryptedContactValue!,
            wrappedKey: saved.reward!.contactKeyWrapped! }, saved.trackingId)).toBe(contactValue);
    });

    it.each([
        { contactMethod: 'email', contactValue: '' },
        { contactMethod: 'encrypted', contactValue: '  ' },
        { contactMethod: 'email', contactValue: 'invalid' },
        { contactMethod: 'phone', contactValue: '-------' },
        { contactMethod: 'fax', contactValue: '2025550123' },
        { contactMethod: 'email' },
        { contactValue: 'reporter@example.invalid' },
    ])('rejects invalid supplied contact even without a reward: %p', async contact => {
        const response = await request(app()).post('/api/whistleblower/submit')
            .send({ description: 'Synthetic contact validation report', wantsReward: 'false', ...contact });
        expect(response.status).toBe(400);
        expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    });

    it('rejects a multipart object category even when categories is supplied', async () => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .field('description', 'Synthetic review report')
            .field('categories', '[]')
            .field('evidenceType[poison]', 'value');
        expect(response.status).toBe(400);
        expect(response.body.error).toContain('Evidence type must be a string');
        expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
        expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    });

    it.each(
        [null, false, 0, ['fraud'], { poison: 'value' }, 'x'.repeat(101)].map((evidenceType) => ({ evidenceType })),
    )('rejects invalid JSON evidenceType: $evidenceType', async ({ evidenceType }) => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .send({ description: 'Synthetic review report', categories: '[]', evidenceType });
        expect(response.status).toBe(400);
        expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
        expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    });

    it('rejects repeated multipart evidenceType fields', async () => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .field('description', 'Synthetic review report')
            .field('categories', '[]')
            .field('evidenceType', 'fraud')
            .field('evidenceType', 'safety');
        expect(response.status).toBe(400);
        expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    });

    it('rejects repeated categories fields instead of coercing an array into JSON text', async () => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .field('description', 'Synthetic review report')
            .field('categories[]', '[]');
        expect(response.status).toBe(400);
        expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    });

    it.each([
        '  O\'Brien wrote "value < limit > threshold".\n' + 'A'.repeat(10000) + '\nCRITICAL EVIDENCE  ',
        ' \tUTF-8: \u00e9 \ud83d\udd12 & <unescaped>\r\n ',
    ])('preserves original JSON narrative bytes through encryption and versioned commitment', async description => {
        const response = await request(app()).post('/api/whistleblower/submit').send({ description });
        expect(response.status).toBe(200);
        expect(jest.mocked(evidenceEncryptionService.encryptEvidence).mock.calls[0][0]).toBe(description);
        const commitment = {
            evidenceHash: evidenceCommitment(description, [], 'sha256-framed-v2'),
            evidenceHashVersion: 'sha256-framed-v2',
        };
        expect(response.body).toMatchObject(commitment);
        expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0]).toMatchObject(commitment);
    });

    it.each([50000, 50001])('enforces the route narrative limit for %i JSON characters', async (length) => {
        const description = 'x'.repeat(length);
        const response = await request(app()).post('/api/whistleblower/submit').send({ description });
        expect(response.status).toBe(length === 50000 ? 200 : 400);
        if (length === 50000) {
            expect(jest.mocked(evidenceEncryptionService.encryptEvidence).mock.calls[0][0]).toBe(description);
        } else {
            expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
            expect(evidenceEncryptionService.encryptEvidence).not.toHaveBeenCalled();
        }
    });

    it('preserves JSON-encoded categories and metadata selections inside JSON intake', async () => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .send({
                description: 'Synthetic review report',
                categories: '["financial-fraud"]',
                stripSelection: '{"author":true}',
            });
        expect(response.status).toBe(200);
        expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0].categories).toEqual(['financial-fraud']);
        expect(jest.mocked(persistSubmissionEvidence).mock.calls[0].slice(0, 3)).toEqual([expect.any(String), [], { author: true }]);
    });

    it.each(['fraud', 'financial-fraud'])('retains supported category input %s', async (evidenceType) => {
        const response = await request(app())
            .post('/api/whistleblower/submit')
            .field('description', 'Synthetic review report')
            .field('evidenceType', evidenceType);
        expect(response.status).toBe(200);
        expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0]).toMatchObject({
            category: evidenceType,
            categories: ['financial-fraud'],
        });
    });

    it('renders and processes historical malformed categories without throwing', () => {
        const row = {
            trackingId: 'VRA-0000000000000000',
            status: 'pending',
            category: { poison: 'value' },
            categories: [{ poison: 'value' }, 'financial-fraud'],
            createdAt: new Date(),
            updatedAt: new Date(),
        };
        const dashboard = mapReports([row])[0];
        expect(renderToStaticMarkup(React.createElement('span', null, dashboard.category))).toBe('<span>other</span>');
        expect(computeStats([row]).byCategory).toEqual({ other: 1 });
        const view = buildDisseminationView(
            row as unknown as Parameters<typeof buildDisseminationView>[0],
            'Synthetic review report',
        );
        expect(view.categories).toEqual(['financial-fraud']);
        expect(view.rawCategories).toEqual(['financial-fraud']);
    });

    it.each(['__proto__', 'constructor'])(
        'does not interpret category %s as an inherited property',
        async (evidenceType) => {
            const response = await request(app())
                .post('/api/whistleblower/submit')
                .field('description', 'Synthetic review report')
                .field('evidenceType', evidenceType);
            expect(response.status).toBe(200);
            const row = jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
            expect(row.categories).toBeUndefined();
            expect(buildDisseminationView(row, 'Synthetic review report').categories).toEqual([]);
            expect(computeStats([row]).byCategory[evidenceType]).toBe(1);
        },
    );
});

it('keeps all supplied contact methods encrypted even when rewards are declined', async () => {
    jest.clearAllMocks();
    const contactValue = 'Email: private@example.com\nSignal: +15555550100\niMessage: private-imessage@example.com';
    const response = await request(app()).post('/api/whistleblower/submit').send({
        description: 'Synthetic report', wantsReward: 'false', contactMethod: 'multiple', contactValue,
    });
    expect(response.status).toBe(200);
    const record = jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
    expect(record.reward).toMatchObject({ wantsReward: false, contactMethod: 'multiple' });
    expect(JSON.stringify(record)).not.toContain('private@example.com');
    expect(await decryptRewardContact({ ciphertext: record.reward!.encryptedContactValue!,
        wrappedKey: record.reward!.contactKeyWrapped! }, record.trackingId)).toBe(contactValue);
});

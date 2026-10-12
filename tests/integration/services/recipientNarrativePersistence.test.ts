const mockSettings: { writes: boolean; reader?: { encrypt: jest.Mock; decrypt: jest.Mock } } = { writes: false };
jest.mock('../../../src/services/attestedNarrative', () => ({ attestedNarrativeConfiguration: () => mockSettings }));
import { MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { reportPersistenceService as reports } from '../../../src/services/reportPersistence';
import { encryptReportNarrative, decryptReportNarrative } from '../../../src/services/reportNarrative';
import { keyEnvelope } from '../../../src/services/keyEnvelope';
import { type RecipientNarrativeEnvelope } from '../../../src/services/recipientNarrativeEnvelope';
useDisseminationMongo();
const tid = 'VRA-1234567890ABCDEF';
const envelope: RecipientNarrativeEnvelope = {
    format: 'recipient-narrative:v1',
    trackingId: tid,
    purpose: 'narrative',
    key: 'enc:kms:recipient:v1:YWJj',
    iv: Buffer.alloc(12).toString('base64'),
    tag: Buffer.alloc(16).toString('base64'),
    data: 'YWJj',
};
beforeEach(() => {
    mockSettings.writes = true;
    mockSettings.reader = {
        encrypt: jest.fn(async () => ({ ...envelope })),
        decrypt: jest.fn(async () => 'offline restored narrative'),
    };
});
afterEach(() => jest.restoreAllMocks());
test('new envelope survives Mongo client reconnect without key unwrap/rewrap or legacy downgrade', async () => {
    const wrap = jest.spyOn(keyEnvelope, 'wrap');
    const unwrap = jest.spyOn(keyEnvelope, 'unwrap');
    const encrypted = await encryptReportNarrative(tid, 'offline restored narrative');
    await reports.upsert({
        trackingId: tid,
        createdAt: new Date(),
        updatedAt: new Date(),
        status: 'pending',
        encryptedNarrative: encrypted,
    });
    await reports.close();
    const rawClient = await new MongoClient(process.env.MONGODB_URI!).connect();
    try {
        const raw = await rawClient
            .db(process.env.MONGODB_DB_NAME)
            .collection('whistleblower_reports')
            .findOne({ trackingId: tid });
        expect(raw?.encryptedNarrative).toEqual(envelope);
        expect(JSON.stringify(raw)).not.toContain('offline restored narrative');
    } finally {
        await rawClient.close();
    }
    const row = await reports.get(tid);
    expect(await decryptReportNarrative(row!)).toBe('offline restored narrative');
    expect(wrap).not.toHaveBeenCalled();
    expect(unwrap).not.toHaveBeenCalled();
    // Disabling new writes cannot send an existing recipient envelope to a legacy decryptor.
    mockSettings.writes = false;
    expect(await decryptReportNarrative(row!)).toBe('offline restored narrative');
    mockSettings.reader = undefined;
    await expect(decryptReportNarrative({ ...row!, encryptedDescription: 'legacy' })).rejects.toThrow(
        'Narrative unavailable',
    );
    expect(unwrap).not.toHaveBeenCalled();
});
test('wrong report/version/extra key material cannot be persisted', async () => {
    const untouched = 'VRA-0000000000000001';
    for (const delta of [
        { trackingId: 'VRA-AAAAAAAAAAAAAAAA' },
        { format: 'recipient-narrative:v2' },
        { handle: 'private-handle' },
        { key: 'raw-private-key' },
    ])
        await expect(
            reports.upsert({
                trackingId: untouched,
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'pending',
                encryptedNarrative: { ...envelope, trackingId: untouched, ...delta } as any,
            }),
        ).rejects.toThrow('Narrative unavailable');
    expect(await reports.get(untouched)).toBeNull();
});
test('recipient failure is propagated, never legacy fallback', async () => {
    const wrap = jest.spyOn(keyEnvelope, 'wrap');
    mockSettings.reader!.encrypt.mockRejectedValue(new Error('Narrative unavailable'));
    await expect(encryptReportNarrative(tid, 'offline')).rejects.toThrow('Narrative unavailable');
    expect(wrap).not.toHaveBeenCalled();
    mockSettings.reader!.decrypt.mockRejectedValue(new Error('Narrative unavailable'));
    await expect(
        decryptReportNarrative({
            trackingId: tid,
            encryptedNarrative: envelope,
            encryptedDescription: 'legacy',
        } as any),
    ).rejects.toThrow('Narrative unavailable');
});

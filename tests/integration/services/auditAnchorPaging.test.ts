import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { DisseminationPersistenceService } from '../../../src/services/dissemination/disseminationPersistence';
import type { AuditEventDoc } from '../../../src/services/dissemination/types';

describe('audit anchor pagination in MongoDB', () => {
  let mongo: MongoMemoryServer;
  let client: MongoClient;
  let service: DisseminationPersistenceService;
  const at = new Date('2026-09-15T00:00:00Z');
  const dbName = 'anchor_paging';

  beforeAll(async () => {
    mongo = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongo.getUri();
    process.env.MONGODB_DB_NAME = dbName;
    client = await MongoClient.connect(mongo.getUri());
    service = new DisseminationPersistenceService();
  });
  afterAll(async () => {
    await service?.disconnect();
    await client?.close();
    await mongo?.stop();
    process.env.MONGODB_URI = '';
    process.env.MONGODB_DB_NAME = '';
  });

  it('excludes all earlier batches before limiting and resumes after reconnect', async () => {
    const events: AuditEventDoc[] = Array.from({ length: 4097 }, (_, i) => ({
      eventId: `event-${i}`, trackingId: 'synthetic-audit-paging', event: 'approved', actor: 'test', at,
    }));
    await client.db(dbName).collection('dissemination_audit_log').insertMany(events);
    const seen = new Set<string>();
    for (const [batch, expectedCount] of [2048, 2048, 1].entries()) {
      const page = await service.getUnanchoredAuditEvents(2048);
      expect(page).toHaveLength(expectedCount);
      for (const event of page) {
        expect(seen.has(event.eventId)).toBe(false);
        seen.add(event.eventId);
      }
      // Synthetic stored anchors test database selection, not chain finality.
      await service.insertAuditAnchor({
        anchorId: `batch-${batch}`, root: '0'.repeat(64),
        leaves: page.map(event => ({ eventId: event.eventId, leafHash: '0'.repeat(64) })),
        eventCount: page.length, firstEventAt: at, lastEventAt: at, network: 'local', anchoredAt: new Date(),
      });
      await service.disconnect();
      service = new DisseminationPersistenceService();
    }
    expect(seen.size).toBe(events.length);
    expect(await service.getUnanchoredAuditEvents()).toEqual([]);

    // An event inserted later at the cursor timestamp must still be selected.
    await client.db(dbName).collection('dissemination_audit_log').insertOne({ ...events[0], _id: undefined, eventId: 'late-boundary' });
    const older = new Date(at.getTime() - 86400000);
    await client.db(dbName).collection('dissemination_audit_log').insertOne({
      ...events[0], _id: undefined, eventId: 'late-historical', at: older,
    });
    await service.disconnect();
    service = new DisseminationPersistenceService();
    const recovered = await service.getUnanchoredAuditEvents();
    expect(recovered.map(event => event.eventId)).toEqual(['late-historical', 'late-boundary']);
    await service.insertAuditAnchor({
      anchorId: 'recovered', root: '0'.repeat(64),
      leaves: recovered.map(event => ({ eventId: event.eventId, leafHash: '0'.repeat(64) })),
      eventCount: 2, firstEventAt: older, lastEventAt: at, network: 'local', anchoredAt: new Date(),
    });
    expect(await service.getUnanchoredAuditEvents()).toEqual([]);
  });
});

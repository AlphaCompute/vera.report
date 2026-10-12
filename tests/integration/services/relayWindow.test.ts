import { MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { disseminationPersistence as store } from '../../../src/services/dissemination/disseminationPersistence';
import { relayService } from '../../../src/services/dissemination/relayService';
useDisseminationMongo();

it('returns the newest 200 messages chronologically and keeps older questions open for replies', async () => {
  const trackingId = 'VRA-9999999999999999';
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  try {
    // Equal timestamps exercise the stable insertion-order tiebreaker as well.
    await client.db(process.env.MONGODB_DB_NAME).collection('relay_threads').insertMany(
      Array.from({ length: 201 }, (_, i) => ({
        trackingId, messageId: `window-${i}`, body: `message ${i}`,
        direction: i === 0 ? 'to-reporter' : 'from-reporter', createdAt: new Date(1000),
      })),
    );
    await store.disconnect();
    const thread = await relayService.getThread(trackingId);
    expect(thread).toHaveLength(200);
    expect(thread[0].body).toBe('message 1');
    expect(thread[199].body).toBe('message 200');
    expect(await relayService.postFromReporter(trackingId, 'new reply')).toEqual({ ok: true });
    expect((await relayService.getThread(trackingId)).at(-1)?.body).toBe('new reply');
    expect(await store.hasRelayQuestion('VRA-8888888888888888')).toBe(false);
    await expect(store.getRelayThread(trackingId, 0)).rejects.toThrow('Invalid relay window size');
  } finally { await client.close(); }
});

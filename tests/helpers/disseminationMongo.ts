import { MongoMemoryServer } from 'mongodb-memory-server';
import { reportPersistenceService } from '../../src/services/reportPersistence';
import { disseminationPersistence } from '../../src/services/dissemination/disseminationPersistence';

/** Real disposable storage for service tests; never enable a production fallback. */
export function useDisseminationMongo(): void {
  let mongo: MongoMemoryServer;
  const originalUri = process.env.MONGODB_URI;
  const originalSecret = process.env.DISSEMINATION_WEBHOOK_SECRET;
  const originalDb = process.env.MONGODB_DB_NAME;
  const configure = () => {
    process.env.MONGODB_URI = mongo.getUri();
    process.env.MONGODB_DB_NAME = 'dissemination_tests';
    process.env.DISSEMINATION_WEBHOOK_SECRET = originalSecret || 'dissemination-fixture-secret';
  };
  beforeAll(async () => { mongo = await MongoMemoryServer.create(); configure(); });
  // Several suites restore process.env after each case.
  beforeEach(configure);
  afterAll(async () => {
    await reportPersistenceService.close();
    await disseminationPersistence.disconnect();
    await mongo.stop();
    if (originalUri === undefined) delete process.env.MONGODB_URI; else process.env.MONGODB_URI = originalUri;
    if (originalSecret === undefined) delete process.env.DISSEMINATION_WEBHOOK_SECRET; else process.env.DISSEMINATION_WEBHOOK_SECRET = originalSecret;
    if (originalDb === undefined) delete process.env.MONGODB_DB_NAME; else process.env.MONGODB_DB_NAME = originalDb;
  });
}

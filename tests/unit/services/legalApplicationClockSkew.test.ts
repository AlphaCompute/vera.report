import express from 'express';
import request from 'supertest';
import type { Db } from 'mongodb';
import { createLegalApplicationsRouter } from '../../../src/api/legalApplications';
import { LegalApplications } from '../../../src/services/legalApplications';
import { applicationOrganizationId } from '../../../src/utils/legalApplicationEnrollment';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';

afterEach(() => jest.useRealTimers());

it.each([-5_000, 5_000])('accepts the first HTTP application with %i ms device skew; retry remains idempotent', async skew => {
  const now = Math.floor(Date.now() / 1000) * 1000;
  jest.useFakeTimers({ now: now + skew, doNotFake: ['nextTick', 'setImmediate', 'setTimeout', 'clearTimeout', 'performance'] });
  const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic applicant' }], format: 'object' });
  const recipientKeyId = await caseRecipientKeyId(privateKey.toPublic());
  const organizationId = await applicationOrganizationId(recipientKeyId);
  const bindingDocument = await createFirmKeyBinding({ domain: 'firm.example', organizationId, issuedAt: Date.now(),
    profile: { practiceAreas: ['whistleblower'], jurisdiction: 'Example', website: 'https://firm.example/' } }, privateKey);
  const input = { displayName: 'Synthetic firm', domain: 'firm.example', email: 'counsel@firm.example',
    lawyerName: 'Synthetic lawyer', jurisdiction: 'Example', registrationNumber: 'TEST',
    enrollment: { organizationId, recipientKeyId, bindingDocument } };
  // Only persistence is in-memory. The service, signature verifier and HTTP
  // handler are the same path that previously returned 503 before writing.
  const rows = new Map<string, { _id: string }>();
  const collection = {
    createIndex: async () => '', updateMany: async () => ({}),
    find: () => ({ async *[Symbol.asyncIterator]() {} }),
    findOne: async ({ _id }: { _id: string }) => rows.get(_id) ?? null,
    insertOne: async (row: { _id: string }) => { rows.set(row._id, row); },
  };
  jest.setSystemTime(now);
  const service = await LegalApplications.fromDatabase({ collection: () => collection } as unknown as Db);
  const app = express().use(createLegalApplicationsRouter(async () => service, (_req, _res, next) => next()));
  await request(app).post('/submit').send(input).expect(202);
  expect(rows.size).toBe(1);
  jest.setSystemTime(now + 6_000);
  await request(app).post('/submit').send(input).expect(202);
  expect(rows.size).toBe(1);
});

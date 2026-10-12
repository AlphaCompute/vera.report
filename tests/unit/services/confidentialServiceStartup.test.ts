import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CONFIDENTIAL_STARTUP_ABANDONED_LOG, confidentialStartupAbandonedMessage, createConfidentialService } from '../../../src/api/confidentialService';
import * as storageRpc from '../../../src/services/confidentialStorageRpc';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { LegalApplicationSocketWorker } from '../../../src/services/legalApplicationSocket';
import { WeeklySubmissionSummaryWorker } from '../../../src/services/weeklySubmissionSummary';
import express from 'express';
import request from 'supertest';

test('weekly summary starts after storage is ready and drains before its database closes', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const order: string[] = [];
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockResolvedValue({
    configureLegalMemberInvitations: jest.fn(), applications: {}, weeklySubmissionSummaries: {},
    close: async () => { order.push('database-close'); },
  } as any);
  const listen = jest.spyOn(storageRpc, 'listenConfidentialStorage').mockImplementation(async () => { order.push('storage-ready'); });
  const start = jest.spyOn(WeeklySubmissionSummaryWorker.prototype, 'start').mockImplementation(() => { order.push('summary-start'); });
  const close = jest.spyOn(WeeklySubmissionSummaryWorker.prototype, 'close').mockImplementation(async () => { order.push('summary-close'); });
  const service = createConfidentialService({ env: {
    CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, DEPLOY_ENV: 'staging', WEEKLY_SUBMISSION_SUMMARY_ENABLED: 'true',
    SLACK_WEEKLY_SUMMARY_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/SYNTHETIC',
  }, adminGuard: (_req, _res, next) => next(), onUnavailable: jest.fn() });
  try {
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('ready');
    await service.runtime.close();
    expect(order).toEqual(['storage-ready', 'summary-start', 'summary-close', 'database-close']);
  } finally {
    await service.runtime.close(); close.mockRestore(); start.mockRestore(); listen.mockRestore(); connect.mockRestore();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('existing legal configuration starts membership provisioning without an enable flag and retires the callback', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const policy = join(directory, 'legal.json'); writeFileSync(policy, JSON.stringify({ issuer: 'https://legal.example/',
    clientId: 'legal-portal-client', audience: 'https://legal-api.example' }));
  const provisionLegalAuth0Membership = jest.fn(async () => false);
  const configureLegalMemberInvitations = jest.fn();
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockResolvedValue({
    configureLegalMemberInvitations, provisionLegalAuth0Membership, close: jest.fn(), applications: {},
  } as any);
  const listen = jest.spyOn(storageRpc, 'listenConfidentialStorage').mockResolvedValue(undefined);
  const interval = jest.spyOn(global, 'setInterval');
  const secret = 'synthetic-obsolete-entry-secret-'.repeat(2);
  const service = createConfidentialService({ env: {
    CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, CONFIDENTIAL_LEGAL_IDENTITY_FILE: policy,
    LEGAL_AUTH0_MGMT_DOMAIN: 'legal.example', LEGAL_AUTH0_MGMT_CLIENT_ID: 'synthetic-client',
    LEGAL_AUTH0_MGMT_CLIENT_SECRET: 'synthetic-secret', LEGAL_AUTH0_CONNECTION_ID: 'con_test',
    LEGAL_AUTH0_ENTRY_SECRET: secret,
  }, adminGuard: (_req, _res, next) => next(), onUnavailable: jest.fn() });
  try {
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('ready');
    expect(connect).toHaveBeenCalledWith('mongodb://synthetic.invalid', 'vera_confidential', undefined,
      expect.objectContaining({ get: expect.any(Function), list: expect.any(Function), update: expect.any(Function) }));
    expect(configureLegalMemberInvitations).toHaveBeenCalledWith(expect.objectContaining({ nativeEntry: true }));
    expect(provisionLegalAuth0Membership).toHaveBeenCalledTimes(1);
    expect(interval.mock.calls.some(([, ms]) => ms === 2000)).toBe(true);
    const app = express(); service.mount(app);
    const response = await request(app).post('/api/auth0/legal-entry').set('Authorization', `Bearer ${secret}`)
      .send({ operation: 'lookup', clientId: 'legal-portal-client', connectionId: 'con_test', email: 'member@firm.example' });
    expect(response.status).toBe(404);
  } finally {
    await service.runtime.close();
    interval.mockRestore(); listen.mockRestore(); connect.mockRestore(); rmSync(directory, { recursive: true, force: true });
  }
});

test.each(['https://hooks.slack.com/services/TEST/TEST/TEST', 'https://untrusted.example/'])('retired report alert settings are ignored without starting Slack delivery (%s)', async webhook => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const claimAdminAlert = jest.fn();
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockResolvedValue({
    configureLegalMemberInvitations: jest.fn(), close: jest.fn(), applications: {}, claimAdminAlert,
  } as any);
  const listen = jest.spyOn(storageRpc, 'listenConfidentialStorage').mockResolvedValue(undefined);
  const fetch = jest.spyOn(global, 'fetch');
  const interval = jest.spyOn(global, 'setInterval');
  const failed = jest.fn();
  const service = createConfidentialService({ env: {
    CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, CONFIDENTIAL_SLACK_WEBHOOK_URL: webhook,
    CONFIDENTIAL_SLACK_ADMIN_URL: 'https://vera.example/admin',
  }, adminGuard: (_req, _res, next) => next(), onUnavailable: failed });
  try {
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('ready');
    expect(failed).not.toHaveBeenCalled();
    expect(claimAdminAlert).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
    expect(interval.mock.calls.filter(([, milliseconds]) => milliseconds === 60_000)).toHaveLength(0);
  } finally {
    await service.runtime.close();
    interval.mockRestore(); fetch.mockRestore(); listen.mockRestore(); connect.mockRestore();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('invalid Roughtime configuration still fails before Mongo with Socket Mode configured', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockRejectedValue(new Error('unexpected database acquisition'));
  const failed = jest.fn();
  const service = createConfidentialService({ env: {
    CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, SLACK_APPLICATION_APP_TOKEN: 'xapp-synthetic-test',
    SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: 'U123',
    CONFIDENTIAL_ROUGHTIME_SERVERS: 'not an address',
  }, adminGuard: (_req, _res, next) => next(), onUnavailable: failed });
  try {
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('unavailable');
    expect(connect).not.toHaveBeenCalled(); expect(failed).toHaveBeenCalledWith('configuration');
  } finally { await service.runtime.close(); connect.mockRestore(); rmSync(directory, { recursive: true, force: true }); }
});

test.each(['U123', ''])('the backend never consumes Slack approvals, including stale worker settings (%s)', async reviewers => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const order: string[] = [];
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockResolvedValue({ configureLegalMemberInvitations: jest.fn(), close: async () => { order.push('database'); }, applications: {} } as any);
  const listen = jest.spyOn(storageRpc, 'listenConfidentialStorage').mockResolvedValue(undefined);
  const start = jest.spyOn(LegalApplicationSocketWorker.prototype, 'start').mockImplementation(() => {});
  const stop = jest.spyOn(LegalApplicationSocketWorker.prototype, 'stop').mockImplementation(async () => { order.push('socket'); });
  try {
    const service = createConfidentialService({ env: {
      CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
      CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, SLACK_APPLICATION_APP_TOKEN: 'xapp-synthetic-test',
      SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: reviewers,
    }, adminGuard: (_req, _res, next) => next(), onUnavailable: jest.fn() });
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('ready'); expect(start).not.toHaveBeenCalled();
    await service.runtime.close(); expect(order).toEqual(['database']); expect(stop).not.toHaveBeenCalled();
  } finally { stop.mockRestore(); start.mockRestore(); listen.mockRestore(); connect.mockRestore(); rmSync(directory, { recursive: true, force: true }); }
});

test('failed listener startup closes the database without starting the application delivery timer', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const close = jest.fn(async () => {}), deliverOne = jest.fn();
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockResolvedValue({ configureLegalMemberInvitations: jest.fn(), close, applications: { deliverOne } } as any);
  const listen = jest.spyOn(storageRpc, 'listenConfidentialStorage').mockRejectedValue(new Error('listener unavailable'));
  const interval = jest.spyOn(global, 'setInterval');
  const failed = jest.fn();
  try {
    const service = createConfidentialService({ env: {
      CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
      CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest, SLACK_APPLICATION_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/TEST',
    }, adminGuard: (_req, _res, next) => next(), onUnavailable: failed });
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('unavailable');
    expect(close).toHaveBeenCalledTimes(1); expect(deliverOne).not.toHaveBeenCalled();
    expect(interval.mock.calls.filter(([, milliseconds]) => milliseconds === 15_000)).toHaveLength(0);
    expect(failed).toHaveBeenCalledWith('storage');
    await service.runtime.close();
  } finally { interval.mockRestore(); listen.mockRestore(); connect.mockRestore(); rmSync(directory, { recursive: true, force: true }); }
});

test('database failures report only a fixed stage, never connection details or exception text', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect')
    .mockRejectedValue(new Error('mongodb://PRIVATE-USER:PRIVATE-PASSWORD@internal.invalid failed'));
  const failed = jest.fn();
  const service = createConfidentialService({ env: {
    CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest,
  }, adminGuard: (_req, _res, next) => next(), onUnavailable: failed });
  try {
    await service.runtime.settled;
    expect(service.runtime.status()).toBe('unavailable');
    expect(failed.mock.calls).toEqual([['database']]);
  } finally { await service.runtime.close(); connect.mockRestore(); rmSync(directory, { recursive: true, force: true }); }
});

test('configuration errors stop retrying after three attempts with one fixed abandonment report', async () => {
  jest.useFakeTimers();
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockRejectedValue(new Error('unexpected database acquisition'));
  const failed = jest.fn(), abandoned = jest.fn();
  const service = createConfidentialService({ env: { CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://PRIVATE-USER@synthetic.invalid' },
    adminGuard: (_req, _res, next) => next(), onUnavailable: failed, onAbandoned: abandoned });
  try {
    await service.runtime.settled;
    await jest.advanceTimersByTimeAsync(60 * 60_000);
    expect(failed.mock.calls).toEqual([['configuration'], ['configuration'], ['configuration']]);
    expect(abandoned.mock.calls).toEqual([['configuration', 3]]);
    expect(connect).not.toHaveBeenCalled();
    expect(service.runtime.status()).toBe('unavailable');
    expect(confidentialStartupAbandonedMessage.startsWith(`${CONFIDENTIAL_STARTUP_ABANDONED_LOG}:`)).toBe(true);
  } finally { await service.runtime.close(); connect.mockRestore(); jest.useRealTimers(); }
});

test('database failures are transient and never abandon initialization', async () => {
  jest.useFakeTimers();
  const directory = mkdtempSync(join(tmpdir(), 'vera-startup-'));
  const manifest = join(directory, 'manifest.json'); writeFileSync(manifest, '{}');
  const connect = jest.spyOn(MongoConfidentialCaseStore, 'connect').mockRejectedValue(new Error('database unavailable'));
  const abandoned = jest.fn();
  const service = createConfidentialService({ env: { CONFIDENTIAL_CASES_ENABLED: 'true', CONFIDENTIAL_MONGODB_URI: 'mongodb://synthetic.invalid',
    CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifest }, adminGuard: (_req, _res, next) => next(), onUnavailable: jest.fn(), onAbandoned: abandoned });
  try {
    await service.runtime.settled;
    await jest.advanceTimersByTimeAsync(10 * 60_000);
    expect(connect.mock.calls.length).toBeGreaterThan(3);
    expect(abandoned).not.toHaveBeenCalled();
  } finally { await service.runtime.close(); connect.mockRestore(); jest.useRealTimers(); rmSync(directory, { recursive: true, force: true }); }
});


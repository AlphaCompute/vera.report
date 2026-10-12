import express from 'express';
import request from 'supertest';
import { EventEmitter } from 'node:events';
import { reserveIntake, reserveUpload, withUploadBudget, recordUploadProgress, configureUploadReadiness } from '../../../src/middleware/uploadBudget';
import {
  MAX_PROCESS_UPLOADS,
  UPLOAD_MIN_BYTES_PER_SEC,
  UPLOAD_RECEIVE_MAX_MS,
  uploadReceiveDeadlineMs,
} from '../../../src/utils/evidenceLimits';

beforeEach(() => { configureUploadReadiness(async () => true); });
afterEach(() => { configureUploadReadiness(null); });

function mockReq(ip = '198.51.100.1') {
  return Object.assign(new EventEmitter(), {
    complete: false,
    destroy: jest.fn(),
    headers: {},
    socket: { remoteAddress: ip },
    ip,
  });
}

function mockRes() {
  return Object.assign(new EventEmitter(), {
    setHeader: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  });
}

it('holds process admission at one transfer until local relay readiness is available', async () => {
  configureUploadReadiness(null);
  const first = mockReq('198.51.100.21'), second = mockReq('198.51.100.22');
  const firstResponse = mockRes(), secondResponse = mockRes();
  const admitted = jest.fn(), denied = jest.fn();
  try {
    await reserveUpload(first, firstResponse, admitted);
    await reserveUpload(second, secondResponse, denied);
    expect(admitted).toHaveBeenCalledTimes(1);
    expect(denied).not.toHaveBeenCalled();
    expect(secondResponse.status).toHaveBeenCalledWith(503);
  } finally { first.emit('aborted'); second.emit('aborted'); }
});

it('rejects a second concurrent transfer from the same client and releases after work completes', async () => {
  let release!: () => void;
  const work = new Promise<void>(resolve => { release = resolve; });
  let admitted!: () => void;
  const ready = new Promise<void>(resolve => { admitted = resolve; });
  let count = 0;
  const app = express();
  app.post('/upload', reserveUpload, withUploadBudget(async (_req, res) => {
    if (++count === 1) admitted();
    await work; res.json({ ok: true });
  }));
  const first = request(app).post('/upload').then(result => result);
  await ready;
  expect((await request(app).post('/upload')).status).toBe(503);
  release();
  expect((await first).status).toBe(200);
  expect((await request(app).post('/upload')).status).toBe(200);
});

it('admits two different clients concurrently and rejects a third process-wide after relay readiness', async () => {
  const resA = mockRes();
  const resB = mockRes();
  const resC = mockRes();
  const nextA = jest.fn();
  const nextB = jest.fn();
  const nextC = jest.fn();
  const reqA = mockReq('198.51.100.1');
  const reqB = mockReq('198.51.100.2');
  const reqC = mockReq('198.51.100.3');
  reserveUpload(reqA, resA, nextA);
  await reserveUpload(reqB, resB, nextB);
  expect(nextA).toHaveBeenCalled();
  expect(nextB).toHaveBeenCalled();
  expect(MAX_PROCESS_UPLOADS).toBe(2);
  reserveUpload(reqC, resC, nextC);
  expect(nextC).not.toHaveBeenCalled();
  expect(resC.status).toHaveBeenCalledWith(503);
  expect(resC.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'upload_capacity_busy' }));
  reqA.emit('aborted');
  reqB.emit('aborted');
  const admitted = jest.fn();
  reserveUpload(reqC, resC, admitted);
  expect(admitted).toHaveBeenCalled();
  reqC.emit('aborted');
});

it.each(['resync', 'observation failure'])('refuses the second slot on %s after an earlier ready observation', async reason => {
  const first = mockReq('198.51.100.31'), second = mockReq('198.51.100.32');
  const firstResponse = mockRes(), secondResponse = mockRes();
  try {
    await reserveUpload(first, firstResponse, jest.fn());
    await reserveUpload(second, secondResponse, jest.fn());
    second.emit('aborted');
    configureUploadReadiness(async () => { if (reason === 'observation failure') throw new Error('offline'); return false; });
    const denied = jest.fn();
    await reserveUpload(mockReq('198.51.100.33'), secondResponse, denied);
    expect(denied).not.toHaveBeenCalled();
    expect(secondResponse.status).toHaveBeenCalledWith(503);
  } finally { first.emit('aborted'); second.emit('aborted'); }
});

it('rechecks the process ceiling after concurrent live-readiness observations resolve', async () => {
  let ready!: (value: boolean) => void;
  const observation = new Promise<boolean>(resolve => { ready = resolve; });
  configureUploadReadiness(() => observation);
  const first = mockReq('198.51.100.41'), second = mockReq('198.51.100.42'), third = mockReq('198.51.100.43');
  const secondResponse = mockRes(), thirdResponse = mockRes();
  const nextSecond = jest.fn(), nextThird = jest.fn();
  try {
    await reserveUpload(first, mockRes(), jest.fn());
    const attempts = [reserveUpload(second, secondResponse, nextSecond), reserveUpload(third, thirdResponse, nextThird)];
    ready(true);
    await Promise.all(attempts);
    expect(nextSecond).toHaveBeenCalledTimes(1);
    expect(nextThird).not.toHaveBeenCalled();
    expect(thirdResponse.status).toHaveBeenCalledWith(503);
  } finally { first.emit('aborted'); second.emit('aborted'); third.emit('aborted'); }
});

it('rejects a second concurrent transfer from the same client while capacity remains', () => {
  const res = mockRes();
  const req1 = mockReq('198.51.100.4');
  const req2 = mockReq('198.51.100.4');
  const admitted = jest.fn();
  const denied = jest.fn();
  reserveUpload(req1, res, admitted);
  expect(admitted).toHaveBeenCalled();
  reserveUpload(req2, res, denied);
  expect(denied).not.toHaveBeenCalled();
  expect(res.status).toHaveBeenCalledWith(503);
  req1.emit('aborted');
  const freed = jest.fn();
  reserveUpload(req2, res, freed);
  expect(freed).toHaveBeenCalled();
  req2.emit('aborted');
});

it('releases an idle receiver before the 15 minute absolute deadline', () => {
  jest.useFakeTimers();
  const req = mockReq();
  const res = mockRes();
  const next = jest.fn();
  try {
    reserveUpload(req, res, next);
    expect(next).toHaveBeenCalled();
    jest.advanceTimersByTime(11_000);
    expect(req.destroy).toHaveBeenCalled();
    const second = mockReq('198.51.100.9');
    const admitted = jest.fn(); reserveUpload(second, res, admitted);
    expect(admitted).toHaveBeenCalled(); second.emit('aborted');
  } finally { jest.useRealTimers(); }
});

it('releases a slow drip below the minimum receive rate after the grace period', () => {
  jest.useFakeTimers();
  const req = mockReq();
  const res = mockRes();
  try {
    reserveUpload(req, res, jest.fn());
    const drip = Buffer.alloc(1024);
    for (let second = 0; second < 31; second++) {
      recordUploadProgress(req, drip);
      jest.advanceTimersByTime(1000);
    }
    expect(req.destroy).toHaveBeenCalled();
    const second = mockReq('198.51.100.9');
    const admitted = jest.fn();
    reserveUpload(second, res, admitted);
    expect(admitted).toHaveBeenCalled();
    second.emit('aborted');
  } finally { jest.useRealTimers(); }
});

it('releases an incomplete body at the scaled receive-phase ceiling even with steady progress', () => {
  jest.useFakeTimers();
  const contentLength = UPLOAD_MIN_BYTES_PER_SEC * (UPLOAD_RECEIVE_MAX_MS / 1000);
  const req = Object.assign(mockReq(), { headers: { 'content-length': String(contentLength) } });
  const res = mockRes();
  try {
    reserveUpload(req, res, jest.fn());
    const chunk = Buffer.alloc(UPLOAD_MIN_BYTES_PER_SEC);
    const deadlineSec = uploadReceiveDeadlineMs(contentLength) / 1000;
    for (let second = 0; second < deadlineSec; second++) {
      recordUploadProgress(req, chunk);
      jest.advanceTimersByTime(1000);
    }
    expect(req.destroy).toHaveBeenCalled();
    const second = mockReq('198.51.100.9');
    const admitted = jest.fn();
    reserveUpload(second, res, admitted);
    expect(admitted).toHaveBeenCalled();
    second.emit('aborted');
  } finally { jest.useRealTimers(); }
});

it('releases above-floor drips that fall behind completion pace after grace', () => {
  jest.useFakeTimers();
  const contentLength = 16 * 1024 * 1024;
  const aboveFloor = Math.floor(UPLOAD_MIN_BYTES_PER_SEC * 1.25);
  const req = Object.assign(mockReq(), { headers: { 'content-length': String(contentLength) } });
  const res = mockRes();
  try {
    reserveUpload(req, res, jest.fn());
    const chunk = Buffer.alloc(aboveFloor);
    for (let second = 0; second < 31; second++) {
      recordUploadProgress(req, chunk);
      jest.advanceTimersByTime(1000);
    }
    expect(req.destroy).toHaveBeenCalled();
    const second = mockReq('198.51.100.9');
    const admitted = jest.fn();
    reserveUpload(second, res, admitted);
    expect(admitted).toHaveBeenCalled();
    second.emit('aborted');
  } finally { jest.useRealTimers(); }
});

it('retains capacity after disconnect while expensive processing is still running', async () => {
  const req = Object.assign(mockReq(), { complete: true });
  const res = Object.assign(mockRes(), { destroyed: false });
  reserveUpload(req, res, jest.fn());
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const processing = withUploadBudget(async () => { await pending; })(req, res);
  res.destroyed = true;
  res.emit('close');
  req.emit('aborted');
  const denied = jest.fn();
  // Different client still blocked while process holds the lease through processing,
  // and same-client concurrent is also denied — fill remaining process slot first.
  const other = mockReq('198.51.100.8');
  await reserveUpload(other, mockRes(), jest.fn());
  const third = mockReq('198.51.100.9');
  const thirdResponse = mockRes();
  await reserveUpload(third, thirdResponse, denied);
  expect(denied).not.toHaveBeenCalled();
  expect(thirdResponse.status).toHaveBeenCalledWith(503);
  other.emit('aborted');
  release();
  await processing;
  const admitted = jest.fn();
  reserveUpload(req, res, admitted);
  expect(admitted).toHaveBeenCalled();
  res.emit('close');
});

it('admits a small intake body while slow uploads hold every evidence slot', async () => {
  const holders = [mockReq('198.51.100.61'), mockReq('198.51.100.62')];
  const small = Object.assign(mockReq('198.51.100.63'), { headers: { 'content-length': '4096' } });
  const large = Object.assign(mockReq('198.51.100.64'), { headers: { 'content-length': String(8 * 1024 * 1024) } });
  const largeResponse = mockRes();
  const admitted = jest.fn(), denied = jest.fn();
  try {
    for (const holder of holders) await reserveUpload(holder, mockRes(), jest.fn());
    await reserveIntake(large, largeResponse, denied);
    expect(denied).not.toHaveBeenCalled();
    expect(largeResponse.status).toHaveBeenCalledWith(503);
    await reserveIntake(small, mockRes(), admitted);
    expect(admitted).toHaveBeenCalledTimes(1);
  } finally { for (const req of [...holders, small, large]) req.emit('aborted'); }
});

it('never gives a small request a small-pool slot outside intake', async () => {
  const holders = [mockReq('198.51.100.81'), mockReq('198.51.100.82')];
  const reveal = Object.assign(mockReq('198.51.100.83'), { headers: { 'content-length': '64' } });
  const response = mockRes();
  const next = jest.fn();
  try {
    for (const holder of holders) await reserveUpload(holder, mockRes(), jest.fn());
    await reserveUpload(reveal, response, next);
    expect(next).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(503);
  } finally { for (const req of [...holders, reveal]) req.emit('aborted'); }
});

it('caps concurrent small intake bodies per client', async () => {
  const reqs = [0, 1].map(() => Object.assign(mockReq('198.51.100.71'), { headers: { 'content-length': '512' } }));
  const second = mockRes();
  const next = jest.fn();
  try {
    await reserveIntake(reqs[0], mockRes(), next);
    await reserveIntake(reqs[1], second, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(second.status).toHaveBeenCalledWith(503);
  } finally { for (const req of reqs) req.emit('aborted'); }
});

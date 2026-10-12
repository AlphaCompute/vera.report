// Runs the actual entry point with synthetic service boundaries. No SDK,
// deployment, database or external provider acceptance is asserted.
const Module = require('node:module');
const path = require('node:path');
const entry = path.resolve(__dirname, '../../src/index.ts');
const originalLoad = Module._load;
// Model the live server's event-loop ownership, so only entry-point shutdown
// can exit successfully and queued OS signals cannot be bypassed by idle exit.
setInterval(() => {}, 1_000);
const event = value => process.stdout.write(`${value}\n`);
const operation = name => async () => { event(name); };
const worker = name => ({
  start() { event(`${name}:start`); },
  async close() {
    event(`${name}:drain`);
    if (name === 'scoring' && process.env.TEST_DRAIN_HANG === '1') await new Promise(() => {});
    if (name === 'scoring') await new Promise(resolve => setImmediate(resolve));
    event(`${name}:done`);
    if (name === 'dispatch' && process.env.TEST_DRAIN_FAIL === '1') throw new Error('synthetic drain failure');
  },
});
const api = {
  async startApiServer() {
    event('api:start');
    if (process.env.TEST_STARTUP_FAIL === '1') throw new Error('synthetic startup failure');
  },
  stopApiServer: operation('api:stop'),
};
const mocks = {
  './utils/logger': { logger: {
    info(message) {
      if (String(message).startsWith('Check runtime health')) {
        // Signals are delivered after startup and signal registration finish.
        setImmediate(() => { process.kill(process.pid, 'SIGTERM'); process.kill(process.pid, 'SIGINT'); });
      }
    }, warn() {}, error() {},
  } },
  './utils/errorMonitor': { errorMonitor: worker('error-monitor') },
  './config/env': { env: { PORT: 0 } },
  './api/server': api,
  './services/shroudClient': { isShroudConfigured: () => true },
  './services/reportPersistence': { reportPersistenceService: { close: operation('reports:close') } },
  './services/dissemination/disseminationPersistence': { disseminationPersistence: { disconnect: operation('dissemination:close') } },
  './services/adminAuditLog': { adminAuditLog: { close: operation('admin-audit:close') } },
  './services/dissemination/dispatchWorker': { dispatchWorker: worker('dispatch') },
  './services/criticalAdminAlertWorker': { criticalAdminAlertWorker: worker('critical-alert') },
  './services/reportAlertWorker': { reportAlertWorker: worker('alert') },
  './services/submissionNotificationWorker': { submissionNotificationWorker: worker('notification') },
  './services/reportScoringWorker': { reportScoringWorker: worker('scoring') },
  './services/dissemination/auditAnchor': { auditAnchorService: worker('audit') },
};
Module._load = function(request, parent, ...rest) {
  if (parent?.filename === entry && Object.hasOwn(mocks, request)) return mocks[request];
  return originalLoad.call(this, request, parent, ...rest);
};
require('ts-node/register/transpile-only');
require(entry);

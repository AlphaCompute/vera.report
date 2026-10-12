import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';

// Exercise the actual IndexedDB implementation in Chromium, with two pages on
// one origin. No test implementation of transactions or local storage is used.
const source = readFileSync(resolve(__dirname, '../../lib/confidential/deviceVault.ts'), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.CommonJS } }).outputText;
const policy = ts.transpileModule(readFileSync(resolve(__dirname, '../../lib/confidential/passphraseStrength.ts'), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const script = `(() => {
  const policy = (() => { const exports = {}; ${policy}; return exports; })();
  const require = name => { if (name === './passphraseStrength') return policy; throw new Error('Unbundled vault dependency: ' + name); };
  const exports = {}; ${compiled}; window.vaultApi = exports;
})();`;
let server: Server, origin: string;
test.beforeAll(async () => {
  server = createServer((_req, res) => { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Vault test</title>'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
test.afterAll(async () => { await new Promise<void>(resolve => server.close(() => resolve())); });

test('reload restores encrypted storage; transactions reject stale tabs and forget removes every vault', async ({ page, context }) => {
  await page.goto(origin); await page.addScriptTag({ content: script });
  const id = await page.evaluate(async () => {
    const api = (window as any).vaultApi;
    const store = api.browserVaultStore();
    const handle = await api.createDeviceVault(store, 'owner', 'a long passphrase outside the browser',
      { code: 'PRIVATE-CASE-SENTINEL' });
    (window as any).handle = handle;
    const records = await store.list();
    if (JSON.stringify(records).includes('PRIVATE-CASE-SENTINEL')) throw new Error('Plaintext in IndexedDB');
    if (localStorage.length || sessionStorage.length) throw new Error('Unexpected web storage');
    return handle.id;
  });
  await page.reload(); await page.addScriptTag({ content: script });
  expect(await page.evaluate(async id => {
    const api = (window as any).vaultApi;
    const handle = await api.unlockDeviceVault(api.browserVaultStore(), id, 'owner', 'a long passphrase outside the browser');
    (window as any).handle = handle;
    return handle.read();
  }, id)).toEqual({ code: 'PRIVATE-CASE-SENTINEL' });
  const second = await context.newPage();
  await second.goto(origin); await second.addScriptTag({ content: script });
  await second.evaluate(async id => {
    const api = (window as any).vaultApi;
    (window as any).handle = await api.unlockDeviceVault(api.browserVaultStore(), id, 'owner', 'a long passphrase outside the browser');
  }, id);
  await page.evaluate(async () => { await (window as any).handle.save({ revision: 2 }); });
  expect(await second.evaluate(async () => {
    try { await (window as any).handle.save({ revision: 1 }); return 'overwrote'; }
    catch (error) { return error instanceof (window as any).vaultApi.VaultConflictError ? 'conflict' : 'other'; }
  })).toBe('conflict');
  await second.evaluate(async () => {
    const api = (window as any).vaultApi;
    await api.createDeviceVault(api.browserVaultStore(), 'legal', 'a second long and separate password', { key: 'PRIVATE-FIRM-SENTINEL' });
    await api.browserVaultStore().clear();
  });
  expect(await page.evaluate(async () => {
    const api = (window as any).vaultApi;
    try { await (window as any).handle.save({ revision: 3 }); return 'recreated'; }
    catch (error) {
      if (!(error instanceof api.VaultConflictError)) throw error;
      return (await api.browserVaultStore().list()).length;
    }
  })).toBe(0);
  await page.reload(); await page.addScriptTag({ content: script });
  expect(await page.evaluate(async () => (window as any).vaultApi.browserVaultStore().list())).toEqual([]);
});

test('an existing version 1 database upgrades in place and keeps its saved workspaces', async ({ page }) => {
  await page.goto(origin);
  await page.evaluate(() => new Promise<void>((resolve, reject) => {
    const request = indexedDB.open('vera-confidential-device/v1', 1);
    request.onupgradeneeded = () => { request.result.createObjectStore('vaults', { keyPath: 'id' }); request.result.createObjectStore('meta'); };
    request.onsuccess = () => { request.result.close(); resolve(); };
    request.onerror = () => reject(request.error);
  }));
  await page.addScriptTag({ content: script });
  const id = await page.evaluate(async () => {
    const api = (window as any).vaultApi;
    // Write a passphrase record through a store limited to the version 1 layout.
    const db = await new Promise<IDBDatabase>(resolve => { const r = indexedDB.open('vera-confidential-device/v1', 1); r.onsuccess = () => resolve(r.result); });
    const records: any[] = [];
    const memory = { generation: async () => 0, list: async () => records, get: async () => null,
      put: async (record: any) => { records.push(record); }, remove: async () => {}, clear: async () => {} };
    const handle = await api.createDeviceVault(memory, 'legal', 'a long passphrase outside the browser', { key: 'SENTINEL' });
    await new Promise<void>(resolve => { const tx = db.transaction('vaults', 'readwrite'); tx.objectStore('vaults').put(records[0]); tx.oncomplete = () => resolve(); });
    db.close();
    return handle.id;
  });
  expect(await page.evaluate(async id => {
    const api = (window as any).vaultApi;
    const store = api.browserVaultStore();
    const handle = await api.unlockDeviceVault(store, id, 'legal', 'a long passphrase outside the browser');
    const bound = await api.createDeviceBoundVault(store, 'legal', { key: 'SECOND' });
    return { first: handle.read(), second: (await api.unlockDeviceBoundVault(store, bound.id, 'legal')).read(), count: (await store.list()).length };
  }, id)).toEqual({ first: { key: 'SENTINEL' }, second: { key: 'SECOND' }, count: 2 });
});

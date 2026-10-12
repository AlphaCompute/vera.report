'use strict';

// Executes the real environment module. No token or authentication substitute.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const repo = path.resolve(__dirname, '../../..');
const tsNode = require.resolve('ts-node');

function validate(mode, database = true) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-env-validation-'));
  try {
    return spawnSync(process.execPath, ['-e', `require(${JSON.stringify(tsNode)}).register({project:${JSON.stringify(path.join(repo, 'tsconfig.json'))},transpileOnly:true});require(${JSON.stringify(path.join(repo, 'src/config/env.ts'))});`], {
      cwd, encoding: 'utf8', timeout: 15000,
      env: { PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH || '', LOG_LEVEL: 'silent',
        ...(database ? { MONGODB_URI: 'mongodb://127.0.0.1:27017', MONGODB_DB_NAME: 'vera_env_validation' } : {}),
        ...(mode === undefined ? {} : { RUN_MODE: mode }) },
    });
  } finally { fs.rmSync(cwd, { recursive: true }); }
}
test('API-only environment accepts database configuration', () => {
  const result = validate('api'); assert.equal(result.status, 0, result.stderr);
});
test('Default runtime starts the API without messaging credentials', () => {
  const result = validate(undefined); assert.equal(result.status, 0, result.stderr);
});
for (const mode of ['bot', 'all']) test(`Retired mode ${mode} is rejected`, () => {
  const result = validate(mode); assert.equal(result.status, 1); assert.match(result.stderr, /Invalid RUN_MODE/);
});
test('Invalid runtime is rejected', () => {
  const result = validate('worker'); assert.equal(result.status, 1); assert.match(result.stderr, /Invalid RUN_MODE/);
});
test('API-only runtime still requires durable database configuration', () => {
  const result = validate('api', false); assert.equal(result.status, 1); assert.match(result.stderr, /MONGODB_URI/); assert.match(result.stderr, /MONGODB_DB_NAME/);
});

import type { Config } from 'jest';
import base from './jest.config.cjs';

// One source of truth for the supported local/CI gate. Browser acceptance
// uses its own configuration and explicit commands.
const config: Config = {
  ...base,
  testMatch: [
    '<rootDir>/tests/unit/**/*.test.ts',
    '<rootDir>/tests/unit/**/*.spec.ts',
    '<rootDir>/enclave/tests/**/*.test.ts',
    '<rootDir>/enclave/tests/**/*.spec.ts',
    '<rootDir>/tests/integration/services/**/*.test.ts',
    '<rootDir>/tests/integration/services/**/*.spec.ts',
  ],
};
export default config;

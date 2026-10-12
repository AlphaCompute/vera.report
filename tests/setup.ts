import { installSupertestLoopback } from './helpers/supertestLoopback';
import 'jest-extended';
import '@testing-library/jest-dom';
import { config } from 'dotenv';
import path from 'path';

installSupertestLoopback();

// Load environment variables for tests
config({ path: path.resolve(__dirname, '../.env.test') });
config({ path: path.resolve(__dirname, '../.env.local'), override: true });

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
// Legacy route fixtures opt in explicitly. Confidential suites select their own mode.
process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';

// Prevent unit tests from connecting to real MongoDB.
// Integration tests that need MongoDB use MongoMemoryServer.
process.env.MONGODB_URI = '';
process.env.MONGODB_DB_NAME = '';

// Synthetic admin domains; suites testing the fail-closed default unset this value.
process.env.ADMIN_ALLOWED_DOMAINS = '@example.com,@example.org';

// Global test helpers
global.testHelpers = {
  generateMockUser: () => ({
    id: Math.random().toString(36).substring(7),
    username: 'testuser',
    email: 'test@example.com',
    createdAt: new Date()
  }),
  
  generateMockTask: () => ({
    id: Math.random().toString(36).substring(7),
    title: 'Test Task',
    description: 'Test Description',
    status: 'To Do',
    priority: 'Medium',
    assignee: 'test@example.com',
    dueDate: new Date()
  }),
  
  delay: (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
};

// Increase timeout for CI/CD environments
if (process.env.CI) {
  jest.setTimeout(60000);
}

declare global {
  var testHelpers: {
    generateMockUser: () => any;
    generateMockTask: () => any;
    delay: (ms: number) => Promise<void>;
  };
}
process.env.RECIPIENT_CAPABILITY_SECRET = 'test-only-independent-recipient-key-20260914';

/** @type {import('jest').Config} */
const config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // The production standalone build contains a second package.json. Keep
  // build output out of Jest's module map when testing a built application.
  modulePathIgnorePatterns: ['<rootDir>/.next/'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/',
    // Playwright specs, not Jest specs. testMatch below globs **/*.spec.ts, so
    // without these Jest picks them up and dies on `import ... from
    // '@playwright/test'`, which it can never resolve: qa/package.json keeps
    // @playwright/test out of the root workspace on purpose ("Isolated from
    // root package.json so QA tooling deps stay separate"). That is the whole
    // reason six qa/staging-tests suites plus qa/playwright have been red in
    // `npx jest` runs. They fail to LOAD; their contents were never the problem.
    //
    // Run them with `npm --prefix qa test` (playwright test) instead.
    //
    '<rootDir>/qa/staging-tests/',
    '<rootDir>/qa/playwright/',
    // Run local browser recovery specs with qa/playwright.local.config.ts.
    '<rootDir>/qa/local-tests/',
    // Confidential browser journeys: qa/playwright.e2e.config.ts.
    '<rootDir>/qa/e2e/',
    // Fixture browser checks: qa/playwright.fixtures.config.ts.
    '<rootDir>/qa/fixture-tests/',
  ],
  transformIgnorePatterns: [
    '/node_modules/(?!(uuid|jose)/).+\\.js$',
  ],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.spec.ts',
    '!src/**/*.test.ts',
    '!src/**/index.ts',
    '!src/contracts/**',
    '!src/wrappers/**'
  ],
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90
    }
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleNameMapper: {
    '\\.module\\.css$': '<rootDir>/tests/styleMock.cjs',
    // enclave/ is built with module NodeNext, so its relative imports carry the
    // .js extension the emitted ESM needs. ts-jest transpiles to CommonJS and
    // resolves against the .ts sources, so strip the extension. Scoped to
    // relative paths; no non-enclave source uses this form.
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@/lib/(.*)$': '<rootDir>/lib/$1',
    // Frontend components and the shared protocol, as tsconfig's "@/*" resolves them.
    '^@/components/(.*)$': '<rootDir>/components/$1',
    '^@/enclave/(.*)$': '<rootDir>/enclave/$1',
    '^@/src/(.*)$': '<rootDir>/src/$1',
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@api/(.*)$': '<rootDir>/src/api/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
    '^@docs/(.*)$': '<rootDir>/src/docs/$1'
  },
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/*.test.ts',
    '**/*.spec.ts'
  ],
  verbose: true,
  testTimeout: 30000,
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        rootDir: '.'
      }
    }],
    // React components rendered to static markup in node tests.
    '^.+\\.tsx$': ['ts-jest', {
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        jsx: 'react-jsx',
        rootDir: '.'
      }
    }],
    '^.+\\.js$': ['ts-jest', {
      tsconfig: {
        esModuleInterop: true,
        allowJs: true,
        rootDir: '.'
      }
    }]
  }
};

module.exports = config;

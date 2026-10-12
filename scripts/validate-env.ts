import { config } from 'dotenv';
import { validateEnvironmentStrict } from '../src/utils/env-validation';

// Match application precedence. Never print configuration values or load services.
config({ path: '.env.local', quiet: true });
config({ quiet: true });
try {
  validateEnvironmentStrict();
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : 'Environment validation failed');
  process.exitCode = 1;
}

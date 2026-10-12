import { webhookConfigurationError } from '../services/submissionWebhook';
import { slackConfigurationError } from '../services/slackNotification';
import { requireLocalIpfs, LOCAL_IPFS_BACKEND } from '../services/localIpfs';
import { logger } from './logger';
import { confidentialCasesConfigurationError } from './confidentialConfiguration';
export { confidentialCasesConfigurationError } from './confidentialConfiguration';
/**
 * Environment Validation Utility
 */

export interface EnvironmentValidationResult {
  isValid: boolean;
  missingRequired: string[];
  missingOptional: string[];
  warnings: string[];
  errors: string[];
}

/**
 * Validate required and optional environment variables.
 */
export function validateEnvironment(): EnvironmentValidationResult {
  logger.info('🔍 [ENV_VALIDATION] Starting environment validation...');

  const runMode = process.env.RUN_MODE || 'api';
  // Names of required variables, never values.
  const required = ['MONGODB_URI', 'MONGODB_DB_NAME', 'INTERNAL_API_SECRET', 'REWARD_ENCRYPTION_KEY'];
  if (!process.env.KMS_AT_REST_KEY_ID?.trim()) required.push('AT_REST_LOCAL_KEY');
  // Evidence ciphertext has one backend, the self-hosted Kubo node.
  required.push('IPFS_STORAGE_BACKEND');

  const optional = [
    'DATABASE_URL',
    'WEBHOOK_URL',
    'WEBHOOK_SECRET',
    'SLACK_WEBHOOK_URL',
    'SLACK_ADMIN_URL',
    'PORT',
    'NODE_ENV',
  ];

  const missingRequired: string[] = [];
  const missingOptional: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  if (runMode !== 'api') errors.push('RUN_MODE must be api');

  // Check required variables
  for (const key of required) {
    if (!process.env[key]?.trim()) {
      missingRequired.push(key);
    } else {
      logger.info(`✅ [ENV_VALIDATION] ${key}: configured`);
    }
  }

  // Check optional variables
  for (const key of optional) {
    if (!process.env[key]?.trim()) {
      missingOptional.push(key);
      logger.info(`⚠️ [ENV_VALIDATION] ${key}: not configured (optional)`);
    } else {
      logger.info(`✅ [ENV_VALIDATION] ${key}: configured`);
    }
  }

  if (process.env.MONGODB_URI && process.env.MONGODB_URI.includes('localhost')) {
    warnings.push('MONGODB_URI points to localhost - ensure this is intended for development');
  }

  const webhookError = webhookConfigurationError();
  if (webhookError) errors.push(webhookError);
  const slackError = slackConfigurationError();
  if (slackError) errors.push(slackError);
  if (process.env.SLACK_WEBHOOK_URL?.trim() && !process.env.SLACK_ADMIN_URL?.trim()) {
    missingRequired.push('SLACK_ADMIN_URL');
  }
  if (process.env.WEBHOOK_URL?.trim() && !process.env.WEBHOOK_SECRET?.trim()) {
    missingRequired.push('WEBHOOK_SECRET');
  }
  const secretNames = ['INTERNAL_API_SECRET', 'REWARD_ENCRYPTION_KEY', 'AT_REST_LOCAL_KEY'];
  for (const name of secretNames) {
    const value = process.env[name];
    if (value && value.trim().length < 32) errors.push(`${name} must contain at least 32 characters`);
  }
  if (process.env.IPFS_STORAGE_BACKEND?.trim() && process.env.IPFS_STORAGE_BACKEND !== LOCAL_IPFS_BACKEND) {
    errors.push(`IPFS_STORAGE_BACKEND must be ${LOCAL_IPFS_BACKEND}`);
  } else if (process.env.IPFS_STORAGE_BACKEND === LOCAL_IPFS_BACKEND && process.env.NODE_ENV === 'production') {
    // The Kubo node is disposable: production needs the S3 archive and an explicit proxy origin.
    try { requireLocalIpfs(); } catch (error) { errors.push(error instanceof Error ? error.message : 'Invalid local IPFS configuration'); }
  }
  if (process.env.FRONTEND_TRUST_PROXY_HOPS && !/^[0-9]$/.test(process.env.FRONTEND_TRUST_PROXY_HOPS)) errors.push('FRONTEND_TRUST_PROXY_HOPS must be an integer from 0 to 9');
  if (process.env.API_TRUST_PROXY_HOPS && !/^[0-9]$/.test(process.env.API_TRUST_PROXY_HOPS)) errors.push('API_TRUST_PROXY_HOPS must be an integer from 0 to 9');
  if (!process.env.SHROUD_API_KEY?.trim()) warnings.push('SHROUD_API_KEY is not configured; report scoring is unavailable');
  if (process.env.ENCLAVE_ENABLED === 'true') errors.push('Attested enclave key operations are not implemented');
  const confidentialError = confidentialCasesConfigurationError();
  if (confidentialError) errors.push(confidentialError);
  const isValid = missingRequired.length === 0 && errors.length === 0;

  if (isValid) {
    logger.info('✅ [ENV_VALIDATION] Environment validation passed');
  } else {
    console.error(`❌ [ENV_VALIDATION] Environment validation failed: ${missingRequired.length} missing required variables${errors.length ? '; invalid configuration' : ''}`);
    missingRequired.forEach(key => {
      console.error(`   ❌ Missing required variable: ${key}`);
    });
  }

  errors.forEach(error => console.error(`   Invalid: ${error}`));

  if (warnings.length > 0) {
    console.warn(`⚠️ [ENV_VALIDATION] ${warnings.length} warnings:`);
    warnings.forEach(warning => {
      console.warn(`   ⚠️ ${warning}`);
    });
  }

  return {
    isValid,
    missingRequired,
    missingOptional,
    warnings,
    errors
  };
}

/**
 * Validate environment with strict mode (throws on any issues)
 */
export function validateEnvironmentStrict(): void {
  const result = validateEnvironment();

  if (!result.isValid) {
    const errorMessage = `Invalid environment configuration: ${[...result.missingRequired, ...result.errors].join('; ')}`;
    throw new Error(errorMessage);
  }

  if (result.warnings.length > 0) {
    console.warn('⚠️ [ENV_VALIDATION] Environment has warnings but proceeding...');
  }
}

/**
 * Get environment info for debugging
 */
export function getEnvironmentInfo(): Record<string, unknown> {
  return {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || '3000',
    hasMongoConfig: !!process.env.MONGODB_URI,
    timestamp: new Date().toISOString()
  };
}

/**
 * Log environment status for debugging
 */
export function logEnvironmentStatus(): void {
  const info = getEnvironmentInfo();
  logger.info('🔧 [ENV_INFO] Environment Information:');
  logger.info(`   Node.js: ${info.nodeVersion}`);
  logger.info(`   Platform: ${info.platform} (${info.arch})`);
  logger.info(`   Environment: ${info.env}`);
  logger.info(`   Port: ${info.port}`);
  logger.info(`   MongoDB: ${info.hasMongoConfig ? '✅' : '❌'}`);
  logger.info(`   Timestamp: ${info.timestamp}`);
}

export default validateEnvironment;

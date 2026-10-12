import { logger } from '../utils/logger';
import dotenv from 'dotenv';

// Load environment variables in order of priority
dotenv.config({ path: '.env.local' });
dotenv.config(); // Fallback to .env

export interface EnvironmentConfig {
    MONGODB_URI: string;
    MONGODB_DB_NAME: string;
    MONGODB_TLS_CA_FILE: string;
    RAILWAY_PROJECT?: string;
    SHROUD_API_KEY?: string;
    SHROUD_BASE_URL: string;
    SHROUD_MODEL: string;
    PORT: string;
}

function validateEnvironment(): EnvironmentConfig {
    const runMode = process.env.RUN_MODE || 'api';
    if (runMode !== 'api') {
        console.error('Invalid RUN_MODE: expected api');
        process.exit(1);
    }
    const requiredEnvVars = ['MONGODB_URI', 'MONGODB_DB_NAME'];
    const missingVars = requiredEnvVars.filter((varName) => !process.env[varName]);

    if (missingVars.length > 0) {
        console.error('❌ Missing required environment variables:', missingVars.join(', '));
        logger.info('🔍 Please check your .env.local or deployment environment settings');
        process.exit(1);
    }

    return {
        MONGODB_URI: process.env.MONGODB_URI!,
        MONGODB_DB_NAME: process.env.MONGODB_DB_NAME!,
        MONGODB_TLS_CA_FILE: process.env.MONGODB_TLS_CA_FILE || '/app/rds-combined-ca-bundle.pem',
        RAILWAY_PROJECT: process.env.RAILWAY_PROJECT,
        SHROUD_API_KEY: process.env.SHROUD_API_KEY,
        SHROUD_BASE_URL: process.env.SHROUD_BASE_URL || 'https://dev-gateway.shroud.us',
        SHROUD_MODEL: process.env.SHROUD_MODEL || 'nemotron-3-ultra',
        PORT: process.env.API_PORT || process.env.PORT || '3001',
    };
}

export const env = validateEnvironment();

// Optional: SES email notification config
export const sesConfig = {
  senderEmail: process.env.SES_SENDER_EMAIL?.trim() || '',
  region: process.env.SES_REGION?.trim() || '',
};

logger.info('✅ Environment variables loaded and validated');
logger.info(`🔗 MongoDB: ${env.MONGODB_DB_NAME} database`);
if (sesConfig.senderEmail) {
  logger.info(`📧 SES notifications: enabled (${sesConfig.senderEmail})`);
}

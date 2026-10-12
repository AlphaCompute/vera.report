import { logger } from '../utils/logger';
/**
 * Venice AI Service — configuration/health only.
 *
 * Report scoring moved to Shroud confidential inference (see reportScoring.ts /
 * shroudClient.ts). Venice no longer performs any scoring or evidence analysis;
 * this service now only exposes isConfigured() for the /health status field and
 * the shared VerificationResult type.
 */

export interface VerificationResult {
  isLegitimate: boolean;
  credibilityScore: number; // 0-100
  spamIndicators: string[];
  contentAnalysis: string;
  category: string;
  riskLevel: 'low' | 'medium' | 'high';
  /** Org-type in the Psst taxonomy (FR-2 routing dimension), 'unknown' when unclear. */
  organizationType: string;
  /** The organization the report concerns, or null when not identifiable. */
  namedOrganization: string | null;
}

export class VeniceAIService {
  private apiKey: string;

  constructor() {
    this.apiKey = process.env.VENICE_API_KEY || '';

    if (!this.apiKey) {
      logger.warn('⚠️ [VENICE_AI] VENICE_API_KEY not configured');
    } else {
      logger.info('✅ [VENICE_AI] Service initialized');
    }
  }

  /**
   * Check if Venice AI is properly configured (used by the /health endpoint).
   */
  isConfigured(): boolean {
    return !!this.apiKey && this.apiKey !== 'your_venice_api_key_here';
  }
}

// Singleton instance
export const veniceAIService = new VeniceAIService();

export default VeniceAIService;

import { logger } from '../utils/logger';
import { shroudChat, type ChatMessage } from './shroudClient';
import { isOrgType } from './dissemination/taxonomy';
import type { VerificationResult } from './veniceAI';

export async function verifyReport(report: {
  description: string;
  evidenceType: string;
  hasEvidence: boolean;
}, signal?: AbortSignal): Promise<VerificationResult> {
  logger.info(`🔍 [SHROUD] Verifying report - Type: ${report.evidenceType}`);

  const messages: ChatMessage[] = [
    {
      role: 'system',
      content: `You are a report verification AI for a whistleblower platform. Analyze the following report for:
1. Spam indicators (repetitive content, nonsense, promotional material, obvious fake content)
2. Credibility signals (specific details, verifiable claims, consistency, professional language)
3. Content legitimacy (real-world plausibility, logical coherence)
4. The organization the report concerns: its name (as written in the report) and its type

You must respond with ONLY valid JSON in this exact format, no other text:
{
  "isLegitimate": true/false,
  "credibilityScore": 0-100,
  "spamIndicators": ["indicator1", "indicator2"],
  "contentAnalysis": "brief analysis",
  "category": "fraud/corruption/safety/environmental/harassment/other",
  "riskLevel": "low/medium/high",
  "organizationType": "us-federal-government/state-government/local-government/other-government/for-profit/nonprofit/unknown",
  "namedOrganization": "organization name exactly as stated in the report, or null if none is identifiable"
}`,
    },
    {
      role: 'user',
      content: `Report Type: ${report.evidenceType}
Has Evidence: ${report.hasEvidence}
Description: ${report.description}`,
    },
  ];

  const content = await shroudChat(messages, signal);

  let result: any;
  try {
    result = JSON.parse(content.trim());
  } catch {
    logger.error('[SHROUD] Verification response was not valid JSON');
    throw new Error('Shroud verification unavailable: invalid response');
  }

  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      typeof result.isLegitimate !== 'boolean' || typeof result.credibilityScore !== 'number' ||
      !Number.isFinite(result.credibilityScore) || result.credibilityScore < 0 || result.credibilityScore > 100 ||
      !Array.isArray(result.spamIndicators) || result.spamIndicators.length > 50 ||
      result.spamIndicators.some((value: unknown) => typeof value !== 'string' || value.length > 1000) ||
      typeof result.contentAnalysis !== 'string' || result.contentAnalysis.length > 10000 ||
      typeof result.category !== 'string' || result.category.length > 100 ||
      !['low', 'medium', 'high'].includes(result.riskLevel)) {
    throw new Error('Shroud verification unavailable: invalid result schema');
  }

  logger.info(`✅ [SHROUD] Verification complete - Legitimate: ${result.isLegitimate}, Score: ${result.credibilityScore}`);

  const orgType =
    typeof result.organizationType === 'string' && isOrgType(result.organizationType)
      ? result.organizationType
      : 'unknown';
  const namedOrganization =
    typeof result.namedOrganization === 'string' && result.namedOrganization.trim() &&
    result.namedOrganization.trim().toLowerCase() !== 'null'
      ? result.namedOrganization.trim().slice(0, 300)
      : null;

  return {
    isLegitimate: result.isLegitimate,
    credibilityScore: result.credibilityScore,
    spamIndicators: result.spamIndicators,
    contentAnalysis: result.contentAnalysis,
    category: result.category,
    riskLevel: result.riskLevel,
    organizationType: orgType,
    namedOrganization,
  };
}

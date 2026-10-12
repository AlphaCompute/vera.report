jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => true),
}));

import { verifyReport } from '../../../src/services/reportScoring';
import { shroudChat } from '../../../src/services/shroudClient';

const mockedShroudChat = shroudChat as jest.MockedFunction<typeof shroudChat>;

const report = {
  description: 'A detailed, specific account of misconduct.',
  evidenceType: 'fraud',
  hasEvidence: true,
};

describe('verifyReport', () => {
  afterEach(() => {
    mockedShroudChat.mockReset();
  });

  it('returns a VerificationResult with all fields populated on a valid score', async () => {
    mockedShroudChat.mockResolvedValue(
      JSON.stringify({
        isLegitimate: true,
        credibilityScore: 85,
        spamIndicators: [],
        contentAnalysis: 'Consistent and specific.',
        category: 'fraud',
        riskLevel: 'high',
        organizationType: 'for-profit',
        namedOrganization: 'Acme Corp',
      }),
    );

    const result = await verifyReport(report);

    expect(result).toEqual({
      isLegitimate: true,
      credibilityScore: 85,
      spamIndicators: [],
      contentAnalysis: 'Consistent and specific.',
      category: 'fraud',
      riskLevel: 'high',
      organizationType: 'for-profit',
      namedOrganization: 'Acme Corp',
    });
    expect(typeof result.credibilityScore).toBe('number');
  });

  it('defaults organizationType to unknown and namedOrganization to null outside the taxonomy', async () => {
    mockedShroudChat.mockResolvedValue(
      JSON.stringify({
        isLegitimate: true,
        credibilityScore: 60,
        spamIndicators: [],
        contentAnalysis: 'Some analysis.',
        category: 'other',
        riskLevel: 'low',
        organizationType: 'not-a-real-type',
        namedOrganization: 'null',
      }),
    );

    const result = await verifyReport(report);

    expect(result.organizationType).toBe('unknown');
    expect(result.namedOrganization).toBeNull();
  });

  it('throws when shroudChat resolves unparseable output', async () => {
    mockedShroudChat.mockResolvedValue('not json at all');

    await expect(verifyReport(report)).rejects.toThrow();
  });

  it.each([{}, {isLegitimate:'true',credibilityScore:200}, null])('rejects malformed analysis instead of defaulting to legitimacy', async value => {
    mockedShroudChat.mockResolvedValue(JSON.stringify(value));
    await expect(verifyReport(report)).rejects.toThrow('invalid result schema');
  });
  it('does not expose private bytes from JSON parse errors', async () => {
    mockedShroudChat.mockResolvedValue('private-report-canary');
    await expect(verifyReport(report)).rejects.not.toThrow('private-report-canary');
  });
  it('propagates rejection when shroudChat rejects', async () => {
    mockedShroudChat.mockRejectedValue(new Error('unverified attestation'));

    await expect(verifyReport(report)).rejects.toThrow('unverified attestation');
  });
});

import { test, expect } from '@playwright/test';

const trackingId = 'VRA-1234567890ABCDEF';
const verifiedProof = {
    proofHash: 'synthetic-proof',
    verified: true,
    proofType: 'compact_circuit',
    txHash: 'synthetic-transaction',
    contractAddress: 'synthetic-contract',
};

// Existing legacy receipts remain readable; new submissions use confidential recovery.
test('status automatically refreshes pending, failed and verified proofs without another search', async ({ page }) => {
    let proofStatus = 'pending';
    let failNextLookup = false;
    let followUp = 'Initial follow-up question';
    let zkProof: typeof verifiedProof | null = null;
    await page.route('**/api/whistleblower/status/**', (route) => {
        if (failNextLookup) {
            failNextLookup = false;
            return route.fulfill({ status: 503, json: { success: false } });
        }
        return route.fulfill({
            json: {
                success: true,
                trackingId,
                status: 'received',
                relay: [{ direction: 'to-reporter', body: followUp, at: '2026-09-15T00:00:00.000Z' }],
                proofStatus,
                zkProof,
                createdAt: '2026-09-15T00:00:00.000Z',
                category: 'cyber-security',
            },
        });
    });

    await page.goto('/status');
    const input = page.getByRole('textbox', { name: 'Recovery code', exact: true });
    await input.fill(trackingId);
    await input.press('Enter');
    const proofStatusRow = page.getByText('Proof status:', { exact: true }).locator('..');
    await expect(proofStatusRow.getByText('Pending', { exact: true })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'Its blockchain proof is still pending' })).toBeVisible();

    proofStatus = 'failed';
    failNextLookup = true;
    await expect(
        page.getByRole('status').filter({ hasText: 'saved report remains available for review' }),
    ).toBeVisible();
    await expect(page.getByText(trackingId, { exact: true })).toBeVisible();
    await expect(proofStatusRow.getByText('Failed', { exact: true })).toBeVisible();
    await expect(proofStatusRow.getByText('Pending', { exact: true })).toHaveCount(0);

    proofStatus = 'attached';
    followUp = 'Updated follow-up question';
    zkProof = verifiedProof;
    await expect(proofStatusRow.getByText('Verified', { exact: true })).toBeVisible();
    await expect(
        page.getByRole('status').filter({ hasText: 'verified blockchain transaction reference is recorded' }),
    ).toBeVisible();

    zkProof = { ...verifiedProof, proofType: 'hash_commitment' };
    await expect(proofStatusRow.getByText('Not verified', { exact: true })).toBeVisible();
    await expect(proofStatusRow.getByText('Verified', { exact: true })).toHaveCount(0);
});

test('status polling follows the searched report, preserves the view on errors, and stops on navigation', async ({ page }) => {
    const otherId = 'VRA-ABCDEF1234567890';
    const credentials: string[] = [];
    let fail = false;
    await page.route('**/api/whistleblower/status/access', (route) => {
        const credential = route.request().headers()['x-reporter-credential'];
        credentials.push(credential);
        if (fail) return route.fulfill({ status: 503, json: { success: false } });
        return route.fulfill({ json: {
            success: true, trackingId: credential, status: 'received', proofStatus: 'pending',
        } });
    });
    await page.goto('/status');
    const input = page.getByRole('textbox', { name: 'Recovery code', exact: true });
    await input.fill(trackingId);
    await input.press('Enter');
    await expect(page.getByText(trackingId, { exact: true })).toBeVisible();
    // Editing the search box must not change the credential used by polling.
    await input.fill(otherId);
    fail = true;
    await expect.poll(() => credentials.length).toBeGreaterThanOrEqual(2);
    expect(credentials.every((id) => id === trackingId)).toBe(true);
    await expect(page.getByText(trackingId, { exact: true })).toBeVisible();
    fail = false;
    await input.press('Enter');
    await expect(page.getByText(otherId, { exact: true })).toBeVisible();
    const searches = credentials.length;
    await expect.poll(() => credentials.length).toBeGreaterThan(searches);
    expect(credentials.slice(searches).every((id) => id === otherId)).toBe(true);
    await page.goto('/');
    const stoppedAt = credentials.length;
    await page.waitForTimeout(5500);
    expect(credentials).toHaveLength(stoppedAt);
});

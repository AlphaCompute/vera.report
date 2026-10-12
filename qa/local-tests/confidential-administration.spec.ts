import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import type { Download } from '@playwright/test';
import { KEY_CEREMONY_COPY as copy } from '../../components/vera/confidential/legalKeyCopy';

// Real browser crypto and rendered controls, with synthetic keys only. This
// does not simulate a successful Auth0 login or attest deployed hardware.
test('private key creation, wrong-code rejection and rotation stay on this device', async ({ page }) => {
  const downloads: Download[] = [];
  const sentBodies: string[] = [];
  const apiRequests: string[] = [];
  page.on('download', download => downloads.push(download));
  page.on('request', request => {
    if (request.postData()) sentBodies.push(request.postData()!);
    if (new URL(request.url()).pathname.startsWith('/api/')) apiRequests.push(request.url());
  });
  await page.goto('/legal/keys');
  await expect(page.getByRole('heading', { name: copy.title })).toBeVisible();
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute('content', 'noindex, nofollow');
  const referrerPolicies = await page.locator('meta[name="referrer"]').evaluateAll(nodes => nodes.map(node => node.getAttribute('content')));
  expect(referrerPolicies.length).toBeGreaterThan(0);
  expect(referrerPolicies.every(policy => policy === 'no-referrer')).toBe(true);
  const originalCode = 'synthetic-local-key-recovery-2026';
  const rotatedCode = 'synthetic-rotated-key-recovery-2026';
  await page.getByLabel(copy.organizationId, { exact: true }).fill('b'.repeat(64));
  await page.getByLabel(copy.organizationDomain, { exact: true }).fill('counsel.example');
  await page.getByLabel(copy.outputRecoveryCode, { exact: true }).fill(originalCode);
  await page.getByRole('button', { name: copy.submit }).click();
  await expect(page.getByRole('status')).toHaveText(copy.prepared);
  await expect.poll(() => downloads.length).toBe(2);
  const original = downloads.find(item => item.suggestedFilename().endsWith('-PRIVATE.txt'))!;
  const originalText = await readFile((await original.path())!, 'utf8');
  const originalEnvelope = JSON.parse(originalText.split('\n').find(line => line.startsWith('{"format":'))!);
  expect(originalEnvelope.format).toBe('vera-firm-key-export/v1');
  expect(originalEnvelope.ciphertext.length).toBeGreaterThan(100);
  expect(originalText).not.toContain('BEGIN PGP PRIVATE KEY');
  expect(originalText).not.toContain(originalCode);
  await expect(page.getByLabel(copy.outputRecoveryCode, { exact: true })).toHaveValue('');

  await page.getByRole('combobox', { name: copy.actionLabel }).selectOption({ label: copy.modes.rotate });
  await page.getByLabel(copy.organizationKeyFile, { exact: true }).setInputFiles({
    name: original.suggestedFilename(), mimeType: 'text/plain', buffer: Buffer.from(originalText),
  });
  await page.getByLabel(copy.keyRecoveryCode, { exact: true }).fill('synthetic-wrong-recovery-code');
  // Key version detail sits behind the advanced section.
  await page.getByText(copy.advancedSummary, { exact: true }).click();
  await page.getByLabel(copy.currentKeyVersion, { exact: true }).fill('1');
  await page.getByLabel(copy.removedMembers, { exact: true }).fill('c'.repeat(64));
  await page.getByLabel(copy.outputRecoveryCode, { exact: true }).fill(rotatedCode);
  await page.getByRole('button', { name: copy.submit }).click();
  await expect(page.locator('main').getByRole('alert')).toHaveText(copy.failed);
  expect(downloads).toHaveLength(2);

  await page.getByLabel(copy.keyRecoveryCode, { exact: true }).fill(originalCode);
  await page.getByRole('button', { name: copy.submit }).click();
  await expect(page.getByRole('status')).toHaveText(copy.rotated);
  // Private key, public key and continuity statement for the new epoch; nothing to publish on a website.
  await expect.poll(() => downloads.slice(2).map(item => item.suggestedFilename()).sort()).toEqual([
    'vera-key-continuity.json', 'vera-organization-epoch-2-PRIVATE.txt', 'vera-organization-epoch-2-public.asc',
  ]);
  expect(downloads.map(item => item.suggestedFilename())).not.toContain('vera-legal-key.json');
  const rotated = downloads.find(item => item.suggestedFilename() === 'vera-organization-epoch-2-PRIVATE.txt')!;
  const rotatedText = await readFile((await rotated.path())!, 'utf8');
  const rotatedEnvelope = JSON.parse(rotatedText.split('\n').find(line => line.startsWith('{"format":'))!);
  expect(rotatedEnvelope.recipientKeyId).not.toBe(originalEnvelope.recipientKeyId);
  expect(rotatedText).not.toContain('BEGIN PGP PRIVATE KEY');
  const continuity = downloads.find(item => item.suggestedFilename() === 'vera-key-continuity.json')!;
  const document = JSON.parse(await readFile((await continuity.path())!, 'utf8'));
  expect(document.statement).toMatchObject({ ownerApproval: 'required', keyEpoch: 2,
    previousRecipientKeyId: originalEnvelope.recipientKeyId, nextRecipientKeyId: rotatedEnvelope.recipientKeyId,
    removedMemberIds: ['c'.repeat(64)] });
  expect(apiRequests).toEqual([]);
  expect(sentBodies.join('\n')).not.toContain(originalCode);
  expect(sentBodies.join('\n')).not.toContain(rotatedCode);
});

test('participant lock clears key administration and onboarding tabs', async ({ page, context }) => {
  await page.goto('/legal/keys');
  await page.getByLabel(copy.outputRecoveryCode, { exact: true }).fill('synthetic-unsubmitted-recovery-secret');
  const onboarding = await context.newPage();
  await onboarding.goto('/legal/administration');
  await expect(onboarding.getByRole('heading', { name: 'Legal onboarding' })).toBeVisible();
  await page.evaluate(() => {
    window.dispatchEvent(new Event('vera-participant-lock'));
    const channel = new BroadcastChannel('vera-participant-device/v1');
    channel.postMessage('lock'); channel.close();
  });
  await expect(page).toHaveURL(/\/legal$/);
  await expect(onboarding).toHaveURL(/\/legal$/);
  await expect(page.getByLabel(copy.outputRecoveryCode, { exact: true })).toHaveCount(0);
  await onboarding.close();
});

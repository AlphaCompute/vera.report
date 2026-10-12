import { readFileSync } from 'node:fs';
import path from 'node:path';
import { webcrypto } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { encodeRecoveryCodeV2, recoveryCodeGroups } from '../../../enclave/src/confidential/recoveryCode';
import {
  copyRecoveryCode, RecoveryLeaveBody, RECOVERY_LEAVE_DESCRIPTION, RECOVERY_LEAVE_TITLE,
} from '../../../components/vera/confidential/RecoveryLeaveDialog';

const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, '\'').replace(/\s+/g, ' ');
const noop = () => {};

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

async function sampleCode() { return encodeRecoveryCodeV2(new Uint8Array(32).fill(7)); }

describe('leave-page warning after a confidential submit', () => {
  test('asks for the recovery code, shows it grouped and never mentions a Report ID', async () => {
    const code = await sampleCode();
    const html = renderToStaticMarkup(createElement(RecoveryLeaveBody, {
      recoveryCode: code, clipboard: 'idle', copyError: false, onCopy: noop, onStay: noop, onLeave: noop,
    }));
    const body = text(html);
    for (const group of recoveryCodeGroups(code)) expect(body).toContain(group);
    expect(body).toContain('Copy recovery code');
    expect(body).toContain('I saved my recovery code, leave');
    expect(`${RECOVERY_LEAVE_TITLE} ${RECOVERY_LEAVE_DESCRIPTION} ${body}`).not.toMatch(/report id|copy id|leave without copying/i);
    expect(RECOVERY_LEAVE_TITLE).toBe('Save your recovery code before leaving');
  });

  test('a copy shows the one-minute clipboard clear notice', async () => {
    const html = renderToStaticMarkup(createElement(RecoveryLeaveBody, {
      recoveryCode: await sampleCode(), clipboard: 'copied', copyError: false, onCopy: noop, onStay: noop, onLeave: noop,
    }));
    expect(text(html)).toMatch(/clear your clipboard in 1 minute/);
  });

  test('copies through the auto-clearing clipboard guard', async () => {
    const code = await sampleCode();
    const copy = jest.fn(async () => true);
    await expect(copyRecoveryCode({ copy }, code.toLowerCase().replace(/-/g, ''))).resolves.toBe(true);
    expect(copy).toHaveBeenCalledWith(code);
    await expect(copyRecoveryCode(null, code)).resolves.toBe(false);
  });

  test('the report page uses it on the confidential path and never writes the code with a plain copy', () => {
    expect(report).toContain('<RecoveryLeaveDialog open={receiptGuard.open} recoveryCode={confidentialReceipt.recoveryCode}');
    expect(report).not.toMatch(/copyText\(\s*confidentialReceipt/);
    expect(report).toMatch(/confidentialReceipt \? \(\s*<RecoveryLeaveDialog/);
  });
});

describe('confidential receipt screen', () => {
  const start = report.indexOf('key="confidential-submitted-view"');
  const view = report.slice(start, report.indexOf('</motion.div>', report.indexOf('Go to the status page', start)));

  test('links to the status page and home', () => {
    expect(start).toBeGreaterThan(0);
    expect(view).toMatch(/<Link\s+href="\/status"[\s\S]*Go to the status page/);
    expect(view).toMatch(/<Link\s+href="\/"[\s\S]*Back to home/);
  });

  test('opens at the top and moves focus to its heading', () => {
    expect(view).toMatch(/onAnimationStart=\{\(\) => \{[\s\S]*scrollRef\.current\.scrollTop = 0[\s\S]*confidentialHeadingRef\.current\?\.focus/);
    expect(view).toMatch(/<h2 ref=\{confidentialHeadingRef\} tabIndex=\{-1\}/);
  });
});

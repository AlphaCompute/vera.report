import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  ACTION_STAGE_TEXT, FIRM_STAGE_TEXT, FirmLoadProgress, LOAD_STAGE_TEXT, LoadProgress, firmProgressSteps, progressSteps,
} from '../../../components/vera/confidential/LoadProgress';
import type { LoadStage } from '../../../components/vera/confidential/LoadProgress';

const render = (stage: LoadStage) => renderToStaticMarkup(React.createElement(LoadProgress, { stage, className: 'panel' }));

describe('confidential report load progress', () => {
  test('announces the current stage politely and marks earlier steps done', () => {
    const html = render('opening');
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('<p class="mb-3">Opening your encrypted report on this device…</p>');
    expect(progressSteps('opening')).toEqual([
      { step: 'verifying', state: 'done' }, { step: 'opening', state: 'current' }, { step: 'checking', state: 'pending' }]);
    expect(html).toContain('aria-current="step"');
    expect(html).toContain('(in progress)');
  });

  test('"Unlocking" appears only while the report is actually being unlocked', () => {
    expect(render('verifying')).not.toContain('Unlocking');
    expect(render('checking')).not.toContain('Unlocking');
    expect(progressSteps('unlocking').map(item => [item.step, item.state])).toEqual([
      ['verifying', 'done'], ['unlocking', 'current'], ['opening', 'pending'], ['checking', 'pending']]);
    expect(render('unlocking')).toContain('<p class="mb-3">Unlocking your report…</p>');
  });

  test('a legal organization sees the same staged progress while a report opens', () => {
    const html = renderToStaticMarkup(React.createElement(FirmLoadProgress, { stage: 'loading', className: 'panel' }));
    expect(html).toContain('role="status"');
    expect(html).toContain('<p class="mb-3">Loading and decrypting the report…</p>');
    expect(html).not.toContain('Unlocking');
    expect(firmProgressSteps('unlocking')).toEqual([
      { step: 'verifying', state: 'done' }, { step: 'unlocking', state: 'current' }, { step: 'loading', state: 'pending' }]);
    expect(firmProgressSteps('verifying')).toEqual([{ step: 'verifying', state: 'current' }, { step: 'loading', state: 'pending' }]);
  });

  test('copy uses the site terms and never names internals', () => {
    const copy = [...Object.values(LOAD_STAGE_TEXT), ...Object.values(FIRM_STAGE_TEXT), ...Object.values(ACTION_STAGE_TEXT)].join(' ');
    expect(copy).toContain('your report');
    for (const word of [/\bcase\b/i, /\bowner\b/i, /\bgrant\b/i, /enclave/i, /attest/i, /session/i, /challenge/i]) {
      expect(copy).not.toMatch(word);
    }
  });
});

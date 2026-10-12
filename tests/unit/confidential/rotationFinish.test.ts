import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { RotationFinish, WORKSPACE_NOT_UPDATED, finishRotation } from '../../../components/vera/confidential/RotationFinish';

/** The last step of an organization key replacement on /legal/members. */
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/\s+/g, ' ');
const noop = () => undefined;
const render = (error: string | null) => renderToStaticMarkup(React.createElement(RotationFinish,
  { savedWorkspace: true, sent: true, busy: false, error, onFinish: noop, onDownloadKey: noop, onLockAnyway: noop }));

describe('finishing a key replacement', () => {
  test('locks after the saved workspace switches to the new key', async () => {
    const order: string[] = [];
    const result = await finishRotation(async () => { order.push('saved'); return true; }, () => order.push('locked'));
    expect(result).toBeNull();
    expect(order).toEqual(['saved', 'locked']);
  });

  test('a failed workspace update stays unlocked and says so instead of failing silently', async () => {
    const lock = jest.fn();
    const result = await finishRotation(async () => { throw new Error('quota exceeded: secret detail'); }, lock);
    expect(lock).not.toHaveBeenCalled();
    expect(result).toBe(WORKSPACE_NOT_UPDATED);
    expect(result).not.toContain('secret detail');
  });

  test('the checklist shows the failure next to Finish with the key file and Lock anyway', () => {
    const html = render(WORKSPACE_NOT_UPDATED);
    expect(html).toContain('role="alert"');
    expect(text(html)).toContain("This device's saved workspace could not be updated and still holds the old key.");
    expect(text(html)).toContain('Download the key file');
    expect(text(html)).toContain('Lock anyway');
    expect(text(html)).toContain('Try again');
  });

  test('without a failure there is no alert and the button reads Finish and lock', () => {
    const html = render(null);
    expect(html).not.toContain('role="alert"');
    expect(text(html)).toContain('Finish and lock');
    expect(text(html)).not.toContain('Lock anyway');
  });
});

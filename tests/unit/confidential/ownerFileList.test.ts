import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ownerFileListReducer, type OwnerFileListState } from '../../../lib/confidential/ownerFileList';
import { OwnerFileList } from '../../../components/vera/confidential/OwnerFiles';

type File = { objectId: string; name?: string; size?: number; original: boolean; chunked: boolean };
const files: File[] = [
  { objectId: 'obj-video', name: 'video.mp4', size: 900_000_000, original: true, chunked: true },
  { objectId: 'obj-notes', name: 'notes.pdf', size: 2_000, original: false, chunked: false },
];
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const render = (state: OwnerFileListState<File>) => renderToStaticMarkup(createElement(OwnerFileList<File>, {
  state, panel: '', onRetry: () => undefined,
  renderDownload: (file: File) => createElement('button', { 'data-download': file.objectId }, 'Download'),
}));

describe('owner file list refresh', () => {
  test('a refresh keeps the ready list (and its download rows) instead of going back to loading', () => {
    const ready = ownerFileListReducer<File>({ kind: 'loading' }, { type: 'loaded', files });
    const refreshing = ownerFileListReducer(ready, { type: 'start' });
    expect(refreshing).toEqual({ kind: 'ready', files, refreshing: true, refreshFailed: false });
    const html = render(refreshing);
    expect(text(html)).not.toContain('Decrypting the file list');
    expect(html).toContain('data-download="obj-video"');
    expect(html).toContain('data-download="obj-notes"');
    expect(html).toContain('aria-busy="true"');
  });

  test('a failed refresh keeps the list and says it may be out of date', () => {
    const ready = ownerFileListReducer<File>({ kind: 'loading' }, { type: 'loaded', files });
    const failed = ownerFileListReducer(ownerFileListReducer(ready, { type: 'start' }), { type: 'failed' });
    expect(failed).toEqual({ kind: 'ready', files, refreshing: false, refreshFailed: true });
    const html = render(failed);
    expect(html).toContain('data-download="obj-video"');
    expect(text(html)).toContain('This list could not be updated');
    // The next attempt clears the notice but still keeps the rows.
    expect(ownerFileListReducer(failed, { type: 'start' })).toEqual({ kind: 'ready', files, refreshing: true, refreshFailed: false });
  });

  test('only the first listing shows loading or a blocking error', () => {
    const loading = ownerFileListReducer<File>({ kind: 'error' }, { type: 'start' });
    expect(loading).toEqual({ kind: 'loading' });
    expect(text(render(loading))).toContain('Decrypting the file list on this device');
    const error = ownerFileListReducer<File>(loading, { type: 'failed' });
    expect(error).toEqual({ kind: 'error' });
    expect(text(render(error))).toContain('Your files could not be listed');
  });

  test('the component re-lists by signed state, drops stale results and keys rows by objectId', () => {
    const source = readFileSync(join(__dirname, '../../../components/vera/confidential/OwnerFiles.tsx'), 'utf8');
    expect(source).toContain('[session, inbox.checkpointDigest]');
    expect(source).not.toMatch(/\[session, inbox\]/);
    expect(source).toMatch(/run === sequence\.current\) dispatch\(\{ type: "loaded"/);
    expect(source).toContain('key={file.objectId}');
    const status = readFileSync(join(__dirname, '../../../components/vera/confidential/ConfidentialCaseStatus.tsx'), 'utf8');
    expect(status).not.toContain('setState({ kind: "loading" })');
    expect(status).toContain('<OwnerFiles session={session.current} inbox={inbox} panel={panel} />');
  });
});

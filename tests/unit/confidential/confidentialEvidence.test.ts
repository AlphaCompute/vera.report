import {
  CONFIDENTIAL_EVIDENCE_LIMIT_TEXT, CONFIDENTIAL_EVIDENCE_TOTAL_LIMIT, CONFIDENTIAL_MAX_FILES,
  checkConfidentialSelection, confidentialFileError, confidentialSelectionError, formatBytes, percent, progressText,
} from '../../../lib/confidential/evidence';
import { CONFIDENTIAL_EVIDENCE_LIMIT, CONFIDENTIAL_EVIDENCE_UPLOAD_LIMIT } from '../../../lib/confidential/config';
import {
  CONFIDENTIAL_FILE_LIMIT, CONFIDENTIAL_MAX_FILES as SUBMISSION_MAX_FILES, CONFIDENTIAL_UPLOAD_LIMIT,
} from '../../../enclave/src/confidential/ownerSubmission';

const MB = 1_000_000, MiB = 1024 * 1024;

test('stated limits match, and are never more generous than, what the encrypted format accepts', () => {
  expect(CONFIDENTIAL_EVIDENCE_LIMIT).toBe(CONFIDENTIAL_FILE_LIMIT);
  expect(CONFIDENTIAL_EVIDENCE_UPLOAD_LIMIT).toBe(CONFIDENTIAL_UPLOAD_LIMIT);
  expect(CONFIDENTIAL_EVIDENCE_TOTAL_LIMIT).toBe(CONFIDENTIAL_UPLOAD_LIMIT);
  expect(CONFIDENTIAL_EVIDENCE_LIMIT).toBe(256 * MiB);
  // "256 MB" (decimal) is below 256 MiB.
  expect(256 * MB).toBeLessThanOrEqual(CONFIDENTIAL_EVIDENCE_LIMIT);
  expect(CONFIDENTIAL_MAX_FILES).toBeLessThanOrEqual(SUBMISSION_MAX_FILES);
  expect(CONFIDENTIAL_EVIDENCE_LIMIT_TEXT).toContain(`${CONFIDENTIAL_MAX_FILES} files`);
  expect(CONFIDENTIAL_EVIDENCE_LIMIT_TEXT).toContain('256 MB');
});

test('each file is checked for type, emptiness and size', () => {
  expect(confidentialFileError({ name: 'a.pdf', type: 'application/pdf', size: 200 * MB })).toBeNull();
  expect(confidentialFileError({ name: 'a.mkv', type: '', size: 1 })).toBeNull();
  expect(confidentialFileError({ name: 'a.mp4', type: 'video/mp4', size: CONFIDENTIAL_EVIDENCE_LIMIT })).toBeNull();
  expect(confidentialFileError({ name: 'a.mp4', type: 'video/mp4', size: CONFIDENTIAL_EVIDENCE_LIMIT + 1 })).toMatch(/256 MB/);
  expect(confidentialFileError({ name: 'a.pdf', type: 'application/pdf', size: 0 })).toMatch(/empty/);
  expect(confidentialFileError({ name: 'a.exe', type: 'application/x-msdownload', size: 1 })).toMatch(/not supported/);
});

test('the selection is bounded by count and total size', () => {
  expect(confidentialSelectionError(Array.from({ length: CONFIDENTIAL_MAX_FILES }, () => ({ size: MB })))).toBeNull();
  expect(confidentialSelectionError(Array.from({ length: CONFIDENTIAL_MAX_FILES + 1 }, () => ({ size: 1 })))).toMatch(/up to 10/);
  expect(confidentialSelectionError([{ size: 200 * MiB }, { size: 57 * MiB }])).toMatch(/total 256 MB/);
  expect(confidentialSelectionError([{ size: 200 * MiB }, { size: 56 * MiB }])).toBeNull();
});

test('a new selection keeps valid files and reports each problem', () => {
  const file = (name: string, type: string, size: number) => ({ name, type, size }) as File;
  const result = checkConfidentialSelection([], [file('ok.pdf', 'application/pdf', 10), file('bad.exe', 'application/x-msdownload', 1)]);
  expect(result.accepted.map(item => item.name)).toEqual(['ok.pdf']);
  expect(result.problems).toEqual([expect.stringContaining('bad.exe: ')]);
  const over = checkConfidentialSelection([{ size: 200 * MiB }], [file('big.mp4', 'video/mp4', 100 * MiB)]);
  expect(over.accepted).toEqual([]);
  expect(over.problems.join(' ')).toMatch(/total 256 MB/);
});

test('progress text is plain and bounded', () => {
  expect(formatBytes(512)).toBe('512 B');
  expect(formatBytes(1536)).toBe('2 KB');
  expect(formatBytes(5 * MiB)).toBe('5.0 MB');
  expect(formatBytes(256 * MiB)).toBe('256 MB');
  expect(percent({ bytesDone: 5, bytesTotal: 0 })).toBe(0);
  expect(percent({ bytesDone: 11, bytesTotal: 10 })).toBe(100);
  expect(progressText('Uploading encrypted files', { bytesDone: 64 * MiB, bytesTotal: 256 * MiB }))
    .toBe('Uploading encrypted files: 25% (64 MB of 256 MB)');
});

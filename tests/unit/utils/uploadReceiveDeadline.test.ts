import {
  MAX_MEDIA_BYTES,
  UPLOAD_MIN_BYTES_PER_SEC,
  UPLOAD_PROGRESS_GRACE_MS,
  UPLOAD_RECEIVE_MAX_MS,
  UPLOAD_RECEIVE_MIN_MS,
  uploadBehindReceivePace,
  uploadReceiveDeadlineMs,
} from '../../../src/utils/evidenceLimits';

describe('uploadReceiveDeadlineMs', () => {
  it('clamps tiny bodies to the minimum window', () => {
    expect(uploadReceiveDeadlineMs(1)).toBe(UPLOAD_RECEIVE_MIN_MS);
    expect(uploadReceiveDeadlineMs(UPLOAD_MIN_BYTES_PER_SEC * 30)).toBe(UPLOAD_RECEIVE_MIN_MS);
  });

  it('scales mid-size bodies with the receive-rate floor', () => {
    const bytes = UPLOAD_MIN_BYTES_PER_SEC * 90;
    expect(uploadReceiveDeadlineMs(bytes)).toBe(90_000);
  });

  it('caps max-size media at five minutes', () => {
    expect(uploadReceiveDeadlineMs(MAX_MEDIA_BYTES)).toBe(UPLOAD_RECEIVE_MAX_MS);
  });

  it('defaults missing or invalid lengths to the five-minute cap', () => {
    expect(uploadReceiveDeadlineMs(Number.NaN)).toBe(UPLOAD_RECEIVE_MAX_MS);
    expect(uploadReceiveDeadlineMs(-1)).toBe(UPLOAD_RECEIVE_MAX_MS);
    expect(uploadReceiveDeadlineMs(0)).toBe(UPLOAD_RECEIVE_MAX_MS);
  });
});

describe('uploadBehindReceivePace', () => {
  const contentLength = 16 * 1024 * 1024;
  const deadlineMs = uploadReceiveDeadlineMs(contentLength);

  it('does not flag during the progress grace window', () => {
    expect(uploadBehindReceivePace(0, contentLength, UPLOAD_PROGRESS_GRACE_MS - 1, deadlineMs)).toBe(false);
  });

  it('does not flag when received bytes match the linear schedule', () => {
    const elapsedMs = UPLOAD_PROGRESS_GRACE_MS;
    const onPace = contentLength * (elapsedMs / deadlineMs);
    expect(uploadBehindReceivePace(onPace, contentLength, elapsedMs, deadlineMs)).toBe(false);
  });

  it('flags when received bytes fall behind the linear schedule after grace', () => {
    const elapsedMs = UPLOAD_PROGRESS_GRACE_MS;
    const expected = contentLength * (elapsedMs / deadlineMs);
    expect(uploadBehindReceivePace(expected - 1, contentLength, elapsedMs, deadlineMs)).toBe(true);
  });

  it('ignores invalid content length or deadline', () => {
    expect(uploadBehindReceivePace(0, 0, UPLOAD_PROGRESS_GRACE_MS, deadlineMs)).toBe(false);
    expect(uploadBehindReceivePace(0, Number.NaN, UPLOAD_PROGRESS_GRACE_MS, deadlineMs)).toBe(false);
    expect(uploadBehindReceivePace(0, contentLength, UPLOAD_PROGRESS_GRACE_MS, 0)).toBe(false);
  });
});

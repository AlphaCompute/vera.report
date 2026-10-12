import { retryBounded } from '../../../enclave/src/cases/startupRetry';

test('startup retry backs off exponentially, caps the delay and gives up', async () => {
  const delays: number[] = [];
  const attempt = jest.fn(async () => { throw new Error('manifest unavailable'); });
  await expect(retryBounded(attempt, { attempts: 6, initialDelayMs: 1000, maxDelayMs: 4000, sleep: async ms => { delays.push(ms); } }))
    .rejects.toThrow('manifest unavailable');
  expect(attempt).toHaveBeenCalledTimes(6);
  expect(delays).toEqual([1000, 2000, 4000, 4000, 4000]);
});

test('startup retry returns the first success', async () => {
  let calls = 0;
  const sleep = jest.fn(async () => undefined);
  await expect(retryBounded(async () => { calls += 1; if (calls < 3) throw new Error(); return 'ok'; }, { sleep })).resolves.toBe('ok');
  expect(sleep).toHaveBeenCalledTimes(2);
});

test('the default bound is finite', async () => {
  const sleep = jest.fn(async () => undefined);
  await expect(retryBounded(async () => { throw new Error('x'); }, { sleep })).rejects.toThrow('x');
  expect(sleep).toHaveBeenCalledTimes(7);
  await expect(retryBounded(async () => 1, { attempts: 0 })).rejects.toThrow('Invalid retry bound');
});

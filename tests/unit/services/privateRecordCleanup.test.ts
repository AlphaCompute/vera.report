import crypto from 'node:crypto';
import { keyEnvelope } from '../../../src/services/keyEnvelope';
import { openPrivateValue } from '../../../src/services/privateRecord';

afterEach(() => jest.restoreAllMocks());

it.each(['success', 'bad-tag', 'invalid-json'])('clears owned private-record buffers after %s', async outcome => {
  const sourceKey = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sourceKey, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(['record', 'verification'])));
  const content = outcome === 'invalid-json' ? '{invalid' : '{"synthetic":true}';
  const data = Buffer.concat([cipher.update(content, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (outcome === 'bad-tag') tag[0] ^= 1;
  const stored = 'private:v1:' + JSON.stringify({ key: 'enc:local:v1:synthetic',
    iv: iv.toString('base64'), tag: tag.toString('base64'), data: data.toString('base64') });
  const originalKey = Buffer.from(sourceKey);
  jest.spyOn(keyEnvelope, 'unwrap').mockResolvedValue(sourceKey.toString('hex'));
  const create = crypto.createDecipheriv.bind(crypto);
  const owned: Buffer[] = [];
  jest.spyOn(crypto, 'createDecipheriv').mockImplementation(((...args: Parameters<typeof crypto.createDecipheriv>) => {
    const decipher = create(...args);
    if (Buffer.isBuffer(args[1])) owned.push(args[1]);
    const update = decipher.update.bind(decipher);
    jest.spyOn(decipher, 'update').mockImplementation(((...input: Parameters<typeof decipher.update>) => {
      const result = update(...input);
      if (Buffer.isBuffer(result)) owned.push(result);
      return result;
    }) as typeof decipher.update);
    return decipher;
  }) as typeof crypto.createDecipheriv);
  const read = openPrivateValue(stored, 'record', 'verification');
  if (outcome === 'success') await expect(read).resolves.toEqual({ synthetic: true });
  else await expect(read).rejects.toThrow();
  expect(owned.length).toBeGreaterThanOrEqual(2);
  expect(owned.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
  expect(sourceKey).toEqual(originalKey);
});

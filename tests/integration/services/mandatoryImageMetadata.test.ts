import sharp from 'sharp';
import EvidenceEncryptionService from '../../../src/services/evidenceEncryption';


it.each(['jpeg', 'png', 'webp'] as const)('cannot retain identifying %s metadata using legacy selections', async format => {
  const input = await sharp({ create: { width: 16, height: 16, channels: 3, background: 'red' } })
    .withExif({ IFD0: { Artist: 'identity-canary-camera-owner' } }).toFormat(format).toBuffer();
  expect((await sharp(input).metadata()).exif).toBeDefined();
  const output = await new EvidenceEncryptionService().stripFileMetadata(input, `image/${format}`, { artist: false, gps_location: false, unrelated_field: true });
  expect((await sharp(output).metadata()).exif).toBeUndefined();
  expect(output.toString('latin1')).not.toContain('identity-canary');
  expect(await sharp(output).raw().toBuffer()).toEqual(await sharp(input).raw().toBuffer());
});

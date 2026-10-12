import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import EvidenceEncryptionService from '../../../src/services/evidenceEncryption';


import { MEDIA_FORMATS } from '../../../src/utils/mediaFormats';
import { stripMediaMetadata } from '../../../src/services/mediaMetadata';
import { EvidenceValidationError } from '../../../src/utils/evidenceValidationError';

const cases = [
  ['audio/mpeg', 'mp3', 'libmp3lame'], ['audio/wav', 'wav', 'pcm_s16le'],
  ['audio/mp4', 'm4a', 'aac'], ['audio/aac', 'aac', 'aac'],
  ['audio/ogg', 'ogg', 'libvorbis'], ['audio/opus', 'opus', 'libopus'],
  ['audio/flac', 'flac', 'flac'], ['audio/webm', 'webm', 'libopus'],
  ['video/webm', 'webm', 'libvpx'], ['video/x-matroska', 'mkv', 'mpeg4'],
  ['video/x-msvideo', 'avi', 'mpeg4'], ['video/ogg', 'ogv', 'libtheora'],
  ['video/mp4', 'mp4', 'mpeg4'], ['video/quicktime', 'mov', 'mpeg4'],
];
// Local ffmpeg builds (e.g. Homebrew) may lack some encoders used only to create
// fixtures. CI must have all of them; locally, missing fixture encoders are skipped.
const encoders = execFileSync('ffmpeg', ['-hide_banner', '-encoders'], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
const requireAllEncoders = !!process.env.CI && !['false', '0'].includes(process.env.CI.toLowerCase());
const ffprobe = (file: string) => JSON.parse(execFileSync('ffprobe', ['-v', 'error', '-show_format', '-show_chapters', '-show_streams', '-show_packets', '-show_data_hash', 'sha256', '-of', 'json', file], { encoding: 'utf8', maxBuffer: 1024 * 1024 }));

describe('real media sanitization', () => {
  describe.each(cases)('encoded %s packets', (mime, extension, codec) => {
    const fixtureTest = requireAllEncoders || new RegExp(`\\s${codec}\\s`).test(encoders) ? it : it.skip;
    fixtureTest('removes identifying metadata while preserving encoded packets', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'vera-media-fixture-'));
      try {
        const original = path.join(dir, `original.${extension}`);
        const clean = path.join(dir, `clean.${extension}`);
        const video = mime.startsWith('video/');
        execFileSync('ffmpeg', ['-v', 'error', '-y', '-f', 'lavfi', '-i', video ? 'color=c=black:s=32x32:r=5' : 'sine=frequency=440:sample_rate=44100', '-t', '0.4', video ? '-c:v' : '-c:a', codec,
          '-metadata', 'title=identity-test', '-metadata', 'artist=identity-test', '-metadata', 'comment=identity-test', '-metadata', 'location=+40.0000-070.0000/', '-metadata', 'creation_time=2001-01-01T00:00:00Z', original], { timeout: 15000 });
        const before = ffprobe(original);
        if (extension !== 'aac') expect(JSON.stringify({ tags: before.format.tags, streams: before.streams })).toContain('identity-test');
        await writeFile(clean, await new EvidenceEncryptionService().stripFileMetadata(await readFile(original), mime, { gps: false }));
        const after = ffprobe(clean);
        expect(JSON.stringify({ tags: after.format.tags, streams: after.streams.map((s: any) => s.tags) })).not.toContain('identity-test');
        expect(JSON.stringify(after)).not.toContain('+40.0000');
        expect(JSON.stringify(after)).not.toContain('2001-01-01');
        expect(after.packets.map((p: any) => p.data_hash)).toEqual(before.packets.map((p: any) => p.data_hash));
        // Decode the result too: a metadata-free but unplayable file is not success.
        execFileSync('ffmpeg', ['-v', 'error', '-i', clean, '-f', 'null', '-'], { timeout: 15000 });
      } finally { await rm(dir, { recursive: true, force: true }); }
    });
  });
  it('preserves both AV streams while dropping chapters, subtitles and attachments', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'vera-media-fixture-'));
    try {
      const original = path.join(dir, 'original.mkv');
      const clean = path.join(dir, 'clean.mkv');
      const subtitle = path.join(dir, 'subtitles.srt');
      const chapters = path.join(dir, 'chapters.txt');
      const attachment = path.join(dir, 'identity.txt');
      await writeFile(subtitle, '1\n00:00:00,000 --> 00:00:00,300\nidentity-test\n');
      await writeFile(chapters, ';FFMETADATA1\n[CHAPTER]\nTIMEBASE=1/1000\nSTART=0\nEND=300\ntitle=identity-test\n');
      await writeFile(attachment, 'identity-test');
      execFileSync('ffmpeg', ['-v', 'error', '-y', '-f', 'lavfi', '-i', 'color=c=black:s=32x32:r=5',
        '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=44100', '-i', subtitle, '-i', chapters,
        '-map', '0:v', '-map', '1:a', '-map', '2:s', '-map_chapters', '3', '-t', '0.4',
        '-c:v', 'mpeg4', '-c:a', 'aac', '-c:s', 'srt', '-attach', attachment,
        '-metadata:s:t', 'mimetype=text/plain', '-metadata:s:a', 'title=identity-test', original]);
      const before = ffprobe(original);
      expect(before.streams.map((s: any) => s.codec_type)).toEqual(['video', 'audio', 'subtitle', 'attachment']);
      await writeFile(clean, await stripMediaMetadata(await readFile(original), 'video/x-matroska'));
      const after = ffprobe(clean);
      expect(after.streams.map((s: any) => s.codec_type)).toEqual(['video', 'audio']);
      expect(JSON.stringify(after)).not.toContain('identity-test');
      expect(after.chapters).toEqual([]);
      for (const stream of [0, 1]) {
        expect(after.packets.filter((p: any) => p.stream_index === stream).map((p: any) => p.data_hash))
          .toEqual(before.packets.filter((p: any) => p.stream_index === stream).map((p: any) => p.data_hash));
      }
      execFileSync('ffmpeg', ['-v', 'error', '-i', clean, '-f', 'null', '-']);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  it.each(Object.keys(MEDIA_FORMATS))('rejects malformed %s without returning plaintext', async mime => {
    await expect(stripMediaMetadata(Buffer.from('not media identity-test'), mime)).rejects.toBeInstanceOf(EvidenceValidationError);
  });
  it('fails closed on a forged media type or playlist instead of passing through bytes', async () => {
    const playlist = Buffer.from('#EXTM3U\n#EXTINF:1,\nhttps://example.invalid/private.ts\n');
    await expect(stripMediaMetadata(playlist, 'video/mp4')).rejects.toBeInstanceOf(EvidenceValidationError);
    await expect(stripMediaMetadata(Buffer.from('not audio'), 'audio/mpeg')).rejects.toBeInstanceOf(EvidenceValidationError);
    await expect(stripMediaMetadata(Buffer.from('data'), 'audio/unknown')).rejects.toBeInstanceOf(EvidenceValidationError);
  });
});

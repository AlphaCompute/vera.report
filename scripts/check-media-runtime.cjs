#!/usr/bin/env node
// Synthetic inputs only. Run against the compiled sanitizer and production tools.
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtemp, readFile, writeFile, rm, readdir } = require('node:fs/promises');
const { join } = require('node:path');
const { performance } = require('node:perf_hooks');
const { stripMediaMetadata, mediaScratchRoot } = require('../dist/services/mediaMetadata');
const { EvidenceValidationError } = require('../dist/utils/evidenceValidationError');
const { MEDIA_FORMATS } = require('../dist/utils/mediaFormats');

const cases = [
  ['audio/mpeg', 'mp3', 'libmp3lame'], ['audio/wav', 'wav', 'pcm_s16le', 118],
  ['audio/mp4', 'm4a', 'aac'], ['audio/aac', 'aac', 'aac'],
  ['audio/ogg', 'ogg', 'libvorbis'], ['audio/opus', 'opus', 'libopus'],
  ['audio/flac', 'flac', 'flac'], ['audio/webm', 'webm', 'libopus'],
  ['video/mp4', 'mp4', 'libx264'], ['video/quicktime', 'mov', 'libx265'],
  ['video/webm', 'webm', 'libvpx-vp9'],
  ['video/mp4', 'mp4', 'mpeg4'], ['video/quicktime', 'mov', 'mpeg4'],
  ['video/webm', 'webm', 'libvpx'], ['video/x-matroska', 'mkv', 'mpeg4'],
  ['video/x-msvideo', 'avi', 'mpeg4'], ['video/ogg', 'ogv', 'libtheora'],
];
const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
const probe = file => JSON.parse(run('ffprobe', ['-v', 'error', '-show_format', '-show_streams', '-show_packets', '-show_data_hash', 'sha256', '-of', 'json', file]));

(async () => {
  const root = await mediaScratchRoot();
  const prior = (await readdir(root)).filter(name => name.startsWith('vera-media-')).sort();
  const dir = await mkdtemp(join(root, 'vera-fixtures-'));
  const results = [];
  try {
    for (const [mime, ext, codec, duration = 2] of cases) {
      const input = join(dir, `input.${ext}`);
      const output = join(dir, `output.${ext}`);
      const video = mime.startsWith('video/');
      run('ffmpeg', ['-v', 'error', '-y', '-f', 'lavfi', '-i', video ? 'color=c=black:s=320x240:r=25' : 'sine=frequency=440:sample_rate=44100',
        '-t', String(duration), video ? '-c:v' : '-c:a', codec, '-threads', '1',
        ...(codec === 'libx265' ? ['-x265-params', 'pools=none:frame-threads=1:log-level=error'] : []),
        '-metadata', 'title=synthetic-identity', '-metadata', 'artist=synthetic-identity',
        '-metadata', 'location=+40.0000-070.0000/', input]);
      const bytes = await readFile(input);
      const before = probe(input);
      if (ext !== 'aac') assert.match(JSON.stringify({ tags: before.format.tags, streams: before.streams }), /synthetic-identity/);
      const start = performance.now();
      const processing = stripMediaMetadata(bytes, mime);
      await assert.rejects(stripMediaMetadata(bytes, mime), /busy/);
      const clean = await processing;
      const milliseconds = Math.round(performance.now() - start);
      await writeFile(output, clean);
      const after = probe(output);
      assert.doesNotMatch(JSON.stringify(after), /synthetic-identity|\+40\.0000/);
      assert.deepEqual(after.packets.map(p => p.data_hash), before.packets.map(p => p.data_hash));
      run('ffmpeg', ['-v', 'error', '-i', output, '-f', 'null', '-']);
      try {
        await assert.rejects(stripMediaMetadata(Buffer.from('invalid synthetic media'), mime), EvidenceValidationError);
      } catch (error) {
        const diagnostic = spawnSync('ffmpeg', ['-v', 'error', '-f', MEDIA_FORMATS[mime].input,
          '-i', 'pipe:0', '-f', 'null', '-'], { input: 'invalid synthetic media', timeout: 10000 });
        console.error('Synthetic malformed fixture:', { mime, exitCode: diagnostic.status, signal: diagnostic.signal });
        throw error;
      }
      results.push({ mime, codec, inputBytes: bytes.length, outputBytes: clean.length, milliseconds });
      await rm(input); await rm(output);
    }
    await assert.rejects(stripMediaMetadata(Buffer.alloc(256 * 1024 * 1024 + 1), 'audio/wav'), EvidenceValidationError);
    assert.deepEqual((await readdir(root)).filter(name => name.startsWith('vera-media-')).sort(), prior);
    console.log(JSON.stringify({ status: 'passed', platform: process.platform, scratch: root, cases: results }, null, 2));
  } finally { await rm(dir, { recursive: true, force: true }); }
// This harness processes only the generated synthetic fixtures above. Retain
// assertion diagnostics so container-only regressions can be investigated.
})().catch(error => { console.error('Media runtime verification failed:', error); process.exitCode = 1; });

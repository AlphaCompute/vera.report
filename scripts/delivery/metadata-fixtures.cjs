// Synthetic fixtures and independent verification only. Sanitization is performed
// by the application's ordinary intake pipeline, never by this helper.
const sharp = require('sharp');
const { PDFDocument } = require('pdf-lib');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const assert = require('node:assert/strict');
const canary = 'synthetic-metadata-owner-canary';
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
exports.create = async (tiff) => {
    const files = [];
    for (const [format, extension] of [
        ['jpeg', 'jpg'],
        ['png', 'png'],
    ]) {
        const image = sharp({ create: { width: 16, height: 16, channels: 3, background: '#c34436' } }).withExif({
            IFD0: { Artist: canary },
        });
        const bytes = await (
            format === 'tiff' ? image.tiff({ compression: 'none' }) : image.toFormat(format)
        ).toBuffer();
        files.push({ name: `tagged.${extension}`, mime: `image/${format}`, bytes });
    }
    files.push({ name: 'tagged.tiff', mime: 'image/tiff', bytes: tiff, canary: 'identity-canary' });
    const pdf = await PDFDocument.create();
    pdf.setAuthor(canary);
    pdf.setTitle('Synthetic metadata-bearing document');
    pdf.addPage([250, 120]).drawText('Synthetic evidence: retain this text.', { x: 12, y: 65, size: 12 });
    files.push({ name: 'tagged.pdf', mime: 'application/pdf', bytes: Buffer.from(await pdf.save()) });
    return files;
};
exports.verify = async (fixture, after, directory) => {
    assert(Buffer.isBuffer(after));
    let beforeContent, afterContent;
    if (fixture.mime.startsWith('image/')) {
        const beforeMeta = await sharp(fixture.bytes).metadata(),
            afterMeta = await sharp(after).metadata();
        assert(
            fixture.mime === 'image/tiff'
                ? fixture.bytes.includes(Buffer.from(fixture.canary))
                : beforeMeta.exif?.includes(Buffer.from(canary)),
            'Fixture must contain identifying metadata',
        );
        assert.equal(afterMeta.exif, undefined);
        assert.equal(afterMeta.xmp, undefined);
        beforeContent = await sharp(fixture.bytes).raw().toBuffer();
        afterContent = await sharp(after).raw().toBuffer();
        if (fixture.mime === 'image/tiff') {
            const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-tiff-demo-'));
            try {
                const decode = (bytes, name) => {
                    const file = path.join(temporary, name + '.tiff');
                    fs.writeFileSync(file, bytes, { mode: 0o600 });
                    return execFileSync(
                        'ffmpeg',
                        [
                            '-v',
                            'error',
                            '-protocol_whitelist',
                            'file,pipe',
                            '-i',
                            file,
                            '-f',
                            'rawvideo',
                            '-pix_fmt',
                            'rgb24',
                            'pipe:1',
                        ],
                        { timeout: 10000, maxBuffer: 1024 * 1024 },
                    );
                };
                beforeContent = decode(fixture.bytes, 'before');
                afterContent = decode(after, 'after');
            } finally {
                fs.rmSync(temporary, { recursive: true, force: true });
            }
        }
    } else {
        const beforePdf = await PDFDocument.load(fixture.bytes, { updateMetadata: false });
        const afterPdf = await PDFDocument.load(after, { updateMetadata: false });
        assert.equal(beforePdf.getAuthor(), canary);
        assert.equal(afterPdf.getAuthor(), undefined);
        const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-metadata-demo-'));
        try {
            const outputs = [];
            for (const [name, bytes] of [
                ['before', fixture.bytes],
                ['after', after],
            ]) {
                const file = path.join(temp, name + '.pdf');
                fs.writeFileSync(file, bytes);
                execFileSync('pdftoppm', ['-singlefile', '-r', '72', '-png', file, path.join(temp, name)], {
                    timeout: 10000,
                });
                const text = execFileSync('pdftotext', [file, '-'], { timeout: 10000 });
                outputs.push({ pixels: fs.readFileSync(path.join(temp, name + '.png')), text });
            }
            assert.deepEqual(outputs[0].text, outputs[1].text);
            beforeContent = outputs[0].pixels;
            afterContent = outputs[1].pixels;
        } finally {
            fs.rmSync(temp, { recursive: true, force: true });
        }
    }
    assert.deepEqual(afterContent, beforeContent, 'Intended visible content changed');
    assert(!after.includes(Buffer.from(fixture.canary || canary)), 'Raw identifying canary retained');
    if (directory) {
        fs.writeFileSync(path.join(directory, 'before-' + fixture.name), fixture.bytes);
        fs.writeFileSync(path.join(directory, 'after-' + fixture.name), after);
    }
    return {
        file: fixture.name,
        verifiedBy:
            fixture.mime === 'application/pdf'
                ? 'pdf-lib metadata + independent Poppler text/render'
                : fixture.mime === 'image/tiff'
                  ? 'Sharp metadata + independent FFmpeg pixel decode'
                  : 'independent Sharp metadata/pixel decode',
        metadataPresentBefore: true,
        metadataRemovedAfter: true,
        contentPreserved: true,
        inputSha256: hash(fixture.bytes),
        outputSha256: hash(after),
        decodedContentSha256: hash(afterContent),
    };
};

import crypto from 'node:crypto';

export type EvidenceHashVersion = 'sha256-concat-v1' | 'sha256-framed-v2';
export const CURRENT_EVIDENCE_HASH_VERSION: EvidenceHashVersion = 'sha256-framed-v2';
type EvidenceFile = { buffer: Buffer; mimetype: string };

/** Commit the submitted original bytes; sanitization may later remove metadata. */
export function evidenceCommitment(
    description: string,
    files: readonly EvidenceFile[],
    version: EvidenceHashVersion = CURRENT_EVIDENCE_HASH_VERSION,
): string {
    const hash = crypto.createHash('sha256');
    if (version === 'sha256-concat-v1') {
        hash.update(description);
        for (const file of files) hash.update(file.buffer);
    } else if (version === 'sha256-framed-v2') {
        hash.update('VERA-REPORT-EVIDENCE\0v2\0');
        const length = (value: number) => {
            const encoded = Buffer.alloc(8);
            encoded.writeBigUInt64BE(BigInt(value));
            hash.update(encoded);
        };
        const field = (value: Buffer | string) => {
            const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
            length(bytes.length);
            hash.update(bytes);
        };
        field(description);
        length(files.length);
        for (const file of files) {
            field(file.mimetype);
            field(file.buffer);
        }
    } else {
        throw new Error('Unsupported evidence commitment version');
    }
    return hash.digest('hex');
}

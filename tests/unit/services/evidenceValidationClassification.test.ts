jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { uploadEncryptedFile: jest.fn() } }));
jest.mock('../../../src/services/reportPersistence', () => ({
    reportPersistenceService: { saveEvidenceParams: jest.fn() },
}));
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { EvidenceValidationError } from '../../../src/utils/evidenceValidationError';
import { EvidenceStorageError } from '../../../src/services/evidenceStorageError';
import { evidenceEncryptionService } from '../../../src/services/evidenceEncryption';
import { evidenceStorageService } from '../../../src/services/evidenceStorage';

it.each(['image/jpeg', 'image/webp', 'image/png', 'image/tiff', 'application/pdf'])(
    'classifies malformed %s as correctable before any upload',
    async (mimetype) => {
        const file = {
            buffer: Buffer.from('invalid synthetic file'),
            mimetype,
            originalname: 'broken.bin',
        } as Express.Multer.File;
        await expect(persistSubmissionEvidence('VRA-00000000000000AC', [file])).rejects.toBeInstanceOf(
            EvidenceValidationError,
        );
        expect(evidenceStorageService.uploadEncryptedFile).not.toHaveBeenCalled();
    },
);

it('keeps an actual encryption service outage retryable', async () => {
    const encrypt = jest
        .spyOn(evidenceEncryptionService, 'encryptEvidence')
        .mockRejectedValueOnce(new Error('synthetic service failure'));
    try {
        const file = {
            buffer: Buffer.from('synthetic text'),
            mimetype: 'text/plain',
            originalname: 'evidence.txt',
        } as Express.Multer.File;
        await expect(persistSubmissionEvidence('VRA-00000000000000AD', [file])).rejects.toBeInstanceOf(
            EvidenceStorageError,
        );
    } finally {
        encrypt.mockRestore();
    }
});

it('uploads nothing when a later file is rejected, so earlier evidence is not orphaned', async () => {
    const valid = { buffer: Buffer.from('synthetic text evidence'), mimetype: 'text/plain', originalname: 'a.txt' } as Express.Multer.File;
    const broken = { buffer: Buffer.from('invalid synthetic file'), mimetype: 'image/png', originalname: 'b.png' } as Express.Multer.File;
    jest.mocked(evidenceStorageService.uploadEncryptedFile).mockClear();
    await expect(persistSubmissionEvidence('VRA-00000000000000AE', [valid, broken])).rejects.toBeInstanceOf(EvidenceValidationError);
    expect(evidenceStorageService.uploadEncryptedFile).not.toHaveBeenCalled();
});

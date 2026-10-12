import { evidenceCommitment } from '../../../src/utils/evidenceCommitment';

const file = (text: string, mimetype = 'text/csv') => ({ buffer: Buffer.from(text), mimetype });

it('has a stable independently encoded v2 test vector', () => {
    expect(evidenceCommitment('Incident', [file('a,b\n')])).toBe(
        '16df3ce914dff4a80cb3d7e094920da180a618388a08b5578f56fdf2804de454',
    );
});

it('binds file boundaries, order, count and declared format', () => {
    const original = evidenceCommitment('Report', [file('A'), file('B')]);
    expect(evidenceCommitment('Report', [file('AB')])).not.toBe(original);
    expect(evidenceCommitment('Report', [file('B'), file('A')])).not.toBe(original);
    expect(evidenceCommitment('Report', [file('A'), file('B'), file('')])).not.toBe(original);
    expect(evidenceCommitment('Report', [file('A', 'text/plain'), file('B')])).not.toBe(original);
});

it('binds the boundary between narrative and attachments', () => {
    expect(evidenceCommitment('A', [file('BC')])).not.toBe(evidenceCommitment('AB', [file('C')]));
});

it('retains the historical algorithm only for explicit legacy retries', () => {
    expect(evidenceCommitment('A', [file('BC')], 'sha256-concat-v1')).toBe(
        evidenceCommitment('AB', [file('C')], 'sha256-concat-v1'),
    );
    expect(evidenceCommitment('A', [file('BC')])).not.toBe(evidenceCommitment('A', [file('BC')], 'sha256-concat-v1'));
});

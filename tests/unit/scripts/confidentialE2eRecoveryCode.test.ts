import { randomBytes } from 'node:crypto';
import { encodeRecoveryCodeV2 } from '../../../enclave/src/confidential/recoveryCode';
import { DISPLAYED_RECOVERY_CODE, displayedRecoveryCodeProblem } from '../../../qa/e2e/support/recoveryCode';

// The smoke spec's recovery-code check used to be "longer than 20 characters",
// which any scraped error message passes. It must now demand the exact grouped
// format the restore flow reads, with a valid checksum.

async function sampleCode(): Promise<string> {
  const secret = new Uint8Array(randomBytes(32));
  try { return await encodeRecoveryCodeV2(secret); } finally { secret.fill(0); }
}

describe('click-through suite: displayed recovery code check', () => {
  it('accepts real recovery codes as the receipt shows them', async () => {
    for (let run = 0; run < 25; run += 1) {
      const code = await sampleCode();
      expect(code).toMatch(DISPLAYED_RECOVERY_CODE);
      expect(await displayedRecoveryCodeProblem(code)).toBeNull();
    }
  });

  it('rejects long strings that are not recovery codes', async () => {
    for (const text of [
      'We could not create your report. Please try again later.',
      'Recovery code, 14 groups of four characters',
      'x'.repeat(80),
      '',
    ]) {
      expect(text.length > 20 || text === '').toBe(true);
      expect(await displayedRecoveryCodeProblem(text)).not.toBeNull();
    }
  });

  it('rejects codes with the wrong group count or group size', async () => {
    const groups = (await sampleCode()).split('-');
    expect(groups).toHaveLength(14);
    expect(await displayedRecoveryCodeProblem(groups.slice(0, 13).join('-'))).not.toBeNull();
    expect(await displayedRecoveryCodeProblem([...groups, 'ABCD'].join('-'))).not.toBeNull();
    expect(await displayedRecoveryCodeProblem(groups.join(''))).not.toBeNull();
    expect(await displayedRecoveryCodeProblem(groups.join(' '))).not.toBeNull();
    const regrouped = groups.join('').match(/.{1,5}/g)!.join('-');
    expect(await displayedRecoveryCodeProblem(regrouped)).not.toBeNull();
  });

  it('rejects non-display forms of a valid code', async () => {
    const code = await sampleCode();
    // Still restorable when typed, but not what the receipt must show.
    expect(await displayedRecoveryCodeProblem(code.toLowerCase())).not.toBeNull();
    expect(await displayedRecoveryCodeProblem(` ${code}`)).not.toBeNull();
  });

  it('rejects a well-shaped code whose checksum does not match', async () => {
    const code = await sampleCode();
    const last = code.at(-1)!;
    const typo = code.slice(0, -1) + (last === '0' ? '1' : '0');
    expect(typo).toMatch(DISPLAYED_RECOVERY_CODE);
    expect(await displayedRecoveryCodeProblem(typo)).toBe('checksum does not match');
  });

  it('rejects the ambiguous letters the display never uses', async () => {
    const code = await sampleCode();
    for (const letter of ['I', 'L', 'O', 'U']) {
      expect(await displayedRecoveryCodeProblem(letter + code.slice(1))).not.toBeNull();
    }
  });

  it('never echoes the code in its reason', async () => {
    const code = await sampleCode();
    const typo = code.slice(0, -1) + (code.at(-1) === '0' ? '1' : '0');
    for (const input of [typo, code.slice(0, 20)]) {
      expect(await displayedRecoveryCodeProblem(input)).not.toContain(input.slice(0, 4));
    }
  });
});

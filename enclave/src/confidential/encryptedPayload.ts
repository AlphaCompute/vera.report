import { enums, readMessage } from './pgp.ts';

/** Reject accidental plaintext at the relay boundary. This validates only the
 * encrypted container, not its recipients, inner signature or case context;
 * those remain mandatory checks when the participant decrypts it. */
export async function requireEncryptedPayload(value: unknown, recipients: 0 | 1 | 2, maxLength: number): Promise<string> {
  try {
    if (typeof value !== 'string' || value.length > maxLength ||
        !value.startsWith('-----BEGIN PGP MESSAGE-----') ||
        !value.trimEnd().endsWith('-----END PGP MESSAGE-----')) throw new Error();
    const message = await readMessage({ armoredMessage: value,
      config: { maxDecompressedMessageSize: maxLength } });
    if (message.packets.length !== recipients + 1 ||
        message.packets.indexOfTag(enums.packet.publicKeyEncryptedSessionKey).join(',') !==
          (recipients === 0 ? '' : recipients === 1 ? '0' : '0,1') ||
        message.packets.indexOfTag(enums.packet.symEncryptedIntegrityProtectedData).join(',') !== String(recipients)) {
      throw new Error();
    }
    return value;
  } catch { throw new Error('Invalid encrypted payload'); }
}

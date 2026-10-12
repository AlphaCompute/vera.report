/** Explicit recipient-owned binary-DEK format; never interpreted as legacy PBKDF2. */
export interface RecipientNarrativeEnvelope {
    format: 'recipient-narrative:v1';
    trackingId: string;
    purpose: 'narrative';
    key: string;
    iv: string;
    tag: string;
    data: string;
}
export interface LegacyNarrativeEnvelope {
    format?: undefined;
    encryptedData: string;
    encryptionKey: string;
    salt: string;
    iv: string;
    authTag: string;
}
export type NarrativeEnvelope = LegacyNarrativeEnvelope | RecipientNarrativeEnvelope;
export const MAX_NARRATIVE = 8 * 1024 * 1024;
export function validateRecipientNarrative(value: unknown, trackingId: string): RecipientNarrativeEnvelope {
    const fail = () => {
        throw new Error('Narrative unavailable');
    };
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
    const v = value as RecipientNarrativeEnvelope;
    if (
        Object.keys(v).sort().join(',') !== 'data,format,iv,key,purpose,tag,trackingId' ||
        v.format !== 'recipient-narrative:v1' ||
        v.purpose !== 'narrative' ||
        v.trackingId !== trackingId ||
        !/^VRA-[A-F0-9]{16}$/.test(trackingId) ||
        typeof v.key !== 'string' ||
        !v.key.startsWith('enc:kms:recipient:v1:')
    )
        return fail();
    for (const [raw, max, exact] of [
        [v.key.slice('enc:kms:recipient:v1:'.length), 6144, false],
        [v.iv, 12, true],
        [v.tag, 16, true],
        [v.data, MAX_NARRATIVE, false],
    ] as const) {
        if (typeof raw !== 'string' || raw.length > 4 * Math.ceil(max / 3)) return fail();
        const b = Buffer.from(raw, 'base64');
        if (!b.length || b.length > max || (exact && b.length !== max) || b.toString('base64') !== raw) return fail();
    }
    return { ...v };
}

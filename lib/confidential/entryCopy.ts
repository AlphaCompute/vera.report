/** Home page and "Before you send" copy for the two intake modes. The legacy
 * path processes files on VERA's servers and lets authorized administrators
 * read reports; the confidential path encrypts everything on the device, so
 * VERA can neither strip file metadata nor read the report, and the reporter
 * keeps a recovery code instead of a Report ID. Claims here must match the
 * disclosure boundary in docs/security/README.md#trust-boundaries and
 * WHO_CAN_SEE_ROWS in components/vera/confidential/WhoCanSee.tsx. */
export type EntryFeature = { icon: string; title: string; desc: string };
export type EntryCopy = {
    metaDescription: string;
    features: readonly EntryFeature[];
    heroFollow: string;
    handlingReview: string;
    ctaReview: string;
    ctaKeep: string;
    welcomeDescription: string;
    whoSeesIt: string;
    whatYouShare: string;
};

const LEGACY: EntryCopy = {
    metaDescription: 'Report misconduct, attach evidence, and check progress with your Report ID. No account required.',
    features: [
        {
            icon: '/redesign/icon-metadata.svg',
            title: 'Metadata Cleanup',
            desc: 'Supported metadata fields are stripped on VERA’s servers before encryption. File contents may still identify you.',
        },
        {
            icon: '/redesign/icon-anonymous.svg',
            title: 'No Account Required',
            desc: 'Submit without creating an account. Add at least one contact method. Review your report and files for information that could identify you.',
        },
        {
            icon: '/redesign/icon-isolation.svg',
            title: 'Encrypted Storage',
            desc: 'VERA processes evidence on its servers and encrypts it for storage. Authorized administrators can access reports and evidence for review.',
        },
    ],
    heroFollow: 'Describe what happened, attach evidence, and follow your report with your Report ID.',
    handlingReview: 'VERA processes and stores your report for authorized review.',
    ctaReview: 'Submit your report for authorized review.',
    ctaKeep: 'Save your Report ID to check progress.',
    welcomeDescription:
        'Describe what happened, add evidence if you have it, and send it for review. No account needed. Keep your Report ID to check updates.',
    whoSeesIt:
        'Authorized VERA administrators can read your report and files for review. Your Report ID lets you check for updates.',
    whatYouShare:
        'You choose what to include. Provide at least one contact method. Authorized VERA administrators can read your contact details for follow-up. Review your report and files for information that could identify you before you send them.',
};

const CONFIDENTIAL: EntryCopy = {
    metaDescription:
        'A confidential safe way to report fraud and misconduct. Your browser encrypts your full report before it sends it, and you decide who can open it.',
    features: [
        {
            icon: '/redesign/icon-metadata.svg',
            title: 'Check Your Files',
            desc: 'Files are encrypted on your device. Remove hidden details (photo location, document author) before attaching.',
        },
        {
            icon: '/redesign/icon-anonymous.svg',
            title: 'No Account Required',
            desc: 'Submit without creating an account. Add at least one contact method. Review your report and files for information that could identify you.',
        },
        {
            icon: '/redesign/icon-isolation.svg',
            title: 'Encrypted On Your Device',
            desc: 'We see your short summary, submission time and whether you included attachments. Your full report, files, contact details stay encrypted; a legal organization can read more only if you allow it.',
        },
    ],
    heroFollow: 'Describe what happened, attach evidence, and follow your report with your recovery code.',
    handlingReview:
        'Your report is encrypted on your device before it is sent. We see your short summary, submission time and whether you included attachments.',
    ctaReview: 'Your report is encrypted on your device before it is sent.',
    ctaKeep: 'Save your recovery code to check progress. It is the only way back to your report.',
    welcomeDescription:
        'Describe what happened, add evidence if you have it, and send it. No account needed. Keep your recovery code to check updates.',
    whoSeesIt:
        'Your full report is encrypted on your device. We see your short summary, submission time and whether you included attachments. We cannot read your full report, files or contact details. Legal organizations see those same submission facts and can read more only if you allow it. Your recovery code lets you check for updates.',
    whatYouShare:
        'You choose what to include. Provide at least one contact method. Only you can see it unless you later share it with a specific legal organization. Review your summary, your report, and files for information that could identify you before you send them. Do not include classified information. If you are not sure whether you can share a document, ask a lawyer first.',
};

export function entryCopy(confidential: boolean): EntryCopy {
    return confidential ? CONFIDENTIAL : LEGACY;
}

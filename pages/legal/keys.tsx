import { useParticipantLock } from '@/components/vera/confidential/DeviceWorkspaces';
import { useState } from 'react';
import { LegalPortalDisabled, LegalPortalLayout, downloadBytes, panel, primaryButton } from '@/components/vera/confidential/LegalPortal';
import { confidentialCasesEnabled } from '@/lib/confidential/config';
import { KEY_CEREMONY_COPY as copy } from '@/components/vera/confidential/legalKeyCopy';
import type { KeyCeremonyMode } from '@/components/vera/confidential/legalKeyCopy';

/** Private-link key ceremony. All key processing stays in this browser. The
 * ceremony is unavailable unless this build enables confidential cases. */
export default function LegalKeys() {
  return confidentialCasesEnabled() ? <LegalKeyCeremony /> : <LegalPortalDisabled title="Organization key administration" />;
}

function LegalKeyCeremony() {
  useParticipantLock('/legal', true);
  const [mode, setMode] = useState<KeyCeremonyMode>('create');
  const [values, setValues] = useState({ organizationId: '', domain: '', secret: '', stewardSecret: '', outputSecret: '', memberId: '', epoch: '1', memberPublic: '', stewardPublic: '', organizationPublic: '', removed: '' });
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [stewardFile, setStewardFile] = useState<File | null>(null);
  const [envelopeFile, setEnvelopeFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [failed, setFailed] = useState(false);
  const field = (name: keyof typeof values, label: string, multiline = false, secret = false) => <label className="mb-3 block" key={name}>{label}
    {multiline ? <textarea rows={4} className="block w-full border p-2" value={values[name]} autoComplete="off" spellCheck={false} onChange={e => setValues(v => ({ ...v, [name]: e.target.value }))} /> :
      <input type={secret ? 'password' : 'text'} className="block w-full border p-2" value={values[name]} autoComplete="off" spellCheck={false} onChange={e => setValues(v => ({ ...v, [name]: e.target.value }))} />}</label>;
  const read = async (file: File | null) => { if (!file || file.size > 131072) throw new Error(); return file.text(); };
  const run = async () => {
    setBusy(true); setMessage(''); setFailed(false);
    try {
      const [keys, members, pgp, objects] = await Promise.all([import('@/lib/confidential/firmKey'), import('@/enclave/src/confidential/firmMembers'), import('@/enclave/src/confidential/pgp'), import('@/enclave/src/confidential/caseObject')]);
      const epoch = Number(values.epoch);
      if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error();
      const save = async (identity: Awaited<ReturnType<typeof keys.generateFirmIdentity>>, prefix: string) => {
        const exportFile = await keys.exportFirmIdentity(identity, values.outputSecret);
        downloadBytes(exportFile, `${prefix}-PRIVATE.txt`, 'text/plain');
        downloadBytes(identity.privateKey.toPublic().armor(), `${prefix}-public.asc`, 'text/plain');
      };
      if (mode === 'create') {
        await save(await keys.generateFirmIdentity({ organizationId: values.organizationId, domain: values.domain }), 'vera-individual-key');
      } else {
        const identity = await keys.importFirmIdentity(await read(keyFile), values.secret);
        if (mode === 'wrap') {
          const steward = await keys.importFirmIdentity(await read(stewardFile), values.stewardSecret);
          if (steward.privateKey.getFingerprint() === identity.privateKey.getFingerprint()) throw new Error();
          const envelope = await members.wrapOrganizationKeyForMember({ organizationId: identity.organizationId, memberId: values.memberId,
            keyEpoch: epoch, issuedAt: Date.now() }, identity.privateKey, await pgp.readKey({ armoredKey: values.memberPublic }), steward.privateKey);
          downloadBytes(envelope, `vera-member-${values.memberId}-epoch-${epoch}.asc`, 'text/plain');
        } else if (mode === 'unwrap') {
          const opened = await members.unwrapOrganizationKey(await read(envelopeFile), { organizationId: identity.organizationId,
            memberId: values.memberId, keyEpoch: epoch, organizationPublicKey: await pgp.readKey({ armoredKey: values.organizationPublic }),
            steward: await pgp.readKey({ armoredKey: values.stewardPublic }) }, identity.privateKey);
          await save({ ...identity, privateKey: opened.organizationKey, recipientKeyId: await objects.caseRecipientKeyId(opened.organizationKey.toPublic()) }, 'vera-organization-key');
        } else {
          const rotated = await members.rotateOrganizationKey({ organizationId: identity.organizationId, previousKeyEpoch: epoch,
            removedMemberIds: values.removed.split(/\s+/).filter(Boolean), issuedAt: Date.now() }, identity.privateKey);
          const next = { ...identity, privateKey: rotated.organizationKey, recipientKeyId: rotated.statement.nextRecipientKeyId };
          await save(next, `vera-organization-epoch-${epoch + 1}`);
          downloadBytes(rotated.continuity, 'vera-key-continuity.json', 'application/json');
        }
      }
      setValues(v => ({ ...v, secret: '', stewardSecret: '', outputSecret: '' }));
      setMessage(mode === 'rotate' ? copy.rotated : copy.prepared);
    } catch { setFailed(true); setMessage(copy.failed); }
    finally { setBusy(false); }
  };
  return <LegalPortalLayout title={copy.title}><section className={panel}>
    <p className="mb-4">{copy.intro}</p>
    <label className="mb-4 block">{copy.actionLabel}<select className="mt-1 block w-full max-w-full border p-2" value={mode} onChange={e => { setMode(e.target.value as KeyCeremonyMode); setMessage(''); }}>
      {(Object.keys(copy.modes) as KeyCeremonyMode[]).map(value => <option key={value} value={value}>{copy.modes[value]}</option>)}</select></label>
    {mode === 'create' ? <>{field('organizationId', copy.organizationId)}{field('domain', copy.organizationDomain)}</> : <>
      <label className="mb-3 block">{mode === 'unwrap' ? copy.individualKeyFile : copy.organizationKeyFile}<input className="block" type="file" onChange={e => setKeyFile(e.target.files?.[0] ?? null)} /></label>
      {field('secret', copy.keyRecoveryCode, false, true)}
    </>}
    {mode === 'wrap' && <><label className="mb-3 block">{copy.stewardKeyFile}<input className="block" type="file" onChange={e => setStewardFile(e.target.files?.[0] ?? null)} /></label>{field('stewardSecret', copy.stewardRecoveryCode, false, true)}{field('memberPublic', copy.memberPublicKey, true)}</>}
    {(mode === 'wrap' || mode === 'unwrap') && field('memberId', copy.memberId)}
    {mode === 'unwrap' && <><label className="mb-3 block">{copy.memberKeyFile}<input className="block" type="file" onChange={e => setEnvelopeFile(e.target.files?.[0] ?? null)} /></label>{field('stewardPublic', copy.stewardPublicKey, true)}{field('organizationPublic', copy.organizationPublicKey, true)}</>}
    {mode === 'rotate' && <>{field('removed', copy.removedMembers, true)}<p className="mb-4">{copy.rotateHint}</p></>}
    {mode !== 'wrap' && field('outputSecret', copy.outputRecoveryCode, false, true)}
    {mode !== 'create' && <details className="mb-4 border border-black/20 p-3"><summary className="cursor-pointer">{copy.advancedSummary}</summary>
      <p className="my-2 text-sm">{copy.advancedHint}</p>{field('epoch', mode === 'rotate' ? copy.currentKeyVersion : copy.expectedKeyVersion)}</details>}
    <button className={primaryButton} disabled={busy} onClick={() => void run()}>{copy.submit}</button>
    {message && <p className="mt-4" role={failed ? 'alert' : 'status'}>{message}</p>}
  </section></LegalPortalLayout>;
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });

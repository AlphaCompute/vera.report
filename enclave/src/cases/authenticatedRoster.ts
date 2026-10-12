import { verifyFirmKeyBinding } from '../confidential/firmKeyBinding.js';
import { readKey } from '../confidential/pgp.js';
import { verifyApprovedOrganization } from '../confidential/initialRegistration.js';
import type { CaseStore } from './service.js';

/** Host rows cannot change a signed firm's display name, domain or public key.
 * Freshness still needs participant pins: an older valid registration may replay. */
export function authenticatedRoster(store: CaseStore, authority: string | undefined, clock: () => number, initialAuthority?: string): CaseStore {
  return new Proxy(store, { get(target, property) {
    if (property === 'listLegalOrganizations') return async () => {
      if (!authority || !target.listLegalOrganizations) return [];
      const key = await readKey({ armoredKey: authority });
      const worker = initialAuthority ? await readKey({ armoredKey: initialAuthority }) : undefined;
      const rows = await target.listLegalOrganizations();
      if (!Array.isArray(rows) || rows.length > 256) throw new Error('Legal roster unavailable');
      const verified = [];
      for (const row of rows) {
        // A current administrative withdrawal is a denial even when the earlier
        // registration was signed as approved. Host rollback remains possible.
        if (row.approved !== true) continue;
        try {
          const value = await verifyApprovedOrganization((row as typeof row & { registration?: string }).registration!, key, clock(), worker);
          if (value.organizationId !== row.organizationId || !value.approved) continue;
          if (row.bindingDocument) {
            const binding = await verifyFirmKeyBinding(row.bindingDocument, { organizationId: value.organizationId, domain: value.domain });
            if (binding.publicKey.armor() !== value.publicKey || binding.binding.recipientKeyId !== value.recipientKeyId) continue;
          }
          verified.push({ organizationId: value.organizationId, displayName: value.displayName,
            domain: value.domain, publicKey: value.publicKey, approved: true,
            ...(row.bindingDocument ? { bindingDocument: row.bindingDocument } : {}) });
        } catch { /* Unauthenticated host rows never become candidate recipients. */ }
      }
      return verified;
    };
    const value = Reflect.get(target, property);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
}

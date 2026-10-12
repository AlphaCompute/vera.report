import { LegalProvisioningError } from '../utils/legalApplications';

/** Auth0 is the application directory, including applications awaiting review. */
export type ApplicationOrganization = { id: string; name: string; display_name?: string; metadata: Record<string, string> };
export type ApplicationOrganizations = {
  get(name: string, signal: AbortSignal): Promise<ApplicationOrganization | null>;
  getById(id: string, signal: AbortSignal): Promise<ApplicationOrganization | null>;
  list(signal: AbortSignal): Promise<ApplicationOrganization[]>;
  create(value: Omit<ApplicationOrganization, 'id'>, signal: AbortSignal): Promise<ApplicationOrganization>;
  update(value: ApplicationOrganization, signal: AbortSignal): Promise<void>;
  remove(id: string, signal: AbortSignal): Promise<void>;
};

export function applicationOrganizations(
  request: (path: string, signal: AbortSignal, body?: unknown, method?: 'PATCH' | 'DELETE') => Promise<Response>,
  checkStatus: (response: Response) => Promise<never>, connectionId: string,
): ApplicationOrganizations {
  const invalid = (): never => { throw new LegalProvisioningError('provider_binding'); };
  const checked = (value: any): ApplicationOrganization => {
    if (!value || !/^org_[A-Za-z0-9]+$/.test(value.id) || typeof value.name !== 'string' ||
        (value.metadata !== undefined && (!value.metadata || typeof value.metadata !== 'object' || Array.isArray(value.metadata)))) return invalid();
    return { id: value.id, name: value.name, display_name: value.display_name, metadata: value.metadata ?? {} };
  };
  const metadata = (value: Record<string, string>) => {
    if (Object.keys(value).length > 25 || Object.entries(value).some(([key, item]) =>
      key.length > 255 || typeof item !== 'string' || item.length > 255)) throw new LegalProvisioningError('provider_configuration');
    return value;
  };
  async function read(path: string, signal: AbortSignal) {
    const response = await request(path, signal);
    if (response.status === 404) { await response.body?.cancel(); return null; }
    if (response.status !== 200) return checkStatus(response);
    return checked(await response.json());
  }
  return {
    get: (name, signal) => read(`organizations/name/${encodeURIComponent(name)}`, signal),
    getById: (id, signal) => read(`organizations/${encodeURIComponent(id)}`, signal),
    async list(signal) {
      const result: ApplicationOrganization[] = [];
      // Fail closed at the provider's page limit; never use a partial listing to
      // assert that a domain has no approved organization.
      for (let page = 0; page < 10; page++) {
        const response = await request(`organizations?per_page=100&page=${page}`, signal);
        if (response.status !== 200) return checkStatus(response);
        const rows = await response.json();
        if (!Array.isArray(rows) || rows.length > 100) return invalid();
        result.push(...rows.map(checked));
        if (rows.length < 100) return result;
      }
      throw new LegalProvisioningError('lookup_limit');
    },
    async create(value, signal) {
      const response = await request('organizations', signal, { ...value, metadata: metadata(value.metadata),
        branding: { logo_url: 'https://vera.report/apple-touch-icon.png' },
        enabled_connections: [{ connection_id: connectionId, assign_membership_on_login: false }] });
      if (response.status === 409) {
        await response.body?.cancel();
        return await read(`organizations/name/${encodeURIComponent(value.name)}`, signal) ?? invalid();
      }
      if (response.status !== 201) return checkStatus(response);
      return checked(await response.json());
    },
    async update(value, signal) {
      const response = await request(`organizations/${encodeURIComponent(value.id)}`, signal,
        { metadata: metadata(value.metadata) }, 'PATCH');
      if (response.status !== 200) return checkStatus(response);
      const saved = checked(await response.json());
      if (saved.id !== value.id || saved.name !== value.name || Object.entries(value.metadata).some(([key, item]) => saved.metadata[key] !== item)) invalid();
    },
    async remove(id, signal) {
      const response = await request(`organizations/${encodeURIComponent(id)}`, signal, undefined, 'DELETE');
      if (response.status !== 204 && response.status !== 404) return checkStatus(response);
      await response.body?.cancel();
    },
  };
}

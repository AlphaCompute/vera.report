import type { GetServerSidePropsContext } from 'next';
import { auth0 } from '../../../lib/auth0';
import { currentAdminAuthorization } from '../../../lib/currentAdminAuthorization';
import { confidentialCasesEnabled } from '../../../lib/confidential/config';
import { getServerSideProps } from '../../../pages/legal/organizations';

jest.mock('../../../lib/auth0', () => ({ auth0: { getSession: jest.fn() } }));
jest.mock('../../../lib/currentAdminAuthorization', () => ({ currentAdminAuthorization: jest.fn() }));
jest.mock('../../../lib/confidential/config', () => ({ confidentialCasesEnabled: jest.fn() }));
jest.mock('../../../components/vera/confidential/LegalPortal', () => ({ LegalPortalLayout: () => null }));
jest.mock('../../../components/vera/admin/LegalOrganizationsView', () => ({ LegalOrganizationsView: () => null }));

const getSession = auth0.getSession as jest.Mock;
const authorize = jest.mocked(currentAdminAuthorization);
const enabled = jest.mocked(confidentialCasesEnabled);
const user = { sub: 'auth0|staff', 'https://vera.app/roles': ['admin'] };
const setHeader = jest.fn();
const context = { req: {}, res: { setHeader } } as unknown as GetServerSidePropsContext;

beforeEach(() => {
  jest.resetAllMocks();
  enabled.mockReturnValue(true);
  getSession.mockResolvedValue({ user });
});

afterEach(() => {
  expect(setHeader).toHaveBeenCalledWith('Cache-Control', 'private, no-store');
});

test('disabled confidential mode never loads a session or organization roster', async () => {
  enabled.mockReturnValue(false);
  expect(await getServerSideProps(context)).toEqual({ notFound: true });
  expect(getSession).not.toHaveBeenCalled();
  expect(authorize).not.toHaveBeenCalled();
});

test('signed-out staff return to the legal organization page after login', async () => {
  getSession.mockResolvedValue(null);
  expect(await getServerSideProps(context)).toEqual({
    redirect: { destination: '/auth/login?returnTo=/legal/organizations', permanent: false },
  });
  expect(authorize).not.toHaveBeenCalled();
});

test('a current admin can open the roster without session data in page props', async () => {
  authorize.mockResolvedValue({ userId: user.sub, email: 'staff@example.org', roles: ['admin'] });
  expect(await getServerSideProps(context)).toEqual({ props: {} });
  expect(authorize).toHaveBeenCalledWith(user);
});

test('a stale admin cookie cannot elevate a current employee', async () => {
  authorize.mockResolvedValue({ userId: user.sub, email: 'staff@example.org', roles: ['employee'] });
  expect(await getServerSideProps(context)).toEqual({ notFound: true });
});

test('a revoked or unrecognized identity cannot open the roster', async () => {
  authorize.mockResolvedValue(null);
  expect(await getServerSideProps(context)).toEqual({ notFound: true });
});

test('provider failure cannot fall back to the cached session role', async () => {
  authorize.mockRejectedValue(new Error('provider unavailable'));
  expect(await getServerSideProps(context)).toEqual({ notFound: true });
});

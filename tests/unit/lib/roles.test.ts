import { getRolesFromSession, hasRole, isAdmin, ROLES_CLAIM } from '@/lib/roles';

describe('getRolesFromSession', () => {
  it('returns empty array for null user', () => {
    expect(getRolesFromSession(null)).toEqual([]);
  });

  it('returns empty array for undefined user', () => {
    expect(getRolesFromSession(undefined)).toEqual([]);
  });

  it('returns empty array when roles claim is missing', () => {
    expect(getRolesFromSession({ email: 'a@b.com' })).toEqual([]);
  });

  it('returns empty array when roles claim is not an array', () => {
    expect(getRolesFromSession({ [ROLES_CLAIM]: 'admin' })).toEqual([]);
    expect(getRolesFromSession({ [ROLES_CLAIM]: 42 })).toEqual([]);
    expect(getRolesFromSession({ [ROLES_CLAIM]: null })).toEqual([]);
  });

  it('extracts valid roles and filters invalid ones', () => {
    expect(getRolesFromSession({ [ROLES_CLAIM]: ['admin', 'employee'] })).toEqual([
      'admin',
      'employee',
    ]);
    expect(getRolesFromSession({ [ROLES_CLAIM]: ['admin', 'superuser', 123] })).toEqual([
      'admin',
    ]);
  });

  it('returns empty array when all roles are invalid', () => {
    expect(getRolesFromSession({ [ROLES_CLAIM]: ['superuser', 'manager'] })).toEqual([]);
  });
});

describe('hasRole', () => {
  it('admin satisfies admin requirement', () => {
    expect(hasRole(['admin'], 'admin')).toBe(true);
  });

  it('admin satisfies employee requirement (hierarchy)', () => {
    expect(hasRole(['admin'], 'employee')).toBe(true);
  });

  it('employee satisfies employee requirement', () => {
    expect(hasRole(['employee'], 'employee')).toBe(true);
  });

  it('employee does NOT satisfy admin requirement', () => {
    expect(hasRole(['employee'], 'admin')).toBe(false);
  });

  it('empty roles satisfies neither', () => {
    expect(hasRole([], 'admin')).toBe(false);
    expect(hasRole([], 'employee')).toBe(false);
  });
});

describe('isAdmin', () => {
  it('returns true when admin role is present', () => {
    expect(isAdmin(['admin'])).toBe(true);
    expect(isAdmin(['admin', 'employee'])).toBe(true);
  });

  it('returns false when only employee role', () => {
    expect(isAdmin(['employee'])).toBe(false);
  });

  it('returns false for empty roles', () => {
    expect(isAdmin([])).toBe(false);
  });
});

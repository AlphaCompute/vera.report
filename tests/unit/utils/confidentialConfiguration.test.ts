import { confidentialCasesConfigurationError, legacyApiConfidentialHostingError } from '../../../src/utils/confidentialConfiguration';

const REFUSED = 'CONFIDENTIAL_CASES_ENABLED under NODE_ENV=production requires DEPLOY_ENV to be prod, staging or rehearsal';
const env = (values: Record<string, string | undefined>) => values as NodeJS.ProcessEnv;

describe('confidential cases under NODE_ENV=production', () => {
  it.each(['prod', 'staging', 'rehearsal'])('allows the terraform-prod stack DEPLOY_ENV=%s', deployEnv => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_CASES_ENABLED: 'true', DEPLOY_ENV: deployEnv })))
      .toBeUndefined();
  });

  it.each(['production', 'Prod', ' prod', 'Staging', ' staging', 'rehearsal-prod', 'stg', 'dev', ''])('refuses DEPLOY_ENV=%p', deployEnv => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_CASES_ENABLED: 'true', DEPLOY_ENV: deployEnv })))
      .toBe(REFUSED);
  });

  it('refuses when DEPLOY_ENV is unset', () => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_CASES_ENABLED: 'true' }))).toBe(REFUSED);
  });

  it.each(['prod', 'staging', undefined])('leaves confidential cases off untouched (DEPLOY_ENV=%p)', deployEnv => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_CASES_ENABLED: 'false', DEPLOY_ENV: deployEnv })))
      .toBeUndefined();
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', DEPLOY_ENV: deployEnv }))).toBeUndefined();
  });
});

describe('malformed confidential flag', () => {
  it.each(['TRUE', '1', 'yes', ''])('still rejects a malformed flag %p', value => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_CASES_ENABLED: value, DEPLOY_ENV: 'prod' })))
      .toBe('CONFIDENTIAL_CASES_ENABLED must be true or false');
  });
});

describe('CONFIDENTIAL_INTAKE_REQUIRED', () => {
  it.each(['prod', 'staging', 'rehearsal', undefined])('accepts true on DEPLOY_ENV=%p', deployEnv => {
    expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_INTAKE_REQUIRED: 'true', DEPLOY_ENV: deployEnv })))
      .toBeUndefined();
  });

  it.each(['false', '1', 'TRUE', ''])('rejects %p on every environment, staging included', value => {
    for (const deployEnv of ['prod', 'staging', 'rehearsal']) {
      expect(confidentialCasesConfigurationError(env({ NODE_ENV: 'production', CONFIDENTIAL_INTAKE_REQUIRED: value, DEPLOY_ENV: deployEnv })))
        .toBe('CONFIDENTIAL_INTAKE_REQUIRED must be true when set');
    }
  });
});

describe('legacy API hosting under NODE_ENV=production', () => {
  const REFUSED = /confidential-only task \(RUN_MODE=confidential\)/;
  it.each([{ CONFIDENTIAL_CASES_ENABLED: 'true' }, { NEXT_PUBLIC_CONFIDENTIAL_CASES: '1' }])('refuses %p on the legacy API', flags => {
    for (const deployEnv of ['prod', 'staging', 'rehearsal', undefined]) {
      expect(legacyApiConfidentialHostingError(env({ NODE_ENV: 'production', DEPLOY_ENV: deployEnv, RUN_MODE: 'api', ...flags }))).toMatch(REFUSED);
    }
  });

  it('allows the dedicated layout and legacy-only production', () => {
    expect(legacyApiConfidentialHostingError(env({ NODE_ENV: 'production', RUN_MODE: 'api', CONFIDENTIAL_INTAKE_REQUIRED: 'true' }))).toBeUndefined();
    expect(legacyApiConfidentialHostingError(env({ NODE_ENV: 'production', RUN_MODE: 'api', NEXT_PUBLIC_CONFIDENTIAL_CASES: '0' }))).toBeUndefined();
  });

  it.each(['development', 'test', undefined])('leaves the shared local layout alone under NODE_ENV=%p', nodeEnv => {
    expect(legacyApiConfidentialHostingError(env({ NODE_ENV: nodeEnv, CONFIDENTIAL_CASES_ENABLED: 'true' }))).toBeUndefined();
  });
});

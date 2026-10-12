/** Confidential-case startup configuration checks. Deliberately dependency-free:
 * the confidential-only process (src/confidentialServer.ts) must not load legacy
 * services, secrets or their configuration modules to run these checks. */

/** Under NODE_ENV=production, confidential mode runs only on the stacks built
 * from the terraform-prod modules: production (environment = "prod"), the
 * same-account staging stack (environments/staging.tfvars, its own VPC, keys,
 * secrets and domain) and the isolated rehearsal stack
 * (environments/rehearsal.tfvars, separate AWS account). Terraform sets
 * DEPLOY_ENV from `environment` and refuses activation unless the pinned
 * release, manifest and logging decisions are in place
 * (terraform-prod/confidential-variables.tf). Any other or unset DEPLOY_ENV
 * stays refused; there is no bypass variable. */
export const CONFIDENTIAL_PRODUCTION_ENVIRONMENT = 'prod';
export const CONFIDENTIAL_REHEARSAL_ENVIRONMENT = 'rehearsal';
export const CONFIDENTIAL_STAGING_ENVIRONMENT = 'staging';
export const CONFIDENTIAL_DEPLOY_ENVIRONMENTS: readonly string[] =
  [CONFIDENTIAL_PRODUCTION_ENVIRONMENT, CONFIDENTIAL_STAGING_ENVIRONMENT, CONFIDENTIAL_REHEARSAL_ENVIRONMENT];

/** Shared by the CLI validator, the legacy API and the confidential-only server. */
export function confidentialCasesConfigurationError(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.CONFIDENTIAL_CASES_ENABLED !== undefined && !['true', 'false'].includes(env.CONFIDENTIAL_CASES_ENABLED)) {
    return 'CONFIDENTIAL_CASES_ENABLED must be true or false';
  }
  if (env.CONFIDENTIAL_INTAKE_REQUIRED !== undefined && env.CONFIDENTIAL_INTAKE_REQUIRED !== 'true') {
    return 'CONFIDENTIAL_INTAKE_REQUIRED must be true when set';
  }
  if (env.CONFIDENTIAL_CASES_ENABLED === 'true' && env.NODE_ENV === 'production' &&
      !CONFIDENTIAL_DEPLOY_ENVIRONMENTS.includes(env.DEPLOY_ENV ?? '')) {
    return 'CONFIDENTIAL_CASES_ENABLED under NODE_ENV=production requires DEPLOY_ENV to be prod, staging or rehearsal';
  }
}

/** The legacy API (src/api/server.ts) never hosts confidential cases under
 * NODE_ENV=production: there they run only in the confidential-only task
 * (RUN_MODE=confidential, src/confidentialServer.ts) with dedicated database
 * custody, and the legacy API sets CONFIDENTIAL_INTAKE_REQUIRED=true instead.
 * Terraform enforces the same layout (terraform-prod/rehearsal.tf); this keeps a
 * hand-edited task or override from mounting them beside legacy secrets. */
export function legacyApiConfidentialHostingError(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.NODE_ENV === 'production' && confidentialServiceHostedHere(env)) {
    return 'Under NODE_ENV=production confidential cases run only in the confidential-only task (RUN_MODE=confidential); set CONFIDENTIAL_INTAKE_REQUIRED=true on the legacy API instead';
  }
}

/** True when this process hosts the confidential routes itself. False in the
 * dedicated layout, where the legacy API only refuses legacy intake
 * (CONFIDENTIAL_INTAKE_REQUIRED=true) and the confidential-only task serves
 * /api/confidential/* and the admin listing. */
export function confidentialServiceHostedHere(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.CONFIDENTIAL_CASES_ENABLED === 'true' || env.NEXT_PUBLIC_CONFIDENTIAL_CASES === '1';
}

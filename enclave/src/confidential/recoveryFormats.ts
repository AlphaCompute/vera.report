/** Opaque owner recovery package formats the case service stores. The service
 * cannot open either; it only bounds the shape. v1: legacy long codes that carry
 * the case locator and owner fingerprint. v2: codes that are the bare secret. */
export const RECOVERY_PACKAGE_FORMATS: readonly string[] = ['vera-owner-recovery/v1', 'vera-owner-recovery/v2'];

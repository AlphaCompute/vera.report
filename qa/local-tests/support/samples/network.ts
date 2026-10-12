// @ts-nocheck -- deliberately unresolvable for the qa typecheck; bundled by fixture-bundle.spec.ts.
// Sample for fixture-bundle.spec.ts: reaches a module that talks to the identity provider.
import { legalAuthConfig } from '@/lib/confidential/legalAuth';
import { selectedLegalCase } from '@/lib/confidential/legalCaseSelection';
export const value = { legalAuthConfig, selectedLegalCase };

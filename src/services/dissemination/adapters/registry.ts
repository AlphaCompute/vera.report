/**
 * Adapter registry: entityId → dispatchable adapter.
 *
 * Tiers are a config property, not separate systems — the dispatch worker
 * looks adapters up here and treats them uniformly. Entities in the
 * taxonomy without a registered adapter are routable (they appear in
 * recommendations as unsupported) but cannot be approved for dispatch
 * until their adapter ships in a later slice. This slice registers the
 * Tier A automated email channels + the Psst Stage-1 handoff; Tier B
 * portal companions and Tier C counsel adapters arrive later.
 */

import type { SubmissionAdapter } from '../types';
import { cisaAdapter } from './cisa';
import { gaoFraudnetAdapter } from './gaoFraudnet';
import { epaOigAdapter } from './epaOig';
import { psstSafeAdapter } from './psstSafe';
import { securedropAdapter } from './securedrop';
import {
  secTcrAdapter,
  cftcTcrAdapter,
  fincenAdapter,
  irs211Adapter,
  fbiIc3Adapter,
  epaViolationAdapter,
  ftcAdapter,
  dojAdapter,
  euOlafAdapter,
  ecCompetitionAdapter,
} from './companionAdapter';
import { eeocAdapter, oshaAdapter, oscAdapter, agencyOigAdapter } from './counselAdapter';

const adapters = new Map<string, SubmissionAdapter>(
  [
    // Tier A — automated email
    cisaAdapter,
    gaoFraudnetAdapter,
    epaOigAdapter,
    // Partner channel — Stage-1 deep-link handoff
    psstSafeAdapter,
    // Press/media disclosure — Stage-1 deep-link handoff (reporter-elected, consent.press)
    securedropAdapter,
    // Tier B — assisted portal companions (packet + guided portal session):
    // US federal (Phase 2c) + registry breadth + EU Directive tools (Phase 4c).
    secTcrAdapter,
    cftcTcrAdapter,
    fincenAdapter,
    irs211Adapter,
    fbiIc3Adapter,
    epaViolationAdapter,
    ftcAdapter,
    dojAdapter,
    euOlafAdapter,
    ecCompetitionAdapter,
    // Tier C — counsel-mediated workflow (Phase 3): packet handed to retained
    // counsel who files under their own credentials (anonymous SEC/CFTC, EEOC…).
    eeocAdapter,
    oshaAdapter,
    oscAdapter,
    agencyOigAdapter,
  ].map((a) => [a.entityId, a]),
);

export function getAdapter(entityId: string): SubmissionAdapter | null {
  return adapters.get(entityId) ?? null;
}

export function hasAdapter(entityId: string): boolean {
  return adapters.has(entityId);
}

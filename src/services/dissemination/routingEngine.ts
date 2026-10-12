/**
 * Routing engine (VERA-PDR-001 FR-2, §6, §7.1).
 *
 * Evaluates data-driven routing rules against report facts (categories,
 * urgency) and emits a recommended dissemination plan. Rules live in the
 * routing_rules collection (seeded from the taxonomy defaults) so
 * compliance admins can change routing without a redeploy. Nothing here
 * dispatches — the plan is a recommendation until an admin approves it.
 */

import { disseminationPersistence } from './disseminationPersistence';
import { getEntity, type CategorySlug } from './taxonomy';
import { channelConsented } from './consentScope';
import type { ConsentSnapshot, DisseminationPlan, DisseminationView, RecommendedChannel } from './types';

class RoutingEngine {
  /**
   * Produce the recommended plan for a report.
   *
   * Consent gating (FR-8): each channel requires its own consent (see
   * consentScope — agency consent counts only where it was asked). Channels
   * without consent are still listed (so admins can see what routing would
   * apply) but are flagged and can never be approved.
   */
  async recommend(view: DisseminationView, consent: ConsentSnapshot | null): Promise<DisseminationPlan> {
    await disseminationPersistence.seedDefaultRules();
    const rules = await disseminationPersistence.getActiveRules();

    // Collect matched route targets, first match per entity wins.
    const matched = new Map<string, { tier: RecommendedChannel['tier']; reason: string }>();

    for (const rule of rules) {
      if (!this.ruleMatches(rule.match, view)) continue;
      for (const target of rule.route) {
        if (!matched.has(target.entityId)) {
          const because = rule.match.categories?.length
            ? `matched categories: ${rule.match.categories.join(', ')}`
            : `matched rule ${rule.ruleId}`;
          matched.set(target.entityId, { tier: target.tier, reason: because });
        }
      }
    }

    const channels: RecommendedChannel[] = [];
    for (const [entityId, info] of matched) {
      const entity = getEntity(entityId);
      if (!entity) continue;

      const consentSatisfied = channelConsented(consent, entityId);

      channels.push({
        entityId,
        entityName: entity.name,
        tier: info.tier,
        supported: entity.implemented,
        consentSatisfied,
        reason: info.reason,
        notes: entity.notes,
      });
    }

    // Deterministic ordering: dispatchable channels first, then by tier.
    channels.sort((a, b) => {
      if (a.supported !== b.supported) return a.supported ? -1 : 1;
      return a.tier.localeCompare(b.tier);
    });

    return {
      trackingId: view.trackingId,
      categories: view.categories,
      channels,
      consent,
      generatedAt: new Date(),
    };
  }

  private ruleMatches(
    match: { categories?: string[]; orgType?: string | string[]; severity?: string[]; jurisdiction?: string[] },
    view: DisseminationView,
  ): boolean {
    if (match.categories?.length) {
      const hit = match.categories.some((c) => view.categories.includes(c as CategorySlug));
      if (!hit) return false;
    }
    if (match.severity?.length) {
      if (!view.urgency || !match.severity.includes(view.urgency)) return false;
    }
    // Jurisdiction dimension (Phase 4c): jurisdiction-constrained rules
    // (e.g. EU Directive channels) fire only when the report's recorded
    // jurisdiction is listed. Reports without one route as US-default.
    if (match.jurisdiction?.length) {
      if (!view.jurisdiction || !match.jurisdiction.includes(view.jurisdiction)) return false;
    }
    // Org-type dimension (FR-2): fires only when AI triage identified the
    // subject org's type. 'unknown' never satisfies an orgType constraint.
    const orgTypes = typeof match.orgType === 'string' ? [match.orgType] : match.orgType;
    if (orgTypes?.length) {
      if (!view.orgType || view.orgType === 'unknown' || !orgTypes.includes(view.orgType)) {
        return false;
      }
    }
    return true;
  }
}

export const routingEngine = new RoutingEngine();

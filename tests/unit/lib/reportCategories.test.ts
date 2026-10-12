/**
 * Unit tests for the shared report taxonomy (#451).
 *
 * The bug: /status kept its own stale six-category label map, so every category
 * the current /report wizard produces (the ten-category PDR §6 taxonomy) missed
 * the map and rendered as a raw slug. These tests pin the single source of truth.
 */
import { REPORT_CATEGORIES, categoryLabel } from "../../../lib/reportCategories";

describe("report taxonomy", () => {
  it("has the full ten-category PDR §6 taxonomy", () => {
    expect(REPORT_CATEGORIES).toHaveLength(10);
    const values = REPORT_CATEGORIES.map((c) => c.value);
    expect(values).toEqual(
      expect.arrayContaining([
        "ai-safety",
        "trust-safety",
        "encryption",
        "financial-fraud",
        "discrimination-harassment",
        "cyber-security",
        "crypto",
        "environment-climate",
        "government-accountability",
        "illegal-government-activity",
      ]),
    );
  });

  it("resolves current wizard slugs to human labels (the ones /status used to slug)", () => {
    expect(categoryLabel("cyber-security")).toBe("Cyber Security");
    expect(categoryLabel("ai-safety")).toBe("AI Safety");
    expect(categoryLabel("government-accountability")).toBe(
      "Government Accountability",
    );
    expect(categoryLabel("financial-fraud")).toBe("Financial Fraud");
  });

  it("falls back to the raw value for an unknown slug", () => {
    expect(categoryLabel("something-new")).toBe("something-new");
  });

  it("returns empty string for missing input", () => {
    expect(categoryLabel(null)).toBe("");
    expect(categoryLabel(undefined)).toBe("");
    expect(categoryLabel("")).toBe("");
  });
});

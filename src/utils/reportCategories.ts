/**
 * The ten-category dissemination taxonomy (VERA-PDR-001 §6), adopted verbatim
 * from Psst Safe. Single source of truth for reporter-facing category labels —
 * shared by the /report wizard and the /status case file so the two cannot
 * drift. (They did: /status kept an older six-category map and rendered every
 * current category as a raw slug — #451.)
 */
export interface ReportCategory {
  value: string;
  label: string;
}

export const REPORT_CATEGORIES: ReportCategory[] = [
  { value: "ai-safety", label: "AI Safety" },
  { value: "trust-safety", label: "Trust & Safety" },
  { value: "encryption", label: "Encryption" },
  { value: "financial-fraud", label: "Financial Fraud" },
  { value: "discrimination-harassment", label: "Discrimination/Harassment" },
  { value: "cyber-security", label: "Cyber Security" },
  { value: "crypto", label: "Crypto" },
  { value: "environment-climate", label: "Environment or Climate Issues" },
  { value: "government-accountability", label: "Government Accountability" },
  { value: "illegal-government-activity", label: "Illegal Government Activity" },
];

/** Human label for a category slug; falls back to the raw value if unknown. */
export function categoryLabel(value: string | null | undefined): string {
  if (!value) return "";
  return REPORT_CATEGORIES.find((c) => c.value === value)?.label ?? value;
}

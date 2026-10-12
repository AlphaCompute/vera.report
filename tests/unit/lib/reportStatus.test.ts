/**
 * Unit tests for the /status timeline mapping (#450).
 *
 * The bug: dismissed/rejected reports fell through `mapBackendStatus`'s
 * `|| "received"` default and were shown to the whistleblower as a freshly
 * logged case with three stages still pending — a closed case presented as
 * in-progress. These tests lock in the terminal-state handling.
 */
import {
  mapBackendStatus,
  buildTimeline,
  TRACKING_ID_PATTERN,
  TRACKING_ID_EXAMPLE,
  CREDENTIAL_EXAMPLE,
  classifyLookupStatus,
  lookupFailureMessage,
  ReportLookupError,
} from "../../../lib/reportStatus";

const CREATED = "2026-08-26T14:21:38.347Z";

describe("mapBackendStatus", () => {
  it("maps terminal-negative backend states to 'declined' (not 'received')", () => {
    expect(mapBackendStatus("dismissed")).toBe("declined");
    expect(mapBackendStatus("rejected")).toBe("declined");
  });

  it("is case-insensitive", () => {
    expect(mapBackendStatus("DISMISSED")).toBe("declined");
    expect(mapBackendStatus("Rejected")).toBe("declined");
  });

  it("surfaces an unmapped status as 'unknown' rather than flattering it as 'received'", () => {
    expect(mapBackendStatus("some_new_backend_state")).toBe("unknown");
    expect(mapBackendStatus("")).toBe("unknown");
  });

  it("keeps the positive path unchanged", () => {
    expect(mapBackendStatus("processing")).toBe("received");
    expect(mapBackendStatus("pending")).toBe("received");
    expect(mapBackendStatus("received")).toBe("received");
    expect(mapBackendStatus("under_review")).toBe("review");
    expect(mapBackendStatus("verified")).toBe("investigation");
    expect(mapBackendStatus("investigation")).toBe("investigation");
    expect(mapBackendStatus("resolved")).toBe("resolved");
    expect(mapBackendStatus("closed")).toBe("resolved");
  });
});

describe("buildTimeline", () => {
  it("ends a dismissed report at a terminal 'Report Closed' entry — no pending stages", () => {
    const tl = buildTimeline("dismissed", CREATED);

    expect(tl).toHaveLength(2);
    expect(tl[0].status).toBe("received");
    expect(tl[0].date).toBe("2026-08-26"); // the report WAS received, dated
    expect(tl[1].status).toBe("declined");
    expect(tl[1].label).toBe("Report Closed");

    // The core defect: it must NOT present the optimistic in-progress stages.
    const statuses = tl.map((e) => e.status);
    expect(statuses).not.toContain("review");
    expect(statuses).not.toContain("investigation");
    expect(statuses).not.toContain("resolved");
  });

  it("treats rejected the same as dismissed (terminal)", () => {
    const tl = buildTimeline("rejected", CREATED);
    expect(tl.map((e) => e.status)).toEqual(["received", "declined"]);
  });

  it("surfaces an unknown backend status honestly", () => {
    const tl = buildTimeline("wat", CREATED);
    expect(tl).toHaveLength(2);
    expect(tl[1].status).toBe("unknown");
    expect(tl[1].label).toBe("Status Unavailable");
  });

  it("still builds the full four-stage timeline for the positive path", () => {
    const tl = buildTimeline("review", CREATED);
    expect(tl.map((e) => e.status)).toEqual([
      "received",
      "review",
      "investigation",
      "resolved",
    ]);
    // stages after the current one are not yet noted/dated
    expect(tl[0].note).not.toBeNull();
    expect(tl[1].note).not.toBeNull();
    expect(tl[2].note).toBeNull();
    expect(tl[3].note).toBeNull();
  });
});

describe("tracking-ID hint (#452)", () => {
  it("advertises an example the API validator would accept", () => {
    // The /status placeholder used to show a 6-char shape; the validator wants
    // VRA- + 16 hex. Lock the advertised example to the canonical pattern.
    expect(TRACKING_ID_PATTERN.test(TRACKING_ID_EXAMPLE)).toBe(true);
    expect(TRACKING_ID_PATTERN.test("VRA-A1B2C3")).toBe(false); // the old bad hint
  });

  it("uses the reserved all-zero sentinel, never a resolvable ID (#498)", () => {
    // /status is unauthenticated, so a working example ID is a public link to
    // that report. The example must be the reserved all-zero sentinel: valid in
    // shape but guaranteed to 404 and impossible for a random real ID to hit.
    expect(TRACKING_ID_EXAMPLE).toBe("VRA-0000000000000000");
    expect(/^VRA-0{16}$/.test(TRACKING_ID_EXAMPLE)).toBe(true);
  });
});

describe("credential hint (#853)", () => {
  it("advertises the shape the web wizard actually issues", () => {
    // /status used to show the VRA- tracking ID, which only ever reaches a
    // reporter through a retired intake channel. A web reporter's own receipt is a
    // VRC- credential, so the example never matched what they held.
    expect(CREDENTIAL_EXAMPLE.startsWith("VRC-")).toBe(true);
    expect(TRACKING_ID_PATTERN.test(CREDENTIAL_EXAMPLE)).toBe(true);
  });

  it("uses the reserved all-zero sentinel, never a resolvable credential", () => {
    expect(/^VRC-0{64}$/.test(CREDENTIAL_EXAMPLE)).toBe(true);
  });
});

describe("lookup failure classification (#853)", () => {
  it("treats a rejected ID as a format problem, not an unreachable server", () => {
    // The page collapsed every non-404 into "Unable to reach the server", so a
    // mistyped ID sent the reporter off to debug their network.
    expect(classifyLookupStatus(400)).toBe("format");
    expect(classifyLookupStatus(422)).toBe("format");
    expect(lookupFailureMessage("format")).not.toMatch(/reach the server/i);
  });

  it("names rate limiting as itself", () => {
    expect(classifyLookupStatus(429)).toBe("rate-limited");
    expect(lookupFailureMessage("rate-limited")).toMatch(/wait/i);
  });

  it("still reports a genuine server failure as unavailable", () => {
    expect(classifyLookupStatus(500)).toBe("unavailable");
    expect(classifyLookupStatus(503)).toBe("unavailable");
    expect(lookupFailureMessage("unavailable")).toMatch(/reach the server/i);
  });

  it("carries the reason on the thrown error so the page can branch on it", () => {
    expect(new ReportLookupError("rate-limited").reason).toBe("rate-limited");
  });
});

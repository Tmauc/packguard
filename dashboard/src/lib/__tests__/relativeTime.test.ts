import { describe, expect, it } from "vitest";
import { formatRelativeTime } from "@/lib/relativeTime";

const NOW = new Date("2026-04-26T12:00:00.000Z");

describe("formatRelativeTime", () => {
  it("returns 'never scanned' for null", () => {
    expect(formatRelativeTime(null, NOW)).toBe("never scanned");
  });

  it("returns 'never scanned' for undefined", () => {
    expect(formatRelativeTime(undefined, NOW)).toBe("never scanned");
  });

  it("returns 'never scanned' for empty string", () => {
    expect(formatRelativeTime("", NOW)).toBe("never scanned");
  });

  it("returns 'never scanned' for an unparseable ISO string", () => {
    expect(formatRelativeTime("not-a-date", NOW)).toBe("never scanned");
  });

  it("returns 'just now' for a future timestamp (clock skew tolerance)", () => {
    expect(
      formatRelativeTime("2026-04-26T12:00:30.000Z", NOW),
    ).toBe("just now");
  });

  it("returns '<1m ago' under one minute", () => {
    expect(
      formatRelativeTime("2026-04-26T11:59:30.000Z", NOW),
    ).toBe("<1m ago");
  });

  it("returns minute granularity under one hour", () => {
    expect(
      formatRelativeTime("2026-04-26T11:55:00.000Z", NOW),
    ).toBe("5m ago");
    expect(
      formatRelativeTime("2026-04-26T11:01:00.000Z", NOW),
    ).toBe("59m ago");
  });

  it("returns hour granularity under 24 hours", () => {
    expect(
      formatRelativeTime("2026-04-26T10:00:00.000Z", NOW),
    ).toBe("2h ago");
    expect(
      formatRelativeTime("2026-04-25T13:00:00.000Z", NOW),
    ).toBe("23h ago");
  });

  it("returns day granularity under 30 days", () => {
    expect(
      formatRelativeTime("2026-04-23T12:00:00.000Z", NOW),
    ).toBe("3d ago");
    expect(
      formatRelativeTime("2026-03-28T12:00:00.000Z", NOW),
    ).toBe("29d ago");
  });

  it("falls back to ISO date for >= 30 days", () => {
    expect(
      formatRelativeTime("2026-01-15T08:30:00.000Z", NOW),
    ).toBe("2026-01-15");
  });
});

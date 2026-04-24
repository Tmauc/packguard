import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import {
  COLLAPSED_FOLDERS_STORAGE_KEY,
  useCollapsedFolders,
} from "@/lib/useCollapsedFolders";

beforeEach(() => {
  window.localStorage.clear();
});

describe("useCollapsedFolders", () => {
  it("hydrates from localStorage when a valid JSON array is present", () => {
    window.localStorage.setItem(
      COLLAPSED_FOLDERS_STORAGE_KEY,
      JSON.stringify(["front", "services"]),
    );
    const { result } = renderHook(() => useCollapsedFolders([]));
    expect(result.current.collapsed.has("front")).toBe(true);
    expect(result.current.collapsed.has("services")).toBe(true);
  });

  it("persists toggles back to localStorage after each change", () => {
    const { result } = renderHook(() => useCollapsedFolders(["front"]));
    // Initial state derived from the seed since localStorage was clear.
    expect(result.current.collapsed.has("front")).toBe(true);
    act(() => result.current.toggle("front"));
    expect(result.current.collapsed.has("front")).toBe(false);
    // Written back — keys are sorted for deterministic storage shape.
    expect(window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY)).toBe(
      JSON.stringify([]),
    );
    act(() => result.current.toggle("services"));
    expect(window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY)).toBe(
      JSON.stringify(["services"]),
    );
  });

  it("falls back to the seed when localStorage holds garbage", () => {
    window.localStorage.setItem(COLLAPSED_FOLDERS_STORAGE_KEY, "not json");
    const { result } = renderHook(() => useCollapsedFolders(["front"]));
    expect(result.current.collapsed.has("front")).toBe(true);
  });

  it("seedFrom adds newly scanned folder IDs without overriding user toggles", () => {
    window.localStorage.setItem(
      COLLAPSED_FOLDERS_STORAGE_KEY,
      JSON.stringify([]), // user opened everything
    );
    const { result } = renderHook(() => useCollapsedFolders([]));
    expect(result.current.collapsed.size).toBe(0);
    // A new scan drops in a `services` folder — it should default to
    // collapsed, but the `front` folder the user opened stays open.
    act(() => result.current.seedFrom(["front", "services"]));
    expect(result.current.collapsed.has("front")).toBe(true);
    expect(result.current.collapsed.has("services")).toBe(true);
    // Second seedFrom with same IDs is a no-op (stable reference so
    // the effect below doesn't thrash).
    const before = result.current.collapsed;
    act(() => result.current.seedFrom(["front", "services"]));
    expect(result.current.collapsed).toBe(before);
  });
});

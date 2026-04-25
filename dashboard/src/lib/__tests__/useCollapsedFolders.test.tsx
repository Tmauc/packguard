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
    const { result } = renderHook(() => useCollapsedFolders());
    expect(result.current.collapsed.has("front")).toBe(true);
    expect(result.current.collapsed.has("services")).toBe(true);
  });

  it("starts with no folders collapsed when localStorage is empty", () => {
    const { result } = renderHook(() => useCollapsedFolders());
    expect(result.current.collapsed.size).toBe(0);
  });

  it("persists toggles back to localStorage after each change", () => {
    const { result } = renderHook(() => useCollapsedFolders());
    expect(result.current.collapsed.size).toBe(0);
    act(() => result.current.toggle("front"));
    expect(result.current.collapsed.has("front")).toBe(true);
    expect(window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY)).toBe(
      JSON.stringify(["front"]),
    );
    act(() => result.current.toggle("services"));
    // Keys are sorted for deterministic storage shape.
    expect(window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY)).toBe(
      JSON.stringify(["front", "services"]),
    );
    act(() => result.current.toggle("front"));
    expect(result.current.collapsed.has("front")).toBe(false);
  });

  it("falls back to an empty set when localStorage holds garbage", () => {
    window.localStorage.setItem(COLLAPSED_FOLDERS_STORAGE_KEY, "not json");
    const { result } = renderHook(() => useCollapsedFolders());
    expect(result.current.collapsed.size).toBe(0);
  });
});

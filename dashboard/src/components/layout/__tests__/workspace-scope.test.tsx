import { renderHook } from "@testing-library/react";
import { MemoryRouter, useLocation, useSearchParams } from "react-router-dom";
import { vi } from "vitest";
import type { ProjectDto } from "@/api/types/ProjectDto";
import {
  useLegacyProjectRedirect,
  useProjectScope,
  useRestoreProjectScopeFromStorage,
  useWorkspaceScope,
  PROJECT_SCOPE_STORAGE_KEY,
} from "@/components/layout/workspace-scope";

vi.mock("sonner", () => ({
  toast: { message: vi.fn(), error: vi.fn(), success: vi.fn() },
}));

import { toast } from "sonner";

function wrapper(initialEntry: string) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <MemoryRouter initialEntries={[initialEntry]}>{children}</MemoryRouter>;
  };
}

beforeEach(() => {
  (toast.message as ReturnType<typeof vi.fn>).mockReset();
});

describe("useProjectScope", () => {
  it("returns the slug when ?project=<slug>", () => {
    const { result } = renderHook(() => useProjectScope(), {
      wrapper: wrapper("/?project=foo-bar"),
    });
    expect(result.current).toBe("foo-bar");
  });

  it("returns undefined when ?project= holds an absolute path (legacy form)", () => {
    const { result } = renderHook(() => useProjectScope(), {
      wrapper: wrapper("/?project=/Users/x/Repo/Nalo/monorepo"),
    });
    // Slug discriminator: anything starting with `/` is a legacy path
    // and the redirect hook owns it — useProjectScope refuses to claim
    // it as a current scope.
    expect(result.current).toBeUndefined();
  });

  it("returns undefined when the ?project= param is absent", () => {
    const { result } = renderHook(() => useProjectScope(), {
      wrapper: wrapper("/"),
    });
    expect(result.current).toBeUndefined();
  });
});

describe("useWorkspaceScope", () => {
  it("returns the value of ?workspace=", () => {
    const { result } = renderHook(() => useWorkspaceScope(), {
      wrapper: wrapper("/?workspace=/tmp/alpha"),
    });
    expect(result.current).toBe("/tmp/alpha");
  });

  it("ignores ?project= entirely (project + workspace are independent slots)", () => {
    const { result } = renderHook(() => useWorkspaceScope(), {
      wrapper: wrapper("/?project=foo-bar"),
    });
    expect(result.current).toBeUndefined();
  });

  it("returns undefined when neither param is present", () => {
    const { result } = renderHook(() => useWorkspaceScope(), {
      wrapper: wrapper("/"),
    });
    expect(result.current).toBeUndefined();
  });
});

describe("useLegacyProjectRedirect", () => {
  const PROJECTS: ProjectDto[] = [
    {
      id: 1n,
      slug: "Users-x-Repo-Nalo-monorepo",
      path: "/Users/x/Repo/Nalo/monorepo",
      name: "monorepo",
      created_at: "2026-04-24T10:00:00Z",
      last_scan: null,
    },
    {
      id: 2n,
      slug: "tmp-other",
      path: "/tmp/other",
      name: "other",
      created_at: "2026-04-24T10:00:00Z",
      last_scan: null,
    },
  ];

  // Helper that exposes the resolved URL alongside the redirect hook so
  // the assertion can read `?project=<slug>&workspace=<path>` after the
  // effect runs.
  function useProbe(projects: ProjectDto[] | undefined) {
    useLegacyProjectRedirect(projects);
    const [params] = useSearchParams();
    const loc = useLocation();
    return { search: loc.search, params };
  }

  it("rewrites ?project=<legacy path> → ?project=<slug>&workspace=<path>", async () => {
    const { result, rerender } = renderHook(
      ({ projects }: { projects: ProjectDto[] | undefined }) =>
        useProbe(projects),
      {
        wrapper: wrapper(
          "/?project=/Users/x/Repo/Nalo/monorepo/front/vesta",
        ),
        initialProps: { projects: undefined as ProjectDto[] | undefined },
      },
    );
    // Before the projects list lands the URL is untouched.
    expect(result.current.params.get("project")).toBe(
      "/Users/x/Repo/Nalo/monorepo/front/vesta",
    );
    expect(result.current.params.get("workspace")).toBeNull();

    rerender({ projects: PROJECTS });
    // The deepest-ancestor match (the monorepo root) wins → the slug
    // moves into ?project= and the legacy path is preserved as
    // ?workspace=.
    expect(result.current.params.get("project")).toBe(
      "Users-x-Repo-Nalo-monorepo",
    );
    expect(result.current.params.get("workspace")).toBe(
      "/Users/x/Repo/Nalo/monorepo/front/vesta",
    );
    // One-shot toast — the user is told once that the URL changed
    // under them.
    expect(toast.message).toHaveBeenCalledTimes(1);
    expect(toast.message).toHaveBeenCalledWith(
      "URL updated",
      expect.objectContaining({ description: expect.any(String) }),
    );
  });

  it("leaves the URL untouched when no project root is an ancestor of the legacy path", () => {
    const { result, rerender } = renderHook(
      ({ projects }: { projects: ProjectDto[] | undefined }) =>
        useProbe(projects),
      {
        wrapper: wrapper("/?project=/some/unknown/path"),
        initialProps: { projects: undefined as ProjectDto[] | undefined },
      },
    );
    rerender({ projects: PROJECTS });
    // No match → URL stays as-is, no toast fired, the backend will 404
    // on the legacy path with its known-projects list.
    expect(result.current.params.get("project")).toBe("/some/unknown/path");
    expect(result.current.params.get("workspace")).toBeNull();
    expect(toast.message).not.toHaveBeenCalled();
  });

  it("is a no-op when ?project= already holds a slug (already on the new contract)", () => {
    const { result, rerender } = renderHook(
      ({ projects }: { projects: ProjectDto[] | undefined }) =>
        useProbe(projects),
      {
        wrapper: wrapper("/?project=Users-x-Repo-Nalo-monorepo"),
        initialProps: { projects: undefined as ProjectDto[] | undefined },
      },
    );
    rerender({ projects: PROJECTS });
    // Already-slug URLs are owned by useProjectScope; the legacy
    // redirect hook ignores them.
    expect(result.current.params.get("project")).toBe(
      "Users-x-Repo-Nalo-monorepo",
    );
    expect(result.current.params.get("workspace")).toBeNull();
    expect(toast.message).not.toHaveBeenCalled();
  });
});

describe("useRestoreProjectScopeFromStorage — Bug D (stale URL slug)", () => {
  function useScopeProbe(known: string[] | undefined, skipRestore: boolean) {
    useRestoreProjectScopeFromStorage(known, skipRestore);
    const [params] = useSearchParams();
    return { project: params.get("project") };
  }

  beforeEach(() => {
    window.localStorage.clear();
  });

  it("clears ?project=<slug> from the URL when projects loaded and slug is unknown", () => {
    const { result, rerender } = renderHook(
      ({ known }: { known: string[] | undefined }) =>
        useScopeProbe(known, false),
      {
        wrapper: wrapper("/?project=ghost-slug"),
        initialProps: { known: undefined as string[] | undefined },
      },
    );
    // Pre-load: known === undefined → no-op, slug stays.
    expect(result.current.project).toBe("ghost-slug");
    rerender({ known: ["alpha", "beta"] });
    // Post-load: ghost-slug not in known set → URL slug dropped.
    expect(result.current.project).toBeNull();
  });

  it("keeps ?project=<slug> when the slug IS in the known set", () => {
    const { result, rerender } = renderHook(
      ({ known }: { known: string[] | undefined }) =>
        useScopeProbe(known, false),
      {
        wrapper: wrapper("/?project=alpha"),
        initialProps: { known: undefined as string[] | undefined },
      },
    );
    rerender({ known: ["alpha", "beta"] });
    // alpha is known → URL untouched.
    expect(result.current.project).toBe("alpha");
  });

  it("does not clear the URL while the projects list is still loading", () => {
    const { result } = renderHook(
      () => useScopeProbe(undefined, false),
      {
        wrapper: wrapper("/?project=anything"),
      },
    );
    // known === undefined → guard short-circuits, URL preserved.
    expect(result.current.project).toBe("anything");
  });

  it("after clearing a stale URL slug, restores from localStorage when valid", () => {
    window.localStorage.setItem(PROJECT_SCOPE_STORAGE_KEY, "alpha");
    const { result, rerender } = renderHook(
      ({ known }: { known: string[] | undefined }) =>
        useScopeProbe(known, false),
      {
        wrapper: wrapper("/?project=ghost-slug"),
        initialProps: { known: undefined as string[] | undefined },
      },
    );
    rerender({ known: ["alpha", "beta"] });
    // Two-pass settle: first pass clears the bad slug, the next render
    // (driven by the URL change) re-fires the effect and the
    // localStorage-restore branch puts "alpha" in.
    rerender({ known: ["alpha", "beta"] });
    expect(result.current.project).toBe("alpha");
  });
});

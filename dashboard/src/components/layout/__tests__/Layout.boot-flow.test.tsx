import { act, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import type { ProjectDto } from "@/api/types/ProjectDto";
import { Layout } from "@/components/Layout";
import { PROJECT_SCOPE_STORAGE_KEY } from "@/components/layout/workspace-scope";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      projects: vi.fn(),
      workspaces: vi.fn(),
      actions: vi.fn(),
      startScan: vi.fn(),
      startSync: vi.fn(),
      job: vi.fn(),
    },
  };
});

vi.mock("sonner", () => ({
  toast: { message: vi.fn(), error: vi.fn(), success: vi.fn() },
}));

import { api } from "@/lib/api";

function CurrentUrl() {
  const loc = useLocation();
  return (
    <div data-testid="url">
      {loc.pathname}
      {loc.search}
    </div>
  );
}

function wrap(initialEntries: string[] = ["/"]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route
            path="*"
            element={
              <>
                <Layout />
                <CurrentUrl />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, client };
}

const TWO_PROJECTS: ProjectDto[] = [
  {
    id: 1n,
    slug: "Users-mauc-Repo-Nalo-monorepo",
    path: "/Users/mauc/Repo/Nalo/monorepo",
    name: "monorepo",
    created_at: "2026-04-20T10:00:00Z",
    last_scan: "2026-04-26T09:00:00.000Z",
  },
  {
    id: 2n,
    slug: "Users-mauc-Repo-AnotherCo-foo",
    path: "/Users/mauc/Repo/AnotherCo/foo",
    name: "foo",
    created_at: "2026-04-23T10:00:00Z",
    last_scan: "2026-04-25T08:00:00.000Z",
  },
];

beforeEach(() => {
  window.localStorage.clear();
  // The Layout subscribes to /api/workspaces + /api/actions for the
  // header's WorkspaceSelector + ActionsNavBadge. Stub them with empty
  // payloads so React Query resolves without the test having to
  // care about either surface — boot-flow assertions are about the
  // project scope only.
  (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue({
    workspaces: [],
  });
  (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue({
    actions: [],
    total: 0,
  });
});

describe("Layout boot flow — project scope auto-select", () => {
  it("auto-selects the most-recently-scanned project when URL has no slug", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_PROJECTS);
    wrap(["/"]);
    // monorepo's last_scan (Apr 26 09:00) is more recent than foo's
    // (Apr 25 08:00) → auto-selected, URL written, localStorage set.
    await waitFor(() => {
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-Nalo-monorepo",
      );
    });
    expect(window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY)).toBe(
      "Users-mauc-Repo-Nalo-monorepo",
    );
  });

  it("restores the project scope from localStorage when the slug is known", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_PROJECTS);
    // foo is older but stored — restore must win over the most-recent
    // auto-select.
    window.localStorage.setItem(
      PROJECT_SCOPE_STORAGE_KEY,
      "Users-mauc-Repo-AnotherCo-foo",
    );
    wrap(["/"]);
    await waitFor(() => {
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-AnotherCo-foo",
      );
    });
    expect(screen.getByTestId("url").textContent).not.toContain(
      "Users-mauc-Repo-Nalo-monorepo",
    );
  });

  it("clears stale localStorage and falls back to most-recent when stored slug is unknown", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_PROJECTS);
    window.localStorage.setItem(PROJECT_SCOPE_STORAGE_KEY, "ghost-project");
    wrap(["/"]);
    // Restore hook clears the stale entry; auto-select picks the most
    // recent (monorepo). The localStorage write under that fresh slug
    // happens via setProjectScope.
    await waitFor(() => {
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-Nalo-monorepo",
      );
    });
    expect(window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY)).toBe(
      "Users-mauc-Repo-Nalo-monorepo",
    );
  });

  it("respects an explicit ?project= URL — no restore, no auto-select", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_PROJECTS);
    // Even with localStorage seeded with foo, an explicit URL slug wins.
    window.localStorage.setItem(
      PROJECT_SCOPE_STORAGE_KEY,
      "Users-mauc-Repo-AnotherCo-foo",
    );
    wrap(["/?project=Users-mauc-Repo-Nalo-monorepo"]);
    await waitFor(() => {
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-Nalo-monorepo",
      );
    });
    // Restore must not overwrite the URL slug with the stored one.
    expect(screen.getByTestId("url").textContent).not.toContain(
      "Users-mauc-Repo-AnotherCo-foo",
    );
  });

  it("renders EmptyProjectGate when the projects list is empty", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    wrap(["/"]);
    await waitFor(() => {
      expect(screen.getByTestId("empty-project-gate")).toBeInTheDocument();
    });
    // Sidebar nav should NOT render — the gate replaces the whole
    // dashboard chrome. The Overview NavLink would render text
    // "Overview" inside the sidebar; its absence confirms the gate
    // is doing its job.
    expect(screen.queryByText("Overview")).not.toBeInTheDocument();
    // Header chrome (Project / Workspace selectors) is also gone.
    expect(screen.queryByTestId("project-selector")).not.toBeInTheDocument();
  });

  it("does NOT render EmptyProjectGate while the projects query is still loading", async () => {
    // never-resolving mock → query stays in `isLoading`
    (api.projects as ReturnType<typeof vi.fn>).mockReturnValue(
      new Promise(() => {}),
    );
    wrap(["/"]);
    // Layout must render the chrome (loading state), not the gate.
    expect(screen.queryByTestId("empty-project-gate")).not.toBeInTheDocument();
    expect(screen.getByTestId("project-selector")).toBeInTheDocument();
  });

  it("auto-select does NOT re-fire when the projects list grows mid-session (14.3c ref-guard)", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_PROJECTS);
    const { client } = wrap(["/"]);
    // First-pass auto-select picks the most-recent (monorepo).
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-Nalo-monorepo",
      ),
    );
    // Simulate adding a project: a brand-new entry lands at the top
    // of the list (most-recent last_scan). Without the ref-guard the
    // effect would re-fire and yank scope away from the user's
    // current selection — exactly what we don't want when
    // AddProjectModal is in flight.
    const newProject: ProjectDto = {
      id: 99n,
      slug: "Users-mauc-Repo-brand-new",
      path: "/Users/mauc/Repo/brand-new",
      name: "brand-new",
      created_at: "2026-04-26T11:00:00.000Z",
      last_scan: "2026-04-26T12:00:00.000Z",
    };
    await act(async () => {
      client.setQueryData(["projects"], [newProject, ...TWO_PROJECTS]);
      // Give the effect a tick to consider re-firing — it shouldn't.
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.getByTestId("url").textContent).toContain(
      "project=Users-mauc-Repo-Nalo-monorepo",
    );
    expect(screen.getByTestId("url").textContent).not.toContain(
      "Users-mauc-Repo-brand-new",
    );
  });
});

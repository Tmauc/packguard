import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import type { WorkspacesResponse } from "@/api/types/WorkspacesResponse";
import { WorkspaceSelector } from "@/components/layout/WorkspaceSelector";
import { WORKSPACE_SCOPE_STORAGE_KEY } from "@/components/layout/workspace-scope";
import { COLLAPSED_FOLDERS_STORAGE_KEY } from "@/lib/useCollapsedFolders";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      workspaces: vi.fn(),
      startScan: vi.fn(),
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
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route
            path="*"
            element={
              <>
                <WorkspaceSelector />
                <CurrentUrl />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const TWO_WORKSPACES: WorkspacesResponse = {
  workspaces: [
    {
      path: "/tmp/alpha",
      ecosystem: "npm",
      last_scan_at: "2026-04-21T10:00:00Z",
      fingerprint: "abc",
      dependency_count: 42,
    },
    {
      path: "/tmp/beta",
      ecosystem: "npm",
      last_scan_at: "2026-04-20T10:00:00Z",
      fingerprint: "def",
      dependency_count: 17,
    },
  ],
};

const NALO_LIKE: WorkspacesResponse = {
  workspaces: [
    {
      path: "/Users/mauc/Repo/Nalo/monorepo/front/vesta",
      ecosystem: "npm",
      last_scan_at: "2026-04-24T10:00:00Z",
      fingerprint: "v",
      dependency_count: 300,
    },
    {
      path: "/Users/mauc/Repo/Nalo/monorepo/front/mellona",
      ecosystem: "npm",
      last_scan_at: "2026-04-24T10:00:00Z",
      fingerprint: "m",
      dependency_count: 280,
    },
    {
      path: "/Users/mauc/Repo/Nalo/monorepo/services/backend",
      ecosystem: "pypi",
      last_scan_at: "2026-04-24T10:00:00Z",
      fingerprint: "b",
      dependency_count: 150,
    },
    {
      path: "/Users/mauc/Repo/Nalo/monorepo/services/accounting",
      ecosystem: "pypi",
      last_scan_at: "2026-04-24T10:00:00Z",
      fingerprint: "a",
      dependency_count: 120,
    },
  ],
};

async function openPicker() {
  const trigger = await screen.findByTestId("workspace-selector");
  const user = userEvent.setup();
  await user.click(trigger);
  await screen.findByTestId("workspace-picker");
  return user;
}

beforeEach(() => {
  (api.workspaces as ReturnType<typeof vi.fn>).mockReset();
  window.localStorage.clear();
});

describe("WorkspaceSelector", () => {
  it("renders the aggregate entry and every workspace leaf inside the popover", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    wrap();
    await openPicker();
    expect(screen.getByTestId("workspace-aggregate")).toHaveTextContent(
      /All workspaces/i,
    );
    expect(screen.getByTestId("workspace-leaf-/tmp/alpha")).toBeInTheDocument();
    expect(screen.getByTestId("workspace-leaf-/tmp/beta")).toBeInTheDocument();
  });

  it("writes ?project= into the URL and persists to localStorage when a leaf is clicked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    wrap();
    const user = await openPicker();
    await user.click(screen.getByTestId("workspace-leaf-/tmp/alpha"));
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).toContain("project=%2Ftmp%2Falpha"),
    );
    expect(window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY)).toBe("/tmp/alpha");
    // Popover auto-closes after picking.
    expect(screen.queryByTestId("workspace-picker")).not.toBeInTheDocument();
  });

  it("clears the scope (and localStorage) when the aggregate row is clicked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, "/tmp/alpha");
    wrap(["/?project=/tmp/alpha"]);
    const user = await openPicker();
    await user.click(screen.getByTestId("workspace-aggregate"));
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).not.toContain("project="),
    );
    expect(window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY)).toBeNull();
  });

  it("restores the last-picked workspace from localStorage when the URL is unscoped", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, "/tmp/beta");
    wrap(["/"]);
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).toContain("project=%2Ftmp%2Fbeta"),
    );
  });

  it("drops a stale localStorage value that is not in the known workspaces", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, "/tmp/gone");
    wrap(["/"]);
    await waitFor(() =>
      expect(window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY)).toBeNull(),
    );
    expect(screen.getByTestId("url").textContent).not.toContain("project=");
  });

  it("shows the empty-state CTA that opens the add-workspace modal when nothing has been scanned", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue({ workspaces: [] });
    wrap();
    const cta = (await screen.findByTestId("workspace-empty-cta")) as HTMLButtonElement;
    expect(cta).toHaveTextContent(/No workspaces yet/i);
    expect(cta).not.toBeDisabled();
    const user = userEvent.setup();
    await user.click(cta);
    expect(await screen.findByTestId("add-workspace-modal")).toBeInTheDocument();
  });

  it("exposes a footer 'Scan new path' button that opens the add-workspace modal", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    wrap();
    const user = await openPicker();
    await user.click(screen.getByTestId("workspace-add-cta"));
    expect(await screen.findByTestId("add-workspace-modal")).toBeInTheDocument();
    // Opening the modal also closes the picker so the backdrop click
    // is unambiguous.
    expect(screen.queryByTestId("workspace-picker")).not.toBeInTheDocument();
  });

  it("groups a Nalo-style monorepo into folders under a common prefix", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    await openPicker();
    // The `/Users/mauc/Repo/Nalo/monorepo/` prefix is stripped — what
    // survives is a `front` folder (vesta + mellona) and a `services`
    // folder (backend + accounting).
    expect(screen.getByTestId("workspace-folder-front")).toBeInTheDocument();
    expect(screen.getByTestId("workspace-folder-services")).toBeInTheDocument();
  });

  it("defaults all folders to expanded on first mount", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    await openPicker();
    // No prior collapse state in localStorage → every folder is open
    // and every leaf is reachable without clicking a chevron.
    expect(
      screen.getByTestId("workspace-folder-front").getAttribute("data-expanded"),
    ).toBe("true");
    expect(
      screen.getByTestId("workspace-folder-services").getAttribute("data-expanded"),
    ).toBe("true");
    expect(
      screen.getByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/services/backend"),
    ).toBeInTheDocument();
  });

  it("preserves a folder's collapsed state from localStorage across mounts", async () => {
    window.localStorage.setItem(
      COLLAPSED_FOLDERS_STORAGE_KEY,
      JSON.stringify(["front"]),
    );
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    await openPicker();
    // The user collapsed `front` in a previous session — the choice
    // sticks. The unrelated `services` folder still defaults to open.
    expect(
      screen.getByTestId("workspace-folder-front").getAttribute("data-expanded"),
    ).toBe("false");
    expect(
      screen.queryByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByTestId("workspace-folder-services").getAttribute("data-expanded"),
    ).toBe("true");
  });

  it("auto-expands folders that contain a fuzzy-search match and highlights the match", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    const user = await openPicker();
    const search = screen.getByTestId("workspace-search") as HTMLInputElement;
    await user.type(search, "vesta");
    // The `front` folder auto-expands → the matching leaf appears with
    // a <mark> highlight on the matched substring.
    const leaf = await screen.findByTestId(
      "workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta",
    );
    expect(leaf.querySelector("mark")).toHaveTextContent(/vesta/i);
    // The sibling that doesn't match is filtered out.
    expect(
      screen.queryByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/mellona"),
    ).not.toBeInTheDocument();
    // The unrelated `services` folder is hidden too since none of its
    // leaves match.
    expect(
      screen.queryByTestId("workspace-folder-services"),
    ).not.toBeInTheDocument();
  });

  it("shows the empty-state when no leaf matches the query but the aggregate entry stays visible", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    const user = await openPicker();
    await user.type(screen.getByTestId("workspace-search"), "zzzzzz");
    expect(
      await screen.findByTestId("workspace-empty-state"),
    ).toHaveTextContent(/No workspace matches/i);
    // Aggregate row is never filtered — it stays at the top regardless
    // of the query.
    expect(screen.getByTestId("workspace-aggregate")).toBeInTheDocument();
  });

  it("tracks the scan job the modal starts and auto-switches scope when it succeeds", async () => {
    // Start with one existing workspace so the trigger is not in the
    // empty-CTA branch. After the scan completes, the next
    // /api/workspaces refetch includes the new path → the selector's
    // pendingScan effect calls setScope(newPath).
    const newPath = "/tmp/from-ui-scan";
    (api.workspaces as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(TWO_WORKSPACES)
      // After invalidation, the workspace list includes the newly
      // scanned path alongside the existing pair.
      .mockResolvedValue({
        workspaces: [
          ...TWO_WORKSPACES.workspaces,
          {
            path: newPath,
            ecosystem: "npm",
            last_scan_at: "2026-04-24T12:00:00Z",
            fingerprint: "n",
            dependency_count: 5,
          },
        ],
      });
    (api.startScan as ReturnType<typeof vi.fn>).mockResolvedValue({ id: "job-from-ui" });
    (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "job-from-ui",
      kind: "scan",
      status: "succeeded",
      started_at: "2026-04-24T12:00:00Z",
      finished_at: "2026-04-24T12:00:05Z",
      result: { projects_scanned: 1 },
      error: null,
    });
    wrap();
    const user = await openPicker();
    await user.click(screen.getByTestId("workspace-add-cta"));
    const input = await screen.findByTestId("add-workspace-path-input");
    await user.type(input, newPath);
    await user.click(screen.getByTestId("add-workspace-submit"));
    await waitFor(() =>
      expect(api.startScan).toHaveBeenCalledWith(newPath),
    );
    // useJobStatus's poller (real here) hits /api/jobs/:id, sees the
    // succeeded mock, and invalidates queries → the URL flips to
    // ?project=<newPath> once the pendingScan effect runs.
    await waitFor(
      () =>
        expect(screen.getByTestId("url").textContent).toContain(
          `project=${encodeURIComponent(newPath)}`,
        ),
      { timeout: 3000 },
    );
  });

  it("toggles folder collapse when its chevron button is clicked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    const user = await openPicker();
    const frontFolder = screen.getByTestId("workspace-folder-front");
    // Default-expanded: the first click collapses, the second re-opens.
    expect(frontFolder.getAttribute("data-expanded")).toBe("true");
    await user.click(frontFolder);
    expect(screen.getByTestId("workspace-folder-front").getAttribute("data-expanded")).toBe(
      "false",
    );
    expect(
      screen.queryByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).not.toBeInTheDocument();
    await user.click(screen.getByTestId("workspace-folder-front"));
    expect(screen.getByTestId("workspace-folder-front").getAttribute("data-expanded")).toBe(
      "true",
    );
    expect(
      screen.getByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).toBeInTheDocument();
  });
});

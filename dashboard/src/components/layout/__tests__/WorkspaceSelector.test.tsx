import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import type { WorkspacesResponse } from "@/api/types/WorkspacesResponse";
import { WorkspaceSelector } from "@/components/layout/WorkspaceSelector";
import { WORKSPACE_SCOPE_STORAGE_KEY } from "@/components/layout/workspace-scope";

vi.mock("@/lib/api", () => ({ api: { workspaces: vi.fn() } }));

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

  it("disables the trigger when no workspaces have been scanned", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue({ workspaces: [] });
    wrap();
    const trigger = (await screen.findByTestId("workspace-selector")) as HTMLButtonElement;
    await waitFor(() => expect(trigger).toBeDisabled());
    expect(trigger).toHaveTextContent(/No scans yet/i);
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
    // Folders start collapsed: the leaves aren't in the DOM until the
    // chevron is clicked.
    expect(
      screen.queryByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).not.toBeInTheDocument();
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

  it("toggles folder collapse when its chevron button is clicked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(NALO_LIKE);
    wrap();
    const user = await openPicker();
    const frontFolder = screen.getByTestId("workspace-folder-front");
    expect(frontFolder.getAttribute("data-expanded")).toBe("false");
    await user.click(frontFolder);
    expect(screen.getByTestId("workspace-folder-front").getAttribute("data-expanded")).toBe(
      "true",
    );
    // Children now visible.
    expect(
      screen.getByTestId("workspace-leaf-/Users/mauc/Repo/Nalo/monorepo/front/vesta"),
    ).toBeInTheDocument();
  });
});

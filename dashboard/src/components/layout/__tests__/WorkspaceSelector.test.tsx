import { render, screen, waitFor, act } from "@testing-library/react";
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

beforeEach(() => {
  (api.workspaces as ReturnType<typeof vi.fn>).mockReset();
  window.localStorage.clear();
});

describe("WorkspaceSelector", () => {
  it("renders every workspace plus an aggregate option", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    wrap();
    await waitFor(() =>
      expect(screen.getByRole("option", { name: /alpha · 42 deps/i })).toBeInTheDocument(),
    );
    expect(screen.getByRole("option", { name: /beta · 17 deps/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /All workspaces/i })).toBeInTheDocument();
  });

  it("writes ?project= into the URL when a workspace is picked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    wrap();
    const select = (await screen.findByTestId("workspace-selector")) as HTMLSelectElement;
    // Wait for the async react-query fetch to populate options.
    await waitFor(() =>
      expect(screen.getByRole("option", { name: /alpha · 42 deps/i })).toBeInTheDocument(),
    );
    const user = userEvent.setup();
    await user.selectOptions(select, "/tmp/alpha");
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).toContain("project=%2Ftmp%2Falpha"),
    );
    expect(window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY)).toBe("/tmp/alpha");
  });

  it("clears the scope (and localStorage) when the aggregate option is picked", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, "/tmp/alpha");
    wrap(["/?project=/tmp/alpha"]);
    const select = (await screen.findByTestId("workspace-selector")) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe("/tmp/alpha"));
    const user = userEvent.setup();
    await user.selectOptions(select, "__aggregate__");
    await waitFor(() =>
      expect(screen.getByTestId("url").textContent).not.toContain("project="),
    );
    expect(window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY)).toBeNull();
  });

  it("restores the last-picked workspace from localStorage when the URL is unscoped", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue(TWO_WORKSPACES);
    window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, "/tmp/beta");
    wrap(["/"]);
    // The restore effect fires after /api/workspaces lands.
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

  it("disables the selector when no workspaces have been scanned", async () => {
    (api.workspaces as ReturnType<typeof vi.fn>).mockResolvedValue({ workspaces: [] });
    wrap();
    const select = (await screen.findByTestId("workspace-selector")) as HTMLSelectElement;
    await waitFor(() => expect(select).toBeDisabled());
    expect(screen.getByRole("option", { name: /No scans yet/i })).toBeInTheDocument();
  });
});

// Touch `act` so the strict-mode helper is exercised; avoids unused-import
// lint on setups that don't need explicit async act wrapping.
void act;

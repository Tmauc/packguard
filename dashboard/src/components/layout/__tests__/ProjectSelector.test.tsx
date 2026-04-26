import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import type { ProjectDto } from "@/api/types/ProjectDto";
import { ProjectSelector } from "@/components/layout/ProjectSelector";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      projects: vi.fn(),
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
                <ProjectSelector />
                <CurrentUrl />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Two projects: monorepo is the most recently scanned (2h ago against
// real wall-clock time), other has never been scanned. Building
// last_scan from `Date.now()` avoids needing fake timers (which would
// freeze React Query's setTimeout-driven scheduling and cause every
// test to time out).
function makeProjects(): ProjectDto[] {
  const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
  return [
    {
      id: 1n,
      slug: "Users-mauc-Repo-Nalo-monorepo",
      path: "/Users/mauc/Repo/Nalo/monorepo",
      name: "monorepo",
      created_at: "2026-04-20T10:00:00Z",
      last_scan: twoHoursAgo,
    },
    {
      id: 2n,
      slug: "Users-mauc-Repo-AnotherCo-foo",
      path: "/Users/mauc/Repo/AnotherCo/foo",
      name: "foo",
      created_at: "2026-04-23T10:00:00Z",
      last_scan: null,
    },
  ];
}

beforeEach(() => {
  window.localStorage.clear();
});

async function openPicker() {
  const trigger = await screen.findByTestId("project-selector");
  const user = userEvent.setup();
  await user.click(trigger);
  await screen.findByTestId("project-picker");
  return user;
}

describe("ProjectSelector", () => {
  it("renders the active project's name in the trigger when scoped", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/?project=Users-mauc-Repo-Nalo-monorepo"]);
    await waitFor(() => {
      expect(screen.getByTestId("project-selector")).toHaveTextContent(
        "monorepo",
      );
    });
  });

  it("falls back to 'Select project' when scope is unset but projects exist", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    await waitFor(() => {
      expect(screen.getByTestId("project-selector")).toHaveTextContent(
        "Select project",
      );
    });
  });

  it("renders 'No project' when the projects list is empty", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    wrap(["/"]);
    await waitFor(() => {
      expect(screen.getByTestId("project-selector")).toHaveTextContent(
        "No project",
      );
    });
  });

  it("lists projects with their relative last_scan time", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    await openPicker();
    const monorepo = screen.getByTestId(
      "project-row-Users-mauc-Repo-Nalo-monorepo",
    );
    expect(monorepo).toHaveTextContent("monorepo");
    expect(monorepo).toHaveTextContent("/Users/mauc/Repo/Nalo/monorepo");
    expect(monorepo).toHaveTextContent("2h ago");

    const foo = screen.getByTestId("project-row-Users-mauc-Repo-AnotherCo-foo");
    expect(foo).toHaveTextContent("foo");
    expect(foo).toHaveTextContent("never scanned");
  });

  it("marks the active project with data-active=true", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/?project=Users-mauc-Repo-Nalo-monorepo"]);
    await openPicker();
    const monorepo = screen.getByTestId(
      "project-row-Users-mauc-Repo-Nalo-monorepo",
    );
    expect(monorepo).toHaveAttribute("data-active", "true");
    const foo = screen.getByTestId("project-row-Users-mauc-Repo-AnotherCo-foo");
    expect(foo).toHaveAttribute("data-active", "false");
  });

  it("switches scope (URL + localStorage) when a row is clicked", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    const user = await openPicker();
    await user.click(
      screen.getByTestId("project-row-Users-mauc-Repo-AnotherCo-foo"),
    );
    await waitFor(() => {
      expect(screen.getByTestId("url").textContent).toContain(
        "project=Users-mauc-Repo-AnotherCo-foo",
      );
    });
    expect(window.localStorage.getItem("packguard.projectScope")).toBe(
      "Users-mauc-Repo-AnotherCo-foo",
    );
  });

  it("filters rows by name / slug / path substring", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    const user = await openPicker();
    await user.type(screen.getByTestId("project-search"), "monorepo");
    expect(
      screen.queryByTestId("project-row-Users-mauc-Repo-Nalo-monorepo"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("project-row-Users-mauc-Repo-AnotherCo-foo"),
    ).not.toBeInTheDocument();
  });

  it("shows the no-match empty state when the filter excludes everything", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    const user = await openPicker();
    await user.type(screen.getByTestId("project-search"), "zzz-impossible");
    expect(screen.getByTestId("project-no-match")).toBeInTheDocument();
  });

  it("renders a disabled 'Add new project' footer slot (14.3c placeholder)", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue(makeProjects());
    wrap(["/"]);
    await openPicker();
    const cta = screen.getByTestId("project-add-cta");
    expect(cta).toBeDisabled();
  });
});

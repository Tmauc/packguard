import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AddProjectModal } from "@/components/layout/AddProjectModal";
import { ApiError } from "@/lib/api";
import { PROJECT_SCOPE_STORAGE_KEY } from "@/components/layout/workspace-scope";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      startAddProject: vi.fn(),
      job: vi.fn(),
    },
  };
});

vi.mock("sonner", () => ({
  toast: {
    message: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
  },
}));

import { api } from "@/lib/api";
import { toast } from "sonner";

function wrap(
  open: boolean,
  handlers: {
    onClose?: () => void;
    onStarted?: (id: string, path: string) => void;
  } = {},
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <AddProjectModal
          open={open}
          onClose={handlers.onClose ?? (() => {})}
          onStarted={handlers.onStarted ?? (() => {})}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  (api.startAddProject as ReturnType<typeof vi.fn>).mockReset();
  (api.job as ReturnType<typeof vi.fn>).mockReset();
  (toast.success as ReturnType<typeof vi.fn>).mockReset();
  (toast.error as ReturnType<typeof vi.fn>).mockReset();
  window.localStorage.clear();
});

describe("AddProjectModal", () => {
  it("rejects empty input with an inline error before calling the server", async () => {
    wrap(true);
    const user = userEvent.setup();
    await user.click(screen.getByTestId("add-project-submit"));
    expect(screen.getByTestId("add-project-error")).toHaveTextContent(
      /Path is required/i,
    );
    expect(api.startAddProject).not.toHaveBeenCalled();
  });

  it("rejects a relative path with an inline error before calling the server", async () => {
    wrap(true);
    const user = userEvent.setup();
    await user.type(
      screen.getByTestId("add-project-path-input"),
      "relative/path",
    );
    await user.click(screen.getByTestId("add-project-submit"));
    expect(screen.getByTestId("add-project-error")).toHaveTextContent(
      /must be absolute/i,
    );
    expect(api.startAddProject).not.toHaveBeenCalled();
  });

  it("submits an absolute path and stays open while the job is pending", async () => {
    (api.startAddProject as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "job-add-1",
    });
    // Job poller never resolves to terminal state — modal must keep
    // displaying "Registering…" without closing.
    (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "job-add-1",
      kind: "add_project",
      status: "running",
      started_at: "2026-04-26T12:00:00Z",
      finished_at: null,
      result: null,
      error: null,
    });
    const onClose = vi.fn();
    const onStarted = vi.fn();
    wrap(true, { onClose, onStarted });
    const user = userEvent.setup();
    await user.type(
      screen.getByTestId("add-project-path-input"),
      "/Users/me/Repo/proj",
    );
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(api.startAddProject).toHaveBeenCalledWith("/Users/me/Repo/proj"),
    );
    await waitFor(() =>
      expect(onStarted).toHaveBeenCalledWith("job-add-1", "/Users/me/Repo/proj"),
    );
    await waitFor(() =>
      expect(screen.getByTestId("add-project-submit")).toHaveTextContent(
        /Registering…/,
      ),
    );
    expect(onClose).not.toHaveBeenCalled();
  });

  it("surfaces a 400 from POST /api/projects inline and keeps the modal open", async () => {
    (api.startAddProject as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiError(
        "bad_request",
        "bad request: path /tmp/nope is not inside a git repository",
        400,
      ),
    );
    const onClose = vi.fn();
    wrap(true, { onClose });
    const user = userEvent.setup();
    await user.type(
      screen.getByTestId("add-project-path-input"),
      "/tmp/nope",
    );
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-error")).toHaveTextContent(
        /not inside a git repository/i,
      ),
    );
    expect(onClose).not.toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("surfaces a 5xx as a toast AND inline so the user sees the failure", async () => {
    (api.startAddProject as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiError("internal", "internal: server exploded", 500),
    );
    wrap(true);
    const user = userEvent.setup();
    await user.type(screen.getByTestId("add-project-path-input"), "/a/b/c");
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(screen.getByTestId("add-project-error")).toHaveTextContent(
      /server exploded/i,
    );
  });

  it(
    "on job succeeded: invalidates queries, sets project scope to the new slug, toasts, and closes",
    async () => {
      (api.startAddProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-add-2",
      });
      // First /api/jobs/:id call returns succeeded with the documented
      // outcome shape (jobs.rs:139-142).
      (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-add-2",
        kind: "add_project",
        status: "succeeded",
        started_at: "2026-04-26T12:00:00Z",
        finished_at: "2026-04-26T12:00:01Z",
        result: {
          project: {
            id: 7,
            slug: "Users-me-Repo-newone",
            path: "/Users/me/Repo/newone",
            name: "newone",
            created_at: "2026-04-26T12:00:00Z",
            last_scan: "2026-04-26T12:00:01Z",
          },
          scan: { dependencies_added: 12 },
        },
        error: null,
      });
      const onClose = vi.fn();
      wrap(true, { onClose });
      const user = userEvent.setup();
      await user.type(
        screen.getByTestId("add-project-path-input"),
        "/Users/me/Repo/newone",
      );
      await user.click(screen.getByTestId("add-project-submit"));
      // The shared useJobStatus tracker polls every 1s; assertion
      // waits for the modal to react.
      await waitFor(
        () => expect(onClose).toHaveBeenCalledTimes(1),
        { timeout: 4000 },
      );
      // Scope persisted to localStorage via setProjectScope.
      expect(window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY)).toBe(
        "Users-me-Repo-newone",
      );
      // Project-specific success toast (in addition to the generic
      // one fired by the shared tracker).
      expect(toast.success).toHaveBeenCalledWith(
        "Project registered",
        expect.objectContaining({
          description: expect.stringContaining("newone"),
        }),
      );
    },
    8000,
  );

  it(
    "on job failed (e.g. duplicate path / UNIQUE violation): surfaces error inline and keeps modal open",
    async () => {
      (api.startAddProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-add-3",
      });
      (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-add-3",
        kind: "add_project",
        status: "failed",
        started_at: "2026-04-26T12:00:00Z",
        finished_at: "2026-04-26T12:00:01Z",
        result: null,
        error:
          "inserting project Users-me-Repo-foo into registry: UNIQUE constraint failed: projects.slug",
      });
      const onClose = vi.fn();
      wrap(true, { onClose });
      const user = userEvent.setup();
      await user.type(
        screen.getByTestId("add-project-path-input"),
        "/Users/me/Repo/foo",
      );
      await user.click(screen.getByTestId("add-project-submit"));
      await waitFor(
        () =>
          expect(screen.getByTestId("add-project-error")).toHaveTextContent(
            /UNIQUE constraint failed/i,
          ),
        { timeout: 4000 },
      );
      expect(onClose).not.toHaveBeenCalled();
    },
    8000,
  );

  it("closes when the user presses Escape", async () => {
    const onClose = vi.fn();
    wrap(true, { onClose });
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

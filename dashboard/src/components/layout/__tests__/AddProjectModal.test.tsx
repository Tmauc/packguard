import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AddProjectModal } from "@/components/layout/AddProjectModal";
import { ApiError } from "@/lib/api";
import { PROJECT_SCOPE_STORAGE_KEY } from "@/components/layout/workspace-scope";
import type { ProjectDto } from "@/api/types/ProjectDto";
import type { FsBrowseResponse } from "@/api/types/FsBrowseResponse";
import type { FsRootsResponse } from "@/api/types/FsRootsResponse";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      startAddProject: vi.fn(),
      job: vi.fn(),
      projects: vi.fn(),
      fsRoots: vi.fn(),
      fsBrowse: vi.fn(),
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

const HOME = "/Users/mauc";

const ROOTS: FsRootsResponse = {
  home: HOME,
  entries: [
    { label: "$HOME", path: HOME },
    { label: "$HOME/Repo", path: `${HOME}/Repo` },
  ],
};

function browseResponse(
  path: string,
  entries: FsBrowseResponse["entries"],
  opts: { parent?: string | null; truncated?: boolean } = {},
): FsBrowseResponse {
  return {
    path,
    parent: opts.parent ?? null,
    entries,
    truncated: opts.truncated ?? false,
  };
}

const MONOREPO_PROJECT: ProjectDto = {
  id: 1n,
  slug: "Users-mauc-Repo-monorepo",
  path: `${HOME}/Repo/monorepo`,
  name: "monorepo",
  created_at: "2026-04-20T10:00:00Z",
  last_scan: "2026-04-26T09:00:00.000Z",
};

beforeEach(() => {
  (api.startAddProject as ReturnType<typeof vi.fn>).mockReset();
  (api.job as ReturnType<typeof vi.fn>).mockReset();
  (api.projects as ReturnType<typeof vi.fn>).mockReset();
  (api.fsRoots as ReturnType<typeof vi.fn>).mockReset();
  (api.fsBrowse as ReturnType<typeof vi.fn>).mockReset();
  (toast.success as ReturnType<typeof vi.fn>).mockReset();
  (toast.error as ReturnType<typeof vi.fn>).mockReset();
  (toast.message as ReturnType<typeof vi.fn>).mockReset();
  window.localStorage.clear();

  // Default mocks: empty projects list, simple roots, $HOME with one
  // subdir. Tests override per-case.
  (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  (api.fsRoots as ReturnType<typeof vi.fn>).mockResolvedValue(ROOTS);
  (api.fsBrowse as ReturnType<typeof vi.fn>).mockImplementation(
    async (path?: string) => {
      const target = path ?? HOME;
      if (target === HOME) {
        return browseResponse(HOME, [
          { name: "Repo", path: `${HOME}/Repo`, has_git: false, has_manifest: false },
        ]);
      }
      return browseResponse(target, [], { parent: HOME });
    },
  );
});

describe("AddProjectModal — browse mode", () => {
  it("loads roots and lands on $HOME on first mount", async () => {
    wrap(true);
    await waitFor(() =>
      expect(screen.getByTestId("add-project-roots")).toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(screen.getByTestId("add-project-root-$HOME")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("add-project-root-$HOME/Repo")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId("add-project-selected")).toHaveTextContent(
        `Selected: ${HOME}`,
      ),
    );
  });

  it("renders entry rows with git + manifest badges", async () => {
    (api.fsBrowse as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      browseResponse(HOME, [
        { name: "alpha", path: `${HOME}/alpha`, has_git: true, has_manifest: true },
        { name: "beta", path: `${HOME}/beta`, has_git: false, has_manifest: false },
      ]),
    );
    wrap(true);
    await waitFor(() =>
      expect(screen.getByTestId("add-project-entry-alpha")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("add-project-entry-git-alpha")).toBeInTheDocument();
    expect(
      screen.getByTestId("add-project-entry-manifest-alpha"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("add-project-entry-git-beta"),
    ).not.toBeInTheDocument();
  });

  it("navigates into a subdir when an entry is clicked", async () => {
    (api.fsBrowse as ReturnType<typeof vi.fn>).mockImplementation(
      async (path?: string) => {
        const target = path ?? HOME;
        if (target === HOME) {
          return browseResponse(HOME, [
            { name: "Repo", path: `${HOME}/Repo`, has_git: false, has_manifest: false },
          ]);
        }
        if (target === `${HOME}/Repo`) {
          return browseResponse(
            `${HOME}/Repo`,
            [
              {
                name: "monorepo",
                path: `${HOME}/Repo/monorepo`,
                has_git: true,
                has_manifest: false,
              },
            ],
            { parent: HOME },
          );
        }
        return browseResponse(target, [], { parent: `${HOME}/Repo` });
      },
    );
    wrap(true);
    await waitFor(() =>
      expect(screen.getByTestId("add-project-entry-Repo")).toBeInTheDocument(),
    );
    const user = userEvent.setup();
    await user.click(screen.getByTestId("add-project-entry-Repo"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-entry-monorepo")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("add-project-selected")).toHaveTextContent(
      `Selected: ${HOME}/Repo`,
    );
  });

  it("navigates back to the parent via the breadcrumb", async () => {
    (api.fsBrowse as ReturnType<typeof vi.fn>).mockImplementation(
      async (path?: string) => {
        const target = path ?? HOME;
        if (target === `${HOME}/Repo`) {
          return browseResponse(`${HOME}/Repo`, [], { parent: HOME });
        }
        return browseResponse(target, [
          { name: "Repo", path: `${HOME}/Repo`, has_git: false, has_manifest: false },
        ]);
      },
    );
    wrap(true);
    const user = userEvent.setup();
    // Navigate down via the Repo quick-root.
    await waitFor(() =>
      expect(screen.getByTestId("add-project-root-$HOME/Repo")).toBeInTheDocument(),
    );
    await user.click(screen.getByTestId("add-project-root-$HOME/Repo"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-selected")).toHaveTextContent(
        `Selected: ${HOME}/Repo`,
      ),
    );
    // First crumb is "$HOME" — clicking it walks back up.
    await user.click(screen.getByTestId("add-project-crumb-0"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-selected")).toHaveTextContent(
        `Selected: ${HOME}`,
      ),
    );
  });

  it("quick-root jump sets the current path immediately", async () => {
    wrap(true);
    const user = userEvent.setup();
    await waitFor(() =>
      expect(screen.getByTestId("add-project-root-$HOME/Repo")).toBeInTheDocument(),
    );
    await user.click(screen.getByTestId("add-project-root-$HOME/Repo"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-selected")).toHaveTextContent(
        `Selected: ${HOME}/Repo`,
      ),
    );
  });

  it("'Select this folder' submits the current path, not an entry", async () => {
    (api.startAddProject as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "job-x",
    });
    (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "job-x",
      kind: "add_project",
      status: "running",
      started_at: "2026-04-26T12:00:00Z",
      finished_at: null,
      result: null,
      error: null,
    });
    wrap(true);
    const user = userEvent.setup();
    // Navigate from $HOME (where Submit is disabled) into Repo.
    await waitFor(() =>
      expect(screen.getByTestId("add-project-root-$HOME/Repo")).toBeInTheDocument(),
    );
    await user.click(screen.getByTestId("add-project-root-$HOME/Repo"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-submit")).not.toBeDisabled(),
    );
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(api.startAddProject).toHaveBeenCalledWith(`${HOME}/Repo`),
    );
  });

  it("flags already-registered entries with a badge", async () => {
    (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue([
      MONOREPO_PROJECT,
    ]);
    (api.fsBrowse as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      browseResponse(HOME, [
        {
          name: "monorepo",
          path: `${HOME}/Repo/monorepo`,
          has_git: true,
          has_manifest: false,
        },
        {
          name: "other",
          path: `${HOME}/other`,
          has_git: false,
          has_manifest: false,
        },
      ]),
    );
    wrap(true);
    await waitFor(() =>
      expect(
        screen.getByTestId("add-project-entry-registered-monorepo"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByTestId("add-project-entry-registered-other"),
    ).not.toBeInTheDocument();
  });

  it(
    "switches scope to existing project (no POST) when current path is registered",
    async () => {
      (api.projects as ReturnType<typeof vi.fn>).mockResolvedValue([
        MONOREPO_PROJECT,
      ]);
      // Browse query for $HOME returns the monorepo entry; navigating into
      // it makes currentPath === MONOREPO_PROJECT.path → button flips.
      (api.fsBrowse as ReturnType<typeof vi.fn>).mockImplementation(
        async (path?: string) => {
          const target = path ?? HOME;
          if (target === HOME) {
            return browseResponse(HOME, [
              {
                name: "monorepo",
                path: MONOREPO_PROJECT.path,
                has_git: true,
                has_manifest: false,
              },
            ]);
          }
          return browseResponse(target, [], { parent: HOME });
        },
      );
      const onClose = vi.fn();
      wrap(true, { onClose });
      const user = userEvent.setup();
      await waitFor(() =>
        expect(screen.getByTestId("add-project-entry-monorepo")).toBeInTheDocument(),
      );
      await user.click(screen.getByTestId("add-project-entry-monorepo"));
      await waitFor(() =>
        expect(screen.getByTestId("add-project-submit")).toHaveTextContent(
          /Switch to existing project/,
        ),
      );
      await user.click(screen.getByTestId("add-project-submit"));
      // No POST fired — the modal closed via the switch shortcut.
      expect(api.startAddProject).not.toHaveBeenCalled();
      expect(window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY)).toBe(
        MONOREPO_PROJECT.slug,
      );
      expect(onClose).toHaveBeenCalledTimes(1);
    },
  );

  it("shows the truncation hint when the response is truncated", async () => {
    (api.fsBrowse as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      browseResponse(
        HOME,
        [{ name: "alpha", path: `${HOME}/alpha`, has_git: false, has_manifest: false }],
        { truncated: true },
      ),
    );
    wrap(true);
    await waitFor(() =>
      expect(screen.getByTestId("add-project-truncated")).toBeInTheDocument(),
    );
  });
});

describe("AddProjectModal — type-path mode", () => {
  it("type mode preserves the v0.5 input + absolute-path validation", async () => {
    wrap(true);
    const user = userEvent.setup();
    await user.click(screen.getByTestId("add-project-mode-type"));
    await user.type(
      screen.getByTestId("add-project-path-input"),
      "relative/path",
    );
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-error")).toHaveTextContent(
        /must be absolute/i,
      ),
    );
    expect(api.startAddProject).not.toHaveBeenCalled();
  });

  it("toggling between modes clears the error so prior state doesn't leak", async () => {
    wrap(true);
    const user = userEvent.setup();
    // Cause an error in type mode.
    await user.click(screen.getByTestId("add-project-mode-type"));
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-error")).toBeInTheDocument(),
    );
    // Switch back to browse — error should disappear.
    await user.click(screen.getByTestId("add-project-mode-browse"));
    await waitFor(() =>
      expect(screen.queryByTestId("add-project-error")).not.toBeInTheDocument(),
    );
  });

  it(
    "surfaces a UNIQUE-constraint error inline (already-registered path)",
    async () => {
      (api.startAddProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-uniq",
      });
      (api.job as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: "job-uniq",
        kind: "add_project",
        status: "failed",
        started_at: "2026-04-26T12:00:00Z",
        finished_at: "2026-04-26T12:00:01Z",
        result: null,
        error:
          "inserting project Users-mauc-Repo-foo into registry: UNIQUE constraint failed: projects.path",
      });
      wrap(true);
      const user = userEvent.setup();
      await user.click(screen.getByTestId("add-project-mode-type"));
      await user.type(
        screen.getByTestId("add-project-path-input"),
        "/Users/mauc/Repo/foo",
      );
      await user.click(screen.getByTestId("add-project-submit"));
      await waitFor(
        () =>
          expect(screen.getByTestId("add-project-error")).toHaveTextContent(
            /UNIQUE constraint failed/i,
          ),
        { timeout: 4000 },
      );
    },
    8000,
  );

  it("synchronous 400 from the server surfaces inline (path doesn't exist)", async () => {
    (api.startAddProject as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiError(
        "bad_request",
        "bad request: path does not exist: /tmp/nope",
        400,
      ),
    );
    wrap(true);
    const user = userEvent.setup();
    await user.click(screen.getByTestId("add-project-mode-type"));
    await user.type(screen.getByTestId("add-project-path-input"), "/tmp/nope");
    await user.click(screen.getByTestId("add-project-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("add-project-error")).toHaveTextContent(
        /does not exist/,
      ),
    );
  });
});

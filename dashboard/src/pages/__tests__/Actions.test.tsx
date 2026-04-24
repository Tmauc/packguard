import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { ActionsPage } from "@/pages/Actions";
import type { Action } from "@/api/types/Action";
import type { ActionsResponse } from "@/api/types/ActionsResponse";

vi.mock("@/lib/api", () => ({
  api: {
    actions: vi.fn(),
    dismissAction: vi.fn(),
    deferAction: vi.fn(),
    restoreAction: vi.fn(),
  },
}));

import { api } from "@/lib/api";

function wrap(initialEntries: string[] = ["/actions"]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/actions" element={<ActionsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function pkgAction(
  partial: Partial<Action> & Pick<Action, "id" | "kind" | "severity">,
): Action {
  // Use `in` checks — `??` would replace an explicit `null` override
  // with the default, which silently breaks the `suggested_command: null`
  // fallback test.
  const pick = <K extends keyof Action>(key: K, fallback: Action[K]): Action[K] =>
    key in partial ? (partial[key] as Action[K]) : fallback;
  return {
    id: partial.id,
    kind: partial.kind,
    severity: partial.severity,
    workspace: pick("workspace", "/repo/app"),
    target: pick("target", {
      kind: "Package",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.20",
    }),
    title: pick("title", "lodash@4.17.20 → fix"),
    explanation: pick("explanation", "Advisory affects the installed version."),
    suggested_command: pick("suggested_command", "pnpm add lodash@^4.17.21"),
    recommended_version: pick("recommended_version", "4.17.21"),
    dismissed_at: pick("dismissed_at", null),
    deferred_until: pick("deferred_until", null),
  };
}

function resp(actions: Action[], total?: number): ActionsResponse {
  return { actions, total: total ?? actions.length };
}

beforeEach(() => {
  (api.actions as ReturnType<typeof vi.fn>).mockReset();
});

describe("ActionsPage", () => {
  it("groups actions by severity with Malware first", async () => {
    // Phase 12-fix: Malware now sits above Critical in SEVERITY_ORDER.
    // Seed one row per severity tier and assert the headers land in
    // the right DOM order.
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "info-1",
          kind: "RescanStale",
          severity: "Info",
          target: { kind: "Workspace" },
          title: "Workspace scanned 5d ago",
          suggested_command: "packguard scan .",
          recommended_version: null,
        }),
        pkgAction({
          id: "mal-1",
          kind: "FixMalware",
          severity: "Malware",
          title: "posthog-js@1.82.0 flagged as malware (MAL-2026-12)",
        }),
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
          title: "lodash@4.17.20 → fix CVE-2021-99999",
        }),
        pkgAction({
          id: "high-1",
          kind: "FixCveHigh",
          severity: "High",
          title: "lodash@4.17.20 → fix CVE-2021-23337",
        }),
      ]),
    );
    wrap();
    const malware = await screen.findByRole("heading", { name: "Malware" });
    const critical = screen.getByRole("heading", { name: "Critical" });
    const high = screen.getByRole("heading", { name: "High" });
    const info = screen.getByRole("heading", { name: "Info" });
    // Malware > Critical > High > Info.
    expect(malware.compareDocumentPosition(critical)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(critical.compareDocumentPosition(high)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(high.compareDocumentPosition(info)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
  });

  it("renders workspace-agnostic actions in the global banner, not in the severity list", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "global-1",
          kind: "RefreshSync",
          severity: "Info",
          workspace: "_global",
          target: { kind: "Workspace" },
          title: "Advisory DB 9d stale — refresh",
          suggested_command: "packguard sync",
          recommended_version: null,
        }),
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
        }),
      ]),
    );
    wrap();
    expect(
      await screen.findByText("Advisory DB 9d stale — refresh"),
    ).toBeInTheDocument();
    // Global item must NOT live inside the Critical/High/Info section body.
    const infoHeader = screen.queryByRole("heading", { name: "Info" });
    expect(infoHeader).toBeNull();
    // And Critical is still rendered separately.
    expect(
      screen.getByRole("heading", { name: "Critical" }),
    ).toBeInTheDocument();
  });

  it("copies suggested_command to clipboard and toggles feedback", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
          suggested_command: "pnpm add next@^15.5.15",
        }),
      ]),
    );
    // user-event 14 installs its own fake clipboard on setup(). Reading
    // it back round-trips the real writeText call from the component,
    // which is exactly what we want to assert.
    const user = userEvent.setup();
    wrap();
    const copy = await screen.findByRole("button", { name: /Copy fix/i });
    await user.click(copy);
    await waitFor(async () => {
      expect(await navigator.clipboard.readText()).toBe(
        "pnpm add next@^15.5.15",
      );
    });
    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /Copied/i }),
      ).toBeInTheDocument();
    });
  });

  it("replaces the copy button with a 'View advisory' link when command is null", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
          suggested_command: null,
          recommended_version: null,
          target: {
            kind: "Package",
            ecosystem: "pypi",
            name: "h11",
            version: "0.14.0",
          },
        }),
      ]),
    );
    wrap();
    expect(
      await screen.findByRole("link", { name: /View advisory/i }),
    ).toHaveAttribute("href", "/packages/pypi/h11");
    expect(
      screen.queryByRole("button", { name: /Copy fix/i }),
    ).toBeNull();
  });

  it("drops lower severity groups when min_severity filter tightens the URL", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp(
        [
          pkgAction({
            id: "crit-1",
            kind: "FixCveCritical",
            severity: "Critical",
          }),
        ],
        /* total pre-filter */ 12,
      ),
    );
    wrap(["/actions?min_severity=high"]);
    await waitFor(() => {
      expect(api.actions).toHaveBeenLastCalledWith(
        { min_severity: "high" },
        undefined,
      );
    });
    expect(
      await screen.findByRole("heading", { name: "Critical" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Medium" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Low" })).toBeNull();
  });

  it("threads ?project=<path> into the API call and shows the scope label", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(resp([]));
    wrap(["/actions?project=/tmp/repo-a"]);
    await waitFor(() => {
      expect(api.actions).toHaveBeenLastCalledWith({}, "/tmp/repo-a");
    });
    // ScopeBadge renders the canonical tail — "repo-a" in this case.
    expect(await screen.findByText(/Scope:/)).toBeInTheDocument();
  });

  it("shows the empty-state message when no actions match the current scope", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(resp([]));
    wrap();
    expect(
      await screen.findByText(/You're clear/i),
    ).toBeInTheDocument();
  });

  it("opens the dismiss panel, forwards the reason, and invalidates the list on confirm", async () => {
    const first = resp([
      pkgAction({ id: "crit-1", kind: "FixCveCritical", severity: "Critical" }),
    ]);
    const second = resp([]); // after dismiss + invalidate the card is gone
    (api.actions as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(first)
      .mockResolvedValue(second);
    (api.dismissAction as ReturnType<typeof vi.fn>).mockResolvedValue({
      dismissed_at: "2026-04-24T12:00:00Z",
    });
    wrap();
    const user = userEvent.setup();
    const dismissButton = await screen.findByRole("button", {
      name: /Dismiss this action/i,
    });
    await user.click(dismissButton);
    const textarea = await screen.findByLabelText(/Reason \(optional\)/i);
    await user.type(textarea, "accepted risk");
    await user.click(screen.getByRole("button", { name: /Confirm dismiss/i }));
    await waitFor(() => {
      expect(api.dismissAction).toHaveBeenCalledWith("crit-1", "accepted risk");
    });
    // Second fetch (post-invalidation) returns an empty list → empty state.
    await waitFor(() => {
      expect(screen.getByText(/You're clear/i)).toBeInTheDocument();
    });
  });

  it("opens the defer panel and sends the chosen window as days", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({ id: "crit-1", kind: "FixCveCritical", severity: "Critical" }),
      ]),
    );
    (api.deferAction as ReturnType<typeof vi.fn>).mockResolvedValue({
      deferred_until: "2026-05-01T12:00:00Z",
    });
    wrap();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: /Defer this action/i }),
    );
    await user.click(await screen.findByRole("button", { name: /^7 days$/i }));
    await waitFor(() => {
      expect(api.deferAction).toHaveBeenCalledWith("crit-1", 7);
    });
  });

  it("renders a Restore button on an archived action and calls DELETE", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
          dismissed_at: "2026-04-24T12:00:00Z",
        }),
      ]),
    );
    (api.restoreAction as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    wrap();
    const user = userEvent.setup();
    const restore = await screen.findByRole("button", { name: /Restore/i });
    expect(screen.getByText(/Archived/i)).toBeInTheDocument();
    await user.click(restore);
    await waitFor(() => {
      expect(api.restoreAction).toHaveBeenCalledWith("crit-1");
    });
  });

  it("renders the recommended_version arrow for Package targets", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue(
      resp([
        pkgAction({
          id: "crit-1",
          kind: "FixCveCritical",
          severity: "Critical",
          recommended_version: "4.17.21",
          target: {
            kind: "Package",
            ecosystem: "npm",
            name: "lodash",
            version: "4.17.20",
          },
        }),
      ]),
    );
    wrap();
    const group = await screen.findByRole("heading", { name: "Critical" });
    const section = group.closest("section")!;
    // The arrow renders the recommended version as its own span — match
    // the exact text so we don't accidentally pick up "lodash@4.17.20".
    expect(within(section).getByText("4.17.21")).toBeInTheDocument();
    expect(within(section).getByText("@4.17.20")).toBeInTheDocument();
  });
});
